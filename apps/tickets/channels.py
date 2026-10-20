"""
XPAM: approval requests in chat — Microsoft Teams, Slack and Telegram.

When a ticket waits for approval, a message with its details and an "Open approval" button is sent
to the configured channels (in addition to the e-mail to each approver). The button opens the
existing approval page (tickets:direct-approve); a channel link is not bound to one approver, so
the person must sign in there and must be an approver of the ticket. Approve/Reject happen with a
POST on that page, so link previews in chat apps can never approve anything.
"""
import json
import uuid
from urllib.parse import urljoin

from django.conf import settings
from django.core.cache import cache
from django.urls import reverse
from django.utils.translation import gettext as _

from common.utils import get_logger

logger = get_logger(__name__)

KEYS = {
    'teams_webhook': ('XPAM_APPROVAL_TEAMS_WEBHOOK', True),
    'slack_webhook': ('XPAM_APPROVAL_SLACK_WEBHOOK', True),
    'telegram_token': ('XPAM_APPROVAL_TELEGRAM_TOKEN', True),
    'telegram_chat': ('XPAM_APPROVAL_TELEGRAM_CHAT', False),
    'link_hours': ('XPAM_APPROVAL_LINK_HOURS', False),
    'remind_minutes': ('XPAM_APPROVAL_REMIND_MINUTES', False),
    'escalate_minutes': ('XPAM_APPROVAL_ESCALATE_MINUTES', False),
    'expire_hours': ('XPAM_APPROVAL_EXPIRE_HOURS', False),
}
DEFAULT_LINK_HOURS = 24
NUMBER_DEFAULTS = {'link_hours': (24, 1, 168), 'remind_minutes': (30, 0, 1440),
                   'escalate_minutes': (120, 0, 10080), 'expire_hours': (24, 0, 720)}
TIMEOUT = 10


def get_config():
    """{key: value} from the database (secrets decrypted)."""
    from settings.models import Setting
    names = {name: key for key, (name, _enc) in KEYS.items()}
    values = {key: '' for key in KEYS}
    for s in Setting.objects.filter(name__in=list(names)):
        try:
            values[names[s.name]] = s.cleaned_value
        except Exception:
            values[names[s.name]] = ''
    for key, (default, _lo, _hi) in NUMBER_DEFAULTS.items():
        try:
            values[key] = int(values[key]) if values[key] not in ('', None) else default
        except (TypeError, ValueError):
            values[key] = default
    return values


def save_config(data):
    from settings.models import Setting
    for key, (name, encrypted) in KEYS.items():
        if key not in data:
            continue
        value = data[key]
        if key in NUMBER_DEFAULTS:
            default, lo, hi = NUMBER_DEFAULTS[key]
            value = str(max(lo, min(int(value if value not in ('', None) else default), hi)))
        Setting.update_or_create(name=name, value=(value or '').strip() if isinstance(value, str) else value,
                                 encrypted=encrypted, category='xpam_approval')


def link_seconds():
    return get_config()['link_hours'] * 3600


def _approval_link(ticket, content):
    """A link to the approval page that is not bound to one approver (they sign in there)."""
    token = uuid.uuid4().hex
    cache.set(token, {'ticket_id': ticket.id, 'approver_id': None, 'content': content}, link_seconds())
    return urljoin(settings.SITE_URL, reverse('tickets:direct-approve', kwargs={'token': token}))


def _page_content(ticket):
    """The ticket details shown on the approval page (same as in the approval e-mail)."""
    from tickets.notifications import TicketAppliedToAssigneeMessage
    from tickets.views.approve import TicketDirectApproveView
    sub_model = TicketDirectApproveView.TICKET_SUB_MODEL_MAP.get(ticket.type)
    sub = sub_model.objects.filter(id=ticket.id).first() if sub_model else None
    return TicketAppliedToAssigneeMessage(ticket.applicant, sub or ticket).content


def _summary(ticket):
    """(title, [(label, value)], reason) of a ticket for chat messages."""
    from tickets.models import ApplyAssetTicket
    rows = [(_('Applicant'), str(ticket.applicant)), (_('Type'), str(ticket.get_type_display()))]
    reason = (ticket.comment or '').strip()
    sub = ApplyAssetTicket.objects.filter(id=ticket.id).first()
    if sub:
        assets = list(sub.apply_assets.values_list('name', flat=True)[:10])
        nodes = list(sub.apply_nodes.values_list('value', flat=True)[:5])
        if assets:
            rows.append((_('Assets'), ', '.join(assets)))
        if nodes:
            rows.append((_('Nodes'), ', '.join(nodes)))
        if sub.apply_date_start and sub.apply_date_expired:
            from common.utils.timezone import as_current_tz
            fmt = '%Y-%m-%d %H:%M'
            hours = round((sub.apply_date_expired - sub.apply_date_start).total_seconds() / 3600, 1)
            rows.append((_('Time'), '%s → %s (%s h)' % (as_current_tz(sub.apply_date_start).strftime(fmt),
                                                       as_current_tz(sub.apply_date_expired).strftime(fmt), hours)))
    if ticket.process_map and len(ticket.process_map) > 1:
        rows.append((_('Approval level'), '%s / %s' % (ticket.approval_step, len(ticket.process_map))))
    title = _('Approval needed: %s') % ticket.title
    return title, rows, reason


# Request text comes from the requester: no markup of theirs may reach the approvers' channel (fake
# links, @channel mentions...)
def _slack_text(value):
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _teams_text(value):
    # Adaptive Cards have no reliable escaping: break link syntax ([text](url)) instead
    return str(value).replace('[', '\uff3b').replace(']', '\uff3d')


def _teams_payload(title, rows, reason, link):
    facts = [{'title': _teams_text(k), 'value': _teams_text(v)} for k, v in rows]
    if reason:
        facts.append({'title': _('Reason'), 'value': _teams_text(reason)})
    card = {
        '$schema': 'http://adaptivecards.io/schemas/adaptive-card.json', 'type': 'AdaptiveCard', 'version': '1.4',
        'body': [{'type': 'TextBlock', 'text': _teams_text(title), 'weight': 'Bolder', 'size': 'Medium',
                  'wrap': True},
                 {'type': 'FactSet', 'facts': facts}],
        'actions': [{'type': 'Action.OpenUrl', 'title': _('Open approval'), 'url': link}],
    }
    return {'type': 'message', 'attachments': [
        {'contentType': 'application/vnd.microsoft.card.adaptive', 'contentUrl': None, 'content': card}]}


def _slack_payload(title, rows, reason, link):
    lines = '\n'.join(f'*{_slack_text(k)}:* {_slack_text(v)}' for k, v in rows)
    if reason:
        lines += f'\n*{_("Reason")}:* {_slack_text(reason)}'
    return {
        'text': f'{_slack_text(title)} — {link}',
        'blocks': [
            {'type': 'header', 'text': {'type': 'plain_text', 'text': title[:150]}},
            {'type': 'section', 'text': {'type': 'mrkdwn', 'text': lines[:2900]}},
            {'type': 'actions', 'elements': [{'type': 'button', 'style': 'primary', 'url': link,
                                              'text': {'type': 'plain_text', 'text': _('Open approval')}}]},
        ],
    }


def _telegram_payload(chat, title, rows, reason, link):
    from html import escape
    text = f'<b>{escape(title)}</b>\n' + '\n'.join(f'<b>{escape(k)}:</b> {escape(v)}' for k, v in rows)
    if reason:
        text += f'\n<b>{escape(_("Reason"))}:</b> {escape(reason)}'
    text += f'\n\n{escape(link)}'
    return {'chat_id': chat, 'text': text[:4000], 'parse_mode': 'HTML', 'disable_web_page_preview': True,
            'reply_markup': {'inline_keyboard': [[{'text': _('Open approval'), 'url': link}]]}}


def deliveries(title, rows, reason, link, config=None):
    """[(channel, url, payload)] for the configured channels."""
    config = config or get_config()
    out = []
    if config.get('teams_webhook'):
        out.append(('teams', config['teams_webhook'], _teams_payload(title, rows, reason, link)))
    if config.get('slack_webhook'):
        out.append(('slack', config['slack_webhook'], _slack_payload(title, rows, reason, link)))
    if config.get('telegram_token') and config.get('telegram_chat'):
        url = f"https://api.telegram.org/bot{config['telegram_token']}/sendMessage"
        out.append(('telegram', url, _telegram_payload(config['telegram_chat'], title, rows, reason, link)))
    return out


def webhook_problem(url):
    """'' when url may receive messages, else the reason. Teams, Slack and Telegram are public services:
    an address that resolves to a private, loopback, link-local or otherwise non-public IP is refused,
    so the settings and their test button cannot reach XPAM's containers or the internal network."""
    import ipaddress
    import socket
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port or 443
    except ValueError:
        return _('The webhook address is not valid')
    if parts.scheme != 'https' or not host:
        return _('The webhook address must start with https://')
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        import requests
        if requests.utils.get_environ_proxies(url):
            return ''  # (resolved by the outgoing proxy)
        return _('The webhook host cannot be resolved')
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split('%')[0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            return _('The webhook address must be a public internet address')
    return ''


def post(channel, url, payload):
    """(ok, message) — the URL is never logged (it holds the secret)."""
    import requests
    problem = webhook_problem(url)
    if problem:
        return False, problem
    try:
        # no redirects (a 307 would replay the POST elsewhere) and never the response body back to the
        # caller: the test button must not become a way to read internal services
        r = requests.post(url, data=json.dumps(payload), headers={'Content-Type': 'application/json'},
                          timeout=TIMEOUT, allow_redirects=False)
        if 200 <= r.status_code < 300:
            return True, ''
        return False, f'HTTP {r.status_code}'
    except Exception as e:
        return False, e.__class__.__name__


def notify(ticket):
    """Queue chat messages for a ticket that now waits for approval."""
    try:
        config = get_config()
        if not deliveries('', [], '', '', config):
            return
        from tickets.tasks import xpam_send_approval_messages
        xpam_send_approval_messages.delay(str(ticket.id))
    except Exception as e:
        logger.warning('XPAM approval chat messages for %s not queued: %s', ticket, e)


def send_for_ticket(ticket_id, prefix=''):
    from orgs.utils import tmp_to_root_org
    from tickets.models import Ticket
    with tmp_to_root_org():
        ticket = Ticket.all().filter(id=ticket_id).first()
        if not ticket or ticket.status != 'open':
            return {}
        title, rows, reason = _summary(ticket)
        if prefix:
            title = f'{prefix}: {title}'
        link = _approval_link(ticket, _page_content(ticket))
    results = {}
    for channel, url, payload in deliveries(title, rows, reason, link):
        ok, msg = post(channel, url, payload)
        results[channel] = ok
        if not ok:
            logger.warning('XPAM approval message to %s failed: %s', channel, msg)
    return results


def send_test(config):
    """Send a test message to every configured channel. {channel: (ok, message)}"""
    title = _('XPAM test: approval messages work')
    rows = [(_('Applicant'), 'XPAM'), (_('Assets'), 'web-01'), (_('Time'), '1 h')]
    link = urljoin(settings.SITE_URL, '/')
    return {channel: post(channel, url, payload)
            for channel, url, payload in deliveries(title, rows, _('Test message'), link, config)}

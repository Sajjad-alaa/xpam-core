"""
XPAM: approvals inbox — the access requests waiting for the current user, with the context an approver
needs (reason, time, rights, first time on these assets, outside working hours), and approve/reject
with a comment the requester sees.
"""
from django.utils import timezone
from django.utils.translation import gettext as _

from common.utils import get_logger
from orgs.utils import tmp_to_org, tmp_to_root_org
from perms.const import ActionChoices

logger = get_logger(__name__)


class ApprovalError(Exception):
    pass


def _flags(ticket, policies, assets):
    from tickets.models import ApplyAssetTicket
    flags = []
    if ticket.apply_date_start and ticket.apply_date_expired:
        hours = (ticket.apply_date_expired - ticket.apply_date_start).total_seconds() / 3600
        if hours > 8:
            flags.append({'key': 'long', 'text': _('Long access: %s h') % round(hours, 1)})
    if any(p and p.privileged for p in policies):
        flags.append({'key': 'admin', 'text': _('Administrator rights')})
    local = timezone.localtime(ticket.date_created)
    if local.weekday() >= 5 or not 7 <= local.hour < 19:
        flags.append({'key': 'off_hours', 'text': _('Asked outside working hours')})
    since = timezone.now() - timezone.timedelta(days=90)
    asset_ids = [a.id for a in assets]
    before = ApplyAssetTicket.objects.filter(applicant_id=ticket.applicant_id, state='approved',
                                             date_created__gte=since, apply_assets__in=asset_ids) \
        .exclude(id=ticket.id).exists()
    if asset_ids and not before:
        flags.append({'key': 'first_time', 'text': _('First request for these assets (90 days)')})
    if any(p is None for p in policies):
        flags.append({'key': 'no_rule', 'text': _('No just-in-time rule covers some assets')})
    return flags


def pending_for(user, limit=50):
    from tickets.models import ApplyAssetTicket
    from .selfservice import ticket_policies
    result = []
    with tmp_to_root_org():
        qs = ApplyAssetTicket.objects.filter(status='open', ticket_steps__ticket_assignees__assignee=user) \
            .select_related('applicant').distinct().order_by('date_created')
        for ticket in qs[:200]:
            if not ticket.has_current_assignee(user):
                continue
            mapping = ticket_policies(ticket)
            assets = list(mapping.keys())
            policies = list(mapping.values())
            hours = None
            if ticket.apply_date_start and ticket.apply_date_expired:
                hours = round((ticket.apply_date_expired - ticket.apply_date_start).total_seconds() / 3600, 1)
            result.append({
                'id': str(ticket.id), 'serial_num': ticket.serial_num, 'title': ticket.title,
                'org_id': str(ticket.org_id),
                'applicant': {'id': str(ticket.applicant_id), 'name': str(ticket.applicant)},
                'reason': ticket.comment, 'assets': [a.name for a in assets[:20]], 'assets_count': len(assets),
                'rules': sorted({p.name for p in policies if p}),
                'date_start': ticket.apply_date_start, 'date_expired': ticket.apply_date_expired, 'hours': hours,
                'date_created': ticket.date_created,
                # XPAM: what the access would allow (the approver sees what they approve)
                'protocols': list(ticket.apply_protocols or []) or ['all'],
                'actions': [c.name for c in ActionChoices if ticket.apply_actions & c.value],
                'level': ticket.approval_step, 'levels': ticket.ticket_steps.count(),
                'flags': _flags(ticket, policies, assets),
            })
            if len(result) >= limit:
                break
    return result


def decide(user, ticket_id, action, comment=''):
    from tickets.models import ApplyAssetTicket, Comment
    from tickets.errors import AlreadyClosed, TicketStateChanged
    if action not in ('approve', 'reject'):
        raise ApprovalError(_('Illegal approval action'))
    comment = (comment or '').strip()[:1000]
    if action == 'reject' and not comment:
        raise ApprovalError(_('Tell the requester why the request is rejected'))
    with tmp_to_root_org():
        ticket = ApplyAssetTicket.objects.filter(id=ticket_id).first()
    if not ticket:
        raise ApprovalError(_('Request not found'))
    if ticket.applicant_id == user.id:
        raise ApprovalError(_('You cannot approve your own request'))
    if not ticket.has_current_assignee(user):
        raise ApprovalError(_('You are not an approver of this request (or it was already decided)'))
    if comment:
        Comment.objects.create(ticket=ticket, body=comment, user=user, user_display=str(user), type='common')
    try:
        with tmp_to_org(ticket.org_id):
            getattr(ticket, action)(user)
    except (AlreadyClosed, TicketStateChanged) as e:
        raise ApprovalError(str(e))
    ticket.refresh_from_db()
    return ticket


def decision_note(ticket):
    """The last comment of an approver (for the requester)."""
    from tickets.models import Comment
    # comments without a user are XPAM's own (approval route, escalation...), not an approver's note
    c = Comment.objects.filter(ticket=ticket, type='common', user__isnull=False) \
        .exclude(user_id=ticket.applicant_id).order_by('-date_created').first()
    if c:
        return {'by': c.user_display, 'text': c.body}
    if ticket.state == 'closed':
        # closed by XPAM (nobody approved in time, the time was over): say so
        c = Comment.objects.filter(ticket=ticket, type='common', user__isnull=True).order_by('-date_created').first()
        if c:
            return {'by': 'XPAM', 'text': c.body}
    return None


def pending_count(user):
    from tickets.models import ApplyAssetTicket
    with tmp_to_root_org():
        qs = ApplyAssetTicket.objects.filter(status='open', ticket_steps__ticket_assignees__assignee=user).distinct()
        return sum(1 for t in qs[:200] if t.has_current_assignee(user))

"""
Zero standing privilege overview, access trails and converting standing access to just-in-time.
"""
from collections import Counter

from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from common.utils import get_logger
from .policy import PolicyMatcher, target_kind

logger = get_logger(__name__)

NOT_STANDING = {'@SPEC', '@JIT'}


def standing_aliases(perm):
    """The accounts a permission gives all the time (not just-in-time)."""
    return [a for a in (perm.accounts or []) if a not in NOT_STANDING and not str(a).startswith('!')]


def _hidden_by_jit_only(perm, matcher):
    """A "just-in-time account only" policy hides the standing accounts (checked on one user/asset)."""
    user = perm.get_all_users().filter(is_active=True).first()
    asset = perm.get_all_assets().first()
    if not user or not asset:
        return False
    policy = matcher.policy_for(perm, user, asset)
    return bool(policy and policy.jit_only)


def dashboard():
    from accounts.models import JITAccount, JITPolicy
    from perms.models import AssetPermission
    from tickets.models import ApplyAssetTicket
    now = timezone.now()
    today = timezone.localtime(now).replace(hour=0, minute=0, second=0, microsecond=0)
    week = now - timezone.timedelta(days=7)
    jits = JITAccount.objects.all()
    live = jits.filter(status__in=JITAccount.ACTIVE_STATUSES)
    recent = jits.filter(date_created__gte=week)

    days = []
    for i in range(13, -1, -1):
        start = today - timezone.timedelta(days=i)
        end = start + timezone.timedelta(days=1)
        day = jits.filter(date_created__gte=start, date_created__lt=end)
        days.append({'date': start.date().isoformat(), 'created': day.exclude(status='failed').count(),
                     'failed': day.filter(status='failed').count()})

    top_users = Counter(recent.values_list('user_display', flat=True)).most_common(5)
    top_assets = Counter(recent.values_list('asset_display', flat=True)).most_common(5)

    requests = ApplyAssetTicket.objects.filter(date_created__gte=week)
    approved = requests.filter(state='approved')
    auto = approved.exclude(apply_jit_auto='')
    waits = [(t.date_updated - t.date_created).total_seconds() for t in approved.filter(apply_jit_auto='')[:500]]
    waits.sort()

    # Zero standing privilege: assets that people can reach only through just-in-time access
    matcher = PolicyMatcher()
    perms = AssetPermission.objects.valid().prefetch_related('assets', 'nodes')
    with_access, standing_assets, standing_perms = set(), set(), []
    for perm in perms[:2000]:
        asset_ids = set(perm.get_all_assets().values_list('id', flat=True)[:5000])
        with_access |= asset_ids
        aliases = standing_aliases(perm)
        if not aliases or _hidden_by_jit_only(perm, matcher):
            continue
        standing_assets |= asset_ids
        if len(standing_perms) < 50:
            standing_perms.append({
                'id': str(perm.id), 'name': perm.name, 'accounts': aliases[:10],
                'users': perm.get_all_users().count(), 'assets': len(asset_ids),
                'date_expired': perm.date_expired, 'from_ticket': perm.from_ticket,
            })
    total = len(with_access)
    score = round(100 * (total - len(standing_assets)) / total) if total else 100
    standing_perms.sort(key=lambda p: -(p['users'] * p['assets']))

    return {
        'live': live.count(),
        'live_by_status': dict(Counter(live.values_list('status', flat=True))),
        'live_by_kind': dict(Counter(live.values_list('kind', flat=True))),
        'created_today': jits.filter(date_created__gte=today).exclude(status='failed').count(),
        'created_week': recent.exclude(status='failed').count(),
        'failed_week': recent.filter(status='failed').count(),
        'removed_today': jits.filter(date_removed__gte=today).count(),
        'days': days,
        'top_users': [{'name': n, 'count': c} for n, c in top_users if n],
        'top_assets': [{'name': n, 'count': c} for n, c in top_assets if n],
        'policies': JITPolicy.objects.filter(is_active=True).count(),
        'policies_auto': JITPolicy.objects.filter(is_active=True, auto_approve=True).count(),
        'policies_jit_only': JITPolicy.objects.filter(is_active=True, jit_only=True).count(),
        'requests_week': requests.count(),
        'requests_auto_week': auto.count(),
        'requests_pending': ApplyAssetTicket.objects.filter(status='open').count(),
        'median_wait_seconds': int(waits[len(waits) // 2]) if waits else None,
        'zsp': {'score': score, 'assets_with_access': total, 'standing_assets': len(standing_assets),
                'jit_only_assets': total - len(standing_assets), 'standing_permissions': standing_perms},
        'server_time': now,
    }


def trail(jit):
    """Everything that happened around one just-in-time account, oldest first."""
    from perms.models import AssetPermission
    from terminal.models import Command, Session
    from tickets.models import ApplyAssetTicket
    events = []

    order = {'request': 0, 'approve': 1, 'grant': 1, 'create': 2, 'ready': 3, 'session': 4, 'session_end': 5, 'remove': 6}

    def add(when, kind, text, **extra):
        if isinstance(when, str):
            from django.utils.dateparse import parse_datetime
            when = parse_datetime(when.replace(' ', 'T', 1)) or when
        if when:
            events.append({'time': when, 'kind': kind, 'text': text, **extra})

    perm = AssetPermission.objects.filter(id=jit.permission_id).first() if jit.permission_id else None
    ticket = ApplyAssetTicket.objects.filter(id=jit.permission_id).first() if jit.permission_id else None
    if ticket:
        add(ticket.date_created, 'request', _('%(user)s requested access (%(title)s)') % {
            'user': ticket.applicant, 'title': ticket.title}, reason=ticket.comment, ticket=str(ticket.id))
        if ticket.apply_jit_auto:
            add(ticket.date_updated, 'approve', _('Approved automatically by the policy %s') % ticket.apply_jit_auto)
        else:
            for step in ticket.process_map:
                if step['state'] in ('approved', 'rejected'):
                    add(step['approval_date'], 'approve', _('%(who)s %(state)s the request (level %(level)s)') % {
                        'who': step['processor_display'] or '-', 'state': step['state'], 'level': step['approval_level']})
    elif perm:
        add(perm.date_created, 'grant', _('Asset permission "%s"') % perm.name)
    add(jit.date_created, 'create', _('Just-in-time account %(name)s requested on %(asset)s (%(policy)s)') % {
        'name': jit.username, 'asset': jit.asset_display, 'policy': jit.policy or '-'})
    if jit.date_ready:
        add(jit.date_ready, 'ready', _('Account created on the asset') +
            (' (%s)' % _('administrator rights') if jit.privileged else ''))
    # The account row is gone once the account is removed: match the sessions by user, asset and name
    sessions = Session.objects.filter(asset_id=str(jit.asset_id), date_start__gte=jit.date_created)
    if jit.account_id:
        sessions = sessions.filter(account_id=str(jit.account_id))
    else:
        sessions = sessions.filter(user_id=str(jit.user_id), account__icontains=jit.username)
    if jit.date_removed:
        sessions = sessions.filter(date_start__lte=jit.date_removed)
    if jit.asset_id:
        sessions = sessions.order_by('date_start')[:100]
        for s in sessions:
            try:
                commands = Command.objects.filter(session=str(s.id)).count()
            except Exception:
                commands = None
            add(s.date_start, 'session', _('%(proto)s session from %(addr)s') % {
                'proto': s.protocol, 'addr': s.remote_addr or '-'},
                session=str(s.id), date_end=s.date_end, commands=commands, finished=s.is_finished)
            if s.date_end:
                add(s.date_end, 'session_end', _('Session ended'), session=str(s.id))
    if jit.status in ('removed', 'remove_failed', 'failed') or jit.date_removed:
        add(jit.date_removed or jit.date_updated, 'remove',
            _('Account removed') if jit.status == 'removed' else jit.get_status_display(),
            reason=jit.error)
    def key(e):
        t = e['time']
        ts = t.timestamp() if hasattr(t, 'timestamp') else 0
        return int(ts), order.get(e['kind'], 9), ts
    events.sort(key=key)
    return events


def convert_to_jit(perm, user=None):
    """Take the standing accounts out of a permission; its users keep access through just-in-time."""
    aliases = standing_aliases(perm)
    if not aliases:
        return []
    keep = [a for a in perm.accounts if a not in aliases] or ['@SPEC']
    if '@SPEC' not in keep:
        keep.append('@SPEC')
    note = _('XPAM: standing accounts before the conversion to just-in-time (%(when)s, %(who)s): %(accounts)s') % {
        'when': timezone.localtime().strftime('%Y-%m-%d %H:%M'), 'who': user or '-', 'accounts': ', '.join(aliases)}
    perm.accounts = keep
    perm.jit_disabled = False
    perm.comment = ((perm.comment or '') + '\n' + note).strip()[:4096]
    perm.save(update_fields=['accounts', 'jit_disabled', 'comment'])
    return aliases


def coverage_after_convert(perm):
    """Which policy would give the users of `perm` a just-in-time account (sample: first user/asset)."""
    matcher = PolicyMatcher()
    user = perm.get_all_users().filter(is_active=True).first()
    assets = [a for a in perm.get_all_assets()[:20] if target_kind(a)]
    if not user or not assets:
        return None
    for asset in assets:
        policy = matcher.policy_for(perm, user, asset)
        if policy:
            return policy
    return None

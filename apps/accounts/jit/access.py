"""
XPAM: the access a request (ticket) gave, shown on the ticket to the requester, its approvers and administrators —
whether it is active and until when, the assets, protocols and actions, the just-in-time accounts and the
sessions. The requester can end it; an approver or an administrator can revoke it: the access ends now, its
just-in-time accounts are removed and the live sessions it allowed are ended.

The access of a request is the permission with the same id (or, for an extension, the permission it extended).
"""
from django.utils import timezone
from django.utils.translation import gettext as _

from common.utils import get_logger
from orgs.utils import tmp_to_org, tmp_to_root_org
from perms.const import ActionChoices

logger = get_logger(__name__)

ACTIVE_STATES = ('active', 'scheduled')


class AccessError(Exception):
    pass


def permission_id_of(ticket):
    """ the access a request gave: its own permission (same id), or the one an extension extended """
    return str(ticket.apply_extends or ticket.id)


def permission_of(ticket):
    from perms.models import AssetPermission
    if ticket.type != 'apply_asset' or ticket.state != 'approved':
        return None
    with tmp_to_root_org():
        return AssetPermission.objects.filter(id=permission_id_of(ticket), from_ticket=True).first()


def state_of(perm, planned_end, now=None):
    """ scheduled | active | ended (before its planned end: revoked or ended by the requester) | expired """
    now = now or timezone.now()
    if perm.date_start and perm.date_start > now:
        return 'scheduled'
    if perm.date_expired > now:
        return 'active'
    if planned_end and perm.date_expired < planned_end - timezone.timedelta(minutes=1):
        return 'ended'
    return 'expired'


def access_states(tickets):
    """ {ticket id: {state, date_expired}} for the approved access requests among `tickets` (two queries) """
    from perms.models import AssetPermission
    from tickets.models import ApplyAssetTicket
    ids = [t.id for t in tickets if t.type == 'apply_asset' and t.state == 'approved']
    if not ids:
        return {}
    with tmp_to_root_org():
        rows = list(ApplyAssetTicket.objects.filter(id__in=ids).values('id', 'apply_extends', 'apply_date_expired'))
        perms = {str(p.id): p for p in AssetPermission.objects.filter(
            id__in={str(r['apply_extends'] or r['id']) for r in rows}).only('id', 'date_start', 'date_expired')}
    now = timezone.now()
    states = {}
    for r in rows:
        perm = perms.get(str(r['apply_extends'] or r['id']))
        if perm:
            states[str(r['id'])] = {'state': state_of(perm, r['apply_date_expired'], now),
                                    'date_expired': perm.date_expired}
    return states


def can_revoke(ticket, user, perm):
    """ an approver of the request, or whoever may change permissions in its organization """
    if user.is_superuser or ticket.has_all_assignee(user):
        return True
    with tmp_to_org(perm.org_id):
        return user.has_perm('perms.change_assetpermission')


def ticket_access(ticket, viewer):
    """ what the request gave, for the ticket page; None when it gave nothing (pending, rejected, closed) """
    from accounts.models import JITAccount
    from terminal.models import Session
    from tickets.models import ApplyAssetTicket
    from .policy import PolicyMatcher
    perm = permission_of(ticket)
    if perm is None:
        return None
    now = timezone.now()
    state = state_of(perm, ticket.apply_date_expired, now)
    applicant = ticket.applicant
    matcher = PolicyMatcher()
    with tmp_to_org(perm.org_id):
        assets = list(perm.get_all_assets().select_related('platform')[:50])
        policy = next((p for a in assets if (p := matcher.policy_for(perm, applicant, a))), None) if applicant else None
    with tmp_to_root_org():
        jits = list(JITAccount.objects.filter(permission_id=perm.id).order_by('-date_created')[:50])
        extensions_used = ApplyAssetTicket.objects.filter(apply_extends=str(perm.id), state='approved').count()
        sessions = list(Session.objects.filter(
            user_id=str(applicant.id) if applicant else '', asset_id__in=[str(a.id) for a in assets],
            date_start__gte=perm.date_start or perm.date_created,
            date_start__lte=perm.date_expired,
        ).order_by('-date_start')[:20]) if applicant else []
    is_applicant = applicant is not None and viewer.id == applicant.id
    active = state in ACTIVE_STATES
    allow_ext = getattr(policy, 'allow_extension', True) if policy else True
    max_ext = getattr(policy, 'max_extensions', 0) if policy else 0
    ext_allowed = allow_ext and (max_ext == 0 or extensions_used < max_ext)
    return {
        'state': state, 'permission_id': str(perm.id),
        'date_start': perm.date_start, 'date_expired': perm.date_expired,
        'planned_end': ticket.apply_date_expired,
        'seconds_left': max(0, int((perm.date_expired - now).total_seconds())) if active else 0,
        'assets': [{'id': str(a.id), 'name': a.name, 'address': a.address, 'platform': a.platform.name}
                   for a in assets],
        'protocols': list(perm.protocols or []) or ['all'],
        'actions': [c.name for c in ActionChoices if perm.actions & c.value],
        'accounts': [{'id': str(j.id), 'username': j.username, 'asset': j.asset_display, 'status': j.status,
                      'date_ready': j.date_ready, 'date_expired': j.date_expired} for j in jits],
        'sessions': [{'id': str(s.id), 'asset': s.asset, 'account': s.account, 'protocol': s.protocol,
                      'login_from': s.login_from, 'remote_addr': s.remote_addr, 'is_finished': s.is_finished,
                      'date_start': s.date_start, 'date_end': s.date_end} for s in sessions],
        'extension_policy': {
            'policy_name': policy.name if policy else '',
            'allow_extension': allow_ext,
            'extension_approval': getattr(policy, 'extension_approval', 'same') if policy else 'same',
            'max_hours': (getattr(policy, 'extension_max_hours', 0) or policy.max_hours) if policy else 8,
            'max_extensions': max_ext,
            'extensions_used': extensions_used,
            'require_reason': getattr(policy, 'require_reason', False) if policy else False,
        },
        'can': {
            'end': is_applicant and active,
            'extend': is_applicant and state == 'active' and ext_allowed,
            'revoke': active and can_revoke(ticket, viewer, perm),
        },
    }


def _covered_elsewhere(user, perm):
    """ the assets another current access of the user still covers (their sessions are not ended) """
    from django.db.models import Q
    from perms.models import AssetPermission
    if not user:
        return set()
    now = timezone.now()
    covered = set()
    with tmp_to_root_org():
        others = AssetPermission.objects.filter(
            Q(users=user) | Q(user_groups__users=user),
            is_active=True, date_start__lte=now, date_expired__gt=now,
        ).exclude(id=perm.id).distinct()
        for other in others[:50]:
            with tmp_to_org(other.org_id):
                covered |= {str(i) for i in other.get_all_assets().values_list('id', flat=True)[:5000]}
    return covered


def end_sessions(user, perm, by):
    """ the live sessions of `user` on the assets of `perm` (unless another access covers the asset) """
    from terminal.api.session.task import create_sessions_tasks
    from terminal.models import Session
    if not user:
        return []
    with tmp_to_org(perm.org_id):
        assets = {str(i) for i in perm.get_all_assets().values_list('id', flat=True)[:5000]}
    assets -= _covered_elsewhere(user, perm)
    if not assets:
        return []
    with tmp_to_root_org():
        ids = list(Session.objects.filter(user_id=str(user.id), asset_id__in=assets, is_finished=False)
                   .values_list('id', flat=True)[:200])
        return create_sessions_tasks(ids, by)


def revoke(ticket, by, reason=''):
    """ an approver or administrator ends the access now: accounts removed, live sessions ended, noted on the
    request """
    from .selfservice import _comment, release_grant
    perm = permission_of(ticket)
    if perm is None or state_of(perm, ticket.apply_date_expired) not in ACTIVE_STATES:
        raise AccessError(_('This access is not active'))
    if not can_revoke(ticket, by, perm):
        raise AccessError(_('Only an approver of the request or an administrator can revoke it'))
    reason = (reason or '').strip()[:512]
    note = _('Access revoked by %(user)s') % {'user': by} + (f': {reason}' if reason else '')
    release_grant(ticket.applicant, perm, reason=note)
    ended = end_sessions(ticket.applicant, perm, by)
    _comment(ticket, note)
    logger.info(f'access {perm.id} of {ticket.applicant} revoked by {by}; sessions ended: {len(ended)}')
    return {'sessions_ended': len(ended)}


def end(ticket, user):
    """ the requester ends their access now (as on the Access page) """
    from .selfservice import end_now
    if ticket.applicant_id != user.id:
        raise AccessError(_('Only the requester can end this access'))
    perm = permission_of(ticket)
    if perm is None or state_of(perm, ticket.apply_date_expired) not in ACTIVE_STATES:
        raise AccessError(_('This access is not active'))
    end_now(user, perm.id)

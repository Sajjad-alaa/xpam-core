"""
Self-service just-in-time access (zero standing privilege).

Users ask for time-boxed access to the assets a policy lets them request; the request is an
ordinary access request ticket, so the approval flow, history and notifications stay the same.
A policy can approve such requests by itself (who, how long, when), or ask for two approvers.
"""
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from common.utils import get_logger
from orgs.utils import tmp_to_org, tmp_to_root_org
from .policy import PolicyMatcher, asset_supports_jit, target_kind

logger = get_logger(__name__)

REQUEST_ACCOUNTS = ['@SPEC']  # no standing account: the account comes from the policy
MAX_ASSETS = 200


class SelfServiceError(Exception):
    pass


def _request_policy(matcher, user, asset):
    policy = matcher.rule_policy(user, asset, asset.org_id, from_ticket=True)
    if policy and asset_supports_jit(asset, policy):
        return policy
    return None


def requestable_assets(user, search='', limit=50):
    """[(asset, policy)]: the assets a policy lets `user` request (all organizations of the user)."""
    from assets.models import Asset
    matcher = PolicyMatcher()
    q = Q(pk__in=[])
    for org_id, policies in matcher.rules_by_org.items():
        for p in policies:
            if not (p.self_service and p.scope in (p.Scope.all, p.Scope.requests)
                    and matcher._includes(p, 'users', user)):
                continue
            value = p.assets.value or {}
            if value.get('type') == 'all':
                q |= Q(org_id=org_id)
            else:
                with tmp_to_org(org_id):
                    ids = list(p.assets.all().values_list('id', flat=True)[:5000])
                q |= Q(org_id=org_id, id__in=ids)
    with tmp_to_root_org():
        qs = Asset.objects.filter(q, is_active=True).select_related('platform')
        if search:
            qs = qs.filter(Q(name__icontains=search) | Q(address__icontains=search))
        result = []
        for asset in qs.order_by('name')[:limit * 4]:
            if not target_kind(asset):
                continue
            policy = _request_policy(matcher, user, asset)
            if not policy or not policy.self_service:
                continue
            result.append((asset, policy))
            if len(result) >= limit:
                break
    return result


def _expand_assets(ticket):
    assets = list(ticket.apply_assets.all()[:MAX_ASSETS + 1])
    for node in ticket.apply_nodes.all():
        assets.extend(node.get_all_assets()[:MAX_ASSETS + 1])
        if len(assets) > MAX_ASSETS:
            break
    unique = {a.id: a for a in assets}
    return list(unique.values())


def _hours(start, end):
    start = max(start or timezone.now(), timezone.now())
    return max(0.0, (end - start).total_seconds() / 3600)


def ticket_policies(ticket):
    """{asset: policy or None} for the assets of an access request (as the rules would apply)."""
    matcher = PolicyMatcher()
    with tmp_to_org(ticket.org_id):
        return {asset: _request_policy(matcher, ticket.applicant, asset) for asset in _expand_assets(ticket)}


def auto_approve_decision(ticket):
    """(policy names, '') when the policies approve the request by themselves, else (None, why not)."""
    if not ticket.apply_date_expired:
        return None, 'no end date'
    if any(a not in REQUEST_ACCOUNTS + ['@JIT'] for a in (ticket.apply_accounts or [])):
        return None, 'standing accounts requested'
    mapping = ticket_policies(ticket)
    if not mapping or len(mapping) > MAX_ASSETS:
        return None, 'no assets'
    hours = _hours(ticket.apply_date_start, ticket.apply_date_expired)
    names = []
    for asset, policy in mapping.items():
        if not policy:
            return None, f'no policy for {asset}'
        if not policy.auto_approve or policy.approvals_required > 1:
            return None, f'{policy} does not approve by itself'
        if hours > policy.auto_approve_max_hours + 1 / 60:
            return None, f'{policy}: longer than {policy.auto_approve_max_hours}h'
        if not policy.in_auto_approve_window():
            return None, f'{policy}: outside its time window'
        if policy.require_reason and not (ticket.comment or '').strip():
            return None, f'{policy}: reason required'
        if policy.name not in names:
            names.append(policy.name)
    return names, ''


def try_auto_approve(ticket):
    """Approve an access request right away when its policies allow it. True when approved."""
    from tickets.const import StepState, StepStatus, TicketState, TicketStatus
    from tickets.models import TicketStep
    try:
        names, why = auto_approve_decision(ticket)
    except Exception as e:
        logger.warning('JIT auto-approval check of %s failed: %s', ticket, e)
        return False
    if not names:
        logger.debug('JIT auto-approval of %s: %s', ticket, why)
        return False
    with transaction.atomic():
        steps = list(TicketStep.objects.filter(ticket=ticket).order_by('level'))
        if not steps:
            return False
        for step in steps:
            step.state = StepState.approved
            step.status = StepStatus.closed
            step.save(update_fields=['state', 'status', 'date_updated'])
        ticket.approval_step = steps[-1].level
        ticket.state = TicketState.approved
        ticket.status = TicketStatus.closed
        ticket.apply_jit_auto = ', '.join(names)[:128]
        ticket.save(update_fields=['approval_step', 'state', 'status', 'apply_jit_auto'])
        _comment(ticket, _('Approved automatically by the just-in-time policy: %s') % ', '.join(names),
                 kind='state')
        ticket.handler._create_asset_permission()
    try:
        from tickets.utils import send_ticket_processed_mail_to_applicant
        send_ticket_processed_mail_to_applicant(ticket, _('XPAM (approved automatically)'))
    except Exception as e:
        logger.debug('JIT approval mail failed: %s', e)
    logger.info('JIT: access request %s approved automatically by %s', ticket.serial_num, names)
    return True


def _comment(ticket, body, kind='common'):
    from tickets.models import Comment
    try:
        Comment.objects.create(ticket=ticket, body=body, user=None, user_display='XPAM', type=kind)
    except Exception as e:
        logger.debug('JIT ticket comment failed: %s', e)


def require_second_approval(ticket):
    """Policies with "two approvers": add a second approval step (someone other than the first)."""
    from tickets.models import TicketAssignee, TicketStep
    try:
        mapping = ticket_policies(ticket)
    except Exception as e:
        logger.warning('JIT approval check of %s failed: %s', ticket, e)
        return
    if not any(p and p.approvals_required >= 2 for p in mapping.values()):
        return
    steps = list(TicketStep.objects.filter(ticket=ticket).order_by('level'))
    if not steps or len(steps) >= 2:
        return
    first = steps[0]
    from orgs.models import Organization
    from users.models import User
    first_ids = list(first.ticket_assignees.values_list('assignee_id', flat=True))
    org = Organization.get_instance(ticket.org_id)
    candidates = list(first_ids) + [u.id for u in (org.admins if org else [])] + \
        [u.id for u in User.get_super_admins()]
    candidates = [uid for uid in dict.fromkeys(candidates) if uid != ticket.applicant_id]
    second = TicketStep.objects.create(ticket=ticket, level=first.level + 1)
    TicketAssignee.objects.bulk_create([TicketAssignee(assignee_id=uid, step=second) for uid in candidates])
    if len(candidates) < 2:
        logger.warning('JIT: %s needs two approvers but only one person can approve', ticket)
        _comment(ticket, _('Two approvals are required by the just-in-time policy, but only one person can '
                           'approve: add another approver to the approval flow'))
    else:
        _comment(ticket, _('Two approvals are required by the just-in-time policy: a second person approves '
                           'after the first'))


def drop_first_approver(ticket, step):
    """The person who approved the first step cannot approve the second one too."""
    nxt = step.next()
    if not nxt:
        return
    processor = step.processor
    if processor and nxt.ticket_assignees.exclude(assignee=processor).exists():
        nxt.ticket_assignees.filter(assignee=processor).delete()


# ---------------------------------------------------------------- the user's side

def submit(request, asset_ids, hours, reason='', title='', start=None, end=None):
    """Create an access request for `asset_ids`; it may be approved by itself. Returns the ticket."""
    from assets.models import Asset
    with tmp_to_root_org():
        assets = list(Asset.objects.filter(id__in=list(asset_ids)[:MAX_ASSETS], is_active=True)
                      .select_related('platform'))
    if not assets:
        raise SelfServiceError(_('Choose at least one asset you can request'))
    orgs = {str(a.org_id) for a in assets}
    if len(orgs) > 1:
        raise SelfServiceError(_('Request assets of one organization at a time'))
    with tmp_to_org(orgs.pop()):
        return _submit(request, assets, hours, reason, title, start, end)


def _submit(request, assets, hours, reason, title, start, end):
    from orgs.utils import current_org
    from tickets.models import TicketFlow
    from tickets.serializers import ApplyAssetSerializer
    user = request.user
    matcher = PolicyMatcher()
    policies = {}
    for asset in assets:
        policy = _request_policy(matcher, user, asset)
        if not policy or not policy.self_service:
            raise SelfServiceError(_('You cannot request access to %s') % asset)
        policies[asset] = policy
    max_hours = min(p.max_hours for p in policies.values())
    start = start or timezone.now()
    if end is None:
        try:
            hours = float(hours)
        except (TypeError, ValueError):
            raise SelfServiceError(_('Choose how long you need access'))
        end = start + timezone.timedelta(hours=hours)
    if not 0 < _hours(start, end) <= max_hours + 1 / 60:
        raise SelfServiceError(_('You can request at most %s hours for these assets') % max_hours)
    if any(p.require_reason for p in policies.values()) and not (reason or '').strip():
        raise SelfServiceError(_('Enter the reason for the access'))
    flow = TicketFlow.get_org_related_flows(org_id=current_org.id).filter(type='apply_asset') \
        .order_by('date_created').first()
    if not flow:
        raise SelfServiceError(_('No approval flow for access requests is set up in this organization'))
    names = ', '.join(a.name for a in assets[:3]) + (' …' if len(assets) > 3 else '')
    data = {
        'title': (title or _('Access to %(assets)s for %(hours)s h') % {
            'assets': names, 'hours': round(_hours(start, end), 1)})[:128],
        'type': 'apply_asset', 'org_id': str(current_org.id), 'flow_id': str(flow.id),
        'apply_assets': [str(a.id) for a in assets], 'apply_nodes': [],
        'apply_accounts': REQUEST_ACCOUNTS, 'apply_actions': ['connect', 'upload', 'download', 'copy', 'paste'],
        'apply_date_start': start.isoformat(), 'apply_date_expired': end.isoformat(),
        'comment': (reason or '').strip()[:1024],
    }
    serializer = ApplyAssetSerializer(data=data, context={'request': request})
    if not serializer.is_valid():
        raise SelfServiceError('; '.join(f'{k}: {v}' for k, v in serializer.errors.items()))
    ticket = serializer.save()
    ticket.save(update_fields=['applicant'])
    ticket.open()
    ticket.refresh_from_db()
    return ticket


def _perm_assets(perm, limit=50):
    return list(perm.get_all_assets()[:limit])


def my_access(user):
    """What the user can use right now, what is waiting for approval, and the live accounts."""
    from accounts.models import JITAccount
    from perms.models import AssetPermission
    from tickets.models import ApplyAssetTicket
    now = timezone.now()
    matcher = PolicyMatcher()
    grants = []
    with tmp_to_root_org():
        perms = AssetPermission.objects.filter(
            from_ticket=True, is_active=True, date_expired__gt=now, users=user
        ).order_by('date_expired')
        for perm in perms:
            assets = _perm_assets(perm)
            policy = next((matcher.policy_for(perm, user, a) for a in assets if matcher.policy_for(perm, user, a)), None)
            grants.append({
                'id': str(perm.id), 'name': perm.name, 'org_id': str(perm.org_id),
                'assets': [{'id': str(a.id), 'name': a.name, 'address': a.address,
                            'type': a.platform.type, 'category': a.platform.category} for a in assets],
                'date_start': perm.date_start, 'date_expired': perm.date_expired,
                'active': perm.date_start <= now,
                'seconds_left': max(0, int((perm.date_expired - now).total_seconds())),
                'policy': {'id': str(policy.id), 'name': policy.name, 'max_hours': policy.max_hours,
                           'auto_approve': policy.auto_approve,
                           'auto_approve_max_hours': policy.auto_approve_max_hours,
                           'require_reason': policy.require_reason,
                           'warn_minutes': policy.expiry_warning_minutes} if policy else None,
            })
        pending = []
        for t in ApplyAssetTicket.objects.filter(applicant=user, status='open').order_by('-date_created')[:20]:
            pending.append({
                'id': str(t.id), 'title': t.title, 'serial_num': t.serial_num, 'org_id': str(t.org_id),
                'assets': [a.name for a in t.apply_assets.all()[:10]],
                'date_start': t.apply_date_start, 'date_expired': t.apply_date_expired,
                'date_created': t.date_created, 'reason': t.comment,
            })
        recent = []
        for t in ApplyAssetTicket.objects.filter(applicant=user, status='closed',
                                                 date_updated__gt=now - timezone.timedelta(days=7)) \
                .order_by('-date_updated')[:10]:
            recent.append({'id': str(t.id), 'title': t.title, 'state': t.state, 'auto': t.apply_jit_auto,
                           'date_updated': t.date_updated})
        accounts = [{
            'id': str(j.id), 'username': j.username, 'asset': j.asset_display, 'asset_id': str(j.asset_id or ''),
            'mode': j.mode, 'status': j.status, 'date_ready': j.date_ready, 'date_expired': j.date_expired,
        } for j in JITAccount.objects.filter(user=user, status__in=['pending', 'pushing', 'ready'])]
    return {'grants': grants, 'pending': pending, 'recent': recent, 'accounts': accounts,
            'server_time': now}


def _own_grant(user, perm_id):
    from perms.models import AssetPermission
    with tmp_to_root_org():
        perm = AssetPermission.objects.filter(id=perm_id, from_ticket=True, users=user).first()
    if not perm:
        raise SelfServiceError(_('This access is not yours'))
    return perm


def extend(request, perm_id, hours, reason=''):
    """Ask for more time: a new request for the same assets, ending `hours` after the current end."""
    perm = _own_grant(request.user, perm_id)
    try:
        hours = float(hours)
    except (TypeError, ValueError):
        raise SelfServiceError(_('Choose how long you need access'))
    if hours <= 0:
        raise SelfServiceError(_('Choose how long you need access'))
    now = timezone.now()
    end = max(perm.date_expired, now) + timezone.timedelta(hours=hours)
    with tmp_to_org(perm.org_id):
        asset_ids = [str(a.id) for a in perm.get_all_assets()[:MAX_ASSETS]]
    with tmp_to_root_org():
        names = ', '.join(perm.get_all_assets().values_list('name', flat=True)[:3])
    return submit(request, asset_ids, None, reason=reason or _('Extension'), start=now, end=end,
                  title=_('Extend access to %(assets)s by %(hours)s h') % {'assets': names, 'hours': hours})


def end_now(user, perm_id):
    """The user is done: the access ends now, sessions end and just-in-time accounts are removed."""
    from accounts.models import JITAccount
    from accounts.tasks.jit import jit_release_task
    perm = _own_grant(user, perm_id)
    now = timezone.now()
    with tmp_to_org(perm.org_id):
        perm.date_expired = now
        perm.save(update_fields=['date_expired'])
        asset_ids = list(perm.get_all_assets().values_list('id', flat=True)[:MAX_ASSETS])
    with tmp_to_root_org():
        jits = JITAccount.objects.filter(user=user, asset_id__in=asset_ids, status='ready')
        for jit in jits:
            jit_release_task.delay(str(jit.id), reason=str(_('Ended by %s') % user))
    return perm


def cancel(user, ticket_id):
    from tickets.models import ApplyAssetTicket
    with tmp_to_root_org():
        ticket = ApplyAssetTicket.objects.filter(id=ticket_id, applicant=user, status='open').first()
    if not ticket:
        raise SelfServiceError(_('This request cannot be cancelled'))
    ticket.close()
    return ticket

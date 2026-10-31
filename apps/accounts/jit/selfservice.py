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

REQUEST_ACCOUNTS = ['@JIT']  # no standing account: the just-in-time account of the rule
MAX_ASSETS = 200
# what a request asks for when the user does not choose: connecting and moving files/text (not delete, share)
DEFAULT_ACTIONS = ('connect', 'upload', 'download', 'copy', 'paste')


def _action_names(mask):
    from perms.const import ActionChoices
    return [c.name for c in ActionChoices if mask & c.value]


def _action_mask(actions):
    if actions is None or isinstance(actions, int):
        return actions
    from perms.const import ActionChoices
    if 'all' in actions:
        return ActionChoices.all()
    mask = 0
    for name in actions:
        if name in ActionChoices.names:
            mask |= getattr(ActionChoices, name)
    return mask


def request_options(asset, policy):
    """ XPAM: what a request for `asset` under `policy` may choose — the asset's protocols the rule allows, and the
    actions the rule allows """
    allowed = policy.protocols or ['all']
    names = [p.name for p in asset.protocols.all()]
    return {
        'protocols': names if 'all' in allowed else [n for n in names if n in allowed],
        'actions': _action_names(policy.actions),
    }


def _choose(policies, protocols, actions):
    """ (protocols, action names) for a request: within what every rule of the chosen assets allows. Nothing
    chosen: every protocol they allow ([] = all), and the usual actions they allow. """
    from perms.const import ActionChoices
    from tickets.serializers.ticket.apply_asset import clean_protocols
    allowed_protocols = None  # None: every protocol
    allowed_actions = ActionChoices.all()
    for p in policies:
        rule = [] if 'all' in (p.protocols or ['all']) else list(p.protocols)
        if rule:
            allowed_protocols = rule if allowed_protocols is None else [n for n in allowed_protocols if n in rule]
        allowed_actions &= p.actions
    if allowed_protocols == []:
        raise SelfServiceError(_('These assets allow different protocols: request them separately'))
    chosen = clean_protocols(protocols)
    if chosen and allowed_protocols is not None and not set(chosen) <= set(allowed_protocols):
        raise SelfServiceError(_('Protocols you can ask for these assets: %s') % ', '.join(allowed_protocols))
    if not chosen:
        chosen = list(allowed_protocols or [])
    names = [a for a in (actions or DEFAULT_ACTIONS) if a in ActionChoices.names]
    if 'connect' not in names:
        names.insert(0, 'connect')
    refused = [a for a in names if not allowed_actions & getattr(ActionChoices, a)]
    if refused and actions:
        raise SelfServiceError(_('Not allowed for these assets: %s') % ', '.join(refused))
    return chosen, [a for a in names if a not in refused]


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
                for aid in ids:
                    matcher._memo[(str(p.id), 'assets', str(aid))] = True
                q |= Q(org_id=org_id, id__in=ids)
    with tmp_to_root_org():
        qs = Asset.objects.filter(q, is_active=True).select_related(
            'platform', 'platform__automation'
        ).prefetch_related('protocols')
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
    assets = list(ticket.apply_assets.select_related(
        'platform', 'platform__automation'
    ).prefetch_related('protocols')[:MAX_ASSETS + 1])
    for node in ticket.apply_nodes.all():
        assets.extend(node.get_all_assets().select_related(
            'platform', 'platform__automation'
        ).prefetch_related('protocols')[:MAX_ASSETS + 1])
        if len(assets) > MAX_ASSETS:
            break
    unique = {a.id: a for a in assets}
    return list(unique.values())


def _hours(start, end):
    start = max(start or timezone.now(), timezone.now())
    return max(0.0, (end - start).total_seconds() / 3600)


def _visible(user, assets, matcher):
    """ XPAM: of `assets`, those `user` may know of: a rule that includes the user covers them, or a valid
    permission gives them to the user. Names of other assets are never answered (an error counts as "no"). """
    from perms.utils import PermAssetDetailUtil
    result = []
    for asset in assets:
        try:
            if matcher.rule_policy(user, asset, asset.org_id, from_ticket=True) is not None:
                result.append(asset)
                continue
            with tmp_to_org(asset.org_id):
                if list(PermAssetDetailUtil(user, asset).user_asset_perms)[:1]:
                    result.append(asset)
        except Exception as e:
            logger.debug('JIT visibility check of %s failed: %s', asset, e)
    return result


def coverage(user, asset_ids, node_ids, limit=MAX_ASSETS):
    """Which of the chosen assets a rule gives the user a just-in-time account on (request form)."""
    from assets.models import Asset, Node
    from common.utils import is_uuid
    asset_ids = [i for i in asset_ids if is_uuid(i)][:limit]
    node_ids = [i for i in node_ids if is_uuid(i)][:20]
    with tmp_to_root_org():
        assets = list(Asset.objects.filter(id__in=asset_ids).select_related(
            'platform', 'platform__automation'
        ).prefetch_related('protocols'))
        for node in Node.objects.filter(id__in=node_ids):
            assets.extend(node.get_all_assets().select_related(
                'platform', 'platform__automation'
            ).prefetch_related('protocols')[:limit])
    unique = list({a.id: a for a in assets}.values())[:limit]
    matcher = PolicyMatcher()
    # only assets of organizations the user belongs to (no names of other organizations' assets)
    unique = [a for a in unique if matcher._member(a.org_id, user)]
    known = len(unique)
    unique = _visible(user, unique, matcher)
    hidden = known - len(unique)  # (counted, never named)
    covered, uncovered, jit_only = [], [], False
    for asset in unique:
        policy = _request_policy(matcher, user, asset)
        if policy:
            covered.append({'id': str(asset.id), 'name': asset.name, 'rule': policy.name})
            jit_only = jit_only or policy.jit_only
        else:
            uncovered.append({'id': str(asset.id), 'name': asset.name})
    return {'covered': covered, 'uncovered': uncovered, 'jit_only': jit_only, 'unavailable': hidden}


def ticket_policies(ticket, matcher=None):
    """{asset: policy or None} for the assets of an access request (as the rules would apply)."""
    matcher = matcher or PolicyMatcher()
    with tmp_to_org(ticket.org_id):
        return {asset: _request_policy(matcher, ticket.applicant, asset) for asset in _expand_assets(ticket)}


def auto_approve_decision(ticket, mapping=None):
    """(policy names, '') when the policies approve the request by themselves, else (None, why not — in words)."""
    if mapping is None:
        mapping = ticket_policies(ticket)
    # (the reason is the request's comment: a title is not a reason — "Reason required" stays required)
    return _decision(mapping, ticket.apply_date_start, ticket.apply_date_expired, ticket.apply_accounts,
                     ticket.comment, protocols=ticket.apply_protocols, actions=ticket.apply_actions,
                     is_extension=bool(ticket.apply_extends))


def _decision(mapping, start, end, accounts, reason, protocols=None, actions=None, is_extension=False):
    from tickets.serializers.ticket.apply_asset import clean_protocols
    if not end:
        return None, _('the request has no end time')
    if any(a not in ('@JIT', '@SPEC') for a in (accounts or [])):
        return None, _('it asks for existing accounts, not just-in-time ones')
    if not mapping or len(mapping) > MAX_ASSETS:
        return None, _('no assets')
    asked_protocols = clean_protocols(protocols) if protocols is not None else None
    action_mask = _action_mask(actions)
    hours = _hours(start, end)
    names = []
    for asset, policy in mapping.items():
        if not policy:
            return None, _('no just-in-time rule covers %s') % asset
        if not policy.self_service:
            return None, _('the rule %s does not allow self-service requests') % policy
        if is_extension:
            if not getattr(policy, 'allow_extension', True):
                return None, _('the rule %s does not allow access extensions') % policy
            ext_mode = getattr(policy, 'extension_approval', 'same') or 'same'
            if ext_mode == 'manual':
                return None, _('the rule %s requires manual approval for extensions') % policy
            if policy.approvals_required > 1:
                # XPAM: four eyes also for extensions set to "approve automatically"
                return None, _('the rule %s asks for two approvers') % policy
            if ext_mode == 'same' and not policy.auto_approve:
                return None, _('the rule %s does not approve requests by itself') % policy
        elif not policy.auto_approve or policy.approvals_required > 1:
            return None, _('the rule %s does not approve requests by itself') % policy
        rule_protos = [] if 'all' in (policy.protocols or ['all']) else list(policy.protocols)
        if rule_protos and asked_protocols is not None and (
                not asked_protocols or not set(asked_protocols) <= set(rule_protos)):
            return None, _('the rule %(rule)s only allows %(protocols)s') % {
                'rule': policy, 'protocols': ', '.join(rule_protos)}
        if action_mask is not None and (action_mask & ~policy.actions):
            return None, _('the rule %s does not allow all requested actions') % policy
        auto_max = (
            (getattr(policy, 'extension_max_hours', 0) or policy.auto_approve_max_hours or policy.max_hours)
            if is_extension
            else policy.auto_approve_max_hours
        )
        if hours > auto_max + 1 / 60:
            return None, _('%(hours)s h asked; the rule %(rule)s approves up to %(max)s h by itself') % {
                'hours': '%g' % round(hours, 1), 'rule': policy, 'max': auto_max}
        if not policy.in_auto_approve_window():
            return None, _('asked outside the hours the rule %s approves by itself') % policy
        if policy.require_reason and not (reason or '').strip():
            return None, _('no reason given (the rule %s asks for one)') % policy
        if policy.name not in names:
            names.append(policy.name)
    return names, ''


def try_auto_approve(ticket):
    """Approve an access request right away when its policies allow it. True when approved."""
    from tickets.const import StepState, StepStatus, TicketState, TicketStatus
    from tickets.models import TicketStep
    try:
        mapping = ticket_policies(ticket)
        matched = [p for p in mapping.values() if p]
        if matched and len(matched) == len(mapping) and all(
            p.self_service and p.auto_approve and p.approvals_required == 1 and p.auto_approve_max_hours >= p.max_hours
            for p in matched
        ):
            max_h = min(p.auto_approve_max_hours for p in matched)
            if ticket.apply_date_expired and _hours(ticket.apply_date_start, ticket.apply_date_expired) > max_h + 1 / 60:
                # (the rules never allow longer: the request is shortened to their limit, and says so)
                asked = _hours(ticket.apply_date_start, ticket.apply_date_expired)
                start_dt = max(ticket.apply_date_start or timezone.now(), timezone.now())
                ticket.apply_date_start = start_dt
                ticket.apply_date_expired = start_dt + timezone.timedelta(hours=max_h)
                ticket.save(update_fields=['apply_date_start', 'apply_date_expired'])
                _comment(ticket, _('Shortened from %(asked)s h to %(max)s h: the longest the just-in-time rule '
                                   'allows') % {'asked': '%g' % round(asked, 1), 'max': max_h})
        names, why = auto_approve_decision(ticket, mapping)
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
        update_fields = ['approval_step', 'state', 'status', 'apply_jit_auto']
        if not ticket.apply_accounts:
            ticket.apply_accounts = list(REQUEST_ACCOUNTS)
            update_fields.append('apply_accounts')
        ticket.approval_step = steps[-1].level
        ticket.state = TicketState.approved
        ticket.status = TicketStatus.closed
        ticket.apply_jit_auto = ', '.join(names)[:128]
        ticket.save(update_fields=update_fields)
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


MAX_LEVELS = 5  # TicketLevel


def _approver_ids(policy, org_id):
    """Users the rule names as approvers (members of the organization), or None when an approval flow decides."""
    if not policy or policy.approval_route != policy.ApprovalRoute.approvers:
        return None
    value = policy.approvers.value
    if not isinstance(value, dict) or not value.get('type'):
        return []
    from users.models import User
    from common.db.fields import RelatedManager
    from orgs.models import Organization
    org = Organization.get_instance(org_id)
    qs = User.get_org_users(org=org).filter(is_active=True)
    with tmp_to_org(org):
        for q in RelatedManager.get_to_filter_qs(value, User):
            qs = qs.filter(q)
    return list(qs.distinct().values_list('id', flat=True)[:500])


def _flow_sets(flow, org_id, applicant_id):
    """The approvers of each level of an approval flow (never the requester; nobody else: the administrators)."""
    sets = []
    for rule in flow.rules.order_by('level'):
        ids = [uid for uid in rule.get_assignees(org_id=flow.org_id).filter(is_active=True).values_list('id', flat=True)
               if uid != applicant_id]
        sets.append(ids or _admin_ids(org_id, applicant_id))
    return sets


def _route_sets(mapping, org_id, applicant_id, base_sets, base_flow_id):
    """
    The approval steps for the rules of the requested assets (None: the request's own flow, as it is):
    - a rule with specific people: a step with them (assets of several teams: each team approves its part,
      one after the other);
    - a rule with an approval flow other than the request's: that flow's levels;
    - assets without a rule, or whose rule uses the request's flow: the request's flow;
    - "two approvers": a second step with the same people (someone other than the first approver);
    - never the requester; without anybody else the administrators approve.
    """
    policies = sorted(dict.fromkeys(p for p in mapping.values() if p), key=lambda p: p.priority)
    two = any(p.approvals_required >= 2 for p in policies)
    uses_base = any(p is None for p in mapping.values())
    extra, seen = [], set()
    for policy in policies:
        ids = _approver_ids(policy, org_id)
        if ids is not None:
            group = [uid for uid in ids if uid != applicant_id] or _admin_ids(org_id, applicant_id)
            part = [group] * (2 if policy.approvals_required >= 2 else 1)
        elif policy.approval_flow_id and policy.approval_flow_id != base_flow_id:
            part = _flow_sets(policy.approval_flow, org_id, applicant_id) or base_sets
            if policy.approvals_required >= 2 and len(part) == 1:
                part = part * 2
        else:
            uses_base = True
            continue
        key = tuple(tuple(g) for g in part)
        if key not in seen:
            seen.add(key)
            extra.append(part)
    if not extra:
        # the request's flow as it is; "two approvers" adds a second step when the flow has only one
        return base_sets * 2 if two and len(base_sets) == 1 else None
    sets = (list(base_sets) if uses_base else []) + [g for part in extra for g in part]
    if two and len(sets) == 1:
        sets = sets * 2
    sets = [g for g in sets if g]
    if len(sets) > MAX_LEVELS:
        merged = list(dict.fromkeys(uid for group in sets[MAX_LEVELS - 1:] for uid in group))
        sets = sets[:MAX_LEVELS - 1] + [merged]
    return sets


def route_approvers(ticket):
    """Build the approval steps of an access request from the rules of its assets (see _route_sets)."""
    from tickets.models import TicketAssignee, TicketStep
    try:
        mapping = ticket_policies(ticket)
    except Exception as e:
        logger.warning('JIT approval routing of %s failed: %s', ticket, e)
        return
    steps = list(TicketStep.objects.filter(ticket=ticket).prefetch_related('ticket_assignees').order_by('level'))
    flow_sets = [[uid for uid in st.ticket_assignees.values_list('assignee_id', flat=True)
                  if uid != ticket.applicant_id] or _admin_ids(ticket.org_id, ticket.applicant_id) for st in steps]
    sets = _route_sets(mapping, ticket.org_id, ticket.applicant_id, flow_sets, ticket.flow_id)
    if not sets:
        return
    with transaction.atomic():
        TicketStep.objects.filter(ticket=ticket).delete()
        for level, group in enumerate(sets, start=1):
            step = TicketStep.objects.create(ticket=ticket, level=level, status='active' if level == 1 else 'pending')
            TicketAssignee.objects.bulk_create([TicketAssignee(assignee_id=uid, step=step) for uid in group])
        named_flows = {
            p.approval_flow_id
            for p in mapping.values()
            if p and p.approval_route == p.ApprovalRoute.flow and p.approval_flow_id
        }
        update_fields = []
        if len(named_flows) == 1 and not any(p is None for p in mapping.values()):
            target_flow_id = next(iter(named_flows))
            if str(ticket.flow_id) != str(target_flow_id):
                ticket.flow_id = target_flow_id
                update_fields.append('flow')
        if ticket.approval_step != 1:
            ticket.approval_step = 1
            update_fields.append('approval_step')
        if update_fields:
            ticket.save(update_fields=update_fields)


def org_flows(org_id):
    """The approval flows for access requests an organization can use (its own and the global ones)."""
    from tickets.models import TicketFlow
    return TicketFlow.get_org_related_flows(org_id=org_id).filter(type='apply_asset') \
        .prefetch_related('rules').order_by('date_created')


def request_flow(policies, org_id):
    """The approval flow of a self-service request: the one its rules name when they all name the same, else the
    organization's flow for access requests."""
    flows = org_flows(org_id)
    named = {p.approval_flow_id for p in policies if p and p.approval_route == p.ApprovalRoute.flow}
    if len(named) == 1 and None not in named:
        flow = flows.filter(id=named.pop()).first()
        if flow:
            return flow
    return flows.first()


def preview(user, asset_ids, hours=None, reason='', node_ids=(), start=None, end=None, accounts=None,
            flow_id=None, protocols=None, actions=None):
    """What happens if `user` sends this request now: approved at once, or who approves it and why it is not
    approved by itself (the Workspace and the console's request form show it before sending)."""
    from assets.models import Asset, Node
    from common.utils import is_uuid
    asset_ids = [i for i in asset_ids if is_uuid(i)][:MAX_ASSETS]
    node_ids = [i for i in node_ids if is_uuid(i)][:20]
    with tmp_to_root_org():
        assets = list(Asset.objects.filter(id__in=asset_ids, is_active=True).select_related(
            'platform', 'platform__automation'
        ).prefetch_related('protocols'))
        for node in Node.objects.filter(id__in=node_ids):
            assets.extend(node.get_all_assets().filter(is_active=True).select_related(
                'platform', 'platform__automation'
            ).prefetch_related('protocols')[:MAX_ASSETS])
    assets = list({a.id: a for a in assets}.values())[:MAX_ASSETS + 1]
    orgs = {str(a.org_id) for a in assets}
    matcher = PolicyMatcher()
    if len(orgs) != 1 or not matcher._member(next(iter(orgs)), user):
        return {'instant': False, 'covered': False, 'why': '', 'route': []}
    org_id = orgs.pop()
    # XPAM: only assets the user may know of (a rule covers them, or a permission gives them): no names of others
    assets = _visible(user, assets, matcher)
    if not assets:
        return {'instant': False, 'covered': False, 'why': '', 'route': []}
    if end is None:
        try:
            hours = float(hours)
        except (TypeError, ValueError):
            hours = 0
        if not 0 < hours < 24 * 365:
            hours = 0
        start = timezone.now()
        end = start + timezone.timedelta(hours=hours) if hours > 0 else None
    with tmp_to_org(org_id):
        from perms.const import ActionChoices
        mapping = {a: _request_policy(matcher, user, a) for a in assets}
        covered = any(mapping.values())
        all_covered = bool(assets) and all(mapping.values())
        matched_policies = list(dict.fromkeys(p for p in mapping.values() if p))
        policy_names = [p.name for p in matched_policies]
        policy_flow = request_flow(mapping.values(), org_id) if covered else None
        policy_locks_flow = bool(
            covered and any(p.approval_flow_id or p.approval_route == p.ApprovalRoute.approvers for p in matched_policies)
        )
        auto_ok = bool(
            all_covered and all(
                p.self_service and p.auto_approve and p.approvals_required == 1 and p.in_auto_approve_window()
                for p in matched_policies
            )
        )
        auto_approve_hours = min((p.auto_approve_max_hours for p in matched_policies), default=0) if auto_ok else 0
        max_hours = min((p.max_hours for p in matched_policies), default=0) if all_covered else 0
        require_reason = bool(covered and any(p.require_reason for p in matched_policies))
        allowed_actions_mask = ActionChoices.all()
        allowed_protocols_list = None
        for p in matched_policies:
            allowed_actions_mask &= p.actions
            rule_protos = [] if 'all' in (p.protocols or ['all']) else list(p.protocols)
            if rule_protos:
                allowed_protocols_list = (
                    rule_protos
                    if allowed_protocols_list is None
                    else [n for n in allowed_protocols_list if n in rule_protos]
                )
        allowed_actions = ['all'] if allowed_actions_mask == ActionChoices.all() else _action_names(allowed_actions_mask)
        allowed_protocols = ['all'] if allowed_protocols_list is None else allowed_protocols_list
        names, why = _decision(mapping, start, end, REQUEST_ACCOUNTS if accounts is None else accounts, reason,
                               protocols=protocols, actions=actions)
        if names:
            return {
                'instant': True,
                'covered': True,
                'rules': names,
                'policies': policy_names,
                'policy_flow_id': str(policy_flow.id) if policy_flow else '',
                'policy_locks_flow': True,
                'auto_approve_hours': auto_approve_hours,
                'max_hours': max_hours,
                'require_reason': require_reason,
                'allowed_actions': allowed_actions,
                'allowed_protocols': allowed_protocols,
                'why': '',
                'route': [],
            }
        flow = None
        if not policy_locks_flow and flow_id and is_uuid(flow_id):
            flow = org_flows(org_id).filter(id=flow_id).first()
        flow = flow or policy_flow or request_flow(mapping.values(), org_id)
        base = _flow_sets(flow, org_id, user.id) if flow else []
        sets = _route_sets(mapping, org_id, user.id, base, flow.id if flow else None) or base
        return {
            'instant': False,
            'covered': covered,
            'why': why if covered else '',
            'route': describe_route(sets),
            'flow': str(flow) if flow else '',
            'policies': policy_names,
            'policy_flow_id': str(policy_flow.id) if policy_flow else '',
            'policy_locks_flow': policy_locks_flow,
            'auto_approve_hours': auto_approve_hours,
            'max_hours': max_hours,
            'require_reason': require_reason,
            'allowed_actions': allowed_actions,
            'allowed_protocols': allowed_protocols,
        }


def _admin_ids(org_id, applicant_id):
    from orgs.models import Organization
    from users.models import User
    org = Organization.get_instance(org_id)
    admins = set(org.admins if org else []) | set(User.get_super_admins())
    ids = [u.id for u in admins if u.id != applicant_id and u.is_valid]
    return ids


def describe_route(sets):
    """[{'level': 1, 'approvers': ['Ann', 'Bob'], 'more': 0}, ...] for people to read."""
    from users.models import User
    ids = {uid for g in sets for uid in g[:5]}
    names = {u.id: str(u) for u in User.objects.filter(id__in=ids)}
    return [{'level': i, 'approvers': [names[uid] for uid in g[:5] if uid in names], 'more': max(0, len(g) - 5)}
            for i, g in enumerate(sets, start=1)]


def route_text(route):
    return '; '.join(
        _('level %(n)s: %(who)s') % {'n': r['level'], 'who': ', '.join(r['approvers']) + (
            ' ' + _('and %s more') % r['more'] if r['more'] else '')} for r in route)


def explain_pending(ticket):
    """On a request that waits for approval: why it was not approved by itself (when a rule could have), and who
    approves — as a comment everyone on the ticket sees."""
    try:
        mapping = ticket_policies(ticket)
        if not any(mapping.values()):
            return
        lines = []
        if any(p and p.auto_approve for p in mapping.values()):
            _names, why = auto_approve_decision(ticket, mapping)
            if why:
                lines.append(_('Not approved automatically: %s.') % why)
        sets = [list(st.ticket_assignees.values_list('assignee_id', flat=True))
                for st in ticket.ticket_steps.prefetch_related('ticket_assignees').order_by('level')]
        route = describe_route(sets)
        if route:
            lines.append(_('Approval: %s.') % route_text(route))
        if lines:
            _comment(ticket, ' '.join(lines))
    except Exception as e:
        logger.warning('JIT approval note on %s failed: %s', ticket, e)


def drop_first_approver(ticket, step):
    """The person who approved the first step cannot approve the second one too."""
    nxt = step.next()
    if not nxt:
        return
    processor = step.processor
    if processor and nxt.ticket_assignees.exclude(assignee=processor).exists():
        nxt.ticket_assignees.filter(assignee=processor).delete()


# ---------------------------------------------------------------- the user's side

def submit(request, asset_ids, hours, reason='', title='', start=None, end=None, extends=None,
           protocols=None, actions=None):
    """Create an access request for `asset_ids`; it may be approved by itself. Returns the ticket."""
    from assets.models import Asset
    from common.utils import is_uuid
    if not isinstance(asset_ids, (list, tuple)):
        raise SelfServiceError(_('Choose at least one asset you can request'))
    asset_ids = [i for i in asset_ids if is_uuid(i)]
    for name, value in (('protocols', protocols), ('actions', actions)):
        if value is not None and not isinstance(value, (list, tuple)):
            raise SelfServiceError(_('%s must be a list') % name)
    with tmp_to_root_org():
        assets = list(Asset.objects.filter(id__in=asset_ids[:MAX_ASSETS], is_active=True)
                      .select_related('platform'))
    if not assets:
        raise SelfServiceError(_('Choose at least one asset you can request'))
    orgs = {str(a.org_id) for a in assets}
    if len(orgs) > 1:
        raise SelfServiceError(_('Request assets of one organization at a time'))
    org_id = orgs.pop()
    if not PolicyMatcher()._member(org_id, request.user):
        raise SelfServiceError(_('Choose at least one asset you can request'))
    with tmp_to_org(org_id):
        return _submit(request, assets, hours, reason, title, start, end, extends, protocols, actions)


def _already(user, assets, extends):
    """Why a new request is pointless ('' when it is not): the same request is already waiting, or the
    user already has access to all these assets (then: extend it)."""
    from perms.models import AssetPermission
    from tickets.models import ApplyAssetTicket
    wanted = {a.id for a in assets}
    open_requests = ApplyAssetTicket.objects.filter(applicant=user, status='open')
    if extends:
        if open_requests.filter(apply_extends=str(extends)).exists():
            return _('An extension of this access is already waiting for approval')
        return ''
    for t in open_requests.filter(apply_extends='').prefetch_related('apply_assets')[:50]:
        if {a.id for a in t.apply_assets.all()} == wanted:
            return _('A request for these assets is already waiting for approval')
    now = timezone.now()
    for perm in AssetPermission.objects.filter(from_ticket=True, users=user, is_active=True,
                                               date_start__lte=now, date_expired__gt=now):
        if wanted <= set(perm.get_all_assets().filter(id__in=wanted).values_list('id', flat=True)):
            return _('You already have access to these assets until %s; extend it instead') % \
                timezone.localtime(perm.date_expired).strftime('%Y-%m-%d %H:%M')
    return ''


def _submit(request, assets, hours, reason, title, start, end, extends=None, protocols=None, actions=None):
    from orgs.utils import current_org
    from tickets.serializers import ApplyAssetSerializer
    user = request.user
    matcher = PolicyMatcher()
    policies = {}
    for asset in assets:
        policy = _request_policy(matcher, user, asset)
        if not policy or not policy.self_service:
            raise SelfServiceError(_('You cannot request access to %s') % asset)
        policies[asset] = policy
    if extends:
        for p in policies.values():
            if not getattr(p, 'allow_extension', True):
                raise SelfServiceError(_('The policy %s does not allow extending access') % p)
        max_exts = [p.max_extensions for p in policies.values() if getattr(p, 'max_extensions', 0) > 0]
        if max_exts:
            from tickets.models import ApplyAssetTicket
            limit_ext = min(max_exts)
            used_ext = ApplyAssetTicket.objects.filter(apply_extends=str(extends), state='approved').count()
            if used_ext >= limit_ext:
                raise SelfServiceError(_('Maximum number of extensions (%s) reached for this access') % limit_ext)
        max_hours = min((getattr(p, 'extension_max_hours', 0) or p.max_hours) for p in policies.values())
    else:
        max_hours = min(p.max_hours for p in policies.values())
    start = start or timezone.now()
    if end is None:
        try:
            hours = float(hours)
        except (TypeError, ValueError):
            raise SelfServiceError(_('Choose how long you need access'))
        if not 0 < hours < 24 * 365:  # (also refuses nan and inf)
            raise SelfServiceError(_('Choose how long you need access'))
        end = start + timezone.timedelta(hours=hours)
    if not 0 < _hours(start, end) <= max_hours + 1 / 60:
        raise SelfServiceError(_('You can request at most %s hours for these assets') % max_hours)
    if any(p.require_reason for p in policies.values()) and not (reason or '').strip():
        raise SelfServiceError(_('Enter the reason for the access'))
    why = _already(user, assets, extends)
    if why:
        raise SelfServiceError(why)
    chosen_protocols, chosen_actions = _choose(set(policies.values()), protocols, actions)
    flow = request_flow(policies.values(), current_org.id)
    if not flow:
        raise SelfServiceError(_('No approval flow for access requests is set up in this organization'))
    names = ', '.join(a.name for a in assets[:3]) + (' …' if len(assets) > 3 else '')
    data = {
        'title': (title or _('Access to %(assets)s for %(hours)s h') % {
            'assets': names, 'hours': round(_hours(start, end), 1)})[:128],
        'type': 'apply_asset', 'org_id': str(current_org.id), 'flow_id': str(flow.id),
        'apply_assets': [str(a.id) for a in assets], 'apply_nodes': [],
        'apply_accounts': REQUEST_ACCOUNTS, 'apply_actions': chosen_actions, 'apply_protocols': chosen_protocols,
        'apply_date_start': start.isoformat(), 'apply_date_expired': end.isoformat(),
        'comment': (reason or '').strip()[:1024],
    }
    serializer = ApplyAssetSerializer(data=data, context={'request': request})
    if not serializer.is_valid():
        raise SelfServiceError('; '.join(f'{k}: {v}' for k, v in serializer.errors.items()))
    ticket = serializer.save()
    ticket.apply_extends = str(extends or '')
    ticket.save(update_fields=['applicant', 'apply_extends'])
    ticket.open()
    ticket.refresh_from_db()
    return ticket


def _perm_assets(perm, limit=50):
    return list(perm.get_all_assets().select_related('platform')[:limit])


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
            policy = next((p for a in assets if (p := matcher.policy_for(perm, user, a))), None)
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
                           'allow_extension': getattr(policy, 'allow_extension', True),
                           'extension_approval': getattr(policy, 'extension_approval', 'same'),
                           'extension_max_hours': getattr(policy, 'extension_max_hours', 0) or policy.max_hours,
                           'max_extensions': getattr(policy, 'max_extensions', 0),
                           'warn_minutes': policy.expiry_warning_minutes} if policy else None,
            })
        pending = []
        for t in ApplyAssetTicket.objects.filter(applicant=user, status='open') \
                .prefetch_related('apply_assets').order_by('-date_created')[:20]:
            pending.append({
                'id': str(t.id), 'title': t.title, 'serial_num': t.serial_num, 'org_id': str(t.org_id),
                'assets': [a.name for a in t.apply_assets.all()[:10]],
                'date_start': t.apply_date_start, 'date_expired': t.apply_date_expired,
                'date_created': t.date_created, 'reason': t.comment, 'extends': t.apply_extends,
            })
        recent = []
        for t in ApplyAssetTicket.objects.filter(applicant=user, status='closed',
                                                 date_updated__gt=now - timezone.timedelta(days=7)) \
                .order_by('-date_updated')[:10]:
            from .approvals import decision_note
            recent.append({'id': str(t.id), 'title': t.title, 'state': t.state, 'auto': t.apply_jit_auto,
                           'date_updated': t.date_updated, 'note': decision_note(t)})
        accounts = [{
            'id': str(j.id), 'username': j.username, 'asset': j.asset_display, 'asset_id': str(j.asset_id or ''),
            'mode': j.mode, 'status': j.status, 'date_ready': j.date_ready, 'date_expired': j.date_expired,
        } for j in JITAccount.objects.filter(user=user, status__in=['pending', 'pushing', 'ready'])]
    from .approvals import pending_count
    return {'grants': grants, 'pending': pending, 'recent': recent, 'accounts': accounts,
            'approvals_waiting': pending_count(user), 'server_time': now}


def _own_grant(user, perm_id):
    from common.utils import is_uuid
    from perms.models import AssetPermission
    if not is_uuid(perm_id):
        raise SelfServiceError(_('This access is not yours'))
    with tmp_to_root_org():
        perm = AssetPermission.objects.filter(id=perm_id, from_ticket=True, users=user).first()
    if not perm:
        raise SelfServiceError(_('This access is not yours'))
    return perm


def extend(request, perm_id, hours, reason=''):
    """Ask for more time. Approved (or approved by the rule), the same access ends `hours` later; the
    hours count from the current end, so they are checked against the rule's maximum on their own."""
    from tickets.models import ApplyAssetTicket
    perm = _own_grant(request.user, perm_id)
    # (an access that ended, or that an approver revoked, is asked for again, not extended: an approved
    # extension of it would create a new access, under rules meant for continuing one)
    if not perm.is_active or perm.date_expired <= timezone.now():
        raise SelfServiceError(_('This access has ended: request access again'))
    try:
        hours = float(hours)
    except (TypeError, ValueError):
        raise SelfServiceError(_('Choose how long you need access'))
    if not 0 < hours < 24 * 365:  # (also refuses nan and inf)
        raise SelfServiceError(_('Choose how long you need access'))
    start = max(perm.date_expired, timezone.now())
    end = start + timezone.timedelta(hours=hours)
    with tmp_to_org(perm.org_id):
        asset_ids = [str(a.id) for a in perm.get_all_assets()[:MAX_ASSETS]]
    with tmp_to_root_org():
        names = ', '.join(perm.get_all_assets().values_list('name', flat=True)[:3])
        first = ApplyAssetTicket.objects.filter(id=perm.id).first()  # (the permission has the request's id)
    if not (reason or '').strip():
        reason = _('Extension') + (f': {first.comment}' if first and first.comment else '')
    return submit(request, asset_ids, None, reason=reason, start=start, end=end, extends=perm.id,
                  protocols=perm.protocols, actions=_action_names(perm.actions),
                  title=_('Extend access to %(assets)s by %(hours)s h') % {'assets': names, 'hours': hours})


def end_now(user, perm_id):
    """The user is done: the access ends now, and the just-in-time accounts it gave are removed (their
    sessions end) unless another access of the user still covers them. A waiting extension is cancelled."""
    from .access import end_sessions
    perm = _own_grant(user, perm_id)
    release_grant(user, perm, reason=str(_('Ended by %s') % user))
    end_sessions(user, perm, user)
    return perm


def release_grant(user, perm, reason):
    """ XPAM: end the access `perm` gave `user` now (the user ending it, or an approver revoking it): a waiting
    extension is cancelled, its just-in-time accounts removed unless another access of the user covers them """
    from accounts.models import JITAccount
    from accounts.tasks.jit import jit_release_task
    from tickets.models import ApplyAssetTicket
    from .policy import select_policy
    now = timezone.now()
    with tmp_to_org(perm.org_id):
        perm.date_expired = now
        perm.save(update_fields=['date_expired'])
    if not user:
        return perm
    with tmp_to_root_org():
        for ticket in ApplyAssetTicket.objects.filter(applicant=user, status='open', apply_extends=str(perm.id)):
            ticket.close()
        jits = list(JITAccount.objects.filter(
            user=user, permission_id=perm.id, status__in=['pending', 'pushing', 'ready']
        ).select_related('asset'))
    for jit in jits:
        with tmp_to_org(jit.org_id):
            policy, other = select_policy(user, jit.asset) if jit.asset else (None, None)
        if policy and other:
            JITAccount.objects.filter(id=jit.id).update(permission_id=other.id)
            continue
        jit_release_task.delay(str(jit.id), reason=reason)
    return perm


def cancel(user, ticket_id):
    from common.utils import is_uuid
    from tickets.models import ApplyAssetTicket
    ticket = None
    if is_uuid(ticket_id):
        with tmp_to_root_org():
            ticket = ApplyAssetTicket.objects.filter(id=ticket_id, applicant=user, status='open').first()
    if not ticket:
        raise SelfServiceError(_('This request cannot be cancelled'))
    ticket.close()
    return ticket

"""Which just-in-time policy applies to a user and an asset."""
from django.utils import timezone

from common.utils import get_logger
from orgs.utils import tmp_to_org, tmp_to_root_org

logger = get_logger(__name__)

SUPPORTED_TYPES = ('linux', 'unix', 'windows')


def asset_supports_jit(asset):
    """Accounts can be pushed to this asset with the built-in automations (Linux/Unix and Windows)."""
    try:
        if not asset or not asset.is_active:
            return False
        if asset.platform.type not in SUPPORTED_TYPES:
            return False
        auto = asset.auto_config or {}
        return bool(auto.get('ansible_enabled') and auto.get('push_account_enabled'))
    except Exception as e:  # never break permission listing because of JIT
        logger.debug('JIT support check failed for %s: %s', asset, e)
        return False


class PolicyMatcher:
    """
    Decides which just-in-time policy a permission gives a user on an asset:

    1. the permission says "no just-in-time account"           -> none
    2. a policy is linked to the permission (or chosen by the
       approver of an access request)                          -> that policy
    3. otherwise the active rule policies of the organization,
       lowest priority value first: the first one whose users
       and assets include this user and asset                  -> that policy
    """

    def __init__(self):
        from accounts.models import JITPolicy
        with tmp_to_root_org():
            policies = list(JITPolicy.objects.filter(is_active=True).order_by('priority', 'name'))
        self.by_id = {str(p.id): p for p in policies}
        self.rules_by_org = {}
        for p in policies:
            if p.is_rule_based:
                self.rules_by_org.setdefault(str(p.org_id), []).append(p)
        self._memo = {}

    def __bool__(self):
        return bool(self.by_id)

    def _includes(self, policy, field, obj):
        manager = getattr(policy, field)
        value = manager.value
        if not isinstance(value, dict) or not value.get('type'):
            return False  # nothing chosen yet: the rule applies to nobody
        if value['type'] == 'all':
            return True
        if value['type'] == 'ids':
            return str(obj.id) in {str(i) for i in value.get('ids') or []}
        key = (str(policy.id), field, str(obj.id))
        if key not in self._memo:
            org_id = policy.org_id if field == 'assets' else None
            ctx = tmp_to_org(org_id) if org_id else tmp_to_root_org()
            try:
                with ctx:
                    self._memo[key] = manager.all().filter(id=obj.id).exists()
            except Exception as e:  # a broken rule must not break connecting
                logger.warning('JIT policy %s: %s rule could not be checked: %s', policy, field, e)
                self._memo[key] = False
        return self._memo[key]

    def rule_policy(self, user, asset, org_id, from_ticket):
        """(policy, None) of the first rule that covers user and asset for this kind of permission."""
        for policy in self.rules_by_org.get(str(org_id), []):
            if policy.scope == policy.Scope.requests and not from_ticket:
                continue
            if self._includes(policy, 'users', user) and self._includes(policy, 'assets', asset):
                return policy
        return None

    def explain(self, perm, user, asset):
        """(policy, how): how is "disabled", "linked", "rule" or None."""
        if getattr(perm, 'jit_disabled', False):
            return None, 'disabled'
        if perm.jit_policy_id:
            policy = self.by_id.get(str(perm.jit_policy_id))
            return (policy, 'linked') if policy else (None, None)
        policy = self.rule_policy(user, asset, perm.org_id, perm.from_ticket)
        return (policy, 'rule') if policy else (None, None)

    def policy_for(self, perm, user, asset):
        return self.explain(perm, user, asset)[0]


def jit_grant_for_perms(perms, user, asset):
    """(actions, [date_expired]) of the just-in-time account these permissions grant on `asset`."""
    perms = list(perms)
    if not perms or not asset_supports_jit(asset):
        return 0, []
    matcher = PolicyMatcher()
    if not matcher:
        return 0, []
    actions, expired = 0, []
    for perm in perms:
        if matcher.policy_for(perm, user, asset):
            actions |= perm.actions
            expired.append(perm.date_expired)
    return actions, expired


def choose(perms, user, asset, matcher=None, now=None):
    """(policy, permission) from the valid permissions; the one that lasts longest decides."""
    matcher = matcher or PolicyMatcher()
    now = now or timezone.now()
    best = None
    for perm in perms:
        if not (perm.is_active and perm.date_start <= now <= perm.date_expired):
            continue
        policy = matcher.policy_for(perm, user, asset)
        if policy and (best is None or perm.date_expired > best[1].date_expired):
            best = (policy, perm)
    return best or (None, None)


def select_policy(user, asset):
    """(policy, permission) that gives `user` a just-in-time account on `asset`, or (None, None)."""
    from perms.utils import PermAssetDetailUtil
    if not asset_supports_jit(asset):
        return None, None
    perms = PermAssetDetailUtil(user, asset).user_asset_perms
    return choose(perms, user, asset)


def unsupported_reason(asset):
    """Why just-in-time accounts cannot be used on `asset` ('' when they can)."""
    from django.utils.translation import gettext as _
    if not asset.is_active:
        return _('The asset is disabled')
    if asset.platform.type not in SUPPORTED_TYPES:
        return _('Just-in-time accounts work on Linux/Unix and Windows assets only')
    auto = asset.auto_config or {}
    if not (auto.get('ansible_enabled') and auto.get('push_account_enabled')):
        return _('Account push is turned off in the platform of this asset')
    return ''


def _policy_brief(policy):
    return {'id': str(policy.id), 'name': policy.name, 'mode': policy.mode,
            'mode_display': str(policy.get_mode_display())}


def explain(user, asset, request=False, matcher=None):
    """
    Which policy gives `user` a just-in-time account on `asset`, and why, for the console.
    request=True: as if an access request for the asset were approved now (policy rules only).
    """
    from django.utils.translation import gettext as _
    from perms.utils import PermAssetDetailUtil
    matcher = matcher or PolicyMatcher()
    result = {'asset': {'id': str(asset.id), 'name': str(asset)}, 'policy': None,
              'how': None, 'permission': None, 'reason': ''}
    reason = unsupported_reason(asset)
    if reason:
        result['reason'] = reason
        return result
    if request:
        policy = matcher.rule_policy(user, asset, asset.org_id, from_ticket=True)
        if policy:
            result.update(policy=_policy_brief(policy), how='rule',
                          reason=_('Policy rule, priority %s') % policy.priority)
        else:
            result['reason'] = _('No policy rule covers this user and asset')
        return result

    perms = list(PermAssetDetailUtil(user, asset).user_asset_perms)
    now = timezone.now()
    perms = [p for p in perms if p.is_active and p.date_start <= now <= p.date_expired]
    if not perms:
        result['reason'] = _('The user has no valid permission on this asset')
        return result
    policy, perm = choose(perms, user, asset, matcher, now)
    if not policy:
        if all(getattr(p, 'jit_disabled', False) for p in perms):
            result['reason'] = _('Just-in-time accounts are turned off on the permission')
        else:
            result['reason'] = _('No policy rule covers this user and asset, and no policy is linked '
                                 'to the permission')
        return result
    how = matcher.explain(perm, user, asset)[1]
    if how == 'rule':
        reason = _('Policy rule, priority %s') % policy.priority
    elif perm.from_ticket:
        reason = _('Chosen when the access request was approved')
    else:
        reason = _('Linked to the permission')
    result.update(policy=_policy_brief(policy), how=how, reason=reason,
                  permission={'id': str(perm.id), 'name': perm.name})
    return result


def push_params(policy):
    """Parameters for the built-in push automations (per method id)."""
    windows_groups = [g.strip() for g in (policy.windows_groups or '').split(',') if g.strip()]
    if policy.privileged and not any(g.lower() == 'administrators' for g in windows_groups):
        windows_groups.append('Administrators')
    if not any(g.lower() == 'remote desktop users' for g in windows_groups):
        windows_groups.append('Remote Desktop Users')
    posix = {
        'modify_sudo': True,
        'sudo': 'ALL' if policy.privileged else '',
        'shell': policy.linux_shell or '/bin/bash',
        'home': '',
        'group': '',
        'groups': policy.linux_groups or '',
        'uid': '',
    }
    return {
        'push_account_posix': posix,
        'push_account_aix': dict(posix),
        'push_account_local_windows': {'groups': ','.join(windows_groups)},
    }


def remove_params(policy):
    remove_home = True if policy is None else policy.remove_home
    return {
        'remove_account_posix': {
            'home_action': 'delete' if remove_home else 'backup',
            'end_sessions': True,
        },
        'remove_account_windows': {
            'remove_profile': remove_home,
            'end_sessions': True,
        },
    }

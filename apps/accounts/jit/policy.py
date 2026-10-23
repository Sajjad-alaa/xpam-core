"""Which just-in-time policy applies to a user and an asset."""
from django.db.models import Q
from django.utils import timezone

from common.utils import get_logger
from orgs.utils import tmp_to_org, tmp_to_root_org

logger = get_logger(__name__)

SUPPORTED_TYPES = ('linux', 'unix', 'windows')
DB_TYPES = ('mysql', 'mariadb', 'postgresql', 'sqlserver', 'oracle')


def target_kind(asset):
    """host (Linux/Unix/Windows), database, device (network and other SSH devices) or None."""
    try:
        platform = asset.platform
    except Exception:
        return None
    if platform.type in SUPPORTED_TYPES:
        return 'host'
    if platform.category == 'database' and platform.type in DB_TYPES:
        return 'database'
    if platform.category == 'device':
        return 'device'
    return None


def admin_account(asset):
    """The account XPAM uses to create and remove just-in-time accounts on a database or device."""
    qs = asset.accounts.filter(is_active=True, privileged=True).exclude(source='jit')
    return qs.filter(secret_type='password').first() or qs.first()


def unsupported_reason(asset, policy=None):
    """Why just-in-time accounts cannot be used on `asset` with `policy` ('' when they can)."""
    from django.utils.translation import gettext as _
    try:
        if not asset or not asset.is_active:
            return _('The asset is disabled')
        kind = target_kind(asset)
        if kind == 'host':
            auto = asset.auto_config or {}
            if not (auto.get('ansible_enabled') and auto.get('push_account_enabled')):
                return _('Account push is turned off in the platform of this asset')
            if policy and policy.credential_type == 'ssh_key' and asset.platform.type == 'windows':
                return _('SSH keys work on Linux/Unix only; choose "Password" for Windows assets')
            return ''
        if kind in ('database', 'device'):
            if kind == 'database' and getattr(asset, 'zone_id', None) and asset.platform.gateway_enabled:
                return _('Assets reached through a gateway are not supported for this target yet')
            if not admin_account(asset):
                return _('Add a privileged account on the asset that may create users')
            if kind == 'device' and not any(p.name == 'ssh' for p in asset.protocols.all()):
                return _('The device needs the SSH protocol')
            return ''
        return _('Just-in-time accounts work on Linux/Unix and Windows hosts, databases (MySQL, '
                 'MariaDB, PostgreSQL, SQL Server, Oracle) and network devices (FortiGate, Palo Alto, '
                 'Cisco, Juniper, Huawei, H3C and other SSH devices)')
    except Exception as e:  # never break permission listing because of JIT
        logger.debug('JIT support check failed for %s: %s', asset, e)
        return 'error'


def asset_supports_jit(asset, policy=None):
    """Just-in-time accounts can be created on this asset (with this policy)."""
    return not unsupported_reason(asset, policy)


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
            policies = list(JITPolicy.objects.filter(is_active=True)
                            .select_related('approval_flow').order_by('priority', 'name'))
        self.by_id = {str(p.id): p for p in policies}
        self.rules_by_org = {}
        for p in policies:
            if p.is_rule_based:
                self.rules_by_org.setdefault(str(p.org_id), []).append(p)
        self._memo = {}

    def __bool__(self):
        return bool(self.by_id)

    def _member(self, org_id, user):
        """Is `user` a member of the organization (a rule never reaches users of other organizations)."""
        key = ('member', str(org_id), str(user.id))
        if key not in self._memo:
            from orgs.models import Organization
            from users.models import User
            org = Organization.get_instance(org_id)
            if not org or org.is_root():
                self._memo[key] = True
            else:
                self._memo[key] = User.get_org_users(org=org).filter(id=user.id).exists()
        return self._memo[key]

    def _includes(self, policy, field, obj):
        manager = getattr(policy, field)
        value = manager.value
        if not isinstance(value, dict) or not value.get('type'):
            return False  # nothing chosen yet: the rule applies to nobody
        if field == 'users' and not self._member(policy.org_id, obj):
            return False
        if value['type'] == 'all':
            return True
        if value['type'] == 'ids':
            ids_key = ('ids', str(policy.id), field)
            if ids_key not in self._memo:
                self._memo[ids_key] = {str(i) for i in value.get('ids') or []}
            return str(obj.id) in self._memo[ids_key]
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
    """
    (actions, [date_expired], jit_only) of the just-in-time account these permissions grant on
    `asset`. jit_only: a matching policy hides the standing accounts (zero standing privilege).
    """
    perms = list(perms)
    if not perms or not target_kind(asset):
        return 0, [], False
    matcher = PolicyMatcher()
    if not matcher:
        return 0, [], False
    actions, expired, jit_only = 0, [], False
    supported = {}
    for perm in perms:
        policy = matcher.policy_for(perm, user, asset)
        if not policy:
            continue
        if policy.id not in supported:
            supported[policy.id] = asset_supports_jit(asset, policy)
        if not supported[policy.id]:
            # zero standing privilege fails closed: a "JIT only" rule that cannot run here (privileged
            # account deleted, push turned off...) must not bring the standing accounts back
            jit_only = jit_only or policy.jit_only
            continue
        actions |= perm.actions
        expired.append(perm.date_expired)
        jit_only = jit_only or policy.jit_only
    return actions, expired, jit_only


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
    if not target_kind(asset):
        return None, None
    perms = PermAssetDetailUtil(user, asset).user_asset_perms
    policy, perm = choose(perms, user, asset)
    if policy and not asset_supports_jit(asset, policy):
        return None, None
    return policy, perm


def _policy_brief(policy):
    return {'id': str(policy.id), 'name': policy.name, 'mode': policy.mode,
            'mode_display': str(policy.get_mode_display()), 'jit_only': policy.jit_only,
            'auto_approve': policy.auto_approve, 'auto_approve_max_hours': policy.auto_approve_max_hours,
            'max_hours': policy.max_hours, 'require_reason': policy.require_reason,
            'self_service': policy.self_service}


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
    if reason and target_kind(asset) != 'device':  # devices also depend on the policy (commands)
        result['reason'] = reason
        return result
    if request:
        policy = matcher.rule_policy(user, asset, asset.org_id, from_ticket=True)
        reason = unsupported_reason(asset, policy) if policy else ''
        if policy and reason:
            result.update(policy=None, reason=reason)
        elif policy:
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
    reason = unsupported_reason(asset, policy)
    if reason:
        result['reason'] = reason
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


def user_must_keep_mfa(user):
    """A just-in-time rule that asks for MFA covers this user (cached for a minute)."""
    from django.core.cache import cache
    if not getattr(user, 'id', None):
        return False
    key = f'xpam-jit-mfa-user:{user.id}'
    cached = cache.get(key)
    if cached is not None:
        return cached
    result = False
    try:
        from accounts.models import JITPolicy
        any_key = 'xpam-jit-mfa-policies'
        if cache.get(any_key) is False:
            return False
        with tmp_to_root_org():
            policies = list(JITPolicy.objects.filter(is_active=True, require_mfa=True))
        cache.set(any_key, bool(policies), 60)
        if policies:
            matcher = PolicyMatcher()
            result = any(matcher._includes(p, 'users', user) for p in policies if p.is_rule_based) or \
                any(p.asset_permissions.filter(Q(users=user) | Q(user_groups__users=user)).exists() for p in policies)
    except Exception as e:
        logger.debug('JIT MFA check for %s failed: %s', user, e)
    cache.set(key, result, 60)
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

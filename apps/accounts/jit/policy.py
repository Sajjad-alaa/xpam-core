"""Which just-in-time policy applies to a user and an asset."""
from django.utils import timezone

from common.utils import get_logger
from orgs.utils import tmp_to_root_org

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


def _policies_for_perms(perms):
    """[(perm, policy)] for the permissions that grant a just-in-time account."""
    from accounts.models import JITPolicy
    perms = list(perms)
    if not perms:
        return []
    policy_ids = {p.jit_policy_id for p in perms if getattr(p, 'jit_policy_id', None)}
    ticket_orgs = {p.org_id for p in perms if getattr(p, 'from_ticket', False)}
    with tmp_to_root_org():
        policies = {
            str(p.id): p for p in JITPolicy.objects.filter(id__in=policy_ids, is_active=True)
        } if policy_ids else {}
        approved = {}
        for org_id in ticket_orgs:
            p = JITPolicy.request_policy(org_id)
            if p:
                approved[org_id] = p
    result = []
    for perm in perms:
        policy = policies.get(str(perm.jit_policy_id)) if perm.jit_policy_id else None
        if not policy and perm.from_ticket:
            policy = approved.get(perm.org_id)
        if policy:
            result.append((perm, policy))
    return result


def jit_grant_for_perms(perms, asset):
    """(actions, [date_expired]) of the just-in-time account these permissions grant on `asset`."""
    if not asset_supports_jit(asset):
        return 0, []
    actions, expired = 0, []
    for perm, _policy in _policies_for_perms(perms):
        actions |= perm.actions
        expired.append(perm.date_expired)
    return actions, expired


def select_policy(user, asset):
    """(policy, permission) that gives `user` a just-in-time account on `asset`, or (None, None)."""
    from perms.utils import PermAssetDetailUtil
    if not asset_supports_jit(asset):
        return None, None
    perms = PermAssetDetailUtil(user, asset).user_asset_perms
    now = timezone.now()
    candidates = [
        (perm, policy) for perm, policy in _policies_for_perms(perms)
        if perm.is_active and perm.date_start <= now <= perm.date_expired
    ]
    if not candidates:
        return None, None
    # The permission that lasts longest decides (its end is when a granted account is removed)
    perm, policy = max(candidates, key=lambda item: item[0].date_expired)
    return policy, perm


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

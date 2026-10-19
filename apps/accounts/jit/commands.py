"""
Command filters for just-in-time sessions.

A policy with command groups keeps one command filter rule (Console → Command filters, named
"JIT · <policy>") that applies only to the just-in-time accounts of that policy: its account list
holds the marker "@JIT:<policy id>", which the filter matching resolves for JIT accounts.
"""
from django.db import transaction

from common.utils import get_logger
from orgs.utils import tmp_to_org

logger = get_logger(__name__)


def marker(policy_id):
    return f'@JIT:{policy_id}'


def markers_for_account(account):
    """Extra account names that command/ACL rules may use for a just-in-time account."""
    if not account or getattr(account, 'source', '') != 'jit' or not getattr(account, 'source_id', ''):
        return []
    from accounts.models import JITAccount
    from orgs.utils import tmp_to_root_org
    with tmp_to_root_org():
        policy_id = JITAccount.objects.filter(id=account.source_id).values_list('policy_id', flat=True).first()
    return ['@JIT'] + ([marker(policy_id)] if policy_id else [])


def _find(policy_id):
    from acls.models import CommandFilterACL
    return CommandFilterACL.objects.filter(accounts__contains=[marker(policy_id)]).first()


def sync(policy, deleted=False):
    """Create, update or delete the command filter rule of `policy`."""
    from acls.models import CommandFilterACL
    with tmp_to_org(policy.org_id), transaction.atomic():
        acl = _find(policy.id)
        groups = [] if deleted else list(policy.command_groups.all())
        if not groups:
            if acl:
                acl.delete()
            return None
        name = f'JIT · {policy.name}'[:120]
        if CommandFilterACL.objects.filter(name=name).exclude(id=getattr(acl, 'id', None)).exists():
            name = f'{name[:110]} · {str(policy.id)[:8]}'
        values = {
            'name': name, 'priority': policy.priority, 'action': policy.command_action,
            'users': {'type': 'all'}, 'assets': {'type': 'all'}, 'accounts': [marker(policy.id)],
            'is_active': policy.is_active,
            'comment': f'Managed by the just-in-time policy "{policy.name}"; change it there.',
        }
        if acl:
            for k, v in values.items():
                setattr(acl, k, v)
            acl.save()
        else:
            acl = CommandFilterACL.objects.create(org_id=policy.org_id, **values)
        acl.command_groups.set(groups)
        return acl

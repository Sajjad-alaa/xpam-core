from celery import shared_task
from django.utils.translation import gettext_lazy as _

from common.utils import get_logger
from ops.celery.decorator import register_as_period_task
from orgs.utils import tmp_to_root_org

logger = get_logger(__file__)

__all__ = ['jit_release_task', 'jit_release_if_idle_task', 'jit_provision_task', 'jit_reconcile_task']


@shared_task(queue='ansible', verbose_name=_('Remove just-in-time account'))
def jit_release_task(jit_id, reason=''):
    from accounts.jit.service import release
    from accounts.models import JITAccount
    with tmp_to_root_org():
        jit = JITAccount.objects.filter(id=jit_id).first()
    if jit:
        release(jit, reason=reason)


@shared_task(queue='ansible', verbose_name=_('Remove just-in-time account after the session'))
def jit_release_if_idle_task(jit_id):
    from accounts.jit.service import release_if_idle
    from accounts.models import JITAccount
    with tmp_to_root_org():
        jit = JITAccount.objects.filter(id=jit_id).first()
    if jit:
        release_if_idle(jit)


@shared_task(queue='ansible', verbose_name=_('Create just-in-time account'))
def jit_provision_task(policy_id, user_id, asset_id, perm_id):
    from accounts.jit.service import provision_granted
    provision_granted(policy_id, user_id, asset_id, perm_id)


@shared_task(
    verbose_name=_('Reconcile just-in-time accounts'),
    description=_('Creates the just-in-time accounts that permissions call for and removes the ones '
                  'that are no longer needed. Runs every five minutes and after permission changes.')
)
@register_as_period_task(interval=300)
def jit_reconcile_task():
    from django.core.cache import cache
    from accounts.jit.service import reconcile
    # Changes made from now on schedule a new run (see _schedule_jit_reconcile)
    cache.delete('xpam-jit-reconcile-scheduled')
    summary = reconcile()
    if any(summary.values()):
        logger.info('JIT reconcile: %s', summary)
    return summary

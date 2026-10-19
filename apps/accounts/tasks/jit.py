from celery import shared_task
from django.utils.translation import gettext_lazy as _

from common.utils import get_logger
from ops.celery.decorator import register_as_period_task
from orgs.utils import tmp_to_root_org

logger = get_logger(__file__)

__all__ = ['jit_release_task', 'jit_release_if_idle_task', 'jit_provision_task', 'jit_reconcile_task',
           'jit_expiry_task']


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


@shared_task(
    verbose_name=_('Just-in-time access ending'),
    description=_('Warns users shortly before their time-boxed access ends and ends it on time. '
                  'Runs every minute.')
)
@register_as_period_task(interval=60)
def jit_expiry_task():
    from django.core.cache import cache
    from django.utils import timezone
    from accounts.jit.service import expiring_soon
    from accounts.models import JITAccount
    from accounts.notifications import JITAccessEndingMsg
    from perms.models import AssetPermission
    for user, perm, assets, minutes in expiring_soon():
        try:
            JITAccessEndingMsg(user, assets, perm.date_expired, minutes).publish()
        except Exception as e:
            logger.warning('JIT expiry warning for %s failed: %s', user, e)
    # Access that just ended: reconcile now instead of waiting for the five-minute run
    now = timezone.now()
    with tmp_to_root_org():
        ended = AssetPermission.objects.filter(
            date_expired__gt=now - timezone.timedelta(seconds=90), date_expired__lte=now
        ).values_list('id', flat=True)
        live = JITAccount.objects.filter(permission_id__in=list(ended), status=JITAccount.Status.ready).exists()
    if live and cache.add('xpam-jit-reconcile-scheduled', 1, timeout=120):
        jit_reconcile_task.apply_async(countdown=1)

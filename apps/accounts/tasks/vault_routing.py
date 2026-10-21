"""
XPAM: apply the vault storage rules to the secrets already stored (after a rule, mirror or connection change):
each secret whose vault (or mirror) differs from what its rules give now is moved there (and the old copy
removed). External accounts are left alone.
"""
from celery import shared_task
from django.utils.translation import gettext_lazy as _

from common.utils import get_logger
from orgs.utils import tmp_to_root_org

logger = get_logger(__name__)

__all__ = ['move_secrets_by_rules']


@shared_task(verbose_name=_('Move secrets to the vaults given by the storage rules'))
def move_secrets_by_rules():
    from accounts.backends import vault_client
    from accounts.models import Account, AccountTemplate, PersonalAssetCredential
    vault_client.type  # noqa: B018  (set up the lazy client)
    router = vault_client._wrapped
    moved = failed = 0
    with tmp_to_root_org():
        for model in (Account, AccountTemplate, PersonalAssetCredential):
            queryset = model.objects.all()
            if model is Account:
                queryset = queryset.exclude(secret_source='external').select_related('asset')
            for obj in queryset.iterator():
                if (obj.vault_connection_id, obj.vault_mirror_id) == router.target(obj):
                    continue
                try:
                    router.update(obj)
                    moved += 1
                except Exception as e:
                    failed += 1
                    logger.error(f'Moving the secret of {model.__name__} {obj.pk} failed: {e}')
    print(f'moved: {moved}, failed: {failed}')
    return {'moved': moved, 'failed': failed}

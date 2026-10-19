from collections import defaultdict

from django.db import transaction
from django.db.models.signals import post_delete
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.functional import LazyObject
from django.utils.translation import gettext_noop

from accounts.backends import vault_client, refresh_vault_client
from accounts.const import SecretType, Source
from audits.const import ActivityChoices
from audits.signal_handlers import create_activities
from common.decorators import merge_delay_run
from common.signals import django_ready
from common.utils import get_logger, i18n_fmt
from common.utils.connection import RedisPubSub
from .exceptions import VaultException
from .models import Account, AccountTemplate, PersonalAssetCredential
from .tasks.push_account import push_accounts_to_assets_task

logger = get_logger(__name__)


@merge_delay_run(ttl=5)
def push_accounts_if_need(accounts=()):
    from .models import AccountTemplate

    template_accounts = defaultdict(list)
    for ac in accounts:
        # 再强调一次吧
        if ac.source != Source.TEMPLATE:
            continue
        template_accounts[ac.source_id].append(ac)

    for source_id, accounts in template_accounts.items():
        template = AccountTemplate.objects.filter(id=source_id).first()
        if not template or not template.auto_push:
            continue
        logger.debug("Push accounts to source: %s", source_id)
        account_ids = [str(ac.id) for ac in accounts]
        task = push_accounts_to_assets_task.delay(account_ids, params=template.push_params)
        detail = i18n_fmt(
            gettext_noop('Push related accounts to assets: %s, by system'),
            len(account_ids)
        )
        create_activities([str(template.id)], detail, task.id, ActivityChoices.task, template.org_id)
        logger.debug("Push accounts to source: %s, task: %s", source_id, task)


def create_accounts_activities(account, action='create'):
    if action == 'create':
        detail = i18n_fmt(gettext_noop('Add account: %s'), str(account))
    else:
        detail = i18n_fmt(gettext_noop('Delete account: %s'), str(account))
    create_activities([account.asset_id], detail, None, ActivityChoices.operate_log, account.org_id)


@receiver(post_save, sender=Account)
def on_account_create_by_template(sender, instance, created=False, **kwargs):
    if not created:
        return
    push_accounts_if_need.delay(accounts=(instance,))
    create_accounts_activities(instance, action='create')


@receiver(post_delete, sender=Account)
def on_account_delete(sender, instance, **kwargs):
    create_accounts_activities(instance, action='delete')


class VaultSignalHandler(object):
    """ 处理 Vault 相关的信号 """

    @staticmethod
    def save_to_vault(sender, instance, created, **kwargs):
        if instance.secret_type == SecretType.SSH_CERTIFICATE:
            return
        if getattr(instance, 'skip_vault_when_saving', False):
            return
        try:
            if created:
                vault_client.create(instance)
            else:
                vault_client.update(instance)
        except Exception as e:
            logger.exception('Vault save failed: %s', e)
            raise VaultException()

    @staticmethod
    def delete_to_vault(sender, instance, **kwargs):
        if instance.secret_type == SecretType.SSH_CERTIFICATE:
            return
        try:
            vault_client.delete(instance)
        except Exception as e:
            logger.exception('Vault delete failed: %s', e)
            raise VaultException()


for model in (
        Account, AccountTemplate, Account.history.model,
        PersonalAssetCredential,
):
    post_save.connect(VaultSignalHandler.save_to_vault, sender=model)
    post_delete.connect(VaultSignalHandler.delete_to_vault, sender=model)


class VaultPubSub(LazyObject):
    def _setup(self):
        self._wrapped = RedisPubSub('refresh_vault')


vault_pub_sub = VaultPubSub()


@receiver(django_ready)
def subscribe_vault_change(sender, **kwargs):
    logger.debug("Start subscribe vault change")

    vault_pub_sub.subscribe(lambda name: refresh_vault_client())


# ---------------------------------------------------------------- XPAM just-in-time accounts
def _schedule_jit_reconcile():
    """Reconcile shortly after a burst of permission changes (debounced)."""
    from django.core.cache import cache
    from accounts.tasks.jit import jit_reconcile_task
    # The marker is removed when the run starts, so no change is ever left out
    if cache.add('xpam-jit-reconcile-scheduled', 1, timeout=120):
        transaction.on_commit(lambda: jit_reconcile_task.apply_async(countdown=15))


def _jit_in_use():
    """True when a policy keeps accounts for as long as access is granted."""
    from accounts.models import JITPolicy
    from orgs.utils import tmp_to_root_org
    with tmp_to_root_org():
        return JITPolicy.objects.filter(
            mode__in=[JITPolicy.Mode.while_granted, JITPolicy.Mode.approved_window]
        ).exists()


@receiver(post_save, sender='terminal.Session')
def on_session_finished_release_jit(sender, instance, created=False, **kwargs):
    if not instance.is_finished or not instance.account_id:
        return
    from accounts.models import JITAccount
    from accounts.tasks.jit import jit_release_if_idle_task
    from orgs.utils import tmp_to_root_org
    with tmp_to_root_org():
        jit_ids = list(JITAccount.objects.filter(
            account_id=instance.account_id, mode='per_session', status=JITAccount.Status.ready,
        ).values_list('id', flat=True))
    for jit_id in jit_ids:
        # Wait a moment: a dropped remote desktop often reconnects right away
        transaction.on_commit(
            lambda _id=str(jit_id): jit_release_if_idle_task.apply_async(args=(_id,), countdown=60)
        )


@receiver(post_save, sender='accounts.JITPolicy')
@receiver(post_delete, sender='accounts.JITPolicy')
def on_jit_policy_change(sender, instance=None, **kwargs):
    _schedule_jit_reconcile()


@receiver(post_save, sender='perms.AssetPermission')
@receiver(post_delete, sender='perms.AssetPermission')
def on_permission_change_reconcile_jit(sender, instance=None, **kwargs):
    if _jit_in_use():
        _schedule_jit_reconcile()


def _on_m2m_change(sender, action=None, **kwargs):
    if action in ('post_add', 'post_remove', 'post_clear') and _jit_in_use():
        _schedule_jit_reconcile()


def _connect_jit_m2m_signals():
    from django.db.models.signals import m2m_changed
    from perms.models import AssetPermission
    from users.models import User
    for field in ('users', 'user_groups', 'assets', 'nodes'):
        m2m_changed.connect(_on_m2m_change, sender=getattr(AssetPermission, field).through,
                            dispatch_uid=f'xpam-jit-perm-{field}')
    m2m_changed.connect(_on_m2m_change, sender=User.groups.through, dispatch_uid='xpam-jit-user-groups')
    # policy rules can select assets by node
    from assets.models import Asset
    m2m_changed.connect(_on_m2m_change, sender=Asset.nodes.through, dispatch_uid='xpam-jit-asset-nodes')


_connect_jit_m2m_signals()


@receiver(post_save, sender='users.User')
@receiver(post_delete, sender='users.User')
def on_user_change_reconcile_jit(sender, instance=None, created=False, update_fields=None, **kwargs):
    if created:
        return
    # Sign-ins and similar bookkeeping saves do not change who has access
    if update_fields and set(update_fields) <= {'last_login', 'date_api_key_last_used', 'date_updated',
                                                'date_password_last_updated'}:
        return
    if _jit_in_use():
        _schedule_jit_reconcile()

"""
Creating and removing just-in-time accounts.

Per connection:  the account is created when the user connects (before the connection token is
                 issued) and removed shortly after the last session that used it has ended.
While granted /  the account is created while a permission (or an approved request) gives the
approved window: user the asset, and removed when that permission ends, is deleted, or no
                 longer includes the user or the asset. A periodic reconciliation keeps the
                 assets in line with the permissions.
"""
import uuid

from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _, gettext_noop

from common.utils import get_logger
from common.utils.lock import DistributedLock
from orgs.utils import tmp_to_org, tmp_to_root_org
from .naming import build_username, generate_password, JITNameError
from .policy import select_policy, push_params, remove_params, asset_supports_jit

logger = get_logger(__name__)

LOCK_SECONDS = 600


class JITError(Exception):
    pass


def _lock(asset_id, username):
    return DistributedLock(f'xpam-jit:{asset_id}:{username}', expire=LOCK_SECONDS)


def _run_automation(tp, task_name, snapshot):
    from accounts.tasks.common import quickstart_automation_by_snapshot
    return quickstart_automation_by_snapshot(task_name, tp, snapshot)


def _push(account, policy):
    """Push `account` to its asset now, in this process. Returns (ok, error)."""
    from accounts.const import AutomationTypes, ChangeSecretRecordStatusChoice
    from accounts.models import PushSecretRecord
    snapshot = {
        'params': push_params(policy),
        'accounts': [str(account.id)],
        'assets': [str(account.asset_id)],
    }
    name = f"{gettext_noop('Just-in-time account push')} {uuid.uuid4().hex[:8]}"
    try:
        execution = _run_automation(AutomationTypes.push_account, name, snapshot)
    except Exception as e:
        logger.exception('JIT push of %s failed to run', account)
        return False, str(e)
    record = PushSecretRecord.objects.filter(execution=execution, account=account) \
        .order_by('-date_created').first()
    ok_statuses = (ChangeSecretRecordStatusChoice.success, ChangeSecretRecordStatusChoice.unverified)
    if record and record.status in ok_statuses:
        return True, ''
    error = (record.error if record else '') or (execution.summary or {}).get('error', '') \
        or _('The account could not be created on the asset; see the automation log')
    return False, str(error)


def _create_account_row(policy, asset, username, secret):
    from accounts.models import Account
    existing = Account.objects.filter(asset=asset, username=username, secret_type='password').first()
    if existing and existing.source != 'jit':
        raise JITError(_('An account named "%(name)s" already exists on %(asset)s and is not managed by '
                         'just-in-time access') % {'name': username, 'asset': asset})
    # "Privileged" in XPAM marks the accounts automations may log in with. A just-in-time account
    # never is one (it may not exist on the asset yet); its sudo/Administrators rights come from the
    # policy and are recorded on the JIT record.
    if existing:
        existing.secret = secret
        existing.privileged = False
        existing.is_active = True
        existing.save()
        return existing
    return Account.objects.create(
        asset=asset, username=username, name=f'JIT-{username}', secret_type='password',
        secret=secret, privileged=False, source='jit', is_active=True,
        org_id=asset.org_id,
    )


def _provision(policy, user, asset, username, perm, mode):
    """Create the account in XPAM, push it to the asset, and record it. Raises JITError."""
    from accounts.models import JITAccount
    secret = generate_password()
    with transaction.atomic():
        account = _create_account_row(policy, asset, username, secret)
        jit = JITAccount.objects.create(
            policy=policy, mode=mode, user=user, user_display=str(user) if user else '',
            asset=asset, asset_display=str(asset), account=account, username=username,
            privileged=policy.privileged, permission_id=perm.id if perm else None,
            date_expired=perm.date_expired if (perm and mode != policy.Mode.per_session) else None,
            status=JITAccount.Status.pushing, org_id=asset.org_id,
        )
        account.source_id = str(jit.id)
        account.save(update_fields=['source_id'])
    ok, error = _push(account, policy)
    if not ok:
        jit.set_status(JITAccount.Status.failed, error)
        # Do not leave a half-created account behind
        transaction.on_commit(lambda: _schedule_release(jit.id))
        raise JITError(_('The just-in-time account could not be created on %(asset)s: %(error)s')
                       % {'asset': asset, 'error': error})
    jit.set_status(JITAccount.Status.ready)
    logger.info('JIT account %s created on %s for %s (%s)', username, asset, user, mode)
    return jit


def provision_for_connection(user, asset):
    """
    Make sure `user` has a ready just-in-time account on `asset` and return its JITAccount.
    Blocks while the account is pushed (usually a few seconds). Raises JITError.
    """
    from accounts.models import JITAccount, JITPolicy
    with tmp_to_org(asset.org_id):
        policy, perm = select_policy(user, asset)
        if not policy:
            raise JITError(_('No just-in-time policy gives you an account on this asset'))
        try:
            username = build_username(policy, user, new_session=True)
        except JITNameError as e:
            raise JITError(str(e))

        with _lock(asset.id, username):
            reusable = JITAccount.objects.filter(
                asset=asset, username=username, status=JITAccount.Status.ready, account__isnull=False,
            )
            if policy.mode == JITPolicy.Mode.per_session:
                if policy.username_mode != JITPolicy.UsernameMode.random_session:
                    # the same user reconnecting, or a shared specific name: reuse the live account
                    candidates = reusable.filter(mode=JITPolicy.Mode.per_session)
                    if policy.username_mode != JITPolicy.UsernameMode.specific:
                        candidates = candidates.filter(user=user)
                    jit = candidates.first()
                    if jit:
                        return jit
                return _provision(policy, user, asset, username, perm, JITPolicy.Mode.per_session)

            jit = reusable.filter(user=user, policy=policy).first()
            if jit:
                return jit
            return _provision(policy, user, asset, username, perm, policy.mode)


def attach_token(jit, token_id):
    tokens = list(jit.connection_tokens or [])
    if str(token_id) not in tokens:
        tokens.append(str(token_id))
        jit.connection_tokens = tokens[-50:]
        jit.save(update_fields=['connection_tokens', 'date_updated'])


def account_for_token(token):
    """The real account behind a connection token for the @JIT alias (None if there is none)."""
    from accounts.models import JITAccount
    with tmp_to_root_org():
        qs = JITAccount.objects.filter(
            asset_id=token.asset_id, status=JITAccount.Status.ready, account__isnull=False
        ).select_related('account')
        jit = qs.filter(connection_tokens__contains=[str(token.id)]).first()
        if not jit:
            jit = qs.filter(user_id=token.user_id).exclude(mode='per_session').first()
        return jit.account if jit else None


# ---------------------------------------------------------------- removal

def _schedule_release(jit_id, countdown=0):
    from accounts.tasks.jit import jit_release_task
    jit_release_task.apply_async(args=(str(jit_id),), countdown=countdown)


def release(jit, reason=''):
    """Remove the account from the asset and from XPAM. Runs the remove automation in this process."""
    with tmp_to_org(jit.org_id):
        return _release(jit, reason)


def _release(jit, reason=''):
    from accounts.const import AutomationTypes
    from accounts.models import Account, JITAccount
    if jit.status == JITAccount.Status.removed:
        return True
    if not jit.asset_id:
        # The asset is gone and its accounts with it
        jit.set_status(JITAccount.Status.removed, reason)
        return True
    if jit.username.lower() in ('root', 'administrator'):
        jit.set_status(JITAccount.Status.remove_failed, 'Refusing to remove a system account')
        return False

    with _lock(jit.asset_id, jit.username):
        jit.refresh_from_db()
        if jit.status == JITAccount.Status.removed:
            return True
        # Another live record (shared specific name) still uses this account on the asset
        others = JITAccount.objects.filter(
            asset_id=jit.asset_id, username=jit.username,
            status__in=[JITAccount.Status.ready, JITAccount.Status.pushing],
        ).exclude(id=jit.id)
        if others.exists():
            jit.account = None
            jit.save(update_fields=['account'])
            jit.set_status(JITAccount.Status.removed, _('Still used by another just-in-time record'))
            return True

        jit.set_status(JITAccount.Status.removing, reason)
        asset_id = str(jit.asset_id)
        snapshot = {
            'assets': [asset_id],
            'accounts': [{'asset': asset_id, 'username': jit.username}],
            'delete': 'both',
            'params': remove_params(jit.policy),
        }
        error = ''
        try:
            _run_automation(AutomationTypes.remove_account,
                            f"{gettext_noop('Just-in-time account removal')} {uuid.uuid4().hex[:8]}",
                            snapshot)
        except Exception as e:
            logger.exception('JIT removal of %s failed to run', jit)
            error = str(e)
        still_there = Account.objects.filter(asset_id=jit.asset_id, username=jit.username, source='jit').exists()
        jit.attempts += 1
        jit.save(update_fields=['attempts'])
        if still_there:
            jit.set_status(JITAccount.Status.remove_failed,
                           error or _('The account could not be removed from the asset; see the automation log'))
            return False
        jit.set_status(JITAccount.Status.removed, reason)
        logger.info('JIT account %s removed from %s (%s)', jit.username, jit.asset_display, reason)
        return True


def release_if_idle(jit):
    """Per connection: remove the account once no session uses it and no token can still open one."""
    with tmp_to_org(jit.org_id):
        return _release_if_idle(jit)


def _release_if_idle(jit):
    from accounts.models import JITAccount
    from authentication.models import ConnectionToken
    from terminal.models import Session
    if jit.status != JITAccount.Status.ready or jit.mode != 'per_session':
        return False
    if jit.account_id and Session.objects.filter(account_id=str(jit.account_id), is_finished=False).exists():
        return False
    now = timezone.now()
    tokens = ConnectionToken.objects.filter(id__in=jit.connection_tokens or [], is_active=True, date_expired__gt=now)
    if tokens.exists():
        return False
    # A connect is in progress for this account right now (its token is attached a few seconds
    # after the account is ready)
    if (now - jit.date_updated).total_seconds() < 30:
        return False
    return release(jit, reason=_('Session ended'))


# ---------------------------------------------------------------- granted modes

def desired_granted_pairs():
    """{(policy_id, user_id, asset_id): permission} that should have a just-in-time account now."""
    from accounts.models import JITPolicy
    from perms.models import AssetPermission
    desired = {}
    with tmp_to_root_org():
        for policy in JITPolicy.objects.filter(is_active=True, mode__in=[
            JITPolicy.Mode.while_granted, JITPolicy.Mode.approved_window
        ]):
            if policy.mode == JITPolicy.Mode.while_granted:
                perms = AssetPermission.objects.filter(jit_policy=policy)
            else:
                perms = AssetPermission.objects.filter(org_id=policy.org_id, from_ticket=True, jit_policy__isnull=True)
            for perm in perms.valid():
                users = perm.get_all_users().filter(is_active=True)
                assets = [a for a in perm.get_all_assets() if asset_supports_jit(a)]
                for user in users:
                    if not user.is_valid:
                        continue
                    for asset in assets:
                        key = (str(policy.id), str(user.id), str(asset.id))
                        current = desired.get(key)
                        if not current or current.date_expired < perm.date_expired:
                            desired[key] = perm
    return desired


def reconcile():
    """Create missing and remove obsolete accounts of the granted modes; clean up idle ones."""
    from accounts.models import JITAccount
    from accounts.tasks.jit import jit_provision_task
    summary = {'create': 0, 'remove': 0, 'idle': 0, 'retry': 0}
    with tmp_to_root_org():
        desired = desired_granted_pairs()
        live = JITAccount.objects.filter(
            mode__in=['while_granted', 'approved_window'],
            status__in=[JITAccount.Status.pending, JITAccount.Status.pushing, JITAccount.Status.ready],
        )
        have = set()
        for jit in live:
            key = (str(jit.policy_id), str(jit.user_id), str(jit.asset_id))
            perm = desired.get(key)
            if not perm or not jit.policy_id or not jit.user_id:
                _schedule_release(jit.id)
                summary['remove'] += 1
                continue
            have.add(key)
            if jit.date_expired != perm.date_expired or str(jit.permission_id) != str(perm.id):
                jit.date_expired = perm.date_expired
                jit.permission_id = perm.id
                jit.save(update_fields=['date_expired', 'permission_id', 'date_updated'])
        for key, perm in desired.items():
            if key in have:
                continue
            # A failed push is retried at most every 30 minutes
            recent_fail = JITAccount.objects.filter(
                policy_id=key[0], user_id=key[1], asset_id=key[2], date_ready__isnull=True,
                status__in=[JITAccount.Status.failed, JITAccount.Status.remove_failed,
                            JITAccount.Status.removing, JITAccount.Status.removed],
                date_created__gt=timezone.now() - timezone.timedelta(minutes=30),
            ).exists()
            if recent_fail:
                continue
            jit_provision_task.delay(key[0], key[1], key[2], str(perm.id))
            summary['create'] += 1

        for jit in JITAccount.objects.filter(mode='per_session', status=JITAccount.Status.ready):
            if release_if_idle(jit):
                summary['idle'] += 1

        for jit in JITAccount.objects.filter(status__in=[JITAccount.Status.remove_failed,
                                                         JITAccount.Status.failed], attempts__lt=5,
                                             date_updated__lt=timezone.now() - timezone.timedelta(minutes=10)):
            if jit.account_id or jit.status == JITAccount.Status.remove_failed:
                _schedule_release(jit.id)
                summary['retry'] += 1
    return summary


def provision_granted(policy_id, user_id, asset_id, perm_id):
    from accounts.models import JITAccount, JITPolicy
    from assets.models import Asset
    from perms.models import AssetPermission
    from users.models import User
    with tmp_to_root_org():
        policy = JITPolicy.objects.filter(id=policy_id, is_active=True).first()
        user = User.objects.filter(id=user_id).first()
        asset = Asset.objects.filter(id=asset_id).first()
        perm = AssetPermission.objects.filter(id=perm_id).first()
    if not (policy and user and asset and perm):
        return
    with tmp_to_org(asset.org_id):
        username = build_username(policy, user)
        with _lock(asset.id, username):
            if JITAccount.objects.filter(policy=policy, user=user, asset=asset, status__in=[
                JITAccount.Status.ready, JITAccount.Status.pushing
            ]).exists():
                return
            try:
                _provision(policy, user, asset, username, perm, policy.mode)
            except JITError as e:
                logger.warning('JIT provisioning for %s on %s failed: %s', user, asset, e)

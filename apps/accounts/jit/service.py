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
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _, gettext_noop

from common.utils import get_logger
from common.utils.lock import DistributedLock
from orgs.utils import tmp_to_org, tmp_to_root_org
from .naming import build_username, generate_password, JITNameError
from .policy import PolicyMatcher, select_policy, push_params, remove_params, asset_supports_jit, target_kind

logger = get_logger(__name__)

LOCK_SECONDS = 600


class JITError(Exception):
    pass


def _lock(asset_id, username):
    return DistributedLock(f'xpam-jit:{asset_id}:{username}', expire=LOCK_SECONDS)


def _run_automation(tp, task_name, snapshot):
    from accounts.tasks.common import quickstart_automation_by_snapshot
    return quickstart_automation_by_snapshot(task_name, tp, snapshot)


USER_EXISTS_MARK = 'XPAM_JIT_USER_EXISTS'


def _push(account, policy, valid_until=None, allow_existing=False):
    """Create `account` on its asset now, in this process. Returns (ok, error, exists_already)."""
    kind = target_kind(account.asset)
    if kind in ('database', 'device'):
        from .targets import create_database_account, create_device_account, TargetError, TargetExists
        try:
            if kind == 'database':
                valid_until = valid_until or timezone.now() + timezone.timedelta(days=7)
                create_database_account(account.asset, account.username, account.secret, policy, valid_until,
                                        allow_existing=allow_existing)
            else:
                create_device_account(account.asset, account.username, account.secret, policy,
                                      allow_existing=allow_existing)
            return True, '', False
        except TargetExists as e:
            return False, str(e), True
        except TargetError as e:
            return False, str(e), False
        except Exception as e:
            logger.exception('JIT %s account %s failed', kind, account)
            return False, str(e), False
    ok, error = _push_host(account, policy, allow_existing)
    return ok, error, (not ok and USER_EXISTS_MARK in str(error))


def _push_host(account, policy, allow_existing=False):
    from accounts.const import AutomationTypes, ChangeSecretRecordStatusChoice
    from accounts.models import PushSecretRecord
    params = push_params(policy)
    for method_params in params.values():
        method_params['new_only'] = not allow_existing  # never adopt a user XPAM did not create
    snapshot = {
        'params': params,
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


def username_for(policy, user, asset, new_session=False):
    """The account name on `asset` (databases: letters, digits and "_" only)."""
    from accounts.models import JITAccount, JITPolicy
    from .naming import _short_hash
    from .targets import db_username
    name = build_username(policy, user, new_session=new_session)
    final = db_username(name) if target_kind(asset) == 'database' else name
    if user is None or policy.username_mode == JITPolicy.UsernameMode.specific:
        return final  # a specific name is shared on purpose
    # "john.doe" and "john-doe" (or "john_doe" on a database) give the same name: never let two
    # people share one account; the second one gets a short hash of the user id
    taken = JITAccount.objects.filter(
        asset=asset, username=final,
        status__in=[JITAccount.Status.ready, JITAccount.Status.pushing, JITAccount.Status.removing,
                    JITAccount.Status.remove_failed],
    ).exclude(user_id=user.id).exists()
    if taken:
        name = name[:15].rstrip('-_') + '-' + _short_hash(str(user.id), 4)
        final = db_username(name) if target_kind(asset) == 'database' else name
    return final


def _new_secret(policy, asset, username):
    """(secret_type, secret): an SSH key when the policy asks for one on Linux/Unix, else a password."""
    if policy.credential_type == 'ssh_key' and target_kind(asset) == 'host' and asset.platform.type != 'windows':
        from common.utils.encode import ssh_key_gen
        private_key, _public = ssh_key_gen(length=3072, type='rsa', username=username)
        return 'ssh_key', private_key
    if target_kind(asset) == 'device':
        from .naming import DEVICE_PASSWORD_SPECIALS
        return 'password', generate_password(specials=DEVICE_PASSWORD_SPECIALS)
    return 'password', generate_password()


def _create_account_row(policy, asset, username, secret, secret_type='password'):
    from accounts.models import Account
    existing = Account.objects.filter(asset=asset, username=username).first()
    if existing and existing.source != 'jit':
        raise JITError(_('An account named "%(name)s" already exists on %(asset)s and is not managed by '
                         'just-in-time access') % {'name': username, 'asset': asset})
    # "Privileged" in XPAM marks the accounts automations may log in with. A just-in-time account
    # never is one (it may not exist on the asset yet); its sudo/Administrators rights come from the
    # policy and are recorded on the JIT record.
    if existing:
        existing.secret_type = secret_type
        existing.secret = secret
        existing.privileged = False
        existing.is_active = True
        existing.save()
        return existing
    return Account.objects.create(
        asset=asset, username=username, name=f'JIT-{username}', secret_type=secret_type,
        secret=secret, privileged=False, source='jit', is_active=True,
        org_id=asset.org_id,
    )


def _provision(policy, user, asset, username, perm, mode):
    """Create the account in XPAM, push it to the asset, and record it. Raises JITError."""
    from accounts.models import JITAccount
    secret_type, secret = _new_secret(policy, asset, username)
    with transaction.atomic():
        account = _create_account_row(policy, asset, username, secret, secret_type)
        jit = JITAccount.objects.create(
            policy=policy, mode=mode, user=user, user_display=str(user) if user else '',
            asset=asset, asset_display=str(asset), account=account, username=username,
            kind=target_kind(asset) or 'host',
            privileged=policy.privileged, permission_id=perm.id if perm else None,
            date_expired=perm.date_expired if (perm and mode != policy.Mode.per_session) else None,
            status=JITAccount.Status.pushing, org_id=asset.org_id,
        )
        account.source_id = str(jit.id)
        account.save(update_fields=['source_id'])
    valid_until = None
    if jit.date_expired:
        valid_until = jit.date_expired + timezone.timedelta(hours=1)
    # XPAM may only reuse a name on the target that it created itself (a live or not yet removed record)
    allow_existing = JITAccount.objects.filter(
        asset=asset, username=username,
        status__in=[JITAccount.Status.ready, JITAccount.Status.removing, JITAccount.Status.remove_failed],
    ).exclude(id=jit.id).exists()
    ok, error, exists_already = _push(account, policy, valid_until, allow_existing)
    if not ok and exists_already:
        # the name belongs to someone else's account on the target: leave the target alone
        from accounts.models import Account
        jit.account = None
        jit.save(update_fields=['account'])
        Account.objects.filter(id=account.id, source='jit').delete()
        jit.set_status(JITAccount.Status.failed, error)
        raise JITError(_('The just-in-time account could not be created on %(asset)s: %(error)s')
                       % {'asset': asset, 'error': error})
    if not ok:
        jit.set_status(JITAccount.Status.failed, error)
        # Do not leave a half-created account behind (XPAM checked the name was free, so it is ours)
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
            username = username_for(policy, user, asset, new_session=True)
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

def _schedule_release(jit_id, countdown=0, reason=''):
    from accounts.tasks.jit import jit_release_task
    jit_release_task.apply_async(args=(str(jit_id),), kwargs={'reason': str(reason)}, countdown=countdown)


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
    if jit.username.lower() in ('root', 'administrator', 'admin', 'sa', 'sys', 'system', 'postgres', 'mysql'):
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
        end_sessions(jit)
        kind = jit.kind or target_kind(jit.asset) or 'host'
        error = ''
        if kind in ('database', 'device'):
            from .targets import remove_database_account, remove_device_account, TargetError
            try:
                if kind == 'database':
                    remove_database_account(jit.asset, jit.username)
                else:
                    remove_device_account(jit.asset, jit.username, jit.policy)
                Account.objects.filter(asset_id=jit.asset_id, username=jit.username, source='jit').delete()
            except TargetError as e:
                error = str(e)
            except Exception as e:
                logger.exception('JIT removal of %s failed', jit)
                error = str(e)
        else:
            asset_id = str(jit.asset_id)
            snapshot = {
                'assets': [asset_id],
                'accounts': [{'asset': asset_id, 'username': jit.username}],
                'delete': 'both',
                'params': remove_params(jit.policy),
            }
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


def end_sessions(jit):
    """End the XPAM sessions that still use this just-in-time account (the access is over)."""
    from terminal.models import Session
    if not jit.account_id:
        return 0
    if jit.policy and not jit.policy.end_sessions_on_expiry:
        return 0
    try:
        from terminal.api.session.task import create_sessions_tasks
        ids = list(Session.objects.filter(account_id=str(jit.account_id), is_finished=False)
                   .values_list('id', flat=True))
        if ids:
            create_sessions_tasks(ids, 'XPAM just-in-time access')
            logger.info('JIT %s: ending %s live session(s)', jit, len(ids))
        return len(ids)
    except Exception as e:
        logger.warning('JIT %s: live sessions could not be ended: %s', jit, e)
        return 0


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
    from django.db.models import Q
    from perms.models import AssetPermission
    matcher = PolicyMatcher()
    if not any(p.is_granted_mode for p in matcher.by_id.values()):
        return {}
    # Organizations whose rule policies may keep accounts while access is granted
    rule_orgs = [org_id for org_id, policies in matcher.rules_by_org.items()
                 if any(p.is_granted_mode for p in policies)]
    supported = {}
    best = {}  # (user, asset) -> (policy, perm): chosen exactly like at connect time
    with tmp_to_root_org():
        q = Q(jit_policy__isnull=False)
        if rule_orgs:
            q |= Q(jit_policy__isnull=True, org_id__in=rule_orgs)
        for perm in AssetPermission.objects.valid().filter(q, jit_disabled=False):
            users = [u for u in perm.get_all_users().filter(is_active=True) if u.is_valid]
            if not users:
                continue
            for asset in perm.get_all_assets():
                if asset.id not in supported:
                    supported[asset.id] = asset_supports_jit(asset)
                if not supported[asset.id]:
                    continue
                for user in users:
                    policy = matcher.policy_for(perm, user, asset)
                    if not policy:
                        continue
                    key = (user.id, asset.id)
                    current = best.get(key)
                    if not current or current[1].date_expired < perm.date_expired:
                        best[key] = (policy, perm)
    return {
        (str(policy.id), str(user_id), str(asset_id)): perm
        for (user_id, asset_id), (policy, perm) in best.items() if policy.is_granted_mode
    }


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

        # Per connection accounts whose access ended while a session is still open
        summary['ended'] = end_expired_per_session()

        for jit in JITAccount.objects.filter(status__in=[JITAccount.Status.remove_failed,
                                                         JITAccount.Status.failed], attempts__lt=5,
                                             date_updated__lt=timezone.now() - timezone.timedelta(minutes=10)):
            if jit.account_id or jit.status == JITAccount.Status.remove_failed:
                _schedule_release(jit.id)
                summary['retry'] += 1
    return summary


def end_expired_per_session():
    """Per connection accounts outlive their session only until the access behind them ends."""
    from accounts.models import JITAccount
    count = 0
    with tmp_to_root_org():
        for jit in JITAccount.objects.filter(mode='per_session', status=JITAccount.Status.ready) \
                .select_related('policy', 'user', 'asset'):
            # every time, not only when the permission ends: a user taken out of the permission, or
            # disabled, loses the account within a minute too
            user_ok = bool(jit.user and jit.user.is_valid)
            if user_ok and jit.asset:
                with tmp_to_org(jit.org_id):
                    policy, other = select_policy(jit.user, jit.asset)
                if policy and other:
                    JITAccount.objects.filter(id=jit.id).update(permission_id=other.id)
                    continue
            _schedule_release(jit.id, reason=_('Access ended'))
            count += 1
    return count


def expiring_soon():
    """[(user, permission, minutes)] whose time-boxed access ends within the policy's warning time."""
    from django.core.cache import cache
    from perms.models import AssetPermission
    now = timezone.now()
    matcher = PolicyMatcher()
    if not matcher:
        return []
    longest = max([p.expiry_warning_minutes for p in matcher.by_id.values()] + [0])
    if not longest:
        return []
    result = []
    with tmp_to_root_org():
        perms = AssetPermission.objects.filter(
            is_active=True, date_start__lte=now, date_expired__gt=now,
            date_expired__lte=now + timezone.timedelta(minutes=longest),
        ).filter(Q(from_ticket=True) | Q(jit_policy__isnull=False))
        for perm in perms:
            assets = list(perm.get_all_assets()[:20])
            for user in perm.get_all_users().filter(is_active=True):
                policy = next((matcher.policy_for(perm, user, a) for a in assets
                               if matcher.policy_for(perm, user, a)), None)
                if not policy or not policy.expiry_warning_minutes:
                    continue
                left = (perm.date_expired - now).total_seconds() / 60
                if left > policy.expiry_warning_minutes:
                    continue
                key = f'xpam-jit-warned:{perm.id}:{user.id}:{int(perm.date_expired.timestamp())}'
                if not cache.add(key, 1, timeout=24 * 3600):
                    continue
                result.append((user, perm, assets, max(1, round(left))))
    return result


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
        username = username_for(policy, user, asset)
        with _lock(asset.id, username):
            if JITAccount.objects.filter(policy=policy, user=user, asset=asset, status__in=[
                JITAccount.Status.ready, JITAccount.Status.pushing
            ]).exists():
                return
            try:
                _provision(policy, user, asset, username, perm, policy.mode)
            except JITError as e:
                logger.warning('JIT provisioning for %s on %s failed: %s', user, asset, e)

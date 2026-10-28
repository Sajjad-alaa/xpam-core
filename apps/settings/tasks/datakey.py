"""
XPAM: data key rotation without downtime (see common/db/datakey.py).

Once a day:
- local keyring: a new data key version when the last one is older than XPAM_DATA_KEY_ROTATION;
  transit: Vault rotates the key itself (auto_rotate_period, set with `xpamctl vault rotation`);
- every encrypted value not at the newest version (or still in an older format) is re-encrypted in place:
  database columns, encrypted settings, and the secrets XPAM keeps in vaults (they are encrypted the same way);
  transit values are re-wrapped by Vault in batches (XPAM does not see them);
- key versions older than the last XPAM_DATA_KEY_KEEP_VERSIONS are retired once nothing uses them: a leaked old
  key, or an old backup, then opens nothing.
XPAM keeps running throughout; nobody is signed out.
"""
from datetime import timedelta

from celery import shared_task
from django.conf import settings
from django.db import models, transaction
from django.db.models.functions import Cast
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from common.utils import get_logger
from ops.celery.decorator import register_as_period_task

logger = get_logger(__name__)

__all__ = ['rotate_data_keys', 'data_key_status']

ROTATION = {'daily': timedelta(days=1), 'weekly': timedelta(days=7), 'monthly': timedelta(days=30)}


def _plan():
    from django.apps import apps
    from common.db.fields import EncryptMixin
    seen, plan = set(), []
    for model in apps.get_models():
        meta = model._meta
        if meta.proxy or not meta.managed:
            continue
        for field in meta.concrete_fields:
            if isinstance(field, EncryptMixin) and (meta.db_table, field.column) not in seen:
                seen.add((meta.db_table, field.column))
                plan.append((model, field))
    return plan


def _raw_values():
    """ (model, field, pk, raw) for every encrypted value in the database """
    from settings.models import Setting
    for model, field in _plan():
        qs = model._base_manager.exclude(**{f'{field.attname}__isnull': True}).exclude(**{field.attname: ''})
        rows = qs.annotate(_xpam_raw=Cast(field.attname, models.TextField())).values_list('pk', '_xpam_raw')
        for pk, raw in rows.iterator(chunk_size=500):
            yield model, field.attname, pk, raw
    for pk, raw in Setting._base_manager.filter(encrypted=True).exclude(value='').values_list('pk', 'value'):
        yield Setting, 'value', pk, raw


def _current_version():
    from common.db import datakey
    p = datakey.provider()
    if p == 'transit':
        return int(datakey.transit.info()['latest_version'])
    if p == 'local':
        return datakey.keyring.current()[0]
    return None


def _rotate_if_due():
    from common.db import datakey
    if datakey.provider() != 'local':
        return
    period = ROTATION.get((settings.XPAM_DATA_KEY_ROTATION or '').lower())
    if not period:
        return
    from settings.models import DataKey
    last = DataKey.objects.filter(retired=False).order_by('-version').first()
    if last is None or timezone.now() - last.date_created >= period:
        version = datakey.keyring.rotate()
        logger.info(f'data key: new version v{version}')


def _replace(model, attname, pk, raw, value):
    """ the new value, only when the row still holds the one that was read: a value that a user changed in the
    meantime is kept (False) and looked at again tomorrow """
    with transaction.atomic():
        now = model._base_manager.select_for_update().filter(pk=pk) \
            .annotate(_xpam_raw=Cast(attname, models.TextField())).values_list('_xpam_raw', flat=True).first()
        if now != raw:
            return False
        model._base_manager.filter(pk=pk).update(**{attname: models.Value(value, output_field=models.TextField())})
    return True


def _reencrypt_database(current):
    """ every value at the newest version: transit by Vault (rewrap), others decrypted and encrypted again """
    from common.db import datakey
    from common.db.utils import Encryptor
    batch, done, failed, unreadable = [], 0, 0, 0

    def flush():
        nonlocal done, failed
        if not batch:
            return
        try:
            new = datakey.transit.rewrap([raw for *_, raw in batch])
        except Exception as e:
            logger.error(f'data key: re-wrapping {len(batch)} values failed: {e}')
            failed += len(batch)
            batch.clear()
            return
        for (model, attname, pk, raw), value in zip(batch, new):
            done += _replace(model, attname, pk, raw, value)
        batch.clear()

    for model, attname, pk, raw in _raw_values():
        if raw == '# Secret-has-been-saved-to-vault #' or datakey.is_current(raw, current):
            continue
        if datakey.provider() == 'transit' and raw.startswith(datakey.TRANSIT_PREFIX):
            batch.append((model, attname, pk, raw))
            if len(batch) >= 100:
                flush()
            continue
        try:
            plain = Encryptor(raw).decrypt()
            if plain is None:
                continue
            if not plain:
                # ('' is also what Encryptor answers for a value no key opens: that one is left as it is; it does
                # not depend on a data key version, so it does not hold back the retirement of old versions)
                try:
                    datakey.check_readable(raw)
                except ValueError:
                    unreadable += 1
                    logger.warning(f'data key: {model._meta.label} {pk} cannot be opened with SECRET_KEY: left as it is')
                    continue
            done += _replace(model, attname, pk, raw, Encryptor(plain).encrypt())
        except Exception as e:
            # (one value that cannot be opened now must not stop the others; it is retried tomorrow)
            failed += 1
            logger.error(f'data key: {model._meta.label} {pk} could not be re-encrypted: {e}')
    flush()
    _reencrypt_database.failed = failed
    _reencrypt_database.unreadable = unreadable
    return done


def _reencrypt_vaults(current):
    """ the secrets kept in vaults are encrypted the same way: written again with the newest key (the password
    history too: it is kept in the account's vault). What could not be done is counted: no key version may be
    retired while a vault may still hold a value under it """
    from accounts.backends import vault_client
    from accounts.models import Account, AccountTemplate, PersonalAssetCredential
    from common.db import datakey
    from orgs.utils import tmp_to_root_org
    vault_client.type  # noqa: B018
    router = vault_client._wrapped
    done = failed = 0
    if not router.enabled and not hasattr(router, 'target'):
        _reencrypt_vaults.failed = failed
        return done
    with tmp_to_root_org():
        for model in (Account, AccountTemplate, Account.history.model, PersonalAssetCredential):
            queryset = model.objects.all()
            if model is Account:
                queryset = queryset.exclude(secret_source='external')
            for obj in queryset.iterator():
                if not obj.secret_has_save_to_vault:
                    continue
                try:
                    connection, mirror = router._stored(obj)
                    backend = router.backend(connection)
                    if backend.type == 'openbao':
                        continue  # (it keeps the secret as it is: no data key is involved)
                    if backend.type == 'local':
                        if settings.VAULT_ENABLED:
                            # (the configured vault could not be set up: what it holds cannot be checked)
                            raise RuntimeError('the vault client is not available')
                        continue  # (no vault in use: a marker left from an earlier one is not ours to read)
                    entry = backend.build_entry(obj)
                    if backend.type == 'hcp':
                        stored = (backend.client.get(path=entry.full_path).get('data') or {}).get('secret') or ''
                    else:
                        stored = backend.client.get(name=entry.full_path, strict=True) or ''
                    if not stored or datakey.is_current(stored, current):
                        continue
                    obj._secret = entry.get_decrypt_secret(stored, strict=True)
                    backend._update(entry)
                    if mirror:
                        router._mirror_write(mirror, obj)
                    done += 1
                except Exception as e:
                    failed += 1
                    logger.warning(f'data key: {model.__name__} {obj.pk} in its vault could not be re-encrypted: {e}')
    _reencrypt_vaults.failed = failed
    return done


def _retire(current):
    from common.db import datakey
    keep = max(int(getattr(settings, 'XPAM_DATA_KEY_KEEP_VERSIONS', 4) or 4), 1)
    floor = current - keep + 1
    if floor <= 1:
        return None
    if getattr(_reencrypt_database, 'failed', 0) or getattr(_reencrypt_vaults, 'failed', 0):
        return None  # (values could not be re-encrypted: keep every version until they are)
    in_use = [datakey.version_of(raw) for *_, raw in _raw_values() if raw.startswith(datakey.PREFIXES)]
    oldest = min([v for v in in_use if v is not None] or [current])
    floor = min(floor, oldest)
    if datakey.provider() == 'transit':
        if int(datakey.transit.info().get('min_decryption_version') or 1) < floor:
            datakey.transit.set_config(min_decryption_version=floor)
    elif datakey.provider() == 'local':
        datakey.keyring.retire_before(floor)
    return floor


@shared_task(verbose_name=_('Data key rotation'),
             description=_('Rotates the data key on schedule and re-encrypts the secrets with it, without downtime'))
@register_as_period_task(crontab='17 3 * * *')
def rotate_data_keys():
    from common.db import datakey
    if datakey.provider() == 'legacy':
        return {'provider': 'legacy'}
    _rotate_if_due()
    current = _current_version()
    database = _reencrypt_database(current)
    vaults = _reencrypt_vaults(current)
    floor = _retire(current)
    result = {'provider': datakey.provider(), 'version': current, 'database': database, 'vaults': vaults,
              'failed': getattr(_reencrypt_database, 'failed', 0) + getattr(_reencrypt_vaults, 'failed', 0),
              'unreadable': getattr(_reencrypt_database, 'unreadable', 0), 'oldest_kept': floor}
    logger.info(f'data key rotation: {result}')
    return result


def data_key_status():
    """ for the console: provider, current version, values per version """
    from collections import Counter
    from common.db import datakey
    status = {'provider': datakey.provider(), 'rotation': settings.XPAM_DATA_KEY_ROTATION}
    if status['provider'] == 'legacy':
        return status
    status['version'] = _current_version()
    counts = Counter()
    for *_, raw in _raw_values():
        if raw == '# Secret-has-been-saved-to-vault #':
            continue
        counts[datakey.version_of(raw) or 'legacy'] += 1
    status['values'] = {str(k): v for k, v in counts.items()}
    if status['provider'] == 'transit':
        info = datakey.transit.info()
        status['min_decryption_version'] = info.get('min_decryption_version')
        status['auto_rotate_period'] = info.get('auto_rotate_period')
    return status

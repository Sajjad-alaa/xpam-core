"""
XPAM: re-encrypt everything that depends on SECRET_KEY with a new key.

Run with the XPAM services stopped (xpamctl rotate-secret-key does this). The new key comes from the
environment variable NEW_SECRET_KEY (never the command line). Everything happens in one database
transaction: if anything goes wrong, or a value cannot be read with the current key, nothing changes.

Covered: every encrypted model field (account secrets and their history, users' MFA secrets, e-mail,
phone, keys, connection tokens, access keys, storage settings, automation snapshots...), encrypted
settings, and the users' e-mail lookup hashes. Sessions and other signed values in the cache stop
working (everyone signs in again); the installer clears the cache.
"""
import os

from django.apps import apps
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import models, transaction
from django.db.models.functions import Cast

from common.db.fields import EncryptMixin
from common.utils.common import text_hmac_sha256


class DryRun(Exception):
    pass


def read_old(raw):
    """(plain, readable) with the current key. An encrypted empty string is readable (''), a value
    that no current algorithm (nor the legacy signer) can open is not."""
    from common.utils.crypto import crypto
    from common.utils.encode import signer
    plain = crypto.decrypt(raw)
    if plain is not None:
        return plain, True
    try:
        legacy = signer.unsign(raw)
    except Exception:
        legacy = None
    if legacy is not None:
        return str(legacy), True
    return '', False


def new_cryptor(key):
    from common.utils.crypto import get_aes_crypto, get_gm_sm4_ecb_crypto
    if getattr(settings, 'GM_DEVICE_ENABLE', False):
        raise CommandError('The data key is kept in a GM crypto device: rotate it there, not with this command')
    algo = (settings.SECURITY_DATA_CRYPTO_ALGO or 'aes').lower()
    if algo in ('gm', 'gm_sm4_ecb'):
        return get_gm_sm4_ecb_crypto(key)
    if algo == 'aes_ecb':
        return get_aes_crypto(key, 'ECB')
    return get_aes_crypto(key, 'GCM')


class Command(BaseCommand):
    help = 'Re-encrypt every encrypted value with a new SECRET_KEY (services must be stopped)'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true', help='Check everything, then undo')
        parser.add_argument('--force', action='store_true',
                            help='Go on although many values were already unreadable with the current key')

    def plan(self):
        """[(model, field)] once per table (proxy models share their table)."""
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

    def handle(self, *args, **options):
        new_key = os.environ.get('NEW_SECRET_KEY', '')
        if len(new_key) < 32:
            raise CommandError('Set NEW_SECRET_KEY (at least 32 characters) in the environment')
        if new_key == settings.SECRET_KEY:
            raise CommandError('The new key is the current key')
        cryptor = new_cryptor(new_key)
        stats, samples = {}, []
        total = unreadable = 0
        from users.models import User
        try:
            with transaction.atomic():
                # plain e-mail addresses first (the e-mail column itself is re-encrypted below)
                emails = {pk: email or '' for pk, email in User._base_manager.values_list('pk', 'email')}
                for model, field in self.plan():
                    qs = model._base_manager.exclude(**{f'{field.attname}__isnull': True}) \
                        .exclude(**{field.attname: ''})
                    raws = qs.annotate(_xpam_raw=Cast(field.attname, models.TextField())) \
                        .values_list('pk', '_xpam_raw')
                    count = 0
                    for pk, raw in raws.iterator(chunk_size=500):
                        plain, readable = read_old(raw)
                        if not readable:
                            unreadable += 1
                            continue  # (left as it is: it cannot be read with any key XPAM has)
                        new = cryptor.encrypt(plain)
                        model._base_manager.filter(pk=pk).update(
                            **{field.attname: models.Value(new, output_field=models.TextField())})
                        count += 1
                        if len(samples) < 200 and plain:
                            samples.append((model, field, pk, plain))
                    total += count
                    if count:
                        stats[f'{model._meta.label}.{field.name}'] = count

                # encrypted settings (stored as encrypted JSON text)
                from settings.models import Setting
                count = 0
                for setting in Setting._base_manager.filter(encrypted=True).exclude(value=''):
                    plain, readable = read_old(setting.value)
                    if not readable:
                        unreadable += 1
                        continue
                    Setting._base_manager.filter(pk=setting.pk).update(value=cryptor.encrypt(plain))
                    count += 1
                total += count
                if count:
                    stats['settings.Setting (encrypted)'] = count

                # e-mail lookup hashes (HMAC with SECRET_KEY): sign-in and search by e-mail
                count = 0
                for pk, email in emails.items():
                    lookup = text_hmac_sha256(email, secret_key=new_key) if email else ''
                    User._base_manager.filter(pk=pk).update(email_lookup=lookup)
                    count += 1
                stats['users.User.email_lookup'] = count

                checked = total + unreadable
                if checked and (unreadable == checked or (unreadable / checked > 0.1 and not options['force'])):
                    raise CommandError(
                        f'{unreadable} of {checked} encrypted values cannot be read with the current key: '
                        'is SECRET_KEY the key this database was encrypted with? Nothing was changed'
                        + ('.' if unreadable == checked else ' (--force to go on anyway).'))

                # read a sample back with the new key before committing
                for model, field, pk, plain in samples:
                    raw = model._base_manager.filter(pk=pk).annotate(
                        _xpam_raw=Cast(field.attname, models.TextField())).values_list('_xpam_raw', flat=True).first()
                    if cryptor.decrypt(raw) != plain:
                        raise CommandError(f'Verification failed for {model._meta.label}.{field.name}: nothing was changed')

                if options['dry_run']:
                    raise DryRun()
        except DryRun:
            self.stdout.write('Dry run: everything checked, nothing changed.')
        for name, count in sorted(stats.items()):
            self.stdout.write(f'  {name}: {count}')
        self.stdout.write(f'Re-encrypted values: {total}; unreadable and left as they were: {unreadable}; '
                          f'samples verified: {len(samples)}')
        if not options['dry_run']:
            self.stdout.write(self.style.SUCCESS('Re-encrypted. Put the new key in SECRET_KEY before starting XPAM.'))

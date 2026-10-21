"""
XPAM: the vault client of the whole application when several vaults are in use (accounts/models/vault_routing).

- writes: each secret goes to the vault its organization's rules give (asset group, platform, username; first
  match by priority, else the configured vault), and to the rule's mirror too when there is one;
- reads: from the vault the secret is in (it is remembered on the account), from the mirror if that fails;
- a rule change moves a secret the next time it is saved, or for all at once (tasks.vault_routing);
- external accounts (secret_source='external'): read from the customer's vault, never written there.
Without connections and rules it behaves exactly like the configured vault alone.
"""
import threading

from django.db import models

from common.utils import get_logger

logger = get_logger(__name__)

__all__ = ['VaultRouter']


class VaultRouter(object):
    def __init__(self, default):
        self.default = default
        self._backends = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------ the configured vault, as before

    @property
    def type(self):
        return self.default.type

    @property
    def enabled(self):
        return self.default.enabled

    @property
    def client(self):
        return getattr(self.default, 'client', None)

    def is_active(self):
        return self.default.is_active()

    def build_entry(self, instance):
        return self.default.build_entry(instance)

    # ------------------------------------------------------------ connections and rules

    def backend(self, connection_id):
        if not connection_id:
            return self.default
        key = str(connection_id)
        with self._lock:
            if key not in self._backends:
                from accounts.backends import get_vault_client
                from accounts.models import VaultConnection
                connection = VaultConnection.objects.filter(id=connection_id).first()
                if connection is None or not connection.is_active:
                    raise RuntimeError(f'Vault connection {connection_id} is missing or inactive')
                self._backends[key] = get_vault_client(raise_exception=True, **connection.backend_kwargs())
            return self._backends[key]

    @staticmethod
    def _is_history(instance):
        return instance.__class__.__name__ == 'HistoricalAccount'

    @staticmethod
    def _is_external(instance):
        return getattr(instance, 'secret_source', 'xpam') == 'external'

    def _stored(self, instance):
        """ (connection, mirror) where this secret is — a history record follows its account """
        if self._is_history(instance):
            from accounts.models import Account
            row = Account.objects.filter(id=instance.id).values('vault_connection_id', 'vault_mirror_id').first()
            return (row['vault_connection_id'], row['vault_mirror_id']) if row else (None, None)
        return getattr(instance, 'vault_connection_id', None), getattr(instance, 'vault_mirror_id', None)

    def target(self, instance):
        """ (connection, mirror) by the rules of the secret's organization """
        from django.conf import settings
        from accounts.models import VaultStorageRule
        from orgs.utils import tmp_to_org
        org_id = getattr(instance, 'org_id', None)
        asset = getattr(instance, 'asset', None)
        username = getattr(instance, 'username', '') or ''
        if org_id:
            with tmp_to_org(org_id):
                rules = list(VaultStorageRule.objects.filter(is_active=True).order_by('priority', 'name'))
            for rule in rules:
                if rule.matches(asset=asset, username=username):
                    return rule.connection_id, rule.mirror_id
        return None, (getattr(settings, 'VAULT_MIRROR', '') or None)

    @staticmethod
    def _set(instance, connection, mirror):
        """ where the secret is, on the instance first: the save that replaces the database copy by the marker
        sends post_save again, and that nested call must already see the new place """
        instance.vault_connection_id, instance.vault_mirror_id = connection, mirror

    @staticmethod
    def _persist(instance):
        # (a plain update: the model's own queryset would send post_save and come back here)
        models.QuerySet(model=type(instance)).filter(pk=instance.pk).update(
            vault_connection_id=instance.vault_connection_id, vault_mirror_id=instance.vault_mirror_id)

    def _mirror_write(self, mirror, instance):
        """ the plain secret is on the instance at this point (before the primary replaces it by the marker) """
        backend = self.backend(mirror)
        entry = backend.build_entry(instance)
        try:
            backend._update(entry)
        except Exception:
            backend._create(entry)

    def _mirror_delete(self, mirror, instance):
        try:
            self.backend(mirror).delete(instance)
        except Exception as e:
            logger.warning(f'Vault mirror: removing the copy failed: {e}')

    # ------------------------------------------------------------ the vault client contract

    def create(self, instance):
        if self._is_external(instance):
            return
        history = self._is_history(instance)
        if history:
            connection, mirror = self._stored(instance)
        else:
            connection, mirror = self.target(instance)
            previous = self._stored(instance)
            self._set(instance, connection, mirror)
        try:
            if mirror and not instance.secret_has_save_to_vault:
                self._mirror_write(mirror, instance)
            self.backend(connection).create(instance)
        except Exception:
            if not history:
                self._set(instance, *previous)
            raise
        if not history:
            self._persist(instance)

    def update(self, instance):
        if self._is_external(instance):
            return
        if self._is_history(instance):
            return self.create(instance)
        connection, mirror = self.target(instance)
        stored_connection, stored_mirror = self._stored(instance)
        saved = instance.secret_has_save_to_vault
        moving = connection != stored_connection and saved
        plain = None
        if moving:
            # the rules changed: read it where it is (before the instance points elsewhere)
            instance._secret = self.get(instance)
        elif mirror and saved and mirror != stored_mirror:
            # mirroring just turned on (or changed): the current secret is copied
            plain = self.backend(connection).get(instance)
        self._set(instance, connection, mirror)
        try:
            if moving:
                if mirror:
                    self._mirror_write(mirror, instance)
                self.backend(connection).create(instance)
            else:
                if mirror and not saved:
                    self._mirror_write(mirror, instance)
                elif plain is not None:
                    current, instance._secret = instance._secret, plain
                    try:
                        self._mirror_write(mirror, instance)
                    finally:
                        instance._secret = current
                self.backend(connection).update(instance)
        except Exception:
            self._set(instance, stored_connection, stored_mirror)
            raise
        if moving:
            try:
                self.backend(stored_connection).delete(instance)
            except Exception as e:
                logger.warning(f'Vault move: removing the old copy failed: {e}')
        if stored_mirror and stored_mirror != mirror:
            self._mirror_delete(stored_mirror, instance)
        self._persist(instance)

    def get(self, instance):
        if self._is_external(instance):
            return self.read_external(instance)
        connection, mirror = self._stored(instance)
        try:
            secret = self.backend(connection).get(instance)
            if secret or not mirror:
                return secret
        except Exception as e:
            if not mirror:
                raise
            logger.warning(f'Vault read failed, reading the mirror: {e}')
        return self.backend(mirror).get(instance)

    def get_for_restore(self, instance):
        if self._is_external(instance):
            return None
        connection, mirror = self._stored(instance)
        try:
            return self.backend(connection).get_for_restore(instance)
        except Exception:
            if not mirror:
                raise
            return self.backend(mirror).get_for_restore(instance)

    def delete(self, instance):
        if self._is_external(instance):
            return
        connection, mirror = self._stored(instance)
        self.backend(connection).delete(instance)
        if mirror:
            self._mirror_delete(mirror, instance)

    def read_external(self, instance):
        ref = getattr(instance, 'secret_ref', None) or {}
        if not ref.get('connection') or not ref.get('path'):
            return ''
        backend = self.backend(ref['connection'])
        return backend.client.read_external(ref.get('path'), ref.get('field') or '')

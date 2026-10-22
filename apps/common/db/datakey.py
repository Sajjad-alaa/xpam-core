"""
XPAM: data keys — what encrypts XPAM's secret fields (account secrets and their history, MFA seeds, API
secrets, secret settings, connection tokens...). Every encrypted field goes through common.db.utils.Encryptor.

Providers (XPAM_DATA_KEY):
- legacy  (default): AES-256-GCM keyed by SECRET_KEY, as before.
- local   : a keyring in XPAM's database — random 256-bit data keys, versioned, each wrapped by a key derived
            from SECRET_KEY (HKDF-SHA256). A new version is made on schedule (XPAM_DATA_KEY_ROTATION); values are
            re-encrypted in the background; XPAM keeps running and nobody is signed out.
- transit : HashiCorp Vault Transit — the key never leaves Vault (or the HSM behind it). Every value has its own
            derived key (a random context stored with it); Vault rotates the key on schedule and old values are
            re-wrapped in place by Vault, without XPAM seeing them.

A value carries its format, so all of them stay readable whatever the provider is now:
  'xpamt:<context>:vault:v<N>:...'   transit          'xpamk:v<N>:<nonce+ciphertext>'   local keyring
  anything else                      legacy (SECRET_KEY)
"""
import base64
import os
import threading
import time
from collections import OrderedDict

from django.conf import settings

from common.utils import get_logger

logger = get_logger(__name__)

TRANSIT_PREFIX = 'xpamt:'
LOCAL_PREFIX = 'xpamk:'
PREFIXES = (TRANSIT_PREFIX, LOCAL_PREFIX)

__all__ = ['encrypt', 'decrypt', 'provider', 'is_current', 'DataKeyUnavailable', 'transit', 'keyring', 'PREFIXES',
           'version_of']


class DataKeyUnavailable(RuntimeError):
    """ the key that opens a value cannot be reached (Vault down, key retired): never answered with '' """


def provider():
    return (getattr(settings, 'XPAM_DATA_KEY', '') or 'legacy').lower()


# ---------------------------------------------------------------- a short-lived cache of opened values

class _TTLCache:
    def __init__(self, size=5000, ttl=300):
        self.size, self.ttl = size, ttl
        self._data = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            value, at = item
            if time.time() - at > self.ttl:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return value

    def put(self, key, value):
        with self._lock:
            self._data[key] = (value, time.time())
            self._data.move_to_end(key)
            while len(self._data) > self.size:
                self._data.popitem(last=False)

    def clear(self):
        with self._lock:
            self._data.clear()


_opened = _TTLCache()


# ---------------------------------------------------------------- Vault Transit

class TransitKey:
    """ the Transit key of this XPAM (mount VAULT_TRANSIT_MOUNT, key VAULT_TRANSIT_KEY), through the hardened client """

    def __init__(self):
        self._client = None
        self._lock = threading.Lock()

    @property
    def mount(self):
        return (getattr(settings, 'VAULT_TRANSIT_MOUNT', '') or 'xpam-transit').strip('/')

    @property
    def key(self):
        return getattr(settings, 'VAULT_TRANSIT_KEY', '') or 'data'

    def client(self):
        with self._lock:
            if self._client is None:
                from accounts.backends.hcp.service import VaultKVClient
                self._client = VaultKVClient(
                    url=settings.VAULT_HCP_HOST, token=getattr(settings, 'VAULT_HCP_TOKEN', ''),
                    mount_point=self.mount, auth=getattr(settings, 'VAULT_HCP_AUTH', '') or 'token',
                    cert_role=settings.VAULT_HCP_CERT_ROLE, ca_file=settings.VAULT_HCP_CA_FILE,
                    client_cert_file=settings.VAULT_HCP_CLIENT_CERT_FILE,
                    client_key_file=settings.VAULT_HCP_CLIENT_KEY_FILE,
                    namespace=getattr(settings, 'VAULT_HCP_NAMESPACE', ''),
                    timeout=getattr(settings, 'VAULT_HCP_TIMEOUT', 10) or 10,
                    tls_min_version=getattr(settings, 'VAULT_HCP_TLS_MIN_VERSION', '1.3') or '1.3',
                    no_mount_setup=True,
                )
            return self._client

    def reset(self):
        with self._lock:
            self._client = None

    def _post(self, op, body):
        return self.client()._request('POST', f'{self.mount}/{op}/{self.key}', json=body).get('data') or {}

    def encrypt(self, plain):
        context = base64.b64encode(os.urandom(16)).decode()
        data = self._post('encrypt', {'plaintext': base64.b64encode(plain.encode()).decode(), 'context': context})
        return f'{TRANSIT_PREFIX}{context}:{data["ciphertext"]}'

    @staticmethod
    def split(value):
        rest = value[len(TRANSIT_PREFIX):]
        context, _, ciphertext = rest.partition(':')
        return context, ciphertext

    def decrypt(self, value):
        context, ciphertext = self.split(value)
        data = self._post('decrypt', {'ciphertext': ciphertext, 'context': context})
        return base64.b64decode(data['plaintext']).decode()

    def rewrap(self, values):
        """ [value] -> [value at the newest key version] — Vault re-encrypts without XPAM seeing the plain text """
        if not values:
            return []
        parts = [self.split(v) for v in values]
        data = self._post('rewrap', {'batch_input': [{'ciphertext': c, 'context': ctx} for ctx, c in parts]})
        out = []
        for (ctx, _), item in zip(parts, data.get('batch_results') or []):
            if item.get('error'):
                raise DataKeyUnavailable(item['error'])
            out.append(f'{TRANSIT_PREFIX}{ctx}:{item["ciphertext"]}')
        return out

    def info(self):
        return self.client()._request('GET', f'{self.mount}/keys/{self.key}').get('data') or {}

    def set_config(self, **values):
        self.client()._request('POST', f'{self.mount}/keys/{self.key}/config', json=values)


transit = TransitKey()


# ---------------------------------------------------------------- local keyring

class Keyring:
    def __init__(self):
        self._keys = {}
        self._current = None
        self._loaded = 0.0
        self._lock = threading.Lock()

    @staticmethod
    def _kek():
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=b'xpam-data-keyring', info=b'kek-v1') \
            .derive(settings.SECRET_KEY.encode())

    def _load(self, force=False):
        if not force and self._keys and time.time() - self._loaded < 60:
            return
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from settings.models import DataKey
        kek = AESGCM(self._kek())
        keys, current = {}, None
        for row in DataKey.objects.filter(retired=False).order_by('version'):
            raw = base64.b64decode(row.wrapped)
            keys[row.version] = kek.decrypt(raw[:12], raw[12:], f'v{row.version}'.encode())
            current = row.version
        self._keys, self._current, self._loaded = keys, current, time.time()

    def current(self):
        with self._lock:
            self._load()
            if self._current is None:
                self._rotate_locked()
            return self._current, self._keys[self._current]

    def get(self, version):
        with self._lock:
            self._load()
            if version not in self._keys:
                self._load(force=True)
            if version not in self._keys:
                raise DataKeyUnavailable(f'data key v{version} is retired or missing')
            return self._keys[version]

    def _rotate_locked(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from django.db import transaction
        from django.db.models import Max
        from settings.models import DataKey
        with transaction.atomic():
            version = (DataKey.objects.select_for_update().aggregate(v=Max('version'))['v'] or 0) + 1
            key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
            wrapped = nonce + AESGCM(self._kek()).encrypt(nonce, key, f'v{version}'.encode())
            DataKey.objects.create(version=version, wrapped=base64.b64encode(wrapped).decode())
        self._load(force=True)
        return version

    def rotate(self):
        with self._lock:
            return self._rotate_locked()

    def retire_before(self, version):
        from settings.models import DataKey
        DataKey.objects.filter(version__lt=version, retired=False).update(retired=True)
        with self._lock:
            self._load(force=True)

    def encrypt(self, plain):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        version, key = self.current()
        nonce = os.urandom(12)
        sealed = AESGCM(key).encrypt(nonce, plain.encode(), b'xpam')
        return f'{LOCAL_PREFIX}v{version}:{base64.b64encode(nonce + sealed).decode()}'

    def decrypt(self, value):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        version_part, _, body = value[len(LOCAL_PREFIX):].partition(':')
        raw = base64.b64decode(body)
        return AESGCM(self.get(int(version_part[1:]))).decrypt(raw[:12], raw[12:], b'xpam').decode()


keyring = Keyring()


# ---------------------------------------------------------------- the entry points

def encrypt(plain):
    """ a value encrypted by the current provider; None for the legacy provider (the caller does it) """
    p = provider()
    if p == 'transit':
        return transit.encrypt(plain)
    if p == 'local':
        return keyring.encrypt(plain)
    return None


def decrypt(value):
    cached = _opened.get(value)
    if cached is not None:
        return cached
    try:
        plain = transit.decrypt(value) if value.startswith(TRANSIT_PREFIX) else keyring.decrypt(value)
    except DataKeyUnavailable:
        raise
    except Exception as e:
        raise DataKeyUnavailable(f'the data key cannot be used: {e}')
    _opened.put(value, plain)
    return plain


def version_of(value):
    """ the key version a value is encrypted with (None: legacy) """
    if value.startswith(TRANSIT_PREFIX):
        return int(TransitKey.split(value)[1].split(':')[1][1:])
    if value.startswith(LOCAL_PREFIX):
        return int(value[len(LOCAL_PREFIX):].split(':', 1)[0][1:])
    return None


def is_current(value, current_version):
    """ True when the value is in the current provider's format at the current key version """
    p = provider()
    if p == 'transit':
        return value.startswith(TRANSIT_PREFIX) and version_of(value) == current_version
    if p == 'local':
        return value.startswith(LOCAL_PREFIX) and version_of(value) == current_version
    return not value.startswith(PREFIXES)

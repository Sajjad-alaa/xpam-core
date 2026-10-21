from common.db.utils import get_logger
from .service import VaultKVClient
from ..base.vault import BaseVault

from ...const import VaultTypeChoices
from ...exceptions import VaultSecretNotFoundException


logger = get_logger(__name__)

__all__ = ['Vault']


def _pem_file(pem):
    import hashlib
    import os
    import tempfile
    directory = os.path.join('/dev/shm' if os.path.isdir('/dev/shm') else tempfile.gettempdir(), 'xpam-vault-pem')
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, hashlib.sha256(pem.encode()).hexdigest()[:24] + '.pem')
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(pem)
    return path


class Vault(BaseVault):
    type = VaultTypeChoices.hcp

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # XPAM: a vault connection may carry its certificates inline (stored encrypted with SECRET_KEY): written to
        # private files in memory for the TLS library
        for name in ('CA', 'CLIENT_CERT', 'CLIENT_KEY'):
            pem = kwargs.get(f'VAULT_HCP_{name}_PEM')
            if pem:
                kwargs[f'VAULT_HCP_{name}_FILE'] = _pem_file(pem)
        self.client = VaultKVClient(
            url=kwargs.get('VAULT_HCP_HOST'),
            token=kwargs.get('VAULT_HCP_TOKEN'),
            mount_point=kwargs.get('VAULT_HCP_MOUNT_POINT'),
            auth=kwargs.get('VAULT_HCP_AUTH') or 'token',
            cert_role=kwargs.get('VAULT_HCP_CERT_ROLE'),
            ca_file=kwargs.get('VAULT_HCP_CA_FILE'),
            client_cert_file=kwargs.get('VAULT_HCP_CLIENT_CERT_FILE'),
            client_key_file=kwargs.get('VAULT_HCP_CLIENT_KEY_FILE'),
            namespace=kwargs.get('VAULT_HCP_NAMESPACE'),
            timeout=kwargs.get('VAULT_HCP_TIMEOUT') or 10,
            tls_min_version=kwargs.get('VAULT_HCP_TLS_MIN_VERSION') or '1.3',
        )

    def is_active(self):
        return self.client.is_active()

    def _get(self, entry):
        # TODO: get data 是不是层数太多了
        data = self.client.get(path=entry.full_path).get('data') or {}
        data = entry.get_decrypt_secret(data.get('secret'))
        return data

    def _get_for_restore(self, entry):
        data = self.client.get(path=entry.full_path).get('data')
        if not isinstance(data, dict) or 'secret' not in data:
            raise VaultSecretNotFoundException()
        return entry.get_decrypt_secret(data['secret'])

    def _create(self, entry):
        data = {'secret': entry.get_encrypt_secret()}
        self.client.create(path=entry.full_path, data=data)

    def _update(self, entry):
        data = {'secret': entry.get_encrypt_secret()}
        self.client.patch(path=entry.full_path, data=data)

    def _delete(self, entry):
        self.client.delete(path=entry.full_path)

    def _save_metadata(self, entry, metadata):
        try:
            self.client.update_metadata(path=entry.full_path, metadata=metadata)
        except Exception as e:
            logger.error(f'save metadata error: {e}')

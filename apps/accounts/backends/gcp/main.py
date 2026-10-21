from .service import GoogleSecretManagerClient
from ..base.vault import BaseVault
from ..utils.mixins import GeneralVaultMixin
from ...const import VaultTypeChoices

__all__ = ['Vault']


class Vault(GeneralVaultMixin, BaseVault):
    type = VaultTypeChoices.gcp

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = GoogleSecretManagerClient(
            project=kwargs.get('VAULT_GCP_PROJECT'),
            credentials=kwargs.get('VAULT_GCP_CREDENTIALS'),
            locations=kwargs.get('VAULT_GCP_LOCATIONS'),
            api_url=kwargs.get('VAULT_GCP_API_URL'),
            timeout=kwargs.get('VAULT_GCP_TIMEOUT') or 10,
        )

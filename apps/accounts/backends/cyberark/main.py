from .service import ConjurClient
from ..base.vault import BaseVault
from ..utils.mixins import GeneralVaultMixin
from ...const import VaultTypeChoices

__all__ = ['Vault']


class Vault(GeneralVaultMixin, BaseVault):
    type = VaultTypeChoices.cyberark

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = ConjurClient(
            url=kwargs.get('VAULT_CYBERARK_URL'),
            account=kwargs.get('VAULT_CYBERARK_ACCOUNT'),
            login=kwargs.get('VAULT_CYBERARK_LOGIN'),
            api_key=kwargs.get('VAULT_CYBERARK_API_KEY'),
            policy=kwargs.get('VAULT_CYBERARK_POLICY'),
            ca_file=kwargs.get('VAULT_CYBERARK_CA_FILE'),
            timeout=kwargs.get('VAULT_CYBERARK_TIMEOUT') or 10,
        )

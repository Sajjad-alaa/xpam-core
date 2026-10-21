from .service import DelineaClient
from ..base.vault import BaseVault
from ..utils.mixins import GeneralVaultMixin
from ...const import VaultTypeChoices

__all__ = ['Vault']


class Vault(GeneralVaultMixin, BaseVault):
    type = VaultTypeChoices.delinea

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = DelineaClient(
            url=kwargs.get('VAULT_DELINEA_URL'),
            username=kwargs.get('VAULT_DELINEA_USERNAME'),
            password=kwargs.get('VAULT_DELINEA_PASSWORD'),
            domain=kwargs.get('VAULT_DELINEA_DOMAIN'),
            folder_id=kwargs.get('VAULT_DELINEA_FOLDER_ID'),
            template_id=kwargs.get('VAULT_DELINEA_TEMPLATE_ID'),
            field=kwargs.get('VAULT_DELINEA_FIELD'),
            site_id=kwargs.get('VAULT_DELINEA_SITE_ID'),
            ca_file=kwargs.get('VAULT_DELINEA_CA_FILE'),
            timeout=kwargs.get('VAULT_DELINEA_TIMEOUT') or 10,
        )

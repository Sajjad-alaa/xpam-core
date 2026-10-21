from django.db import models
from django.utils.translation import gettext_lazy as _

__all__ = ['VaultTypeChoices']


class VaultTypeChoices(models.TextChoices):
    local = 'local', _('Database')
    openbao = 'openbao', _('OpenBao')
    hcp = 'hcp', _('HashiCorp Vault')
    azure = 'azure', _('Azure Key Vault')
    aws = 'aws', _('Amazon Secrets Manager')
    # XPAM
    cyberark = 'cyberark', _('CyberArk Conjur')
    delinea = 'delinea', _('Delinea Secret Server')
    gcp = 'gcp', _('Google Secret Manager')

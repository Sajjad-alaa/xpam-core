from abc import ABC

from common.db.datakey import check_readable
from common.db.utils import Encryptor
from common.utils import lazyproperty


class BaseEntry(ABC):
    def __init__(self, instance):
        self.instance = instance

    @property
    def path_base(self):
        path = f'orgs/{self.instance.org_id}'
        return path

    @lazyproperty
    def full_path(self):
        path_base = self.path_base
        path_spec = self.path_spec
        path = f'{path_base}/{path_spec}'
        return path

    @property
    def path_spec(self):
        raise NotImplementedError

    def get_encrypt_secret(self):
        secret = getattr(self.instance, '_secret', None)
        if secret is not None:
            secret = Encryptor(secret).encrypt()
        return secret

    @staticmethod
    def get_decrypt_secret(secret, strict=False):
        if secret is not None:
            plain = Encryptor(secret).decrypt()
            if strict and secret and not plain:
                # XPAM: Encryptor answers '' for a value no key opens. A restore (or a move to another vault) must
                # not take that for an empty secret and write it over the stored one.
                check_readable(secret)
            secret = plain
        return secret


class AccountEntry(BaseEntry):
    @property
    def path_spec(self):
        path = f'assets/{self.instance.asset_id}/accounts/{self.instance.id}'
        return path


class PersonalAssetCredentialEntry(BaseEntry):
    @property
    def path_spec(self):
        path = (
            f'assets/{self.instance.asset_id}/personal-credentials/'
            f'{self.instance.id}'
        )
        return path


class AccountTemplateEntry(BaseEntry):
    @property
    def path_spec(self):
        path = f'account-templates/{self.instance.id}'
        return path


class HistoricalAccountEntry(BaseEntry):
    @property
    def path_base(self):
        path = f'accounts/{self.instance.instance.id}'
        return path

    @property
    def path_spec(self):
        path = f'histories/{self.instance.history_id}'
        return path

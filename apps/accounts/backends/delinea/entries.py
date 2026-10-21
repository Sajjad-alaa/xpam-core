from ..base.entries import BaseEntry


class DelineaBaseEntry(BaseEntry):
    """ secret names: xpam:<org>:<path> (one flat folder; Secret Server names cannot hold '/') """

    @property
    def full_path(self):
        return 'xpam:' + super().full_path.replace('orgs/', '', 1).replace('/', ':')


class AccountEntry(DelineaBaseEntry):
    @property
    def path_spec(self):
        return f'assets/{self.instance.asset_id}/accounts/{self.instance.id}'


class PersonalAssetCredentialEntry(DelineaBaseEntry):
    @property
    def path_spec(self):
        return f'assets/{self.instance.asset_id}/personal-credentials/{self.instance.id}'


class AccountTemplateEntry(DelineaBaseEntry):
    @property
    def path_spec(self):
        return f'account-templates/{self.instance.id}'


class HistoricalAccountEntry(DelineaBaseEntry):
    @property
    def path_spec(self):
        return f'accounts/{self.instance.instance.id}/histories/{self.instance.history_id}'

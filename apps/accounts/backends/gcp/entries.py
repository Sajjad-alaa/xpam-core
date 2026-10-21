from ..base.entries import BaseEntry


class GCPBaseEntry(BaseEntry):
    """ secret ids: [A-Za-z0-9_-], at most 255 characters — xpam_<org>_<path with / as _> """

    @property
    def full_path(self):
        return 'xpam_' + super().full_path.replace('orgs/', '', 1).replace('/', '_')


class AccountEntry(GCPBaseEntry):
    @property
    def path_spec(self):
        return f'assets/{self.instance.asset_id}/accounts/{self.instance.id}'


class PersonalAssetCredentialEntry(GCPBaseEntry):
    @property
    def path_spec(self):
        return f'assets/{self.instance.asset_id}/personal-credentials/{self.instance.id}'


class AccountTemplateEntry(GCPBaseEntry):
    @property
    def path_spec(self):
        return f'account-templates/{self.instance.id}'


class HistoricalAccountEntry(GCPBaseEntry):
    @property
    def path_spec(self):
        return f'accounts/{self.instance.instance.id}/histories/{self.instance.history_id}'

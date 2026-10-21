"""
XPAM: several vaults at once.

- VaultConnection: a named vault (type + its settings, encrypted with SECRET_KEY in the database). Connections
  made on the server (`xpamctl vault add-connection`) are `managed`: the console can see and test them but not
  change them; with VAULT_LOCKED the console cannot add any.
- VaultStorageRule (per organization): which vault keeps which secrets — matched by asset group (node), platform
  and account username; the first matching rule by priority wins, a rule without conditions is the
  organization's default. An optional mirror receives a copy of every secret (read from when the primary fails).
- Each secret remembers where it is (vault_connection / vault_mirror on the account, template or personal
  credential): changing the rules moves secrets explicitly (accounts.tasks.vault_routing).
- An account may instead *read* its password from an existing vault (secret_source='external', secret_ref):
  XPAM never writes, rotates or deletes it there.
"""
import fnmatch

from django.db import models
from django.utils.translation import gettext_lazy as _

from common.db.fields import EncryptJsonDictTextField
from common.db.models import JMSBaseModel
from orgs.mixins.models import JMSOrgBaseModel
from ..const import VaultTypeChoices

__all__ = ['VaultConnection', 'VaultStorageRule', 'SecretSource']


class SecretSource(models.TextChoices):
    xpam = 'xpam', _('Kept by XPAM')
    external = 'external', _('Read from an existing vault')


class VaultConnection(JMSBaseModel):
    name = models.CharField(max_length=128, unique=True, verbose_name=_('Name'))
    type = models.CharField(
        max_length=16, choices=[c for c in VaultTypeChoices.choices if c[0] != VaultTypeChoices.local],
        verbose_name=_('Type')
    )
    config = EncryptJsonDictTextField(default=dict, verbose_name=_('Settings'))
    managed = models.BooleanField(default=False, verbose_name=_('Managed on the server'))
    is_active = models.BooleanField(default=True, verbose_name=_('Active'))
    comment = models.TextField(blank=True, default='', verbose_name=_('Comment'))

    class Meta:
        verbose_name = _('Vault connection')
        ordering = ('name',)

    def __str__(self):
        return f'{self.name} ({self.get_type_display()})'

    def backend_kwargs(self):
        """ the settings a backend expects (VAULT_<TYPE>_*), as for the configured vault """
        kwargs = {k: v for k, v in (self.config or {}).items() if str(k).startswith('VAULT_')}
        kwargs.update({'VAULT_ENABLED': True, 'VAULT_BACKEND': self.type})
        return kwargs


class VaultStorageRule(JMSOrgBaseModel):
    name = models.CharField(max_length=128, verbose_name=_('Name'))
    priority = models.IntegerField(default=50, verbose_name=_('Priority'), help_text=_('Lower first'))
    is_active = models.BooleanField(default=True, verbose_name=_('Active'))
    nodes = models.ManyToManyField('assets.Node', blank=True, related_name='+', verbose_name=_('Asset groups'))
    platforms = models.ManyToManyField('assets.Platform', blank=True, related_name='+', verbose_name=_('Platforms'))
    username = models.CharField(
        max_length=128, blank=True, default='', verbose_name=_('Username pattern'), help_text=_('e.g. svc_* (empty: any)')
    )
    connection = models.ForeignKey(
        VaultConnection, null=True, blank=True, on_delete=models.PROTECT, related_name='rules',
        verbose_name=_('Vault'), help_text=_('Empty: the configured vault')
    )
    mirror = models.ForeignKey(
        VaultConnection, null=True, blank=True, on_delete=models.PROTECT, related_name='mirror_rules',
        verbose_name=_('Mirror'), help_text=_('A copy of every secret, read from when the vault fails')
    )
    comment = models.TextField(blank=True, default='', verbose_name=_('Comment'))

    class Meta:
        verbose_name = _('Vault storage rule')
        ordering = ('priority', 'name')
        unique_together = [('org_id', 'name')]

    def __str__(self):
        return self.name

    def matches(self, asset=None, username=''):
        if self.username and not fnmatch.fnmatchcase(username or '', self.username):
            return False
        node_ids = set(self.nodes.values_list('id', flat=True))
        platform_ids = set(self.platforms.values_list('id', flat=True))
        if (node_ids or platform_ids) and asset is None:
            return False
        if platform_ids and asset.platform_id not in platform_ids:
            return False
        if node_ids:
            # the asset's groups and their parents
            from assets.models import Node
            keys = set()
            for key in asset.nodes.values_list('key', flat=True):
                parts = key.split(':')
                keys.update(':'.join(parts[:i]) for i in range(1, len(parts) + 1))
            if not Node.objects.filter(id__in=node_ids, key__in=keys).exists():
                return False
        return True

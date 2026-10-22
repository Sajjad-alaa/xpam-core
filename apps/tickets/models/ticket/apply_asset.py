from django.db import models
from django.utils.translation import gettext_lazy as _

from perms.const import ActionChoices
from tickets.const import TicketType
from .general import Ticket

__all__ = ['ApplyAssetTicket']

asset_or_node_help_text = _("Select at least one asset or node")


class ApplyAssetTicket(Ticket):
    apply_permission_name = models.CharField(max_length=128, verbose_name=_('Permission name'))
    apply_nodes = models.ManyToManyField('assets.Node', verbose_name=_('Node'))
    # 申请信息
    apply_assets = models.ManyToManyField('assets.Asset', verbose_name=_('Asset'))
    apply_accounts = models.JSONField(default=list, verbose_name=_('Apply accounts'))
    apply_actions = models.IntegerField(verbose_name=_('Actions'), default=ActionChoices.connect)
    apply_date_start = models.DateTimeField(verbose_name=_('Date start'), null=True)
    apply_date_expired = models.DateTimeField(verbose_name=_('Date expired'), null=True)
    # XPAM: just-in-time account chosen by the approver: "auto" (policy rules), "none" or a policy id
    apply_jit = models.CharField(max_length=64, default='auto', blank=True, verbose_name=_('Just-in-time account'))
    # XPAM: name of the just-in-time policy that approved the request by itself ('' = approved by people)
    apply_jit_auto = models.CharField(max_length=128, default='', blank=True, verbose_name=_('Approved automatically by'))
    # XPAM: the access (permission id) this request extends: approved, that access just lasts longer
    # XPAM: the protocols asked for (empty: every protocol the rules allow) — the granted access is limited to them
    apply_protocols = models.JSONField(default=list, blank=True, verbose_name=_('Protocols'))
    apply_extends = models.CharField(max_length=36, default='', blank=True, verbose_name=_('Extends access'))

    TICKET_TYPE = TicketType.apply_asset

    def get_apply_jit_display(self):
        value = self.apply_jit or 'auto'
        if value == 'auto':
            return str(_('Automatic (just-in-time policy rules)'))
        if value == 'none':
            return str(_('No just-in-time account'))
        from accounts.models import JITPolicy
        from orgs.utils import tmp_to_root_org
        with tmp_to_root_org():
            policy = JITPolicy.objects.filter(id=value).first()
        return policy.name if policy else value

    def get_apply_actions_display(self):
        return ActionChoices.display(self.apply_actions)

    class Meta:
        verbose_name = _('Apply Asset Ticket')

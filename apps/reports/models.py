from django.db import models
from django.utils.translation import gettext_lazy as _

from orgs.mixins.models import JMSOrgBaseModel

from .mixins import CREATABLE_REPORT_TYPES

REPORT_VISIBILITY_FILTER_FIELDS = {
    'visible_charts',
    'visible_tables',
}

DASHBOARD_WIDGET_IDS = (
    'protection_status',
    'console_realtime',
    'console_user_asset_activity',
    'console_data_summary',
    'console_asset_proportion',
    'console_rank_summary',
    'jit_zsp_overview',
    'jit_standing_converter',
    'pam_data_summary',
    'pam_mission_summary',
    'pam_risk_summary',
    'pam_secret_rotation',
    'pam_account_proportion',
    'audit_card_summary',
    'audit_session_charts',
    'audit_trend_summary',
)


class Report(JMSOrgBaseModel):
    name = models.CharField(max_length=128, verbose_name=_('Name'))
    tp = models.CharField(max_length=64, verbose_name=_('Type'))
    is_builtin = models.BooleanField(default=False, verbose_name=_('Is builtin'))
    is_active = models.BooleanField(default=True, verbose_name=_('Is active'))
    days = models.PositiveIntegerField(default=7, verbose_name=_('Range days'))
    filters = models.JSONField(default=dict, verbose_name=_('Filters'))

    class Meta:
        unique_together = [('org_id', 'name')]
        verbose_name = _('Report')
        ordering = ['-date_created']


class CustomDashboard(JMSOrgBaseModel):
    class Scope(models.TextChoices):
        all = 'all', _('All dashboards (Console, PAM, Audit)')
        console = 'console', _('Console')
        pam = 'pam', _('PAM')
        audit = 'audit', _('Audit')

    name = models.CharField(max_length=128, verbose_name=_('Name'))
    description = models.CharField(max_length=512, blank=True, default='', verbose_name=_('Description'))
    icon = models.CharField(max_length=64, blank=True, default='dashboard', verbose_name=_('Icon'))
    scope = models.CharField(
        max_length=16, choices=Scope.choices, default=Scope.all, verbose_name=_('Section')
    )
    template = models.CharField(max_length=64, blank=True, default='custom', verbose_name=_('Template'))
    layout = models.JSONField(default=list, blank=True, verbose_name=_('Widgets layout'))
    days = models.PositiveIntegerField(default=7, verbose_name=_('Default time range (days)'))
    refresh_seconds = models.PositiveIntegerField(default=0, verbose_name=_('Auto-refresh (seconds)'))
    is_default = models.BooleanField(default=False, verbose_name=_('Default dashboard'))
    is_shared_all = models.BooleanField(
        default=False, verbose_name=_('Share with all organization members')
    )
    sort_order = models.PositiveSmallIntegerField(default=10, verbose_name=_('Sort order'))
    owner = models.ForeignKey(
        'users.User', null=True, blank=True, on_delete=models.SET_NULL,
        related_name='owned_dashboards', verbose_name=_('Owner')
    )
    shared_users = models.ManyToManyField(
        'users.User', blank=True, related_name='shared_dashboards', verbose_name=_('Shared users')
    )
    shared_groups = models.ManyToManyField(
        'users.UserGroup', blank=True, related_name='shared_dashboards', verbose_name=_('Shared user groups')
    )

    class Meta:
        verbose_name = _('Custom dashboard')
        ordering = ['sort_order', 'name', '-date_created']

    def __str__(self):
        return self.name


def validate_report_payload(tp, filters):
    if tp not in CREATABLE_REPORT_TYPES:
        raise ValueError(f'Unsupported report type: {tp}')
    allowed_keys = REPORT_VISIBILITY_FILTER_FIELDS
    invalid_keys = set((filters or {}).keys()) - allowed_keys
    if invalid_keys:
        raise ValueError(f'Invalid filters: {", ".join(sorted(invalid_keys))}')

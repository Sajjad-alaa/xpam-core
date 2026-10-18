"""
XPAM just-in-time (JIT) accounts.

A JIT policy decides when XPAM creates an account on an asset for a user, what the account is
called and which rights it gets, and when the account is removed again. The accounts that exist
because of a policy are tracked as JITAccount rows; the credentials themselves are ordinary
asset accounts (source "jit") so that the existing push and remove automations can be used.
"""
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from orgs.mixins.models import JMSOrgBaseModel

__all__ = ['JITPolicy', 'JITAccount']


class JITPolicy(JMSOrgBaseModel):
    class Mode(models.TextChoices):
        per_session = 'per_session', _('Per connection')
        while_granted = 'while_granted', _('While access is granted')
        approved_window = 'approved_window', _('Approved time window')

    class UsernameMode(models.TextChoices):
        same_as_user = 'same_as_user', _('Same as XPAM username')
        specific = 'specific', _('Specific name')
        random_fixed = 'random_fixed', _('Random, fixed per user')
        random_session = 'random_session', _('Random per session')

    name = models.CharField(max_length=128, verbose_name=_('Name'))
    mode = models.CharField(
        max_length=32, choices=Mode.choices, default=Mode.per_session, verbose_name=_('Account lifetime')
    )
    username_mode = models.CharField(
        max_length=32, choices=UsernameMode.choices, default=UsernameMode.same_as_user,
        verbose_name=_('Account name')
    )
    specific_username = models.CharField(
        max_length=32, blank=True, default='', verbose_name=_('Specific name')
    )
    username_prefix = models.CharField(
        max_length=12, blank=True, default='', verbose_name=_('Name prefix')
    )
    privileged = models.BooleanField(default=False, verbose_name=_('Administrator rights'))
    linux_shell = models.CharField(max_length=64, default='/bin/bash', verbose_name=_('Linux shell'))
    linux_groups = models.CharField(max_length=256, blank=True, default='', verbose_name=_('Linux groups'))
    windows_groups = models.CharField(
        max_length=256, default='Users,Remote Desktop Users', verbose_name=_('Windows groups')
    )
    remove_home = models.BooleanField(default=True, verbose_name=_('Delete home folder on removal'))
    is_active = models.BooleanField(default=True, verbose_name=_('Active'))

    class Meta:
        verbose_name = _('Just-in-time policy')
        unique_together = [('name', 'org_id')]
        ordering = ['name']

    def __str__(self):
        return self.name

    @property
    def is_granted_mode(self):
        return self.mode in (self.Mode.while_granted, self.Mode.approved_window)


class JITAccount(JMSOrgBaseModel):
    class Status(models.TextChoices):
        pending = 'pending', _('Pending')
        pushing = 'pushing', _('Creating')
        ready = 'ready', _('Ready')
        failed = 'failed', _('Creation failed')
        removing = 'removing', _('Removing')
        removed = 'removed', _('Removed')
        remove_failed = 'remove_failed', _('Removal failed')

    ACTIVE_STATUSES = (Status.pending, Status.pushing, Status.ready, Status.removing, Status.remove_failed)

    policy = models.ForeignKey(
        JITPolicy, null=True, blank=True, on_delete=models.SET_NULL,
        related_name='jit_accounts', verbose_name=_('Policy')
    )
    mode = models.CharField(max_length=32, choices=JITPolicy.Mode.choices, verbose_name=_('Account lifetime'))
    user = models.ForeignKey(
        'users.User', null=True, blank=True, on_delete=models.SET_NULL,
        related_name='jit_accounts', verbose_name=_('User')
    )
    user_display = models.CharField(max_length=256, blank=True, default='', verbose_name=_('User'))
    asset = models.ForeignKey(
        'assets.Asset', null=True, blank=True, on_delete=models.SET_NULL,
        related_name='jit_accounts', verbose_name=_('Asset')
    )
    asset_display = models.CharField(max_length=256, blank=True, default='', verbose_name=_('Asset'))
    account = models.ForeignKey(
        'accounts.Account', null=True, blank=True, on_delete=models.SET_NULL,
        related_name='jit_records', verbose_name=_('Account')
    )
    username = models.CharField(max_length=128, verbose_name=_('Username'), db_index=True)
    privileged = models.BooleanField(default=False, verbose_name=_('Administrator rights'))
    permission_id = models.UUIDField(null=True, blank=True, verbose_name=_('Permission'))
    connection_tokens = models.JSONField(default=list, blank=True, verbose_name=_('Connection tokens'))
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.pending, db_index=True, verbose_name=_('Status')
    )
    error = models.TextField(blank=True, default='', verbose_name=_('Error'))
    attempts = models.IntegerField(default=0, verbose_name=_('Removal attempts'))
    date_ready = models.DateTimeField(null=True, blank=True, verbose_name=_('Date created on asset'))
    date_expired = models.DateTimeField(null=True, blank=True, verbose_name=_('Remove at'))
    date_removed = models.DateTimeField(null=True, blank=True, verbose_name=_('Date removed'))

    class Meta:
        verbose_name = _('Just-in-time account')
        ordering = ['-date_created']

    def __str__(self):
        return f'{self.username}@{self.asset_display}'

    def set_status(self, status, error=''):
        self.status = status
        self.error = (error or '')[:4000]
        fields = ['status', 'error', 'date_updated']
        now = timezone.now()
        if status == self.Status.ready and not self.date_ready:
            self.date_ready = now
            fields.append('date_ready')
        if status == self.Status.removed:
            self.date_removed = now
            fields.append('date_removed')
        self.save(update_fields=fields)

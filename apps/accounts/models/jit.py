"""
XPAM just-in-time (JIT) accounts.

A JIT policy decides when XPAM creates an account on an asset for a user, what the account is
called and which rights it gets, and when the account is removed again. The accounts that exist
because of a policy are tracked as JITAccount rows; the credentials themselves are ordinary
asset accounts (source "jit") so that the existing push and remove automations can be used.
"""
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from common.db.fields import JSONManyToManyField
from perms.const import ActionChoices
from orgs.mixins.models import JMSOrgBaseModel

__all__ = ['JITPolicy', 'JITAccount']


def default_rule_protocols():
    return ['all']


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

    class CommandAction(models.TextChoices):
        reject = 'reject', _('Block the command')
        warning = 'warning', _('Allow and warn')

    class CredentialType(models.TextChoices):
        password = 'password', _('Password')
        ssh_key = 'ssh_key', _('SSH key (Linux/Unix)')

    class DBPrivilege(models.TextChoices):
        read_only = 'read_only', _('Read only')
        read_write = 'read_write', _('Read and write')
        admin = 'admin', _('Administrator')
        custom = 'custom', _('Custom SQL')

    class DeviceRole(models.TextChoices):
        read_only = 'read_only', _('Read only')
        operator = 'operator', _('Operator')
        admin = 'admin', _('Administrator')
        custom = 'custom', _('Custom')

    class Scope(models.TextChoices):
        linked = 'linked', _('Only the asset permissions linked to it')
        requests = 'requests', _('Approved access requests')
        all = 'all', _('Asset permissions and approved access requests')

    class ApprovalRoute(models.TextChoices):
        flow = 'flow', _('An approval flow')
        approvers = 'approvers', _('Specific people')

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
    # Rules: which users and assets the policy applies to by itself (no linking needed)
    scope = models.CharField(
        max_length=16, choices=Scope.choices, default=Scope.all, verbose_name=_('Applies to')
    )
    users = JSONManyToManyField('users.User', default=dict, verbose_name=_('Users'))
    assets = JSONManyToManyField('assets.Asset', default=dict, verbose_name=_('Assets'))
    priority = models.IntegerField(
        default=50, verbose_name=_('Priority'),
        help_text=_('1-100, the lower the value will be match first'),
        validators=[MinValueValidator(1), MaxValueValidator(100)]
    )
    # Zero standing privilege: users the policy covers get only the just-in-time account
    jit_only = models.BooleanField(default=False, verbose_name=_('Just-in-time account only'))
    # Self-service requests and approval
    self_service = models.BooleanField(default=True, verbose_name=_('Users can request access'))
    max_hours = models.PositiveIntegerField(default=8, verbose_name=_('Longest access (hours)'))
    require_reason = models.BooleanField(default=True, verbose_name=_('Reason required'))
    auto_approve = models.BooleanField(default=False, verbose_name=_('Approve automatically'))
    auto_approve_max_hours = models.PositiveIntegerField(default=4, verbose_name=_('Approve automatically up to (hours)'))
    auto_approve_time_period = models.JSONField(default=list, blank=True, verbose_name=_('Approve automatically during'))
    approvals_required = models.PositiveSmallIntegerField(default=1, verbose_name=_('Approvals required'))
    # Who approves the requests the rule does not approve by itself: an approval flow of Tickets → Flow setup
    # (approval_flow; empty: the organization's flow for access requests), or the people in `approvers`
    approval_route = models.CharField(max_length=16, choices=ApprovalRoute.choices, default=ApprovalRoute.flow,
                                      verbose_name=_('Approved by'))
    approval_flow = models.ForeignKey('tickets.TicketFlow', null=True, blank=True, on_delete=models.SET_NULL,
                                      related_name='+', verbose_name=_('Approval flow'))
    approvers = JSONManyToManyField('users.User', default=dict, blank=True, verbose_name=_('Approvers'))
    # Security
    require_mfa = models.BooleanField(default=False, verbose_name=_('MFA when connecting'))
    end_sessions_on_expiry = models.BooleanField(default=True, verbose_name=_('End live sessions when access ends'))
    expiry_warning_minutes = models.PositiveIntegerField(default=15, verbose_name=_('Warn before access ends (minutes)'))
    command_groups = models.ManyToManyField(
        'acls.CommandGroup', blank=True, related_name='jit_policies', verbose_name=_('Command groups')
    )
    command_action = models.CharField(
        max_length=16, choices=CommandAction.choices, default=CommandAction.reject, verbose_name=_('Command action')
    )
    credential_type = models.CharField(
        max_length=16, choices=CredentialType.choices, default=CredentialType.password, verbose_name=_('Credential')
    )
    # Databases
    db_privilege = models.CharField(
        max_length=16, choices=DBPrivilege.choices, default=DBPrivilege.read_only, verbose_name=_('Database rights')
    )
    db_custom_sql = models.TextField(blank=True, default='', verbose_name=_('Custom SQL'))
    # Network devices: the role on FortiGate, Palo Alto, Cisco, Juniper, Huawei, H3C (built-in drivers);
    # the commands below replace the built-in driver when filled in (other SSH devices)
    device_role = models.CharField(
        max_length=16, choices=DeviceRole.choices, default=DeviceRole.read_only, verbose_name=_('Device role')
    )
    device_custom_role = models.CharField(max_length=128, blank=True, default='', verbose_name=_('Custom device role'))
    device_create_commands = models.TextField(blank=True, default='', verbose_name=_('Commands to create the account'))
    device_remove_commands = models.TextField(blank=True, default='', verbose_name=_('Commands to remove the account'))
    # XPAM: what an access through this rule may allow — the protocols (['all']: every protocol of the asset) and
    # the actions; a request picks among them, the approver sees them, the granted access enforces them
    protocols = models.JSONField(default=default_rule_protocols, verbose_name=_('Allowed protocols'))
    actions = models.IntegerField(default=ActionChoices.all, verbose_name=_('Allowed actions'))
    is_active = models.BooleanField(default=True, verbose_name=_('Active'))

    class Meta:
        verbose_name = _('Just-in-time policy')
        unique_together = [('name', 'org_id')]
        ordering = ['priority', 'name']

    def __str__(self):
        return self.name

    @property
    def is_granted_mode(self):
        return self.mode in (self.Mode.while_granted, self.Mode.approved_window)

    @property
    def is_rule_based(self):
        return self.scope != self.Scope.linked

    def in_auto_approve_window(self, now=None):
        from common.utils.timezone import contains_time_period
        periods = self.auto_approve_time_period or []
        return contains_time_period(periods) if periods else True

    def applies_to_permission(self, perm):
        """The policy's rules cover this kind of permission (users and assets are checked separately)."""
        if self.scope == self.Scope.all:
            return True
        return self.scope == self.Scope.requests and bool(getattr(perm, 'from_ticket', False))


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
    kind = models.CharField(max_length=16, default='host', verbose_name=_('Target'))
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

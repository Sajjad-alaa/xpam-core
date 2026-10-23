import re

from django.db import transaction
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from common.serializers.fields import BitChoicesField, JSONManyToManyField, LabeledChoiceField, ObjectRelatedField
from orgs.mixins.serializers import BulkOrgResourceModelSerializer
from acls.models import CommandGroup
from perms.models import AssetPermission
from perms.const import ActionChoices
from ..jit.naming import validate_username, JITNameError
from ..models import JITPolicy, JITAccount

__all__ = ['JITPolicySerializer', 'JITAccountSerializer']


class OptionalUsersField(JSONManyToManyField):
    """Users selector where "nobody chosen" is allowed and means "use the approval flow"."""

    def to_internal_value(self, data):
        if not data or (isinstance(data, dict) and data.get('type') == 'ids' and not data.get('ids')):
            return {}
        return super().to_internal_value(data)

    def to_representation(self, manager):
        value = getattr(manager, 'value', manager)
        if not isinstance(value, dict) or not value.get('type'):
            return {'type': 'ids', 'ids': []}
        return super().to_representation(manager)


class ApprovalFlowField(ObjectRelatedField):
    """An approval flow for access requests of the rule's organization (its own or a global one)."""

    def __init__(self, **kwargs):
        from tickets.models import TicketFlow
        kwargs.setdefault('queryset', TicketFlow.objects)
        super().__init__(**kwargs)

    def get_queryset(self):
        from orgs.utils import current_org
        from ..jit.selfservice import org_flows
        return org_flows(current_org.id)


class JITPolicySerializer(BulkOrgResourceModelSerializer):
    mode = LabeledChoiceField(choices=JITPolicy.Mode.choices, default=JITPolicy.Mode.per_session,
                              label=_('Account lifetime'))
    username_mode = LabeledChoiceField(choices=JITPolicy.UsernameMode.choices,
                                       default=JITPolicy.UsernameMode.same_as_user, label=_('Account name'))
    scope = LabeledChoiceField(choices=JITPolicy.Scope.choices, default=JITPolicy.Scope.all,
                               label=_('Applies to'))
    users = JSONManyToManyField(label=_('Users'), required=False)
    approval_route = LabeledChoiceField(choices=JITPolicy.ApprovalRoute.choices,
                                        default=JITPolicy.ApprovalRoute.flow, label=_('Approved by'))
    approval_flow = ApprovalFlowField(required=False, allow_null=True, attrs=('id', 'name'),
                                      label=_('Approval flow'))
    approvers = OptionalUsersField(label=_('Approvers'), required=False, allow_null=True)
    assets = JSONManyToManyField(label=_('Assets'), required=False)
    permissions = ObjectRelatedField(
        source='asset_permissions', many=True, required=False,
        queryset=AssetPermission.objects, label=_('Linked asset permissions'),
    )
    command_groups = ObjectRelatedField(
        many=True, required=False, queryset=CommandGroup.objects, label=_('Command groups')
    )
    command_action = LabeledChoiceField(choices=JITPolicy.CommandAction.choices,
                                        default=JITPolicy.CommandAction.reject, label=_('Command action'))
    credential_type = LabeledChoiceField(choices=JITPolicy.CredentialType.choices,
                                         default=JITPolicy.CredentialType.password, label=_('Credential'))
    db_privilege = LabeledChoiceField(choices=JITPolicy.DBPrivilege.choices,
                                      default=JITPolicy.DBPrivilege.read_only, label=_('Database rights'))
    # XPAM: what an access through the rule may allow (a request picks among them)
    protocols = serializers.ListField(
        child=serializers.RegexField(r'^[A-Za-z][A-Za-z0-9_]{0,31}$'), required=False, max_length=32,
        label=_('Allowed protocols'), help_text=_('["all"] or a list such as ["ssh", "http"]')
    )
    actions = BitChoicesField(choice_cls=ActionChoices, required=False, label=_('Allowed actions'))
    permissions_amount = serializers.SerializerMethodField(label=_('Permissions'))
    live_accounts_amount = serializers.SerializerMethodField(label=_('Live accounts'))

    class Meta:
        model = JITPolicy
        fields = [
            'id', 'name', 'mode', 'username_mode', 'specific_username', 'username_prefix',
            'privileged', 'linux_shell', 'linux_groups', 'windows_groups', 'remove_home',
            'scope', 'users', 'assets', 'priority', 'is_active', 'permissions',
            'jit_only', 'self_service', 'max_hours', 'require_reason', 'auto_approve', 'auto_approve_max_hours',
            'auto_approve_time_period', 'approvals_required', 'approval_route', 'approval_flow', 'approvers', 'require_mfa', 'end_sessions_on_expiry',
            'expiry_warning_minutes', 'command_groups', 'command_action', 'credential_type',
            'db_privilege', 'db_custom_sql', 'device_role', 'device_custom_role', 'device_create_commands',
            'device_remove_commands', 'protocols', 'actions', 'permissions_amount', 'live_accounts_amount',
            'comment', 'created_by', 'date_created', 'date_updated',
        ]
        read_only_fields = ['created_by', 'date_created', 'date_updated']
        extra_kwargs = {
            'specific_username': {'help_text': _('Used when the account name is "Specific name"; the same '
                                                 'account is shared by everyone the policy applies to')},
            'username_prefix': {'help_text': _('Put in front of the XPAM username or the random name, '
                                               'for example "xpam-"')},
            'privileged': {'help_text': _('Linux: sudo for all commands. Windows: member of '
                                          'Administrators')},
            'windows_groups': {'help_text': _('Local groups the account joins; Remote Desktop Users is '
                                              'always added')},
            'remove_home': {'help_text': _('Linux home folder / Windows profile is deleted together '
                                           'with the account (otherwise kept as a backup)')},
            'priority': {'default': 50, 'help_text': _('When several policies match, the lowest value wins '
                                                       '(1-100)')},
            'jit_only': {'help_text': _('Zero standing privilege: the users this policy covers see only the '
                                        'just-in-time account on its assets, no shared accounts')},
            'self_service': {'help_text': _('Users find the assets of this policy under "Access" in the workspace '
                                            'and ask for time-boxed access themselves')},
            'max_hours': {'help_text': _('Longest access a user can ask for at once')},
            'auto_approve': {'help_text': _('Requests that fit the limits below are approved at once, '
                                            'without waiting for an approver')},
            'auto_approve_time_period': {'help_text': _('Leave empty for any time')},
            'approvals_required': {'help_text': _('2 = a second person must also approve (four-eyes)')},
            'require_mfa': {'help_text': _('Users verify their MFA before the just-in-time account is used')},
            'expiry_warning_minutes': {'help_text': _('The user is told this long before the access ends; 0 = off')},
            'db_custom_sql': {'help_text': _('One statement per line, ending with ";". Placeholders: {username}, '
                                             '{database}')},
            'device_role': {'help_text': _('Role of the account on FortiGate, Palo Alto, Cisco, Juniper, Huawei and H3C '
                                           'devices (read only, operator, administrator or a custom role)')},
            'device_custom_role': {'help_text': _('For the Custom role: FortiGate admin profile, PAN-OS role profile, '
                                                  'Cisco/Huawei privilege level (0-15), NX-OS role, Junos login class '
                                                  'or H3C user role')},
            'device_create_commands': {'help_text': _('Only for other SSH devices (the built-in drivers are used when '
                                                      'empty). One command per line. Placeholders: {username}, '
                                                      '{password}, {login_password} (enable password of the admin '
                                                      'account)')},
            'device_remove_commands': {'help_text': _('One command per line. Placeholders: {username}, '
                                                      '{login_password}')},
        }

    @staticmethod
    def get_permissions_amount(obj):
        if hasattr(obj, 'permissions_amount'):
            return obj.permissions_amount
        return obj.asset_permissions.count()

    @staticmethod
    def get_live_accounts_amount(obj):
        if hasattr(obj, 'live_accounts_amount'):
            return obj.live_accounts_amount
        return obj.jit_accounts.filter(status__in=JITAccount.ACTIVE_STATUSES).count()

    def validate_username_prefix(self, value):
        value = (value or '').strip().lower()
        if value and not re.fullmatch(r'[a-z][a-z0-9_-]{0,11}', value):
            raise serializers.ValidationError(_('Use lower-case letters, digits, "-" or "_", starting with a letter'))
        return value

    def validate_specific_username(self, value):
        value = (value or '').strip().lower()
        if value:
            try:
                validate_username(value)
            except JITNameError as e:
                raise serializers.ValidationError(str(e))
        return value

    def validate_linux_shell(self, value):
        value = (value or '').strip() or '/bin/bash'
        if not re.fullmatch(r'/[A-Za-z0-9_./-]{1,62}', value):
            raise serializers.ValidationError(_('Enter a full path, for example /bin/bash'))
        return value

    def _validate_groups(self, value):
        value = (value or '').strip()
        if value and not re.fullmatch(r"[A-Za-z0-9_. ,-]+", value):
            raise serializers.ValidationError(_('Group names separated by commas'))
        return value

    validate_linux_groups = _validate_groups
    validate_windows_groups = _validate_groups

    @staticmethod
    def validate_protocols(value):
        """ ['all'] or the protocol names, once each """
        names = []
        for name in value or []:
            name = str(name).strip().lower()
            if name and name not in names:
                names.append(name)
        return ['all'] if not names or 'all' in names else names

    @staticmethod
    def validate_actions(value):
        return value | ActionChoices.connect  # (an access always lets one connect)

    def validate_approvers(self, value):
        return value or {}

    def validate(self, attrs):
        attrs = super().validate(attrs)
        instance = self.instance
        get = lambda k, d=None: attrs.get(k, getattr(instance, k, d) if instance else d)  # noqa: E731
        mode = get('mode', JITPolicy.Mode.per_session)
        username_mode = get('username_mode', JITPolicy.UsernameMode.same_as_user)
        if username_mode == JITPolicy.UsernameMode.specific and not get('specific_username'):
            raise serializers.ValidationError({'specific_username': _('Enter the account name to use')})
        if username_mode == JITPolicy.UsernameMode.random_session and mode != JITPolicy.Mode.per_session:
            raise serializers.ValidationError({
                'username_mode': _('"Random per session" needs the account lifetime "Per connection"')
            })
        max_hours = get('max_hours', 8) or 8
        if not 1 <= max_hours <= 720:
            raise serializers.ValidationError({'max_hours': _('Between 1 and 720 hours')})
        if get('auto_approve', False):
            auto_hours = get('auto_approve_max_hours', 4) or 0
            if not 1 <= auto_hours <= max_hours:
                raise serializers.ValidationError({'auto_approve_max_hours': _(
                    'Between 1 hour and the longest access (%s hours)') % max_hours})
            if (get('approvals_required', 1) or 1) > 1:
                raise serializers.ValidationError({'auto_approve': _(
                    'A policy cannot approve by itself and also ask for two approvers')})
        if (get('approvals_required', 1) or 1) not in (1, 2):
            raise serializers.ValidationError({'approvals_required': _('1 or 2')})
        if get('approval_route', JITPolicy.ApprovalRoute.flow) == JITPolicy.ApprovalRoute.approvers:
            approvers = get('approvers')
            value = getattr(approvers, 'value', approvers)
            if not (isinstance(value, dict) and value.get('type')):
                raise serializers.ValidationError({'approvers': _('Choose who approves')})
        elif 'approval_route' in attrs:
            attrs['approvers'] = {}  # (an approval flow decides: no people kept on the side)
        if not 0 <= (get('expiry_warning_minutes', 15) or 0) <= 240:
            raise serializers.ValidationError({'expiry_warning_minutes': _('Between 0 and 240 minutes')})
        if get('db_privilege', 'read_only') == 'custom' and not (get('db_custom_sql') or '').strip():
            raise serializers.ValidationError({'db_custom_sql': _('Enter the SQL that gives the rights')})
        if get('device_role', 'read_only') == 'custom' and not (get('device_custom_role') or '').strip():
            raise serializers.ValidationError({'device_custom_role': _('Enter the role name or privilege level')})
        import re
        if (get('device_custom_role') or '') and not re.fullmatch(r'[A-Za-z0-9_.@-]{1,63}', get('device_custom_role')):
            raise serializers.ValidationError({'device_custom_role': _('Letters, digits, . _ @ - only')})
        # Commands and SQL run with the asset's privileged account (and {login_password} is its secret):
        # only someone allowed to see account secrets may write them.
        request = self.context.get('request')
        user = getattr(request, 'user', None)
        for field in ('device_create_commands', 'device_remove_commands', 'db_custom_sql'):
            changed = field in attrs and (attrs.get(field) or '') != (getattr(instance, field, '') if instance else '')
            if changed and (attrs.get(field) or '').strip() and user is not None \
                    and not user.has_perm('accounts.view_accountsecret'):
                raise serializers.ValidationError({field: _(
                    'Only users who may view account secrets can set commands or SQL that run with the '
                    'privileged account')})
        if (get('device_create_commands') or '').strip() and not (get('device_remove_commands') or '').strip():
            raise serializers.ValidationError({'device_remove_commands': _(
                'Enter the commands that remove the account again')})
        scope = get('scope', JITPolicy.Scope.all)
        if mode == JITPolicy.Mode.approved_window:
            if scope == JITPolicy.Scope.all:
                raise serializers.ValidationError({'scope': _(
                    'An approved time window is for approved access requests; choose "Approved access '
                    'requests" or "Only the asset permissions linked to it"')})
            perms = attrs.get('asset_permissions') or []
            if any(not p.from_ticket for p in perms):
                raise serializers.ValidationError({'permissions': _(
                    'An approved time window applies to approved access requests; do not select '
                    'ordinary asset permissions')})
        if scope != JITPolicy.Scope.linked:
            for field in ('users', 'assets'):
                value = get(field)
                value = getattr(value, 'value', value)
                if not isinstance(value, dict) or not value.get('type'):
                    raise serializers.ValidationError({field: _('This field is required.')})
        return attrs

    @transaction.atomic
    def create(self, validated_data):
        perms = validated_data.pop('asset_permissions', None)
        instance = super().create(validated_data)
        if perms is not None:
            self._set_permissions(instance, perms)
        return instance

    @transaction.atomic
    def update(self, instance, validated_data):
        perms = validated_data.pop('asset_permissions', None)
        instance = super().update(instance, validated_data)
        if perms is not None:
            self._set_permissions(instance, perms)
        return instance

    @staticmethod
    def _set_permissions(policy, perms):
        from perms.models import AssetPermission
        ids = [p.id for p in perms]
        # approved requests keep the policy their approver chose
        AssetPermission.objects.filter(jit_policy=policy, from_ticket=False).exclude(id__in=ids) \
            .update(jit_policy=None)
        for perm in AssetPermission.objects.filter(id__in=ids):
            perm.jit_policy = policy
            perm.save(update_fields=['jit_policy'])


class JITAccountSerializer(serializers.ModelSerializer):
    policy = ObjectRelatedField(read_only=True, label=_('Policy'))
    mode = LabeledChoiceField(choices=JITPolicy.Mode.choices, read_only=True, label=_('Account lifetime'))
    status = LabeledChoiceField(choices=JITAccount.Status.choices, read_only=True, label=_('Status'))
    user = serializers.SerializerMethodField(label=_('User'))
    asset = serializers.SerializerMethodField(label=_('Asset'))

    class Meta:
        model = JITAccount
        fields = [
            'id', 'policy', 'mode', 'user', 'asset', 'username', 'kind', 'privileged', 'status', 'error',
            'attempts', 'date_created', 'date_ready', 'date_expired', 'date_removed', 'org_id',
        ]
        read_only_fields = fields

    @staticmethod
    def get_user(obj):
        return {'id': str(obj.user_id) if obj.user_id else None, 'name': obj.user_display}

    @staticmethod
    def get_asset(obj):
        return {'id': str(obj.asset_id) if obj.asset_id else None, 'name': obj.asset_display}

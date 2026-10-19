import re

from django.db import transaction
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from common.serializers.fields import JSONManyToManyField, LabeledChoiceField, ObjectRelatedField
from orgs.mixins.serializers import BulkOrgResourceModelSerializer
from perms.models import AssetPermission
from ..jit.naming import validate_username, JITNameError
from ..models import JITPolicy, JITAccount

__all__ = ['JITPolicySerializer', 'JITAccountSerializer']


class JITPolicySerializer(BulkOrgResourceModelSerializer):
    mode = LabeledChoiceField(choices=JITPolicy.Mode.choices, default=JITPolicy.Mode.per_session,
                              label=_('Account lifetime'))
    username_mode = LabeledChoiceField(choices=JITPolicy.UsernameMode.choices,
                                       default=JITPolicy.UsernameMode.same_as_user, label=_('Account name'))
    scope = LabeledChoiceField(choices=JITPolicy.Scope.choices, default=JITPolicy.Scope.all,
                               label=_('Applies to'))
    users = JSONManyToManyField(label=_('Users'), required=False)
    assets = JSONManyToManyField(label=_('Assets'), required=False)
    permissions = ObjectRelatedField(
        source='asset_permissions', many=True, required=False,
        queryset=AssetPermission.objects, label=_('Linked asset permissions'),
    )
    permissions_amount = serializers.SerializerMethodField(label=_('Permissions'))
    live_accounts_amount = serializers.SerializerMethodField(label=_('Live accounts'))

    class Meta:
        model = JITPolicy
        fields = [
            'id', 'name', 'mode', 'username_mode', 'specific_username', 'username_prefix',
            'privileged', 'linux_shell', 'linux_groups', 'windows_groups', 'remove_home',
            'scope', 'users', 'assets', 'priority', 'is_active', 'permissions', 'permissions_amount', 'live_accounts_amount',
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
        }

    @staticmethod
    def get_permissions_amount(obj):
        return obj.asset_permissions.count()

    @staticmethod
    def get_live_accounts_amount(obj):
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
            'id', 'policy', 'mode', 'user', 'asset', 'username', 'privileged', 'status', 'error',
            'attempts', 'date_created', 'date_ready', 'date_expired', 'date_removed', 'org_id',
        ]
        read_only_fields = fields

    @staticmethod
    def get_user(obj):
        return {'id': str(obj.user_id) if obj.user_id else None, 'name': obj.user_display}

    @staticmethod
    def get_asset(obj):
        return {'id': str(obj.asset_id) if obj.asset_id else None, 'name': obj.asset_display}

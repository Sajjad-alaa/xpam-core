import re

from django.db import transaction
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from common.serializers.fields import LabeledChoiceField, ObjectRelatedField
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
    permissions = ObjectRelatedField(
        source='asset_permissions', many=True, required=False,
        queryset=AssetPermission.objects, label=_('Asset permissions'),
    )
    permissions_amount = serializers.SerializerMethodField(label=_('Permissions'))
    live_accounts_amount = serializers.SerializerMethodField(label=_('Live accounts'))

    class Meta:
        model = JITPolicy
        fields = [
            'id', 'name', 'mode', 'username_mode', 'specific_username', 'username_prefix',
            'privileged', 'linux_shell', 'linux_groups', 'windows_groups', 'remove_home',
            'apply_to_requests', 'is_active', 'permissions', 'permissions_amount', 'live_accounts_amount',
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
            'apply_to_requests': {'help_text': _('When an access request is approved, the permission it '
                                                 'creates uses this policy automatically')},
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
        if mode == JITPolicy.Mode.approved_window:
            attrs['apply_to_requests'] = True
            if attrs.get('asset_permissions'):
                raise serializers.ValidationError({'permissions': _(
                    'An approved time window applies to the permissions created by approved access '
                    'requests; do not select permissions')})
        for_requests = get('apply_to_requests', False) or mode == JITPolicy.Mode.approved_window
        if for_requests and get('is_active', True):
            from django.db.models import Q
            others = JITPolicy.objects.filter(is_active=True).filter(
                Q(apply_to_requests=True) | Q(mode=JITPolicy.Mode.approved_window)
            )
            if instance:
                others = others.exclude(id=instance.id)
            other = others.first()
            if other:
                raise serializers.ValidationError({'apply_to_requests': _(
                    'Approved access requests already use the policy "%s"; only one policy per '
                    'organization can apply to them') % other.name})
        return attrs

    @transaction.atomic
    def create(self, validated_data):
        perms = validated_data.pop('asset_permissions', None)
        instance = super().create(validated_data)
        if perms is not None:
            self._set_permissions(instance, perms)
        self._attach_to_approved_requests(instance)
        return instance

    @transaction.atomic
    def update(self, instance, validated_data):
        perms = validated_data.pop('asset_permissions', None)
        instance = super().update(instance, validated_data)
        if perms is not None:
            self._set_permissions(instance, perms)
        self._attach_to_approved_requests(instance)
        return instance

    @staticmethod
    def _attach_to_approved_requests(policy):
        """Requests approved earlier (and still valid) get the policy too, so nothing is left to do by hand."""
        from django.utils import timezone
        if not (policy.is_active and policy.for_requests):
            return
        AssetPermission.objects.filter(
            org_id=policy.org_id, from_ticket=True, jit_policy__isnull=True,
            is_active=True, date_expired__gt=timezone.now(),
        ).update(jit_policy=policy)

    @staticmethod
    def _set_permissions(policy, perms):
        from perms.models import AssetPermission
        ids = [p.id for p in perms]
        AssetPermission.objects.filter(jit_policy=policy).exclude(id__in=ids).update(jit_policy=None)
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

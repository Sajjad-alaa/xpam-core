from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from common.serializers.fields import ObjectRelatedField
from orgs.mixins.serializers import BulkOrgResourceModelSerializer
from ..models import VaultConnection, VaultStorageRule

__all__ = ['VaultConnectionSerializer', 'VaultStorageRuleSerializer']

SECRET_HINTS = ('PASSWORD', 'TOKEN', 'SECRET', 'API_KEY', 'CREDENTIALS', 'KEY_FILE', 'KEY_PEM')
ENDPOINT_HINTS = ('_ADDR', '_HOST', '_URL', '_REGION_NAME', '_PROJECT')


class VaultConnectionSerializer(serializers.ModelSerializer):
    config = serializers.DictField(required=False, write_only=True, label=_('Settings'))
    settings = serializers.SerializerMethodField(label=_('Settings'))

    class Meta:
        model = VaultConnection
        fields = ['id', 'name', 'type', 'config', 'settings', 'managed', 'is_active', 'comment',
                  'date_created', 'date_updated']
        read_only_fields = ['managed', 'date_created', 'date_updated']

    @staticmethod
    def get_settings(obj):
        """ what the console may see: addresses and names, never a password, token or key """
        return {k: ('******' if any(h in k for h in SECRET_HINTS) and v else v) for k, v in (obj.config or {}).items()}

    def validate(self, attrs):
        if settings.VAULT_LOCKED:
            raise serializers.ValidationError(_('The vaults are managed on the XPAM server (xpamctl vault add-connection)'))
        instance = self.instance
        if instance is not None and instance.managed:
            raise serializers.ValidationError(_('This connection is managed on the XPAM server'))
        vtype = attrs.get('type') or getattr(instance, 'type', '')
        config = attrs.get('config')
        if config is not None:
            prefix = f'VAULT_{vtype.upper()}_'
            wrong = [k for k in config if not str(k).startswith(prefix)]
            if wrong:
                raise serializers.ValidationError({'config': _('Only %s* settings: %s') % (prefix, ', '.join(wrong))})
            if instance is not None:  # an omitted or masked secret keeps its value only if the endpoint did not change
                old_cfg = dict(instance.config or {})
                endpoint_changed = any(
                    any(k.endswith(eh) for eh in ENDPOINT_HINTS)
                    and str(v or '').strip().rstrip('/') != str(old_cfg.get(k) or '').strip().rstrip('/')
                    for k, v in config.items()
                )
                # a stored secret is carried over only when it is omitted or sent masked; an empty value
                # clears it (e.g. switching to role-based auth), so that is not a reuse
                reused_secret = endpoint_changed and any(
                    any(h in k for h in SECRET_HINTS) and old_cfg.get(k)
                    and (k not in config or config.get(k) == '******')
                    for k in old_cfg
                )
                if reused_secret:
                    raise serializers.ValidationError({
                        'config': _('Enter the secret or token again when changing the vault address')
                    })
                merged = dict(old_cfg)
                merged.update({k: v for k, v in config.items() if v != '******'})
                attrs['config'] = merged
        return attrs


class VaultStorageRuleSerializer(BulkOrgResourceModelSerializer):
    connection = ObjectRelatedField(queryset=VaultConnection.objects.all(), required=False, allow_null=True,
                                    label=_('Vault connection'))
    mirror = ObjectRelatedField(queryset=VaultConnection.objects.all(), required=False, allow_null=True,
                                label=_('Mirror'))

    class Meta:
        model = VaultStorageRule
        fields = ['id', 'name', 'priority', 'is_active', 'nodes', 'platforms', 'username', 'connection', 'mirror',
                  'comment', 'org_id', 'date_created', 'date_updated']
        read_only_fields = ['org_id', 'date_created', 'date_updated']

    def validate(self, attrs):
        connection = attrs.get('connection', getattr(self.instance, 'connection', None))
        mirror = attrs.get('mirror', getattr(self.instance, 'mirror', None))
        if mirror is not None and connection is not None and mirror.id == connection.id:
            raise serializers.ValidationError({'mirror': _('The mirror must be another vault')})
        for field, value in (('connection', connection), ('mirror', mirror)):
            if value is not None and not value.is_active:
                raise serializers.ValidationError({field: _('This vault connection is not active')})
        return attrs

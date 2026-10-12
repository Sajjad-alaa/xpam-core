from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from assets.models import Host
from assets.validators import validate_ip_or_hostname
from .common import AssetSerializer
from .info.gathered import HostGatheredInfoSerializer

__all__ = ['HostSerializer']


class HostSerializer(AssetSerializer):
    gathered_info = HostGatheredInfoSerializer(required=False, read_only=True, label=_("Gathered info"))
    # RemoteApp (XPAM): stored in custom_info, used by the Windows-RemoteApp platform
    remote_app = serializers.CharField(
        required=False, allow_blank=True, max_length=300, label=_('RemoteApp program'),
        help_text=_('Published alias such as ||qgis-bin (recommended), or a full path such as '
                    'C:\\Program Files\\App\\app.exe')
    )
    remote_app_dir = serializers.CharField(
        required=False, allow_blank=True, max_length=300, label=_('RemoteApp working directory')
    )
    remote_app_args = serializers.CharField(
        required=False, allow_blank=True, max_length=600, label=_('RemoteApp arguments')
    )

    def validate_address(self, value):
        value = super().validate_address(value)
        validate_ip_or_hostname(value)
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        try:
            from xpack.remote_app import (
                REMOTE_APP_FIELDS, RemoteAppError, is_remote_app_platform,
                normalize_args, normalize_dir, normalize_program,
            )
        except ImportError:
            for field in ('remote_app', 'remote_app_dir', 'remote_app_args'):
                attrs.pop(field, None)
            return attrs

        provided = {f: attrs.pop(f) for f in REMOTE_APP_FIELDS if f in attrs}
        platform = attrs.get('platform') or getattr(self.instance, 'platform', None)
        current = dict(getattr(self.instance, 'custom_info', None) or {})
        if not is_remote_app_platform(platform):
            if any(provided.values()):
                raise serializers.ValidationError(
                    {'remote_app': _('RemoteApp settings are only available on the Windows-RemoteApp platform')})
            return attrs

        values = {f: provided.get(f, current.get(f, '')) for f in REMOTE_APP_FIELDS}
        errors = {}
        for field, func in (('remote_app', normalize_program), ('remote_app_dir', normalize_dir),
                            ('remote_app_args', normalize_args)):
            try:
                values[field] = func(values[field])
            except RemoteAppError as e:
                errors[field] = str(e)
        if not values['remote_app'] and 'remote_app' not in errors:
            errors['remote_app'] = _('Program is required for the Windows-RemoteApp platform')
        if errors:
            raise serializers.ValidationError(errors)
        attrs['custom_info'] = {**current, **values}
        return attrs

    def to_representation(self, instance):
        data = super().to_representation(instance)
        info = getattr(instance, 'custom_info', None) or {}
        for field in ('remote_app', 'remote_app_dir', 'remote_app_args'):
            data[field] = info.get(field, '')
        return data

    class Meta(AssetSerializer.Meta):
        model = Host
        fields = AssetSerializer.Meta.fields + [
            'gathered_info', 'remote_app', 'remote_app_dir', 'remote_app_args'
        ]
        extra_kwargs = {
            **AssetSerializer.Meta.extra_kwargs,
            'address': {
                'label': _("IP/Host")
            },
        }

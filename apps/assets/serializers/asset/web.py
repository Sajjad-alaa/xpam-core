from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from assets.models import Web
from assets.validators import normalize_web_origin, validate_web_script, web_xpack_fields
from .common import AssetSerializer

__all__ = ['WebSerializer']


class WebSerializer(AssetSerializer):
    allowed_urls = serializers.ListField(
        child=serializers.CharField(max_length=512, validators=[normalize_web_origin]),
        max_length=100, required=False, label=_("Allowed sites")
    )

    class Meta(AssetSerializer.Meta):
        model = Web
        fields = AssetSerializer.Meta.fields + [
            'autofill', 'username_selector',
            'password_selector', 'submit_selector',
            'success_selector', 'interactive_selector', 'script', 'allowed_urls', 'verify_cert'
        ]
        extra_kwargs = {
            **AssetSerializer.Meta.extra_kwargs,
            'address': {
                'label': 'URL'
            },
            # XPAM: empty = found automatically (guessed defaults were usually wrong for the site)
            'username_selector': {'required': False, 'allow_blank': True, 'default': ''},
            'password_selector': {'required': False, 'allow_blank': True, 'default': ''},
            'submit_selector': {'required': False, 'allow_blank': True, 'default': ''},
            'success_selector': {
                'required': False,
                'allow_blank': True,
                'default': '',
            },
            'interactive_selector': {
                'required': False,
                'allow_blank': True,
                'default': '',
            },
            'script': {
                'default': [],
            }
        }

    def get_fields(self):
        fields = super().get_fields()
        if not settings.XPACK_LICENSE_IS_VALID:
            fields['autofill'].choices = {
                key: label for key, label in fields['autofill'].choices.items() if key != 'script'
            }
        return fields

    def validate(self, attrs):
        attrs = super().validate(attrs)
        restricted = web_xpack_fields(attrs)
        if restricted:
            raise serializers.ValidationError({
                field: _('A valid enterprise license is required.') for field in restricted
            })
        interactive = attrs.get('interactive_selector', getattr(self.instance, 'interactive_selector', ''))
        if interactive:
            kind, separator, value = interactive.partition('=')
            if not separator or not value.strip() or kind.strip().lower() not in (
                'name', 'id', 'type', 'class_name', 'css', 'css_selector', 'xpath'
            ):
                raise serializers.ValidationError({'interactive_selector': _('Invalid selector')})
        return attrs

    def validate_address(self, value):
        # XPAM: "portal.example.com" means https://portal.example.com
        value = (value or '').strip()
        if value and '://' not in value:
            value = 'https://' + value
        return super().validate_address(value)

    def is_valid(self, raise_exception=False):
        # XPAM: the port of the http protocol follows the address (https://x -> 443, http://x:8080 -> 8080,
        # no scheme = https). Set on the request data: the nested protocol writer reads it from there.
        from urllib.parse import urlsplit
        data = getattr(self, 'initial_data', None)
        address = (data.get('address') or '').strip() if isinstance(data, dict) else ''
        if address:
            self._set_protocols_default()
            try:
                u = urlsplit(address if '://' in address else 'https://' + address)
                port = u.port or (443 if u.scheme == 'https' else 80)
                for p in self.initial_data.get('protocols') or []:
                    if isinstance(p, dict) and p.get('name') == 'http':
                        p['port'] = port
            except (ValueError, TypeError, AttributeError):
                pass
        return super().is_valid(raise_exception=raise_exception)

    def validate_script(self, value):
        validate_web_script(value)
        return value

    def to_internal_value(self, data):
        data = data.copy()
        if data.get('script') in ("", None):
            data.pop('script', None)
        return super().to_internal_value(data)

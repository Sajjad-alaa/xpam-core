from django.conf import settings
from rest_framework import generics
from rest_framework.permissions import AllowAny

from authentication.permissions import IsValidUserOrConnectionToken
from common.const.choices import Language
from common.utils import get_logger, lazyproperty
from common.utils.timezone import local_now
from .. import serializers
from ..utils import get_interface_setting_or_default

logger = get_logger(__name__)

__all__ = ['PublicSettingApi', 'OpenPublicSettingApi', 'ServerInfoApi']


class OpenPublicSettingApi(generics.RetrieveAPIView):
    permission_classes = (AllowAny,)
    serializer_class = serializers.PublicSettingSerializer

    @lazyproperty
    def interface_setting(self):
        return get_interface_setting_or_default()

    def get_object(self):
        try:
            from xpack.utils import has_ticket_license
            has_ticket = has_ticket_license()
        except Exception:
            has_ticket = False

        return {
            "XPACK_ENABLED": settings.XPACK_ENABLED,
            "HAS_TICKET_LICENSE": has_ticket,
            "INTERFACE": self.interface_setting,
            "LANGUAGES":  [
                {
                    'name': title,
                    'code': code,
                    'other_codes': Language.get_other_codes(code),
                }
                for code, title in Language.choices_supported()
            ],
            "VENDOR": settings.VENDOR,
        }


class PublicSettingApi(OpenPublicSettingApi):
    permission_classes = (IsValidUserOrConnectionToken,)
    serializer_class = serializers.PrivateSettingSerializer

    def get_object(self):
        if self.request.user.is_org_admin:
            SECURITY_PASSWORD_EXPIRATION_TIME = settings.SECURITY_PASSWORD_EXPIRATION_TIME_ADMIN
        else:
            SECURITY_PASSWORD_EXPIRATION_TIME = settings.SECURITY_PASSWORD_EXPIRATION_TIME

        try:
            from xpack.utils import get_current_license_info, has_ticket_license
            lic_info = get_current_license_info()
            has_ticket = has_ticket_license()
        except Exception:
            lic_info = settings.XPACK_LICENSE_INFO
            has_ticket = False

        # License internals (installation id, license id, serial) are for system admins only
        is_admin = getattr(self.request.user, 'is_superuser', False)
        if not is_admin:
            lic_info = {
                'corporation': lic_info.get('corporation', 'XPAM'),
                'edition': lic_info.get('edition', 'Standard'),
                'is_valid': bool(lic_info.get('is_valid', False)),
                'has_ticket': bool(lic_info.get('has_ticket', False)),
            }

        values = super().get_object()
        values.update({
            "XPACK_LICENSE_IS_VALID": bool(lic_info.get('is_valid', False)),
            "XPACK_LICENSE_INFO": lic_info,
            "HAS_TICKET_LICENSE": has_ticket,
            "PASSWORD_RULE": {
                'SECURITY_PASSWORD_MIN_LENGTH': settings.SECURITY_PASSWORD_MIN_LENGTH,
                'SECURITY_ADMIN_USER_PASSWORD_MIN_LENGTH': settings.SECURITY_ADMIN_USER_PASSWORD_MIN_LENGTH,
                'SECURITY_PASSWORD_UPPER_CASE': settings.SECURITY_PASSWORD_UPPER_CASE,
                'SECURITY_PASSWORD_LOWER_CASE': settings.SECURITY_PASSWORD_LOWER_CASE,
                'SECURITY_PASSWORD_NUMBER': settings.SECURITY_PASSWORD_NUMBER,
                'SECURITY_PASSWORD_SPECIAL_CHAR': settings.SECURITY_PASSWORD_SPECIAL_CHAR,
            },
            "SECURITY_PASSWORD_EXPIRATION_TIME": SECURITY_PASSWORD_EXPIRATION_TIME,
        })

        serializer = self.serializer_class()
        field_names = list(serializer.fields.keys())
        for name in field_names:
            if name in values:
                continue
            # 提前把异常爆出来
            values[name] = getattr(settings, name)
        return values


class ServerInfoApi(generics.RetrieveAPIView):
    permission_classes = (IsValidUserOrConnectionToken,)
    serializer_class = serializers.ServerInfoSerializer

    def get_object(self):
        return {
            "CURRENT_TIME": local_now(),
        }

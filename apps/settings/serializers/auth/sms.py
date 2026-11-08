from django.db import models
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from common.sdk.sms import BACKENDS
from common.serializers.fields import PhoneField
from common.validators import PhoneValidator

__all__ = [
    'BaseSMSSettingSerializer',
    'SMSSettingSerializer', 'CustomSMSSettingSerializer',
]


class SMSSettingSerializer(serializers.Serializer):
    SMS_ENABLED = serializers.BooleanField(
        default=False, label=_('SMS'), help_text=_('Enable Short Message Service (SMS)')
    )
    SMS_BACKEND = serializers.ChoiceField(
        choices=BACKENDS.choices, default=BACKENDS.CUSTOM, label=_('Provider'),
        help_text=_('Short Message Service (SMS) provider or protocol')
    )
    SMS_CODE_LENGTH = serializers.IntegerField(
        default=4, min_value=4, max_value=16, label=_('Code length'),
        help_text=_('Length of the sent verification code')
    )


class BaseSMSSettingSerializer(serializers.Serializer):
    PREFIX_TITLE = _('SMS')

    SMS_TEST_PHONE = PhoneField(
        validators=[PhoneValidator()], required=False, allow_blank=True, allow_null=True, 
        label=_('Phone')
    )

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # data['SMS_BACKEND'] = self.fields['SMS_BACKEND'].default
        return data


class CustomSMSSettingSerializer(BaseSMSSettingSerializer):
    class RequestType(models.TextChoices):
        get = 'get', 'Get'
        post = 'post', 'Post'

    CUSTOM_SMS_URL = serializers.URLField(required=True, label=_("URL"))
    CUSTOM_SMS_API_PARAMS = serializers.JSONField(
        label=_('Parameters'), default={'phone_number': '{phone_number}', 'code': '{code}'}
    )
    CUSTOM_SMS_REQUEST_METHOD = serializers.ChoiceField(
        default=RequestType.get, choices=RequestType.choices, label=_("Request method")
    )

    def validate(self, attrs):
        need_params = {'{phone_numbers}', '{code}'}
        params = attrs.get('CUSTOM_SMS_API_PARAMS', {})
        # 这里用逗号分隔是保证需要的参数必须是完整的，不能分开在不同的参数中首位相连
        params_string = ','.join(params.values())
        for param in need_params:
            if param not in params_string:
                raise serializers.ValidationError(
                _('The value in the parameter must contain %s') % ','.join(need_params)
            )
        return attrs

import importlib
from collections import OrderedDict

from django.utils.translation import gettext_lazy as _
from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.generics import ListAPIView, GenericAPIView
from rest_framework.response import Response

from common.exceptions import JMSException
from common.sdk.sms import BACKENDS
from settings.models import Setting
from settings.serializers import SMSBackendSerializer
from .. import serializers


class SMSBackendAPI(ListAPIView):
    serializer_class = SMSBackendSerializer
    rbac_perms = {
        'list': 'settings.view_setting'
    }

    def list(self, request, *args, **kwargs):
        # (upstream iterated BACKENDS.choices, plain tuples without .label, so this list always failed)
        data = [
            {
                'name': b.value,
                'label': b.label
            }
            for b in BACKENDS
        ]
        return Response(data)


class SMSTestingAPI(GenericAPIView):
    backends_serializer = {
        'custom': serializers.CustomSMSSettingSerializer,
        'custom_file': serializers.BaseSMSSettingSerializer,
    }
    rbac_perms = {
        'POST': 'settings.change_sms'
    }

    @property
    def test_code(self):
        return '6' * settings.SMS_CODE_LENGTH

    @staticmethod
    def get_or_from_setting(key, value=''):
        if not value:
            secret = Setting.objects.filter(name=key).first()
            if secret:
                value = secret.cleaned_value

        return value or ''





    def get_custom_params(self, data):
        init_params = {}
        send_sms_params = {'template_param': OrderedDict(code=self.test_code)}
        return init_params, send_sms_params

    def get_custom_file_params(self, data):
        return self.get_custom_params(data)

    def get_params_by_backend(self, backend, data):
        """
        返回两部分参数
            1、实例化参数
            2、发送测试短信参数
        """
        get_params_func = getattr(self, 'get_%s_params' % backend)
        return get_params_func(data)

    def post(self, request, backend):
        serializer_class = self.backends_serializer.get(backend)
        if serializer_class is None:
            raise JMSException(_('Invalid SMS platform'))
        serializer = serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        test_phone = serializer.validated_data.get('SMS_TEST_PHONE')
        if not test_phone:
            raise JMSException(code='test_phone_required', detail=_('test_phone is required'))

        init_params, send_sms_params = self.get_params_by_backend(backend, serializer.validated_data)

        m = importlib.import_module(f'common.sdk.sms.{backend}', __package__)
        try:
            client = m.client(**init_params)
            client.send_sms(
                phone_numbers=[test_phone],
                **send_sms_params
            )
            status_code = status.HTTP_200_OK
            data = {'msg': _('Test success')}
        except APIException as e:
            try:
                error = e.detail['errmsg']
            except:
                error = e.detail
            status_code = status.HTTP_400_BAD_REQUEST
            data = {'error': error}
        except Exception as e:
            status_code = status.HTTP_400_BAD_REQUEST
            data = {'error': str(e)}
        return Response(status=status_code, data=data)

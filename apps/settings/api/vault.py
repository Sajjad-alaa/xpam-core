from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.views import Response, APIView

from accounts.backends import get_vault_client
from accounts.tasks.vault import restore_secret_from_vault, sync_secret_to_vault
from common.exceptions import JMSException
from settings.models import Setting
from .. import serializers


class VaultTestingAPI(GenericAPIView):
    backends_serializer = {
        'openbao': serializers.OpenBaoSerializer,
        'azure': serializers.AzureKVSerializer,
        'aws': serializers.AmazonSMSerializer,
        'hcp': serializers.HashicorpKVSerializer,
        'cyberark': serializers.CyberArkSerializer,
        'delinea': serializers.DelineaSerializer,
        'gcp': serializers.GoogleSMSerializer,
    }
    rbac_perms = {
        'POST': 'settings.change_vault'
    }

    def get_config(self, request, backend):
        serializer_class = self.backends_serializer.get(backend)
        if serializer_class is None:
            raise JMSException()
        serializer = serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        for name in serializer.fields:
            if name in data and data[name] not in ('', None):
                continue
            # 页面没有传递值, 从 settings 中获取。False 是有效的开关值。
            data[name] = getattr(settings, name, None)
        if backend == 'openbao':
            data['VAULT_OPENBAO_CACERT_FILE'] = settings.VAULT_OPENBAO_CACERT_FILE
        return data

    def post(self, request, backend):
        if settings.VAULT_LOCKED:
            # XPAM: locked — test the configured vault only, never one given in the request
            names = [k for k in dir(settings) if k.startswith('VAULT_')]
            config = {k: getattr(settings, k) for k in names}
            backend = settings.VAULT_BACKEND
        else:
            config = self.get_config(request, backend)
        config['VAULT_ENABLED'] = settings.VAULT_ENABLED
        config['VAULT_BACKEND'] = backend
        try:
            client = get_vault_client(raise_exception=True, **config)
            ok, error = client.is_active()
        except Exception as e:
            ok, error = False, str(e)

        if ok:
            _status, msg = status.HTTP_200_OK, _('Test success')
        else:
            _status, msg = status.HTTP_400_BAD_REQUEST, error

        return Response(status=_status, data={'msg': msg})


class VaultSyncDataAPI(APIView):
    perm_model = Setting
    rbac_perms = {
        'POST': 'settings.change_vault'
    }

    def post(self, request, *args, **kwargs):
        task = self._run_task()
        return Response({'task': task.id}, status=status.HTTP_201_CREATED)

    @staticmethod
    def _run_task():
        task = sync_secret_to_vault.delay()
        return task


class VaultRestoreDataAPI(VaultSyncDataAPI):
    def post(self, request, *args, **kwargs):
        if settings.VAULT_LOCKED:
            # XPAM: secrets do not come back into the database from the console
            return Response({'detail': _('The vault is managed on the XPAM server (xpamctl vault): secrets cannot be '
                                         'restored into the database from here')}, status=status.HTTP_403_FORBIDDEN)
        return super().post(request, *args, **kwargs)

    @staticmethod
    def _run_task():
        task = restore_secret_from_vault.delay()
        return task


class DataKeyStatusAPI(APIView):
    """ XPAM: the data key — provider, current version, values per version, rotation """
    perm_model = Setting
    # XPAM: platform infrastructure (servers, witness, vault): system roles only, never an organization's role
    rbac_perms = {'GET': 'settings.change_setting'}

    def get(self, request, *args, **kwargs):
        from settings.tasks.datakey import data_key_status
        try:
            return Response(data_key_status())
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

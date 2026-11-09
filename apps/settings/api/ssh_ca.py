from types import SimpleNamespace

from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.services import get_ssh_ca_client
from .. import serializers
from ..serializers.feature import validate_ssh_ca_openbao_address

__all__ = ['SSHCAOpenBaoTestingAPI', 'SSHCAOpenBaoPublicKeyAPI']


class SSHCAOpenBaoTestingAPI(GenericAPIView):
    serializer_class = serializers.SSHCAOpenBaoSerializer
    rbac_perms = {'POST': 'settings.change_vault'}

    def get_config(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data
        address_field = 'SSH_CA_OPENBAO_ADDR'
        stored_addr = (getattr(settings, address_field, None) or '').strip().rstrip('/')
        req_addr = validated_data.get(address_field)
        if req_addr is None:
            effective_addr = getattr(settings, address_field, None)
        else:
            effective_addr = req_addr
        addr_unchanged = (effective_addr or '').strip().rstrip('/') == stored_addr

        data = {}
        for name in serializer.fields:
            value = validated_data.get(name, getattr(settings, name, None))
            if name == 'SSH_CA_OPENBAO_TOKEN' and value in ('', None):
                # Only fall back to the stored token when testing the already-configured address
                value = getattr(settings, name, None) if addr_unchanged else ''
            data[name] = value
        data['SSH_CA_OPENBAO_CACERT_FILE'] = settings.SSH_CA_OPENBAO_CACERT_FILE

        if not data[address_field]:
            raise ValidationError({
                address_field: [_('This field may not be blank.')]
            })
        validate_ssh_ca_openbao_address(data[address_field])
        return SimpleNamespace(**data)

    def post(self, request):
        client = get_ssh_ca_client(self.get_config(request))
        ok, error = client.is_active()
        if not ok:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={'msg': error},
            )
        return Response({
            'msg': _('Test success'),
            'public_key': client.get_public_key(),
        })


class SSHCAOpenBaoPublicKeyAPI(APIView):
    rbac_perms = {'GET': 'settings.change_vault'}

    def get(self, request):
        try:
            public_key = get_ssh_ca_client().get_public_key()
        except Exception as e:
            return Response(
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
                data={'msg': str(e)},
            )
        return Response({'public_key': public_key})

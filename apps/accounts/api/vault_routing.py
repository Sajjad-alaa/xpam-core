from django.conf import settings
from django.utils.translation import gettext_lazy as _
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from common.api import JMSModelViewSet
from orgs.mixins.api import OrgBulkModelViewSet
from orgs.models import Organization
from orgs.utils import current_org, tmp_to_org, tmp_to_root_org
from ..models import VaultConnection, VaultStorageRule
from ..serializers.vault_routing import VaultConnectionSerializer, VaultStorageRuleSerializer

__all__ = ['VaultConnectionViewSet', 'VaultStorageRuleViewSet']


class VaultConnectionViewSet(JMSModelViewSet):
    """ XPAM: the vaults XPAM may use (see accounts/models/vault_routing) """
    queryset = VaultConnection.objects.all()
    serializer_class = VaultConnectionSerializer
    filterset_fields = ('name', 'type', 'is_active', 'managed')
    search_fields = ('name', 'comment')
    rbac_perms = {
        'list': 'settings.view_setting',
        'retrieve': 'settings.view_setting',
        'create': 'settings.change_vault',
        'update': 'settings.change_vault',
        'partial_update': 'settings.change_vault',
        'destroy': 'settings.change_vault',
        'test': 'settings.change_vault',
        'move': 'settings.change_vault',
    }

    def perform_destroy(self, instance):
        if settings.VAULT_LOCKED or instance.managed:
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied(_('This connection is managed on the XPAM server'))
        super().perform_destroy(instance)

    @action(methods=['post'], detail=True, url_path='test')
    def test(self, request, *args, **kwargs):
        from accounts.backends import get_vault_client
        connection = self.get_object()
        try:
            ok, error = get_vault_client(raise_exception=True, **connection.backend_kwargs()).is_active()
        except Exception as e:
            ok, error = False, str(e)
        if ok:
            return Response({'msg': _('Test success')})
        return Response({'msg': error}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['post'], detail=False, url_path='move')
    def move(self, request, *args, **kwargs):
        """ apply the storage rules now: every secret goes to the vault its rules give """
        from ..tasks.vault_routing import move_secrets_by_rules
        task = move_secrets_by_rules.delay()
        return Response({'task': task.id}, status=status.HTTP_201_CREATED)


class VaultStorageRuleViewSet(OrgBulkModelViewSet):
    """
    XPAM: which vault keeps which secrets (per organization).
    System settings run in the System organization: there the rules of every organization are listed, and each
    is created (org_id), changed and deleted in its own organization.
    """
    model = VaultStorageRule
    serializer_class = VaultStorageRuleSerializer
    filterset_fields = ('name', 'is_active', 'org_id')
    search_fields = ('name', 'username', 'comment')
    ordering = ('priority', 'name')
    rbac_perms = {
        'list': 'settings.view_setting',
        'retrieve': 'settings.view_setting',
        'create': 'settings.change_vault',
        'update': 'settings.change_vault',
        'partial_update': 'settings.change_vault',
        'destroy': 'settings.change_vault',
        'bulk_update': 'settings.change_vault',
        'partial_bulk_update': 'settings.change_vault',
        'bulk_destroy': 'settings.change_vault',
    }

    @staticmethod
    def all_orgs():
        return current_org.is_root() or current_org.is_system()

    def get_queryset(self):
        if self.all_orgs():
            with tmp_to_root_org():
                queryset = VaultStorageRule.objects.all()
        else:
            queryset = super().get_queryset()
        return queryset.select_related('connection', 'mirror').prefetch_related('nodes', 'platforms')

    @staticmethod
    def target_org(data):
        items = data if isinstance(data, list) else [data]
        org_ids = {str((item.get('org_id') if isinstance(item, dict) else '') or '') for item in items}
        org = Organization.get_instance(org_ids.pop()) if len(org_ids) == 1 else None
        if org is None or org.is_root() or org.is_system():
            raise ValidationError({'org_id': _('Choose the organization the rule is for')})
        return org

    def create(self, request, *args, **kwargs):
        if not self.all_orgs():
            return super().create(request, *args, **kwargs)
        with tmp_to_org(self.target_org(request.data)):
            return super().create(request, *args, **kwargs)

    def bulk_update(self, request, *args, **kwargs):
        # (from System settings each rule is saved in its own organization: one at a time — a bulk save there
        # would move the rules into the System organization)
        if self.all_orgs():
            raise ValidationError(_('Change rules one at a time from System settings'))
        return super().bulk_update(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        if not self.all_orgs():
            return super().update(request, *args, **kwargs)
        with tmp_to_org(self.get_object().org_id):
            return super().update(request, *args, **kwargs)

    def perform_destroy(self, instance):
        with tmp_to_org(instance.org_id):
            super().perform_destroy(instance)

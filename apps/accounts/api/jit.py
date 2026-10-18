from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from rest_framework.decorators import action
from rest_framework.response import Response

from rest_framework import mixins

from orgs.mixins.api import OrgBulkModelViewSet, OrgGenericViewSet
from ..models import JITPolicy, JITAccount
from ..serializers.jit import JITPolicySerializer, JITAccountSerializer

__all__ = ['JITPolicyViewSet', 'JITAccountViewSet']


class JITPolicyViewSet(OrgBulkModelViewSet):
    model = JITPolicy
    serializer_class = JITPolicySerializer
    filterset_fields = ('name', 'mode', 'username_mode', 'is_active')
    search_fields = ('name', 'comment')
    ordering = ('name',)

    def get_queryset(self):
        qs = super().get_queryset()
        # The permission form only offers policies that are attached to permissions
        if self.request.query_params.get('for_permission'):
            qs = qs.exclude(mode=JITPolicy.Mode.approved_window)
        return qs


class JITAccountViewSet(mixins.ListModelMixin, mixins.RetrieveModelMixin, OrgGenericViewSet):
    # Read-only records; the only change is the "remove now" action below
    model = JITAccount
    serializer_class = JITAccountSerializer
    filterset_fields = ('status', 'mode', 'policy', 'user', 'asset', 'username')
    search_fields = ('username', 'user_display', 'asset_display')
    ordering = ('-date_created',)
    rbac_perms = {
        'remove': 'accounts.delete_jitaccount',
    }

    def get_queryset(self):
        qs = super().get_queryset().select_related('policy')
        state = self.request.query_params.get('state')
        if state == 'live':
            qs = qs.filter(status__in=JITAccount.ACTIVE_STATUSES)
        elif state == 'history':
            qs = qs.filter(Q(status=JITAccount.Status.removed) | Q(status=JITAccount.Status.failed))
        return qs

    @action(methods=['post'], detail=True, url_path='remove')
    def remove(self, request, *args, **kwargs):
        from ..tasks.jit import jit_release_task
        jit = self.get_object()
        if jit.status == JITAccount.Status.removed:
            return Response({'msg': _('Already removed')})
        jit_release_task.delay(str(jit.id), reason=str(_('Removed by %s') % request.user))
        return Response({'msg': _('The account is being removed from the asset')})

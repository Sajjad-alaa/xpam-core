from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from rest_framework.decorators import action
from rest_framework.response import Response

from rest_framework import mixins

from common.utils import is_uuid
from orgs.mixins.api import OrgBulkModelViewSet, OrgGenericViewSet
from ..models import JITPolicy, JITAccount
from ..serializers.jit import JITPolicySerializer, JITAccountSerializer

__all__ = ['JITPolicyViewSet', 'JITAccountViewSet']


class JITPolicyViewSet(OrgBulkModelViewSet):
    model = JITPolicy
    serializer_class = JITPolicySerializer
    filterset_fields = ('name', 'mode', 'username_mode', 'scope', 'is_active')
    search_fields = ('name', 'comment')
    ordering = ('priority', 'name')

    rbac_perms = {
        'match': 'accounts.view_jitpolicy',
    }

    def get_queryset(self):
        qs = super().get_queryset()
        # The permission form only offers policies that are attached to permissions
        if self.request.query_params.get('for_permission'):
            qs = qs.exclude(mode=JITPolicy.Mode.approved_window)
        return qs

    @action(methods=['get'], detail=False, url_path='match')
    def match(self, request, *args, **kwargs):
        """
        Which policy applies to a user on assets.
        ?user=<id> (or ticket=<access request id>)&assets=<id,id>&nodes=<id,id>[&request=1]
        request=1: as if an access request for these assets/nodes were approved now.
        """
        from assets.models import Asset, Node
        from users.models import User
        from ..jit.policy import PolicyMatcher, explain
        limit = 50
        params = request.query_params
        split = lambda name: [i for i in (params.get(name) or '').split(',') if i.strip()]  # noqa: E731
        user = None
        if params.get('ticket') and is_uuid(params['ticket']):
            # the approval screen: the applicant of the request
            from tickets.models import ApplyAssetTicket
            from orgs.utils import tmp_to_root_org
            with tmp_to_root_org():
                ticket = ApplyAssetTicket.objects.filter(id=params['ticket']).select_related('applicant').first()
            user = ticket.applicant if ticket else None
        elif params.get('user') and is_uuid(params['user']):
            user = User.objects.filter(id=params['user']).first()
        if not user:
            return Response({'error': _('Choose a user')}, status=400)
        asset_ids = [i for i in split('assets') if is_uuid(i)]
        assets = list(Asset.objects.filter(id__in=asset_ids).select_related('platform')[:limit])
        for node in Node.objects.filter(id__in=[i for i in split('nodes') if is_uuid(i)]):
            if len(assets) >= limit:
                break
            known = {a.id for a in assets}
            extra = node.get_all_assets().exclude(id__in=known).select_related('platform')
            assets.extend(extra[:limit - len(assets)])
        if not assets:
            return Response({'error': _('Choose an asset or a node')}, status=400)
        matcher = PolicyMatcher()
        is_request = params.get('request') in ('1', 'true')
        results = [explain(user, asset, request=is_request, matcher=matcher) for asset in assets]
        return Response({'results': results, 'limited': len(assets) >= limit})


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

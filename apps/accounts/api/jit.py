from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from rest_framework.decorators import action
from rest_framework.response import Response

from rest_framework import mixins, viewsets

from rbac.permissions import RBACPermission

from common.utils import is_uuid
from orgs.mixins.api import OrgBulkModelViewSet, OrgGenericViewSet
from ..models import JITPolicy, JITAccount
from ..serializers.jit import JITPolicySerializer, JITAccountSerializer

__all__ = ['JITPolicyViewSet', 'JITAccountViewSet', 'JITDashboardViewSet', 'JITApprovalChannelsViewSet']


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
        'trail': 'accounts.view_jitaccount',
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

    @action(methods=['get'], detail=True, url_path='trail')
    def trail(self, request, *args, **kwargs):
        from ..jit.insights import trail
        jit = self.get_object()
        return Response({'id': str(jit.id), 'username': jit.username, 'asset': jit.asset_display,
                         'user': jit.user_display, 'events': trail(jit)})


class JITDashboardViewSet(viewsets.ViewSet):
    """Zero standing privilege overview of the current organization."""
    permission_classes = (RBACPermission,)
    rbac_perms = {
        'list': 'accounts.view_jitaccount',
        'convert': 'perms.change_assetpermission',
    }

    def list(self, request):
        from django.core.cache import cache
        from orgs.utils import current_org
        from ..jit.insights import dashboard
        key = f'xpam-jit-dashboard:{current_org.id}'
        data = None if request.query_params.get('refresh') else cache.get(key)
        if data is None:
            data = dashboard()
            cache.set(key, data, 60)
        return Response(data)

    @action(methods=['post'], detail=False)
    def convert(self, request):
        """Take the standing accounts out of a permission; its users keep access just-in-time."""
        from django.core.cache import cache
        from orgs.utils import current_org
        from perms.models import AssetPermission
        from ..jit.insights import convert_to_jit, coverage_after_convert
        from common.utils import is_uuid
        perm_id = request.data.get('permission')
        perm = AssetPermission.objects.filter(id=perm_id).first() if is_uuid(perm_id) else None
        if not perm:
            return Response({'detail': _('Permission not found')}, status=404)
        policy = coverage_after_convert(perm)
        if not policy and not request.data.get('force'):
            return Response({'detail': _('No just-in-time policy covers the users and assets of this '
                                         'permission; create one first or they lose access'),
                             'code': 'no_policy'}, status=400)
        removed = convert_to_jit(perm, request.user)
        cache.delete(f'xpam-jit-dashboard:{current_org.id}')
        return Response({'removed_accounts': removed, 'policy': policy.name if policy else None})


class JITApprovalChannelsViewSet(viewsets.ViewSet):
    """Where approval requests are sent besides e-mail: Teams, Slack, Telegram. Secrets are never returned."""
    permission_classes = (RBACPermission,)
    rbac_perms = {
        'list': 'accounts.view_jitpolicy',
        # system-wide settings (webhooks, direct approval): system ticket settings permission, never an
        # org-level one (an org admin must not receive every org's approval requests)
        'save': 'settings.change_ticket',
        'test': 'settings.change_ticket',
    }

    @staticmethod
    def _public(config):
        from django.conf import settings as dj_settings
        from settings.models import Setting
        direct = Setting.objects.filter(name='TICKETS_DIRECT_APPROVE').first()
        return {
            'teams_webhook_set': bool(config.get('teams_webhook')),
            'slack_webhook_set': bool(config.get('slack_webhook')),
            'telegram_token_set': bool(config.get('telegram_token')),
            'telegram_chat': config.get('telegram_chat') or '',
            'link_hours': config.get('link_hours'),
            'remind_minutes': config.get('remind_minutes'),
            'escalate_minutes': config.get('escalate_minutes'),
            'expire_hours': config.get('expire_hours'),
            'direct_approve': bool(direct.cleaned_value) if direct else bool(dj_settings.TICKETS_DIRECT_APPROVE),
            'site_url': dj_settings.SITE_URL,
        }

    def list(self, request):
        from tickets.channels import get_config
        return Response(self._public(get_config()))

    @staticmethod
    def _incoming(data, current):
        """Values to store: an empty secret field keeps the stored one, "-" clears it."""
        out = {}
        for key in ('teams_webhook', 'slack_webhook', 'telegram_token'):
            value = (data.get(key) or '').strip()
            if value == '-':
                out[key] = ''
            elif value:
                if key != 'telegram_token' and not value.startswith('https://'):
                    raise ValueError(_('The webhook address must start with https://'))
                out[key] = value
        if 'telegram_chat' in data:
            out['telegram_chat'] = str(data.get('telegram_chat') or '').strip()[:64]
        for key in ('link_hours', 'remind_minutes', 'escalate_minutes', 'expire_hours'):
            if data.get(key) not in (None, ''):
                out[key] = int(data[key])
        merged = dict(current)
        merged.update(out)
        return out, merged

    @action(methods=['post'], detail=False)
    def save(self, request):
        from settings.models import Setting
        from tickets.channels import get_config, save_config
        try:
            out, _merged = self._incoming(request.data, get_config())
        except (ValueError, TypeError) as e:
            return Response({'detail': str(e)}, status=400)
        save_config(out)
        if 'direct_approve' in request.data:
            Setting.update_or_create(name='TICKETS_DIRECT_APPROVE', value=bool(request.data.get('direct_approve')),
                                     encrypted=False, category='ticket')
        return Response(self._public(get_config()))

    @action(methods=['post'], detail=False)
    def test(self, request):
        """Send a test message with the values in the form (or the stored ones)."""
        from tickets.channels import get_config, send_test
        try:
            _out, merged = self._incoming(request.data, get_config())
        except (ValueError, TypeError) as e:
            return Response({'detail': str(e)}, status=400)
        results = send_test(merged)
        if not results:
            return Response({'detail': _('No channel is set up')}, status=400)
        return Response({k: {'ok': ok, 'error': msg} for k, (ok, msg) in results.items()})

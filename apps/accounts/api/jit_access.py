"""XPAM self-service just-in-time access for every signed-in user (the workspace "Access" page)."""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from ..jit import approvals, selfservice
from .jit import JITTicketRequiredMixin

__all__ = ['JITAccessViewSet']


def _ticket_brief(ticket):
    return {
        'id': str(ticket.id), 'serial_num': ticket.serial_num, 'title': ticket.title,
        'state': ticket.state, 'status': ticket.status, 'approved_automatically_by': ticket.apply_jit_auto,
        'date_start': ticket.apply_date_start, 'date_expired': ticket.apply_date_expired,
    }


class JITAccessViewSet(JITTicketRequiredMixin, viewsets.ViewSet):
    """
    GET  /accounts/jit-access/                  the user's access, pending requests and live accounts
    GET  /accounts/jit-access/requestable/      assets the user may request (?search=)
    POST /accounts/jit-access/request/          {assets: [id], hours, reason, protocols: [name], actions: [name]}
    POST /accounts/jit-access/<grant>/extend/   {hours, reason}
    POST /accounts/jit-access/<grant>/end/      end the access now
    POST /accounts/jit-access/<request>/cancel/ cancel a pending request
    """
    permission_classes = (IsAuthenticated,)

    def list(self, request):
        return Response(selfservice.my_access(request.user))

    @action(methods=['get'], detail=False)
    def requestable(self, request):
        search = (request.query_params.get('search') or '').strip()[:128]
        items = selfservice.requestable_assets(request.user, search=search, limit=50)
        return Response([{
            'id': str(a.id), 'name': a.name, 'address': a.address, 'org_id': str(a.org_id),
            'org_name': str(a.org_name) if hasattr(a, 'org_name') else '',
            'type': a.platform.type, 'category': a.platform.category, 'platform': a.platform.name,
            'policy': {'id': str(p.id), 'name': p.name, 'max_hours': p.max_hours,
                       'auto_approve': p.auto_approve and p.approvals_required < 2 and p.in_auto_approve_window(),
                       'auto_approve_max_hours': p.auto_approve_max_hours,
                       'require_reason': p.require_reason, 'privileged': p.privileged,
                       'mode': p.mode, 'mode_display': str(p.get_mode_display())},
            # XPAM: the protocols and actions a request for this asset may choose
            'options': selfservice.request_options(a, p),
        } for a, p in items])

    @action(methods=['post'], detail=False)
    def preview(self, request):
        """ XPAM: before sending — approved at once, or who approves it and why it waits """
        from django.utils.dateparse import parse_datetime
        data = request.data

        def when(name):
            from django.utils import timezone
            try:
                value = parse_datetime(str(data.get(name) or ''))
            except ValueError:
                return None
            if value and timezone.is_naive(value):
                value = timezone.make_aware(value)
            return value
        start, end = when('date_start'), when('date_expired')
        accounts = data.get('accounts')
        protocols = data.get('protocols')
        actions = data.get('actions')
        assets = data.get('assets')
        nodes = data.get('nodes')
        return Response(selfservice.preview(
            request.user, list(assets) if isinstance(assets, (list, tuple)) else [], data.get('hours'),
            reason=str(data.get('reason') or ''),
            node_ids=list(nodes) if isinstance(nodes, (list, tuple)) else [], start=start, end=end,
            accounts=[str(a) for a in accounts] if isinstance(accounts, list) else None,
            flow_id=data.get('flow_id'),
            protocols=[str(p) for p in protocols] if isinstance(protocols, list) else None,
            actions=actions if isinstance(actions, (int, list)) else None))

    @action(methods=['post'], detail=False, url_path='request')
    def submit(self, request):
        data = request.data
        try:
            ticket = selfservice.submit(request, data.get('assets') or [], data.get('hours'),
                                        reason=data.get('reason') or '',
                                        protocols=data.get('protocols') or [], actions=data.get('actions') or [])
        except selfservice.SelfServiceError as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(_ticket_brief(ticket), status=status.HTTP_201_CREATED)

    @action(methods=['post'], detail=True)
    def extend(self, request, pk=None):
        try:
            ticket = selfservice.extend(request, pk, request.data.get('hours'), request.data.get('reason') or '')
        except selfservice.SelfServiceError as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(_ticket_brief(ticket), status=status.HTTP_201_CREATED)

    @action(methods=['post'], detail=True)
    def end(self, request, pk=None):
        try:
            selfservice.end_now(request.user, pk)
        except selfservice.SelfServiceError as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'ok': True})

    @action(methods=['post'], detail=True)
    def cancel(self, request, pk=None):
        try:
            selfservice.cancel(request.user, pk)
        except selfservice.SelfServiceError as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'ok': True})

    @action(methods=['get'], detail=False)
    def approvals(self, request):
        """Requests waiting for the current user's approval."""
        return Response(approvals.pending_for(request.user))

    @action(methods=['post'], detail=True)
    def approve(self, request, pk=None):
        return self._decide(request, pk, 'approve')

    @action(methods=['post'], detail=True)
    def reject(self, request, pk=None):
        return self._decide(request, pk, 'reject')

    @staticmethod
    def _decide(request, pk, act):
        try:
            ticket = approvals.decide(request.user, pk, act, request.data.get('comment') or '')
        except approvals.ApprovalError as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(_ticket_brief(ticket))

    @action(methods=['get'], detail=False)
    def coverage(self, request):
        """For the request form: which chosen assets get a just-in-time account."""
        split = lambda name: [i for i in (request.query_params.get(name) or '').split(',') if i.strip()]  # noqa
        return Response(selfservice.coverage(request.user, split('assets'), split('nodes')))

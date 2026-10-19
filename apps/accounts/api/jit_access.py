"""XPAM self-service just-in-time access for every signed-in user (the workspace "Access" page)."""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from ..jit import approvals, selfservice

__all__ = ['JITAccessViewSet']


def _ticket_brief(ticket):
    return {
        'id': str(ticket.id), 'serial_num': ticket.serial_num, 'title': ticket.title,
        'state': ticket.state, 'status': ticket.status, 'approved_automatically_by': ticket.apply_jit_auto,
        'date_start': ticket.apply_date_start, 'date_expired': ticket.apply_date_expired,
    }


class JITAccessViewSet(viewsets.ViewSet):
    """
    GET  /accounts/jit-access/                  the user's access, pending requests and live accounts
    GET  /accounts/jit-access/requestable/      assets the user may request (?search=)
    POST /accounts/jit-access/request/          {assets: [id], hours, reason}
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
        } for a, p in items])

    @action(methods=['post'], detail=False, url_path='request')
    def submit(self, request):
        data = request.data
        try:
            ticket = selfservice.submit(request, data.get('assets') or [], data.get('hours'),
                                        reason=data.get('reason') or '')
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

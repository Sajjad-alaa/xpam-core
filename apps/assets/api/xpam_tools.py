"""XPAM: bulk add, platform detection of network devices, and the assets that need attention."""
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response

from rbac.permissions import RBACPermission
from .. import xpam_tools

__all__ = ['AssetToolsViewSet']


class AssetToolsViewSet(viewsets.ViewSet):
    """
    POST /assets/tools/bulk-add/         {platform, lines, nodes: [id], account: {username, secret, privileged}, db_name}
    POST /assets/tools/detect-platform/  {assets: [id]}
    GET  /assets/tools/attention/
    """
    permission_classes = (RBACPermission,)
    rbac_perms = {
        'bulk_add': 'assets.add_asset',
        'detect_platform': 'assets.change_asset',
        'attention': 'assets.view_asset',
    }

    @action(methods=['post'], detail=False, url_path='bulk-add')
    def bulk_add(self, request):
        data = request.data
        try:
            result = xpam_tools.bulk_add(request, data.get('platform'), data.get('lines') or '',
                                         data.get('nodes') or [], data.get('account') or None,
                                         db_name=data.get('db_name') or '')
        except xpam_tools.ToolError as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(result)

    @action(methods=['post'], detail=False, url_path='detect-platform')
    def detect_platform(self, request):
        try:
            return Response(xpam_tools.detect_platforms(request.data.get('assets') or []))
        except xpam_tools.ToolError as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @action(methods=['get'], detail=False)
    def attention(self, request):
        return Response(xpam_tools.attention())

from django.conf import settings

from assets.models import Asset, Node
from assets.serializers.asset.common import MiniAssetSerializer
from assets.serializers.node import NodeSerializer
from common.api import SuggestionMixin
from orgs.mixins.api import OrgReadonlyModelViewSet
from orgs.utils import current_org
from perms.utils import AssetPermissionPermAssetUtil
from perms.utils.permission import AssetPermissionUtil
from tickets.const import TicketApplyAssetScope

__all__ = ['ApplyAssetsViewSet', 'ApplyNodesViewSet']


def own_orgs_only(user, queryset):
    """ XPAM: "all organizations" (root) lists what may be requested in the user's own organizations, not in every
    organization of the system (unless the user sees them all) """
    if current_org.is_root() and not user.has_perm('orgs.view_rootorg'):
        queryset = queryset.filter(org_id__in=list(user.orgs.values_list('id', flat=True)))
    return queryset


class ApplyAssetsViewSet(OrgReadonlyModelViewSet, SuggestionMixin):
    model = Asset
    serializer_class = MiniAssetSerializer
    rbac_perms = (
        ("match", "assets.match_asset"),
    )

    search_fields = ("name", "address", "comment")

    def get_queryset(self):
        if TicketApplyAssetScope.is_permed():
            queryset = self.get_assets(with_expired=True)
        elif TicketApplyAssetScope.is_permed_valid():
            queryset = self.get_assets()
        else:
            queryset = own_orgs_only(self.request.user, super().get_queryset())
        return queryset

    def get_assets(self, with_expired=False):
        perms = AssetPermissionUtil().get_permissions_for_user(
            self.request.user, flat=True, with_expired=with_expired
        )
        util = AssetPermissionPermAssetUtil(perms)
        assets = util.get_all_assets()
        return assets


class ApplyNodesViewSet(OrgReadonlyModelViewSet, SuggestionMixin):
    model = Node
    serializer_class = NodeSerializer
    rbac_perms = (
        ("match", "assets.match_node"),
    )

    search_fields = ('full_value',)

    def get_queryset(self):
        if TicketApplyAssetScope.is_permed():
            queryset = self.get_nodes(with_expired=True)
        elif TicketApplyAssetScope.is_permed_valid():
            queryset = self.get_nodes()
        else:
            queryset = own_orgs_only(self.request.user, super().get_queryset())
        return queryset.with_realtime_assets_amount()

    def get_nodes(self, with_expired=False):
        perms = AssetPermissionUtil().get_permissions_for_user(
            self.request.user, flat=True, with_expired=with_expired
        )
        util = AssetPermissionPermAssetUtil(perms)
        nodes = util.get_perm_nodes()
        return nodes

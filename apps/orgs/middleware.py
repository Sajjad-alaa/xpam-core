# -*- coding: utf-8 -*-
#

from .utils import get_org_from_request, set_current_org
from rbac.models import RoleBinding


class OrgMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    @staticmethod
    def set_permed_org_if_need(request):
        if request.path.startswith('/api'):
            return
        if not request.user.is_authenticated:
            return

        org = get_org_from_request(request)

        search_org = None if org.is_root() else org
        has_roles = RoleBinding.objects.filter(user=request.user, org=search_org).exists()
        if has_roles:
            return

        roles_bindings = RoleBinding.objects.filter(user=request.user).exclude(org=None)
        if roles_bindings:
            org_id = str(list(roles_bindings.values_list('org_id', flat=True))[0])
            request.session['oid'] = org_id

    @staticmethod
    def usable_org(request, org):
        """ XPAM: an API request works in an organization the user is a member of. The org comes from the request
        (?oid=, X-JMS-ORG, cookie, session) and was not checked: a view without role checks then showed another
        organization's data to any user. "All organizations" (root) stays: the workbench uses it for the user's own
        organizations, and role checks there only grant system-level permissions. Users with a system-level role
        (administrators, auditors) and service accounts keep their choice. (No permission is computed here: the
        thread's current organization is not set yet.) """
        user = request.user
        if not request.path.startswith('/api') or not user.is_authenticated or user.is_service_account:
            return org
        if org.is_root() or (org.internal and not org.is_default()):
            return org
        from rbac.builtin import BuiltinRole
        bindings = list(RoleBinding._base_manager.filter(user=user).values_list('scope', 'role_id', 'org_id'))
        if any(scope == 'system' and str(role_id) != str(BuiltinRole.system_user.id) for scope, role_id, _ in bindings):
            return org
        member_org_ids = [str(org_id) for scope, _, org_id in bindings if scope == 'org' and org_id]
        if str(org.id) in member_org_ids:
            return org
        from .models import Organization
        fallback = Organization.get_instance(member_org_ids[0]) if member_org_ids else None
        return fallback or Organization.default()

    def __call__(self, request):
        self.set_permed_org_if_need(request)
        org = self.usable_org(request, get_org_from_request(request))
        request.current_org = org
        set_current_org(org)
        response = self.get_response(request)
        return response

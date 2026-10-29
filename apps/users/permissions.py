from rest_framework import permissions



class UserObjectPermission(permissions.IsAuthenticated):

    def has_object_permission(self, request, view, obj):
        if view.action not in ['update', 'partial_update', 'destroy']:
            return True

        if not request.user.is_superuser and obj.is_superuser:
            return False

        return True

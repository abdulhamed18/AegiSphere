from rest_framework import permissions

class HasValidApiKey(permissions.BasePermission):
    """
    Ensures the request has a valid API key and an associated workspace.
    """
    def has_permission(self, request, view):
        api_key = getattr(request, 'api_key', None)
        workspace = getattr(request, 'workspace', None)
        
        if not api_key or not workspace:
            return False
            
        return api_key.is_active

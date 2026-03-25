from rest_framework.throttling import SimpleRateThrottle
from .utils import log_api_security_event

class ApiKeyRateThrottle(SimpleRateThrottle):
    """
    Limits API requests per API key.
    Defaults to 100 requests per minute if not set in settings.
    """
    scope = 'api_key'

    def get_cache_key(self, request, view):
        api_key = getattr(request, 'api_key', None)
        if api_key and hasattr(api_key, 'public_id'):
            return self.cache_format % {
                'scope': self.scope,
                'ident': api_key.public_id
            }
        return None

    def allow_request(self, request, view):
        # We need to compute if the request is allowed first
        allowed = super().allow_request(request, view)
        
        if not allowed:
            api_key = getattr(request, 'api_key', None)
            workspace = getattr(request, 'workspace', None)
            public_id = api_key.public_id if api_key else None
            log_api_security_event(workspace, public_id, request, "API_RATE_LIMIT_EXCEEDED")
            
        return allowed


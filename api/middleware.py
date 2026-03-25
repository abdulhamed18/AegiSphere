from django.http import HttpResponseForbidden
from .utils import log_api_security_event

class LargeRequestMiddleware:
    """
    Middleware to block requests with bodies larger than 2MB.
    Applies only to API endpoints.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.max_body_size = 2 * 1024 * 1024  # 2MB

    def __call__(self, request):
        if request.path.startswith('/api/'):
            content_length = request.META.get('CONTENT_LENGTH')
            if content_length:
                try:
                    length = int(content_length)
                    if length > self.max_body_size:
                        # Attempt to get workspace/api_key if available (unlikely before authentication, 
                        # but we log what we have)
                        log_api_security_event(
                            getattr(request, 'workspace', None), 
                            getattr(request.api_key, 'public_id', None) if hasattr(request, 'api_key') else None, 
                            request, 
                            "API_REQUEST_TOO_LARGE"
                        )
                        return HttpResponseForbidden('Request body too large. Maximum size is 2MB.')
                except (ValueError, TypeError):
                    pass
        
        return self.get_response(request)

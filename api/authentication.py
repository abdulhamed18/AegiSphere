import hashlib
import hmac
from rest_framework import authentication
from rest_framework import exceptions
from django.utils import timezone
from .models import ApiKey
from .utils import log_api_security_event

class ApiKeyAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header:
            return None # Authentication not attempting this scheme
            
        parts = auth_header.split()
        if parts[0].lower() != 'apikey':
            return None
            
        if len(parts) != 2:
            log_api_security_event(None, None, request, "API_KEY_AUTH_FAILED")
            raise exceptions.AuthenticationFailed('Invalid API key header format')
            
        raw_key = parts[1]
        
        # Expected format: PREFIX_public_id.secret
        if '.' not in raw_key:
            log_api_security_event(None, None, request, "API_KEY_AUTH_FAILED")
            raise exceptions.AuthenticationFailed('Invalid API key format')
            
        prefix_and_public_id, secret = raw_key.rsplit('.', 1)
        
        # public_id is after the last underscore
        if '_' not in prefix_and_public_id:
            log_api_security_event(None, None, request, "API_KEY_AUTH_FAILED")
            raise exceptions.AuthenticationFailed('Invalid API key prefix format')
            
        prefix = prefix_and_public_id.rsplit('_', 1)[0] + '_'
        public_id = prefix_and_public_id.rsplit('_', 1)[1]
        
        if prefix not in ['AGS_ORG_', 'AGS_USR_']:
            log_api_security_event(None, None, request, "API_KEY_AUTH_FAILED")
            raise exceptions.AuthenticationFailed('Invalid API key prefix format')
        
        try:
            api_key = ApiKey.objects.select_related('workspace').get(public_id=public_id, is_active=True)
        except ApiKey.DoesNotExist:
            log_api_security_event(None, public_id, request, "API_KEY_AUTH_FAILED")
            raise exceptions.AuthenticationFailed('Invalid or inactive API key')
            
        # Verify secret
        secret_hash = hashlib.sha256(secret.encode('utf-8')).hexdigest()
        if not hmac.compare_digest(secret_hash, api_key.secret_hash):
            log_api_security_event(api_key.workspace, public_id, request, "API_KEY_AUTH_FAILED")
            raise exceptions.AuthenticationFailed('Invalid API key secret')
            
        # Enforce Prefix / Workspace Consistency
        if prefix == 'AGS_ORG_' and api_key.workspace.workspace_type != 'organization':
            log_api_security_event(api_key.workspace, public_id, request, "API_KEY_AUTH_FAILED")
            raise exceptions.AuthenticationFailed('API key prefix does not match workspace type')
            
        if prefix == 'AGS_USR_' and api_key.workspace.workspace_type != 'personal':
            log_api_security_event(api_key.workspace, public_id, request, "API_KEY_AUTH_FAILED")
            raise exceptions.AuthenticationFailed('API key prefix does not match workspace type')
            
        # Authentication successful
        api_key.last_used_at = timezone.now()
        
        # Determine client IP: Priority HTTP_X_FORWARDED_FOR (first IP) then REMOTE_ADDR
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.META.get('REMOTE_ADDR')
            
        api_key.last_used_ip = client_ip
        api_key.usage_count += 1
        api_key.save(update_fields=['last_used_at', 'last_used_ip', 'usage_count'])
        
        request.workspace = api_key.workspace
        request.api_key = api_key
        
        log_api_security_event(api_key.workspace, public_id, request, "API_KEY_AUTH_SUCCESS")
        
        # We don't have a user, so we return None for the user and api_key for the auth
        # Or we can return a dummy user. DRF expects (user, auth).
        # We will return (None, api_key).
        return (None, api_key)

    def authenticate_header(self, request):
        return 'ApiKey'

import secrets
import hashlib
import string

def generate_api_key(workspace):
    """
    Generates a new API key for the given workspace.
    Returns (raw_key, public_id, secret_hash, prefix).
    """
    if workspace.workspace_type == 'organization':
        prefix = 'AGS_ORG'
    else:
        # Default to personal (AGS_USR) workspaces... No API allowed for demo workspaces, mentioned in @api/services.py
        prefix = 'AGS_USR'
        
    # Generate an 8-character public ID using lowercase alphanumeric characters
    public_id = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    
    # Generate a secure secret (16 bytes = 32 hex characters)
    secret = secrets.token_hex(16)
    
    # Format the raw key
    raw_key = f"{prefix}_{public_id}.{secret}"
    
    # Hash the secret
    secret_hash = hashlib.sha256(secret.encode('utf-8')).hexdigest()
    
    return raw_key, public_id, secret_hash, prefix


def get_client_ip(request):
    """Utility to get client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')

def log_api_security_event(workspace, api_key_public_id, request, event_str, event_count=None):
    """
    Log an API security event.
    Events: API_KEY_AUTH_SUCCESS, API_KEY_AUTH_FAILED, API_RATE_LIMIT_EXCEEDED, INGESTION_RECEIVED, INGESTION_STORED, INVALID_PAYLOAD
    Fields required: workspace, api_key_public_id, ip_address, endpoint, timestamp, event_count
    """
    import json
    import logging
    from django.utils import timezone
    
    logger = logging.getLogger("aegisphere.audit")
    
    payload = {
        "event": event_str,
        "workspace_id": getattr(workspace, 'pk', None) if workspace else None,
        "api_key_public_id": api_key_public_id,
        "ip_address": get_client_ip(request) if request else None,
        "endpoint": request.path if request else None,
        "timestamp": timezone.now().isoformat(),
    }
    
    if event_count is not None:
        payload["event_count"] = event_count
        
    logger.info(json.dumps(payload))



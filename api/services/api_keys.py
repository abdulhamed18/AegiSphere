import logging
from django.utils import timezone
import json
from django.db import transaction
from django.core.exceptions import PermissionDenied

from alerts.role_hierarchy import get_role_code
from api.models import ApiKey
from api.utils import generate_api_key

@transaction.atomic
def create_api_key(workspace, name, created_by):
    """
    Creates a new API key for the given workspace.
    Enforces RBAC:
      - Personal workspace: only PERSONAL_OWNER.
      - Organization workspace: ORG_OWNER or SOC_MANAGER.
    """
    if workspace.workspace_type == "demo":
        raise PermissionDenied("Demo workspaces cannot create API keys.")

    if not created_by or not created_by.is_authenticated:
        raise PermissionDenied("Authentication required to create API keys.")

    role_code = get_role_code(created_by, workspace)
    if not role_code:
        raise PermissionDenied("You are not a member of this workspace.")

    if workspace.workspace_type == 'personal':
        if role_code != 'PERSONAL_OWNER':
            raise PermissionDenied("Only the workspace owner can create API keys for personal workspaces.")
    else:
        # Organization workspaces
        if role_code not in ['ORG_OWNER', 'SOC_MANAGER']:
            raise PermissionDenied("Only owners and managers can create API keys for organization workspaces.")

    raw_key, public_id, secret_hash, prefix = generate_api_key(workspace)

    api_key = ApiKey.objects.create(
        workspace=workspace,
        name=name,
        key_prefix=prefix,
        public_id=public_id,
        secret_hash=secret_hash,
        created_by=created_by,
        is_active=True
    )

    logger = logging.getLogger("aegisphere.audit")
    payload = {
        "event": "API_KEY_CREATED",
        "workspace_id": workspace.pk,
        "api_key_public_id": public_id,
        "created_by": created_by.pk if created_by else None,
        "timestamp": timezone.now().isoformat()
    }
    logger.info(json.dumps(payload))

    return api_key, raw_key

@transaction.atomic
def revoke_api_key(api_key, revoked_by=None):
    """
    Revokes an existing API key.
    """
    api_key.is_active = False
    api_key.save(update_fields=['is_active'])

    logger = logging.getLogger("aegisphere.audit")
    payload = {
        "event": "API_KEY_REVOKED",
        "workspace_id": api_key.workspace_id,
        "api_key_public_id": api_key.public_id,
        "revoked_by": revoked_by.pk if revoked_by else None,
        "timestamp": timezone.now().isoformat()
    }
    logger.info(json.dumps(payload))

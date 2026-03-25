"""
Phase 3 – Step 4: Structured audit logging for governance actions.
JSON log format; does not break transaction.
"""

import json
import logging
from datetime import datetime
from uuid import UUID

from django.utils import timezone

AUDIT_LOGGER = logging.getLogger("aegisphere.audit")


def _normalize_value(v):
    """Normalize a single value for JSON. Wrapped in try/except; fallback to str."""
    try:
        if v is None or isinstance(v, (bool, int, float, str)):
            return v
        if isinstance(v, UUID):
            return str(v)
        if isinstance(v, datetime):
            return v.isoformat() if hasattr(v, "isoformat") else str(v)
        if hasattr(v, "pk"):
            return v.pk
        if isinstance(v, dict):
            return _normalize_metadata(v)
        if isinstance(v, (list, tuple)):
            return [_normalize_value(x) for x in v]
        return str(v)
    except Exception:
        return str(v)


def _normalize_metadata(data):
    """
    Convert metadata to JSON-safe dict. UUID→str, datetime→isoformat,
    model instances→pk. Recursive for dict/list. Never log raw model instances.
    """
    try:
        if data is None:
            return {}
        if not isinstance(data, dict):
            return {"_value": str(data)}
        return {k: _normalize_value(v) for k, v in data.items()}
    except Exception:
        return {"_raw": str(data)}


def log_governance_action(actor, workspace, action_type, target_user=None, metadata=None):
    """
    Log a governance action as structured JSON. Never raises; wrapped in try/except.
    action_type: NotificationEvent enum member or string.
    """
    try:
        event_str = getattr(action_type, "value", action_type) if action_type is not None else None
        actor_id = "SYSTEM" if actor is None else (getattr(actor, "pk", None) if actor else None)
        payload = {
            "event": event_str,
            "actor_id": actor_id,
            "workspace_id": getattr(workspace, "pk", None) if workspace else None,
            "target_user_id": getattr(target_user, "pk", None) if target_user else None,
            "timestamp": timezone.now().isoformat(),
            "metadata": _normalize_metadata(metadata) if metadata is not None else {},
        }
        AUDIT_LOGGER.info(json.dumps(payload))
    except Exception:
        AUDIT_LOGGER.exception("audit_log_failed")

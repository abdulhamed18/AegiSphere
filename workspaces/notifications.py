"""
Phase 3 – Step 4: Structured notification system for governance lifecycle.
Logs events; extension point for email/websocket.
"""

import json
import logging
from datetime import datetime
from enum import Enum
from uuid import UUID

from django.utils import timezone

from core.models import WorkspaceMembership

NOTIFICATION_LOGGER = logging.getLogger("aegisphere.notifications")
GOVERNANCE_ADMIN_ROLES = ("ORG_OWNER", "SOC_MANAGER")


class NotificationEvent(str, Enum):
    JOIN_REQUEST_SUBMITTED = "JOIN_REQUEST_SUBMITTED"
    JOIN_REQUEST_APPROVED = "JOIN_REQUEST_APPROVED"
    JOIN_REQUEST_REJECTED = "JOIN_REQUEST_REJECTED"
    JOIN_REQUEST_EXPIRED = "JOIN_REQUEST_EXPIRED"
    JOIN_REQUEST_WITHDRAWN = "JOIN_REQUEST_WITHDRAWN"
    INVITE_CREATED = "INVITE_CREATED"
    INVITE_ACCEPTED = "INVITE_ACCEPTED"
    USER_BLOCKED = "USER_BLOCKED"
    USER_UNBLOCKED = "USER_UNBLOCKED"
    ROLE_CHANGED = "ROLE_CHANGED"
    USER_LEFT_WORKSPACE = "USER_LEFT_WORKSPACE"
    SYSTEM_EXPIRE_JOIN_REQUESTS = "SYSTEM_EXPIRE_JOIN_REQUESTS"


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


def notify_users(event_type, workspace, recipients, metadata=None):
    """
    Notify a set of users. Logs event; does not fail main transaction.
    recipients: queryset or list of user objects.
    """
    try:
        event_str = event_type.value if isinstance(event_type, NotificationEvent) else str(event_type)
        safe_meta = _normalize_metadata(metadata) if metadata is not None else {}
        workspace_id = getattr(workspace, "pk", None) if workspace else None
        recipient_ids = []
        if hasattr(recipients, "__iter__") and not hasattr(recipients, "query"):
            for u in recipients:
                recipient_ids.append(getattr(u, "pk", None))
        elif hasattr(recipients, "values_list"):
            recipient_ids = list(recipients.values_list("pk", flat=True)[:1000])
        else:
            for u in list(recipients)[:1000]:
                recipient_ids.append(getattr(u, "pk", None))
        payload = {
            "event": event_str,
            "workspace_id": workspace_id,
            "recipient_ids": recipient_ids,
            "timestamp": timezone.now().isoformat(),
            "metadata": safe_meta,
        }
        NOTIFICATION_LOGGER.info(json.dumps(payload))
    except Exception:
        NOTIFICATION_LOGGER.exception("notification_delivery_failed")


def notify_workspace_admins(event_type, workspace, metadata=None):
    """Notify ORG_OWNER and SOC_MANAGER members of the workspace. Active memberships only."""
    try:
        if not workspace:
            return
        recipients = WorkspaceMembership.objects.filter(
            workspace=workspace,
            is_active=True,
            role__code__in=GOVERNANCE_ADMIN_ROLES,
        ).select_related("user").values_list("user", flat=True).distinct()
        from django.contrib.auth import get_user_model
        User = get_user_model()
        users = list(User.objects.filter(pk__in=recipients)[:500])
        if users:
            notify_users(event_type, workspace, users, metadata=metadata)
    except Exception:
        NOTIFICATION_LOGGER.exception("notify_workspace_admins_failed")


def notify_user(event_type, workspace, user, metadata=None):
    """Notify a single user. Does not fail caller."""
    try:
        if not user:
            return
        notify_users(event_type, workspace, [user], metadata=metadata)
    except Exception:
        NOTIFICATION_LOGGER.exception("notify_user_failed")

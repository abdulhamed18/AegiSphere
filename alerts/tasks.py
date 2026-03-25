"""
Background-safe operational tasks. Callable functions; no Celery.

SLA breach detection (read-only), auto-unlock of expired locks (via service layer),
and 15-day recycle-bin permanent delete (service-layer only; no direct model delete).
"""

from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from alerts.enums import AlertStatus
from alerts.lock_utils import LOCK_TIMEOUT_MINUTES
from alerts.models import Alert
from alerts.role_hierarchy import get_role_code, is_manager
from alerts.services import permanently_delete_alert, unlock_alert


def check_sla_breaches():
    """
    Detect overdue alerts per workspace. Single query per workspace to enforce tenant isolation.
    Returns {workspace_id: [alert_id, ...]}.
    """
    now = timezone.now()
    from core.models import Workspace
    result = {}
    for workspace in Workspace.objects.all():
        rows = (
            Alert.objects.filter(workspace=workspace, sla_deadline__lt=now)
            .exclude(status__in=[AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE])
            .values_list("id", flat=True)
        )
        if rows:
            result[workspace.id] = list(rows)
    return result


def auto_unlock_expired_locks(system_user):
    """
    Unlock alerts whose lock has expired. Only in workspaces where system_user is manager.
    Mutations via unlock_alert(..., force=True) inside service layer.
    """
    if system_user is None or not system_user.is_authenticated:
        return
    threshold = timezone.now() - timedelta(minutes=LOCK_TIMEOUT_MINUTES)
    from core.models import Workspace
    
    for workspace in Workspace.objects.all():
        role = get_role_code(system_user, workspace)
        if not is_manager(role):
            continue
            
        expired_locked = (
            Alert.objects.filter(
                workspace=workspace,
                locked_by_id__isnull=False,
                locked_at__lt=threshold,
            )
            .select_related("locked_by")
            .order_by("id")
        )
        for alert in expired_locked:
            with transaction.atomic():
                unlock_alert(alert=alert, user=system_user, force=True)


def permanently_delete_expired_alerts(system_user):
    """
    Permanently delete alerts that have been soft-deleted for more than 15 days.
    Only processes alerts in workspaces where system_user is manager. No cross-workspace
    deletion; each alert is deleted via permanently_delete_alert() (service layer only).
    """
    if system_user is None or not system_user.is_authenticated:
        return
    threshold = timezone.now() - timedelta(days=15)
    from core.models import Workspace
    
    for workspace in Workspace.objects.all():
        role = get_role_code(system_user, workspace)
        if not is_manager(role):
            continue
            
        expired_deleted = (
            Alert.objects.filter(
                workspace=workspace,
                is_deleted=True,
                deleted_at__lt=threshold,
            )
            .order_by("id")
        )
        for alert in expired_deleted:
            with transaction.atomic():
                permanently_delete_alert(alert=alert, user=system_user)

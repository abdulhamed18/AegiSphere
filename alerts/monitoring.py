"""
Operational evaluation helpers. Aggregations only; no mutations.
"""

from datetime import timedelta

from django.db.models import Avg, ExpressionWrapper, F, Max
from django.db.models import DurationField
from django.utils import timezone

from alerts.enums import AlertStatus
from alerts.lock_utils import LOCK_TIMEOUT_MINUTES, is_lock_expired
from alerts.models import Alert, AlertSuppressionRule


def get_workspace_sla_summary(workspace):
    """
    Return total_alerts, overdue count, resolved_today count, avg_resolution_time.
    Uses aggregation; no mutation.
    """
    if workspace is None:
        return {
            "total_alerts": 0,
            "overdue": 0,
            "resolved_today": 0,
            "avg_resolution_time": None,
        }
    now = timezone.now()
    today = now.date()
    final_statuses = [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]

    total_alerts = Alert.objects.filter(workspace=workspace).count()

    overdue = (
        Alert.objects.filter(workspace=workspace, sla_deadline__lt=now)
        .exclude(status__in=final_statuses)
        .count()
    )

    resolved_today = (
        Alert.objects.filter(
            workspace=workspace,
            status__in=final_statuses,
            resolved_at__date=today,
        ).count()
    )

    try:
        avg_result = (
            Alert.objects.filter(
                workspace=workspace,
                status__in=final_statuses,
                resolved_at__isnull=False,
            )
            .aggregate(
                avg=Avg(
                    ExpressionWrapper(
                        F("resolved_at") - F("created_at"),
                        output_field=DurationField(),
                    )
                )
            )
        )
        avg_resolution_time = avg_result.get("avg")
    except (TypeError, Exception):
        rows = (
            Alert.objects.filter(
                workspace=workspace,
                status__in=final_statuses,
                resolved_at__isnull=False,
            )
            .values_list("created_at", "resolved_at")
        )
        deltas = []
        for created_at, resolved_at in rows:
            if created_at and resolved_at:
                deltas.append(resolved_at - created_at)
        avg_resolution_time = sum(deltas, timedelta(0)) / len(deltas) if deltas else None

    return {
        "total_alerts": total_alerts,
        "overdue": overdue,
        "resolved_today": resolved_today,
        "avg_resolution_time": avg_resolution_time,
    }


def get_lock_statistics(workspace):
    """
    Return currently_locked count and expired_locks count.
    Expired uses lock_utils.is_lock_expired() per alert.
    """
    if workspace is None:
        return {"currently_locked": 0, "expired_locks": 0}
    locked_qs = Alert.objects.filter(
        workspace=workspace,
        locked_by_id__isnull=False,
        locked_at__isnull=False,
    )
    currently_locked = locked_qs.count()
    expired_locks = sum(1 for alert in locked_qs if is_lock_expired(alert))
    return {
        "currently_locked": currently_locked,
        "expired_locks": expired_locks,
    }


def get_suppression_statistics(workspace):
    """
    Return active suppression rule count and alerts suppressed today.
    No mutation. Suppressed (return-None) alerts are not stored; duplicates merged
    are logged as activity; for now alerts_suppressed_today returns 0.
    """
    if workspace is None:
        return {"active_rules": 0, "alerts_suppressed_today": 0}
    active_rules = AlertSuppressionRule.objects.filter(
        workspace=workspace,
        is_active=True,
    ).count()
    return {
        "active_rules": active_rules,
        "alerts_suppressed_today": 0,
    }


def get_escalation_statistics(workspace):
    """
    Return total escalated count and max escalation level for workspace.
    No mutation.
    """
    if workspace is None:
        return {"total_escalated": 0, "max_escalation_level": 0}
    escalated_qs = Alert.objects.filter(
        workspace=workspace,
        escalation_level__gt=0,
    )
    total_escalated = escalated_qs.count()
    result = escalated_qs.aggregate(max_level=Max("escalation_level"))
    max_escalation_level = result.get("max_level") or 0
    return {
        "total_escalated": total_escalated,
        "max_escalation_level": max_escalation_level,
    }


def get_suppressed_alert_count(workspace):
    """Return count of alerts with is_suppressed=True in workspace. No mutation."""
    if workspace is None:
        return 0
    return Alert.objects.filter(
        workspace=workspace,
        is_suppressed=True,
    ).count()

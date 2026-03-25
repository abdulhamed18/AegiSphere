"""
Phase 8 — Dashboard selectors. Workspace-scoped aggregations. No mutations.
Uses existing metrics and alert/case selectors where available.
"""

from django.db.models import Avg, Count, ExpressionWrapper, F
from django.db.models.fields import DurationField

from alerts.enums import AlertStatus
from alerts.models import Alert
from alerts.selectors import get_overdue_alerts

from cases.metrics import (
    get_case_status_distribution,
    get_workspace_mttr,
)
from cases.models import Case, CaseStatus

from core.models import RoleChangeAuditLog


def get_open_alerts_count(workspace):
    """Alert status = OPEN or IN_PROGRESS. Excludes deleted."""
    if not workspace:
        return 0
    return (
        Alert.objects.filter(
            workspace=workspace,
            is_deleted=False,
            status__in=[AlertStatus.OPEN, AlertStatus.IN_PROGRESS],
        ).count()
    )


def get_open_cases_count(workspace):
    """Case status != CLOSED."""
    if not workspace:
        return 0
    return Case.objects.filter(
        workspace=workspace
    ).exclude(status=CaseStatus.CLOSED).count()


def get_sla_breach_alerts_count(workspace):
    """Alerts where sla_deadline < now AND not resolved."""
    if not workspace:
        return 0
    return get_overdue_alerts(workspace).count()


def get_avg_mttd_hours(workspace):
    """
    Average(alert_created_at - first_seen_at) in hours.
    Uses first_seen_at as event occurrence proxy. Returns 0 if no data.
    """
    if not workspace:
        return 0.0
    qs = Alert.objects.filter(
        workspace=workspace,
        is_deleted=False,
        first_seen_at__isnull=False,
    )
    result = qs.aggregate(
        avg_duration=Avg(
            ExpressionWrapper(
                F("created_at") - F("first_seen_at"),
                output_field=DurationField(),
            )
        )
    )
    avg = result.get("avg_duration")
    if avg is None:
        return 0.0
    return avg.total_seconds() / 3600.0


def get_alerts_by_severity(workspace):
    """Count by severity. Returns dict with LOW, MEDIUM, HIGH, CRITICAL."""
    if not workspace:
        return {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    rows = (
        Alert.objects.filter(workspace=workspace, is_deleted=False)
        .values("severity")
        .annotate(count=Count("id"))
    )
    dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for row in rows:
        if row["severity"] in dist:
            dist[row["severity"]] = row["count"]
    return dist


def get_sla_compliance_percentage_alerts(workspace):
    """
    % of alerts resolved before SLA deadline.
    Of alerts with sla_deadline set that are now RESOLVED/FALSE_POSITIVE,
    count where resolved_at <= sla_deadline.
    Return None if no eligible alerts (avoids misleading 100%).
    """
    if not workspace:
        return None
    resolved = Alert.objects.filter(
        workspace=workspace,
        is_deleted=False,
        status__in=[AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE],
        sla_deadline__isnull=False,
        resolved_at__isnull=False,
    )
    total = resolved.count()
    if total == 0:
        return None
    compliant = resolved.filter(resolved_at__lte=F("sla_deadline")).count()
    return (compliant / total) * 100.0


def get_mitre_distribution_top5(workspace):
    """Top 5 MITRE techniques by count. From workspace alerts."""
    if not workspace:
        return {}
    rows = (
        Alert.objects.filter(workspace=workspace, is_deleted=False)
        .exclude(mitre_technique__isnull=True)
        .exclude(mitre_technique="")
        .values("mitre_technique")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )
    return {row["mitre_technique"]: row["count"] for row in rows}


def get_recent_alerts(workspace, limit=5):
    """Last N alerts. Workspace-scoped."""
    if not workspace:
        return []
    return list(
        Alert.objects.filter(workspace=workspace, is_deleted=False)
        .select_related("assigned_to")
        .order_by("-created_at")[:limit]
    )


def get_recent_cases(workspace, limit=5):
    """Last N cases. Workspace-scoped."""
    if not workspace:
        return []
    return list(
        Case.objects.filter(workspace=workspace)
        .select_related("primary_assignee")
        .order_by("-created_at")[:limit]
    )


def get_recent_audit_events(workspace, limit=5):
    """Last N RoleChangeAuditLog events. Workspace-scoped."""
    if not workspace:
        return []
    return list(
        RoleChangeAuditLog.objects.filter(workspace=workspace)
        .select_related("user", "changed_by")
        .order_by("-changed_at")[:limit]
    )

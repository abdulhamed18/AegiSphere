"""
Phase 6 — Metrics & Reporting Engine

Enterprise SOC analytics for cases. Read-only, workspace-scoped.
Uses ORM annotations and aggregates. No mutations, no N+1.
"""

from datetime import timedelta

from django.db.models import Avg, Count, ExpressionWrapper, F
from django.db.models.fields import DurationField
from django.utils import timezone

from alerts.models import Alert

from .models import Case, CaseStatus


def get_workspace_mttr(workspace):
    """
    MTTR = average of (closed_at - created_at) for CLOSED cases.
    Returns float hours. Zero if no closed cases.
    """
    qs = Case.objects.filter(
        workspace=workspace,
        status=CaseStatus.CLOSED,
    ).exclude(closed_at__isnull=True)

    result = qs.aggregate(
        avg_duration=Avg(
            ExpressionWrapper(
                F("closed_at") - F("created_at"),
                output_field=DurationField(),
            )
        )
    )
    avg = result["avg_duration"]
    if avg is None:
        return 0.0
    return avg.total_seconds() / 3600.0


def get_workspace_sla_compliance(workspace):
    """
    SLA compliance % = (CLOSED cases where sla_breached=False) / (Total CLOSED) * 100.
    Returns 100 if no CLOSED cases.
    """
    closed = Case.objects.filter(
        workspace=workspace,
        status=CaseStatus.CLOSED,
    )
    total = closed.count()
    if total == 0:
        return 100.0
    compliant = closed.filter(sla_breached=False).count()
    return (compliant / total) * 100.0


def get_case_aging_buckets(workspace):
    """
    Count non-closed cases by age buckets (0-1, 1-3, 3-7, 7+ days).
    Uses ORM filters only. Excludes archived (operational backlog only).
    """
    now = timezone.now()
    base = Case.objects.filter(
        workspace=workspace,
        archived=False,
    ).exclude(status=CaseStatus.CLOSED)

    d1 = now - timedelta(days=1)
    d3 = now - timedelta(days=3)
    d7 = now - timedelta(days=7)

    return {
        "0_1_days": base.filter(created_at__gte=d1).count(),
        "1_3_days": base.filter(created_at__gte=d3, created_at__lt=d1).count(),
        "3_7_days": base.filter(created_at__gte=d7, created_at__lt=d3).count(),
        "7_plus_days": base.filter(created_at__lt=d7).count(),
    }


def get_analyst_workload(workspace):
    """
    Count active cases (not CLOSED, not archived) per primary_assignee.
    Returns list of {analyst_id, count}. Unassigned cases as analyst_id="unassigned".
    """
    base_qs = Case.objects.filter(
        workspace=workspace,
        archived=False,
    ).exclude(status=CaseStatus.CLOSED)

    rows = (
        base_qs.exclude(primary_assignee__isnull=True)
        .values("primary_assignee")
        .annotate(count=Count("id"))
        .order_by("-count")
    )
    result = [
        {"analyst_id": row["primary_assignee"], "count": row["count"]}
        for row in rows
    ]
    unassigned_count = base_qs.filter(primary_assignee__isnull=True).count()
    if unassigned_count > 0:
        result.append({"analyst_id": "unassigned", "count": unassigned_count})
    return result


def get_case_severity_distribution(workspace):
    """
    Count cases by severity. Includes active and closed.
    """
    rows = (
        Case.objects.filter(workspace=workspace)
        .values("severity")
        .annotate(count=Count("id"))
    )
    dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for row in rows:
        if row["severity"] in dist:
            dist[row["severity"]] = row["count"]
    return dist


def get_case_status_distribution(workspace):
    """
    Count cases by status.
    """
    rows = (
        Case.objects.filter(workspace=workspace)
        .values("status")
        .annotate(count=Count("id"))
    )
    return {row["status"]: row["count"] for row in rows}


def get_workspace_mitre_distribution(workspace):
    """
    Aggregate count per mitre_technique from alerts linked to workspace cases.
    Single ORM query. Excludes null/empty. Returns sorted list.
    """
    rows = (
        Alert.objects.filter(
            case_alerts__case__workspace=workspace,
        )
        .exclude(mitre_technique__isnull=True)
        .exclude(mitre_technique="")
        .values("mitre_technique")
        .annotate(count=Count("id"))
        .order_by("-count")
    )
    return [
        {"technique": row["mitre_technique"], "count": row["count"]}
        for row in rows
    ]


def get_archive_statistics(workspace):
    """
    Archive analytics: total archived, last 30 days, last 90 days.
    """
    now = timezone.now()
    d30 = now - timedelta(days=30)
    d90 = now - timedelta(days=90)

    archived = Case.objects.filter(workspace=workspace, archived=True)
    total = archived.count()
    last_30 = archived.filter(archived_at__gte=d30).count()
    last_90 = archived.filter(archived_at__gte=d90).count()

    return {
        "total_archived": total,
        "archived_last_30_days": last_30,
        "archived_last_90_days": last_90,
    }

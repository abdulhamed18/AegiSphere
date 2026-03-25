"""
Workload and metrics selectors. Workspace-scoped. DB aggregation only.
Uses core.sla_utils for DB-agnostic SLA logic. No N+1. No .extra() or SQLite-specific code.
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db.models import Avg, Case as CaseExpr, Count, ExpressionWrapper, F, Value, When
from django.db.models.fields import DurationField
from django.utils import timezone

from alerts.enums import AlertStatus
from alerts.models import Alert
from cases.models import Case, CaseStatus
from core.sla_utils import sla_near_breach_annotation_alerts

RESOLVED_ALERT_STATUSES = [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]


def get_workspace_workload_metrics(workspace):
    """
    Compute workload metrics for workspace.
    Returns dict with: alerts_per_analyst, cases_per_analyst, sla_risk_distribution,
    aging_distribution, mttr_per_analyst.
    """
    if workspace is None:
        return {
            "alerts_per_analyst": [],
            "cases_per_analyst": [],
            "sla_risk_distribution": {"overdue": 0, "near_breach": 0, "safe": 0},
            "aging_distribution": {"0_1_days": 0, "1_3_days": 0, "3_7_days": 0, "7_plus_days": 0},
            "mttr_per_analyst": [],
        }

    now = timezone.now()
    User = get_user_model()

    # 1. Alerts per analyst (open alerts)
    alert_rows = (
        Alert.objects.filter(
            workspace=workspace, is_deleted=False
        )
        .exclude(status__in=RESOLVED_ALERT_STATUSES)
        .values("assigned_to")
        .annotate(count=Count("id"))
        .order_by("-count")
    )

    alerts_per_analyst = [
        {
            "analyst_id": r["assigned_to"],
            "analyst_name": "Unassigned" if r["assigned_to"] is None else None,
            "count": r["count"],
        }
        for r in alert_rows
    ]
    # 2. Cases per analyst (active cases)
    case_rows = (
        Case.objects.filter(
            workspace=workspace, archived=False
        )
        .exclude(status=CaseStatus.CLOSED)
        .values("primary_assignee")
        .annotate(count=Count("id"))
        .order_by("-count")
    )
    cases_per_analyst = [
        {
            "analyst_id": r["primary_assignee"],
            "analyst_name": "Unassigned" if r["primary_assignee"] is None else None,
            "count": r["count"],
        }
        for r in case_rows
    ]

    user_ids = {x["analyst_id"] for x in alerts_per_analyst if x["analyst_id"]}
    user_ids.update(x["analyst_id"] for x in cases_per_analyst if x["analyst_id"])

    # 3. SLA Risk buckets (alerts only, open) — DB-agnostic via annotate
    open_alerts_base = Alert.objects.filter(
        workspace=workspace, is_deleted=False
    ).exclude(status__in=RESOLVED_ALERT_STATUSES)

    overdue = open_alerts_base.filter(
        sla_deadline__isnull=False, sla_deadline__lt=now
    ).count()

    open_not_overdue = open_alerts_base.filter(
        sla_deadline__isnull=False, sla_deadline__gte=now
    )
    open_not_overdue_annotated = open_not_overdue.annotate(
        _sla_near_breach_flag=sla_near_breach_annotation_alerts()
    )
    near_breach = open_not_overdue_annotated.filter(_sla_near_breach_flag=1).count()
    safe = open_not_overdue_annotated.filter(_sla_near_breach_flag=0).count()

    sla_risk_distribution = {
        "overdue": overdue,
        "near_breach": near_breach,
        "safe": safe,
    }

    # 4. Aging buckets (cases, non-closed) — single query with Case/When
    d1 = now - timedelta(days=1)
    d3 = now - timedelta(days=3)
    d7 = now - timedelta(days=7)
    active_cases = (
        Case.objects.filter(workspace=workspace, archived=False)
        .exclude(status=CaseStatus.CLOSED)
        .annotate(
            _aging_bucket=CaseExpr(
                When(created_at__gte=d1, then=Value("0_1")),
                When(created_at__gte=d3, created_at__lt=d1, then=Value("1_3")),
                When(created_at__gte=d7, created_at__lt=d3, then=Value("3_7")),
                default=Value("7_plus"),
            )
        )
    )
    buckets = dict(
        active_cases.values("_aging_bucket").annotate(cnt=Count("id")).values_list("_aging_bucket", "cnt")
    )
    aging_distribution = {
        "0_1_days": buckets.get("0_1", 0),
        "1_3_days": buckets.get("1_3", 0),
        "3_7_days": buckets.get("3_7", 0),
        "7_plus_days": buckets.get("7_plus", 0),
    }

    # 5. MTTR per analyst (closed cases)
    mttr_rows = (
        Case.objects.filter(
            workspace=workspace,
            status=CaseStatus.CLOSED,
        )
        .exclude(closed_at__isnull=True)
        .exclude(primary_assignee__isnull=True)
        .values("primary_assignee")
        .annotate(
            avg_duration=Avg(
                ExpressionWrapper(
                    F("closed_at") - F("created_at"),
                    output_field=DurationField(),
                )
            )
        )
    )

    user_ids.update(r["primary_assignee"] for r in mttr_rows)
    users = dict(User.objects.filter(pk__in=user_ids).values_list("pk", "username")) if user_ids else {}
    for item in alerts_per_analyst:
        if item["analyst_id"]:
            item["analyst_name"] = users.get(item["analyst_id"]) or f"User #{item['analyst_id']}"
    for item in cases_per_analyst:
        if item["analyst_id"]:
            item["analyst_name"] = users.get(item["analyst_id"]) or f"User #{item['analyst_id']}"

    mttr_per_analyst = []
    for r in mttr_rows:
        avg = r["avg_duration"]
        hours = avg.total_seconds() / 3600.0 if avg else 0
        mttr_per_analyst.append({
            "analyst_id": r["primary_assignee"],
            "analyst_name": users.get(r["primary_assignee"]) or f"User #{r['primary_assignee']}",
            "avg_hours": round(hours, 2),
        })
    mttr_per_analyst.sort(key=lambda x: -x["avg_hours"])

    return {
        "alerts_per_analyst": alerts_per_analyst,
        "cases_per_analyst": cases_per_analyst,
        "sla_risk_distribution": sla_risk_distribution,
        "aging_distribution": aging_distribution,
        "mttr_per_analyst": mttr_per_analyst,
    }

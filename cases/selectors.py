"""
Phase 5 — Step 5: Investigation Layer Selectors

Read-only queries with workspace scoping. Optimized prefetch patterns.
"""

from django.db.models import BooleanField, Case as CaseWhen, Count, Q, Value, When
from django.utils import timezone

from core.sla_utils import sla_near_breach_annotation_cases

from .models import Case, CaseStatus


RESOLVED_CASE_STATUSES = [CaseStatus.RESOLVED, CaseStatus.CLOSED]


def _case_sla_annotations(queryset):
    """Add case SLA flags: case_is_resolved, case_is_overdue, case_is_near_breach."""
    now = timezone.now()
    return queryset.annotate(
        case_is_resolved=CaseWhen(
            When(status__in=RESOLVED_CASE_STATUSES, then=Value(True)),
            default=Value(False),
            output_field=BooleanField(),
        ),
        case_is_overdue=CaseWhen(
            When(sla_deadline__isnull=True, then=Value(False)),
            When(status__in=RESOLVED_CASE_STATUSES, then=Value(False)),
            When(sla_deadline__lt=now, then=Value(True)),
            default=Value(False),
            output_field=BooleanField(),
        ),
        case_is_near_breach=sla_near_breach_annotation_cases(),
    )


def get_workspace_cases_list(
    workspace,
    search=None,
    status=None,
    severity=None,
    assigned_to=None,
    sla_filter=None,
    ordering="-created_at",
):
    """
    Return queryset of cases for list views. Supports search, filters, SLA filter.
    Excludes archived (soft-deleted). Annotates alert_count and SLA flags.
    """
    if workspace is None:
        return Case.objects.none()

    qs = (
        Case.objects.filter(workspace=workspace, archived=False)
        .only("id", "title", "severity", "status", "sla_deadline", "created_at", "primary_assignee", "workspace", "archived")
        .select_related("primary_assignee")
        .annotate(
            alert_count=Count(
                "case_alerts", filter=Q(case_alerts__alert__is_deleted=False)
            )
        )
        .order_by(ordering)
    )

    if search and search.strip():
        term = search.strip()
        search_q = Q(title__icontains=term) | Q(description__icontains=term)
        if term.isdigit():
            search_q |= Q(pk=int(term))
        qs = qs.filter(search_q)

    if status:
        qs = qs.filter(status=status)
    if severity:
        qs = qs.filter(severity=severity)
    if assigned_to is not None:
        qs = qs.filter(primary_assignee_id=assigned_to)

    now = timezone.now()
    if sla_filter == "overdue":
        qs = qs.filter(sla_deadline__lt=now).exclude(
            status__in=RESOLVED_CASE_STATUSES
        )
    elif sla_filter == "near_breach":
        qs = (
            qs.filter(sla_deadline__isnull=False, sla_deadline__gte=now)
            .exclude(status__in=RESOLVED_CASE_STATUSES)
            .annotate(_sla_near_breach_flag=sla_near_breach_annotation_cases())
            .filter(_sla_near_breach_flag=1)
        )
    elif sla_filter == "ok":
        qs = (
            qs.filter(sla_deadline__isnull=False, sla_deadline__gte=now)
            .exclude(status__in=RESOLVED_CASE_STATUSES)
            .annotate(_sla_near_breach_flag=sla_near_breach_annotation_cases())
            .filter(_sla_near_breach_flag=0)
        )

    return _case_sla_annotations(qs)


def get_workspace_case_detail(workspace, case_id):
    """
    Fetch single case by ID. Workspace-scoped. Excludes archived.
    Prefetches case_alerts (excl. soft-deleted), activities (limit 100), tasks, iocs, attachments, tags.
    Annotates alert_count and SLA flags. Raises 404 if not found.
    """
    from django.db.models import Prefetch
    from django.shortcuts import get_object_or_404

    from .models import CaseActivity, CaseAlert

    if workspace is None:
        from django.http import Http404
        raise Http404("Case not found.")

    case_alerts_qs = CaseAlert.objects.filter(
        alert__is_deleted=False
    ).select_related("alert", "alert__assigned_to")
    # Do not slice here: Django filters this queryset by case_id for Prefetch; filter first, then order, then slice in view if needed.
    activities_qs = CaseActivity.objects.select_related("actor").order_by("-created_at")

    qs = (
        Case.objects.filter(workspace=workspace, archived=False)
        .select_related("primary_assignee")
        .prefetch_related(
            Prefetch("case_alerts", queryset=case_alerts_qs),
            Prefetch("activities", queryset=activities_qs),
            "tasks",
            "iocs",
            "attachments",
            "tags",
        )
        .annotate(
            alert_count=Count(
                "case_alerts", filter=Q(case_alerts__alert__is_deleted=False)
            )
        )
    )
    return get_object_or_404(_case_sla_annotations(qs), pk=case_id)


def get_case_with_related(case_id, workspace):
    """
    Fetch case by ID with all related data. Enforces workspace scoping.
    Returns Case or None if not found / wrong workspace.
    """
    case = (
        Case.objects.filter(id=case_id, workspace=workspace)
        .select_related("workspace", "primary_assignee", "created_by", "closed_by")
        .prefetch_related(
            "case_alerts__alert",
            "collaborators",
            "tasks",
            "iocs",
            "attachments",
            "tags",
            "activities",
        )
        .first()
    )
    return case


def get_workspace_cases(workspace, filters=None):
    """
    Fetch cases for workspace with optional filters.
    Uses select_related and prefetch_related for efficient queries.
    """
    qs = (
        Case.objects.filter(workspace=workspace)
        .select_related("primary_assignee")
        .prefetch_related("case_alerts", "collaborators", "tasks", "iocs", "attachments", "tags")
    )

    if filters:
        if filters.get("status") is not None:
            qs = qs.filter(status=filters["status"])
        if filters.get("severity") is not None:
            qs = qs.filter(severity=filters["severity"])
        if filters.get("assigned_to") is not None:
            qs = qs.filter(primary_assignee=filters["assigned_to"])
        if filters.get("archived") is not None:
            qs = qs.filter(archived=filters["archived"])

    return qs.order_by("-created_at")


def get_case_mitre_techniques(case):
    """
    Aggregate unique MITRE technique IDs from all alerts attached to case.
    Returns sorted unique list. Pure computed property, not stored in DB.
    Single query, no N+1.
    """
    from alerts.models import Alert

    techniques = (
        Alert.objects.filter(case_alerts__case=case)
        .exclude(mitre_technique__isnull=True)
        .exclude(mitre_technique="")
        .values_list("mitre_technique", flat=True)
        .distinct()
    )
    return sorted(list(techniques))

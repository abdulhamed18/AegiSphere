"""
Centralized read queries for alerts. Workspace isolation on all selectors.

No permission checks; no mutations. Uses select_related and indexed fields.
"""

from django.db.models import BooleanField, Case, Count, Q, Value, When
from django.utils import timezone

from alerts.enums import AlertSeverity, AlertStatus
from alerts.models import Alert
from core.sla_utils import sla_near_breach_annotation_alerts

RESOLVED_STATUSES = [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]


def _sla_annotations(queryset):
    """Add SLA flags as annotations: is_resolved, is_overdue, is_near_breach."""
    now = timezone.now()
    return queryset.annotate(
        sla_is_resolved=Case(
            When(status__in=RESOLVED_STATUSES, then=Value(True)),
            default=Value(False),
            output_field=BooleanField(),
        ),
        sla_is_overdue=Case(
            When(sla_deadline__isnull=True, then=Value(False)),
            When(status__in=RESOLVED_STATUSES, then=Value(False)),
            When(sla_deadline__lt=now, then=Value(True)),
            default=Value(False),
            output_field=BooleanField(),
        ),
        sla_is_near_breach=sla_near_breach_annotation_alerts(),
    )


def get_workspace_alerts_list(
    workspace,
    search=None,
    severity=None,
    status=None,
    assigned_to=None,
    sla_filter=None,
    ordering="-created_at",
):
    """
    Return queryset of alerts for list views. Supports search, filters, SLA filter.
    Excludes soft-deleted. Uses select_related for assigned_to.
    """
    if workspace is None:
        return Alert.objects.none()

    qs = (
        Alert.objects.filter(workspace=workspace, is_deleted=False)
        .only("id", "title", "severity", "status", "sla_deadline", "created_at", "source", "assigned_to")
        .select_related("assigned_to")
        .order_by(ordering)
    )

    if search and search.strip():
        term = search.strip()
        qs = qs.filter(
            Q(title__icontains=term)
            | Q(description__icontains=term)
            | Q(source_event_id__icontains=term)
        )

    if severity:
        qs = qs.filter(severity=severity)
    if status:
        qs = qs.filter(status=status)
    if assigned_to is not None:
        qs = qs.filter(assigned_to_id=assigned_to)

    resolved_statuses = [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]
    now = timezone.now()

    if sla_filter == "overdue":
        qs = qs.filter(
            sla_deadline__lt=now,
        ).exclude(status__in=resolved_statuses)
    elif sla_filter == "near_breach":
        qs = (
            qs.filter(sla_deadline__isnull=False, sla_deadline__gte=now)
            .exclude(status__in=resolved_statuses)
            .annotate(_sla_near_breach_flag=sla_near_breach_annotation_alerts())
            .filter(_sla_near_breach_flag=1)
        )
    elif sla_filter == "ok":
        qs = (
            qs.filter(sla_deadline__isnull=False, sla_deadline__gte=now)
            .exclude(status__in=resolved_statuses)
            .annotate(_sla_near_breach_flag=sla_near_breach_annotation_alerts())
            .filter(_sla_near_breach_flag=0)
        )

    return _sla_annotations(qs)


def get_workspace_alert_detail(workspace, alert_id):
    """
    Fetch single alert by ID. Workspace-scoped. Excludes soft-deleted.
    Prefetches audit logs and related case. Annotates SLA flags.
    Raises 404 if not found.
    """
    from django.db.models import Prefetch
    from django.shortcuts import get_object_or_404

    from alerts.models import AlertActivityLog
    from cases.models import CaseAlert

    if workspace is None:
        from django.http import Http404
        raise Http404("Alert not found.")

    qs = (
        Alert.objects.filter(workspace=workspace, is_deleted=False)
        .select_related("assigned_to", "locked_by")
        .prefetch_related(
            Prefetch(
                "activity_logs",
                queryset=AlertActivityLog.objects.select_related("actor").order_by(
                    "-created_at"
                ),
            ),
            Prefetch(
                "case_alerts",
                queryset=CaseAlert.objects.select_related("case"),
            ),
        )
    )
    return get_object_or_404(_sla_annotations(qs), pk=alert_id)


def get_workspace_alerts(
    workspace,
    status=None,
    severity=None,
    assigned_to=None,
    include_deleted=False,
    include_suppressed=False,
    escalation_level=None,
    tags=None,
):
    """
    Return queryset of alerts for workspace with optional filters.
    Excludes is_deleted=True unless include_deleted=True.
    Excludes is_suppressed=True unless include_suppressed=True.
    Optional: escalation_level (exact), tags (list of tag names or IDs to filter by).
    """
    if workspace is None:
        return Alert.objects.none()
    qs = (
        Alert.objects.filter(workspace=workspace)
        .select_related("assigned_to", "locked_by")
        .order_by("-created_at")
    )
    if not include_deleted:
        qs = qs.filter(is_deleted=False)
    if not include_suppressed:
        now = timezone.now()
        currently_suppressed = Q(is_suppressed=True) & (
            Q(suppressed_until__isnull=True) | Q(suppressed_until__gt=now)
        )
        qs = qs.exclude(currently_suppressed)
    if status is not None:
        qs = qs.filter(status=status)
    if severity is not None:
        qs = qs.filter(severity=severity)
    if assigned_to is not None:
        qs = qs.filter(assigned_to=assigned_to)
    if escalation_level is not None:
        qs = qs.filter(escalation_level=escalation_level)
    if tags:
        tag_filter = Q()
        for t in tags:
            if isinstance(t, int):
                tag_filter |= Q(tags__id=t, tags__workspace=workspace)
            else:
                tag_filter |= Q(tags__name=t, tags__workspace=workspace)
        qs = qs.filter(tag_filter).distinct()
    return qs


def get_assigned_alerts(user, include_deleted=False, include_suppressed=False):
    """
    Return alerts assigned to user, restricted to workspaces where user has active membership.
    Excludes is_deleted=True unless include_deleted=True.
    Excludes is_suppressed=True unless include_suppressed=True.
    """
    if user is None or not user.is_authenticated:
        return Alert.objects.none()
    qs = (
        Alert.objects.filter(
            assigned_to=user,
            workspace__memberships__user=user,
            workspace__memberships__is_active=True,
        )
        .distinct()
        .select_related("workspace", "assigned_to", "locked_by")
        .order_by("-created_at")
    )
    if not include_deleted:
        qs = qs.filter(is_deleted=False)
    if not include_suppressed:
        now = timezone.now()
        currently_suppressed = Q(is_suppressed=True) & (
            Q(suppressed_until__isnull=True) | Q(suppressed_until__gt=now)
        )
        qs = qs.exclude(currently_suppressed)
    return qs


def get_overdue_alerts(workspace, include_deleted=False, include_suppressed=False):
    """
    Return alerts in workspace where sla_deadline < now and status not in [RESOLVED, FALSE_POSITIVE].
    Excludes is_deleted=True unless include_deleted=True.
    Excludes is_suppressed=True unless include_suppressed=True.
    """
    if workspace is None:
        return Alert.objects.none()
    now = timezone.now()
    qs = (
        Alert.objects.filter(
            workspace=workspace,
            sla_deadline__lt=now,
        )
        .exclude(status__in=[AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE])
        .select_related("assigned_to", "locked_by")
        .order_by("sla_deadline")
    )
    if not include_deleted:
        qs = qs.filter(is_deleted=False)
    if not include_suppressed:
        now = timezone.now()
        currently_suppressed = Q(is_suppressed=True) & (
            Q(suppressed_until__isnull=True) | Q(suppressed_until__gt=now)
        )
        qs = qs.exclude(currently_suppressed)
    return qs


def get_open_alert_counts(workspace, include_deleted=False, include_suppressed=False):
    """
    Return counts of open (non-resolved) alerts by severity. Uses aggregation.
    Excludes is_deleted=True unless include_deleted=True.
    Excludes is_suppressed=True unless include_suppressed=True.
    """
    if workspace is None:
        return {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
    open_filter = ~Q(status__in=[AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE])
    qs = Alert.objects.filter(workspace=workspace).filter(open_filter)
    if not include_deleted:
        qs = qs.filter(is_deleted=False)
    if not include_suppressed:
        now = timezone.now()
        currently_suppressed = Q(is_suppressed=True) & (
            Q(suppressed_until__isnull=True) | Q(suppressed_until__gt=now)
        )
        qs = qs.exclude(currently_suppressed)
    result = qs.aggregate(
        total=Count("id"),
        critical=Count("id", filter=Q(severity=AlertSeverity.CRITICAL)),
        high=Count("id", filter=Q(severity=AlertSeverity.HIGH)),
        medium=Count("id", filter=Q(severity=AlertSeverity.MEDIUM)),
        low=Count("id", filter=Q(severity=AlertSeverity.LOW)),
    )
    return {
        "total": result["total"] or 0,
        "critical": result["critical"] or 0,
        "high": result["high"] or 0,
        "medium": result["medium"] or 0,
        "low": result["low"] or 0,
    }

"""
Phase 7 — Case Export API + Case Detail UI

Export endpoint and case detail page with Export modal.
"""

from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from alerts.role_hierarchy import get_role_code

from .export import export_case
from .models import CaseStatus
from .selectors import get_case_with_related, get_workspace_case_detail
from .services import _log_case_activity, CASE_EXPORTED

# L2, L3, Manager allowed to export (L1 excluded)
EXPORT_ALLOWED_ROLES = (
    "SOC_TIER_2_ANALYST",
    "SOC_TIER_3_ANALYST",
    "SOC_MANAGER",
    "ORG_OWNER",
    "PERSONAL_OWNER",
)


class CaseExportView(APIView):
    """
    POST /api/cases/<id>/export/
    Body: {"format": "json" | "pdf" | "both"}
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        workspace = getattr(request, "workspace", None)
        if not workspace:
            return Response(
                {"error": "No active workspace."},
                status=status.HTTP_403_FORBIDDEN,
            )

        role = get_role_code(request.user, workspace)
        if role is None:
            return Response(
                {"error": "You are not a member of this workspace."},
                status=status.HTTP_403_FORBIDDEN,
            )

        if role not in EXPORT_ALLOWED_ROLES:
            return Response(
                {"error": "Export requires L2, L3, or Manager role."},
                status=status.HTTP_403_FORBIDDEN,
            )

        case = get_case_with_related(pk, workspace)
        if case is None:
            return Response(
                {"error": "Case not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if case.status != CaseStatus.CLOSED:
            return Response(
                {"error": "Only CLOSED cases can be exported."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        format_str = request.data.get("format", "json")
        if format_str not in ("json", "pdf", "both"):
            return Response(
                {"error": "format must be 'json', 'pdf', or 'both'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            response = export_case(
                case, format_str, actor=request.user,
            )
            with transaction.atomic():
                _log_case_activity(
                    case,
                    CASE_EXPORTED,
                    actor=request.user,
                    metadata={
                        "actor_id": request.user.id,
                        "previous_value": None,
                        "new_value": format_str,
                        "extra": {
                            "exported_at": timezone.now().isoformat(),
                        },
                    },
                )
            return response
        except ValueError as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )


@login_required
def case_list(request):
    """Filterable, paginated cases list."""
    workspace = getattr(request, "workspace", None)
    if not workspace:
        from django.http import HttpResponseForbidden
        return HttpResponseForbidden("No active workspace.")

    from django.core.paginator import Paginator

    from .models import CaseSeverity, CaseStatus
    from .selectors import get_workspace_cases_list
    from workspaces.selectors import get_workspace_members_for_assignment

    q = request.GET.get("q", "").strip()
    status = request.GET.get("status", "")
    severity = request.GET.get("severity", "")
    assigned = request.GET.get("assigned", "")
    sla = request.GET.get("sla", "")
    ordering = request.GET.get("ordering", "-created_at")

    assigned_id = int(assigned) if assigned.isdigit() else None

    qs = get_workspace_cases_list(
        workspace,
        search=q or None,
        status=status or None,
        severity=severity or None,
        assigned_to=assigned_id,
        sla_filter=sla or None,
        ordering=ordering,
    )

    paginator = Paginator(qs, 20)
    page_num = request.GET.get("page", 1)
    try:
        page_num = max(1, int(page_num))
    except (TypeError, ValueError):
        page_num = 1
    page_obj = paginator.get_page(page_num)

    member_users = get_workspace_members_for_assignment(workspace)
    assigned_choices = [{"value": "", "label": "All"}] + [
        {"value": str(m.user_id), "label": m.user.get_username()}
        for m in member_users
    ]

    severity_choices = [{"value": "", "label": "All"}] + [
        {"value": c[0], "label": c[1]} for c in CaseSeverity.choices
    ]
    status_choices = [{"value": "", "label": "All"}] + [
        {"value": c[0], "label": c[1]} for c in CaseStatus.choices
    ]
    sla_choices = [
        {"value": "", "label": "All"},
        {"value": "overdue", "label": "Overdue"},
        {"value": "near_breach", "label": "Near breach"},
        {"value": "ok", "label": "On track"},
    ]

    query_params = request.GET.copy()
    if "page" in query_params:
        query_params.pop("page")
    query_string = query_params.urlencode()

    context = {
        "page_title": "Cases",
        "page_obj": page_obj,
        "filter_q": q,
        "filter_status": status,
        "filter_severity": severity,
        "filter_assigned": assigned,
        "filter_sla": sla,
        "filter_ordering": ordering,
        "severity_choices": severity_choices,
        "status_choices": status_choices,
        "assigned_choices": assigned_choices,
        "sla_choices": sla_choices,
        "query_string": query_string,
    }
    return render(request, "cases/case_list.html", context)


def _sla_flags_for_alert(alert):
    """Build SLA badge dict from alert (for linked alerts without selector annotations)."""
    from alerts.enums import AlertStatus
    from core.sla_constants import SLA_NEAR_BREACH_RATIO
    from django.utils import timezone

    resolved = alert.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE)
    overdue = False
    near_breach = False
    if not resolved and alert.sla_deadline and alert.created_at:
        now = timezone.now()
        if alert.sla_deadline < now:
            overdue = True
        else:
            total = (alert.sla_deadline - alert.created_at).total_seconds()
            remaining = (alert.sla_deadline - now).total_seconds()
            if total > 0 and remaining < total * SLA_NEAR_BREACH_RATIO:
                near_breach = True
    return {"is_resolved": resolved, "is_overdue": overdue, "is_near_breach": near_breach}


@login_required
@require_http_methods(["GET"])
def case_detail(request, pk):
    """Case detail page with tabs and metadata."""
    workspace = getattr(request, "workspace", None)
    if not workspace:
        from django.http import HttpResponseForbidden
        return HttpResponseForbidden("No active workspace.")

    from workspaces.selectors import get_workspace_members_for_assignment

    case = get_workspace_case_detail(workspace, pk)

    linked_alerts = []
    for ca in case.case_alerts.all():
        if ca.alert:
            linked_alerts.append((ca.alert, _sla_flags_for_alert(ca.alert)))

    tasks = list(case.tasks.all())
    iocs = list(case.iocs.all())
    attachments = list(case.attachments.all())
    tags = list(case.tags.all())
    activity_logs = list(case.activities.all())[:100]
    assignment_candidates = get_workspace_members_for_assignment(workspace)

    role = get_role_code(request.user, workspace)
    can_export = (
        role is not None
        and role in EXPORT_ALLOWED_ROLES
        and case.status == CaseStatus.CLOSED
    )

    sla_flags = {
        "is_resolved": getattr(case, "case_is_resolved", False),
        "is_overdue": getattr(case, "case_is_overdue", False),
        "is_near_breach": bool(getattr(case, "case_is_near_breach", False)),
    }

    created_str = timezone.localtime(case.created_at).strftime("%b %d, %Y %H:%M")
    subtitle = f"Case #{case.pk} · {created_str}"

    active_tab = request.GET.get("tab", "timeline")
    valid_tabs = ("timeline", "alerts", "tasks", "iocs", "attachments")
    if active_tab not in valid_tabs:
        active_tab = "timeline"

    context = {
        "case": case,
        "can_export": can_export,
        "linked_alerts": linked_alerts,
        "tasks": tasks,
        "iocs": iocs,
        "attachments": attachments,
        "tags": tags,
        "activity_logs": activity_logs,
        "assignment_candidates": assignment_candidates,
        "sla_flags": sla_flags,
        "subtitle": subtitle,
        "active_tab": active_tab,
    }
    return render(request, "cases/case_detail.html", context)

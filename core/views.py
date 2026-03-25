"""
Phase 8 — App Shell: Dashboard and placeholder views.
"""

import json

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import render

from core.dashboard_selectors import (
    get_alerts_by_severity,
    get_avg_mttd_hours,
    get_mitre_distribution_top5,
    get_open_alerts_count,
    get_open_cases_count,
    get_recent_alerts,
    get_recent_audit_events,
    get_recent_cases,
    get_sla_breach_alerts_count,
    get_sla_compliance_percentage_alerts,
)
from cases.metrics import get_case_status_distribution, get_workspace_mttr


def _ensure_workspace(request):
    """Redirect or forbid if no workspace. Middleware should guarantee; defensive check."""
    if not getattr(request, "workspace", None):
        return HttpResponseForbidden("No active workspace.")
    return None


@login_required
def dashboard(request):
    """Landing page. Workspace-scoped KPIs, charts, recent activity."""
    err = _ensure_workspace(request)
    if err:
        return err

    workspace = request.workspace

    # KPIs — pre-aggregated
    open_alerts_count = get_open_alerts_count(workspace)
    open_cases_count = get_open_cases_count(workspace)
    sla_breach_alerts_count = get_sla_breach_alerts_count(workspace)
    avg_mttd = get_avg_mttd_hours(workspace)
    avg_mttr = get_workspace_mttr(workspace)
    avg_mttd_display = f"{avg_mttd:.2f}" if avg_mttd > 0 else "N/A"
    avg_mttr_display = f"{avg_mttr:.2f}" if avg_mttr > 0 else "N/A"

    # Chart data
    alerts_by_severity = get_alerts_by_severity(workspace)
    cases_by_status_raw = get_case_status_distribution(workspace)
    cases_by_status = {
        "OPEN": cases_by_status_raw.get("OPEN", 0),
        "IN_PROGRESS": cases_by_status_raw.get("IN_PROGRESS", 0),
        "ON_HOLD": cases_by_status_raw.get("ON_HOLD", 0),
        "RESOLVED": cases_by_status_raw.get("RESOLVED", 0),
        "CLOSED": cases_by_status_raw.get("CLOSED", 0),
    }
    sla_compliance_percentage = get_sla_compliance_percentage_alerts(workspace)
    mitre_distribution = get_mitre_distribution_top5(workspace)

    # Recent activity
    recent_alerts = get_recent_alerts(workspace, limit=5)
    recent_cases = get_recent_cases(workspace, limit=5)
    recent_audit_events = get_recent_audit_events(workspace, limit=5)

    chart_data_json = json.dumps(
        {
            "alerts_by_severity": alerts_by_severity,
            "cases_by_status": cases_by_status,
            "sla_compliance_percentage": sla_compliance_percentage,  # None when 0 eligible
            "mitre_distribution": mitre_distribution,
        }
    )

    context = {
        "page_title": "SOC Overview",
        "open_alerts_count": open_alerts_count,
        "open_cases_count": open_cases_count,
        "sla_breach_alerts_count": sla_breach_alerts_count,
        "avg_mttd": avg_mttd,
        "avg_mttr": avg_mttr,
        "avg_mttd_display": avg_mttd_display,
        "avg_mttr_display": avg_mttr_display,
        "alerts_by_severity": alerts_by_severity,
        "cases_by_status": cases_by_status,
        "sla_compliance_percentage": sla_compliance_percentage,
        "mitre_distribution": mitre_distribution,
        "chart_data_json": chart_data_json,
        "recent_alerts": recent_alerts,
        "recent_cases": recent_cases,
        "recent_audit_events": recent_audit_events,
    }
    return render(request, "dashboard/dashboard.html", context)

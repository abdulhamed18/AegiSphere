"""
Analyst workload and metrics views.
"""

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import render

from .selectors import get_workspace_workload_metrics


def _chart_data(metrics):
    """Build JSON-serializable chart data for safe template use."""
    return {
        "alertsPerAnalyst": {
            "labels": [x.get("analyst_name") or "Unassigned" for x in metrics["alerts_per_analyst"]],
            "counts": [x["count"] for x in metrics["alerts_per_analyst"]],
        },
        "casesPerAnalyst": {
            "labels": [x.get("analyst_name") or "Unassigned" for x in metrics["cases_per_analyst"]],
            "counts": [x["count"] for x in metrics["cases_per_analyst"]],
        },
        "slaRisk": {
            "labels": ["Overdue", "Near Breach", "Safe"],
            "counts": [
                metrics["sla_risk_distribution"]["overdue"],
                metrics["sla_risk_distribution"]["near_breach"],
                metrics["sla_risk_distribution"]["safe"],
            ],
        },
        "aging": {
            "labels": ["0-1 days", "1-3 days", "3-7 days", "7+ days"],
            "counts": [
                metrics["aging_distribution"]["0_1_days"],
                metrics["aging_distribution"]["1_3_days"],
                metrics["aging_distribution"]["3_7_days"],
                metrics["aging_distribution"]["7_plus_days"],
            ],
        },
        "mttrPerAnalyst": {
            "labels": [x["analyst_name"] for x in metrics["mttr_per_analyst"]],
            "hours": [x["avg_hours"] for x in metrics["mttr_per_analyst"]],
        },
    }


@login_required
def workload_dashboard(request):
    """Workload metrics dashboard."""
    workspace = getattr(request, "workspace", None)
    if not workspace:
        return HttpResponseForbidden("No active workspace.")

    metrics = get_workspace_workload_metrics(workspace)
    chart_data = _chart_data(metrics)

    context = {
        "page_title": "Analyst Workload & Metrics",
        "alerts_per_analyst": metrics["alerts_per_analyst"],
        "cases_per_analyst": metrics["cases_per_analyst"],
        "sla_risk_distribution": metrics["sla_risk_distribution"],
        "aging_distribution": metrics["aging_distribution"],
        "mttr_per_analyst": metrics["mttr_per_analyst"],
        "chart_data": chart_data,
    }
    return render(request, "metrics/workload.html", context)

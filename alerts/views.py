"""
Phase 8 — Alerts List and Detail Views
"""

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from django.utils import timezone

from django.contrib.auth import get_user_model

from alerts.enums import AlertSeverity, AlertStatus
from alerts.role_hierarchy import get_role_code, is_manager
from alerts.selectors import get_workspace_alert_detail, get_workspace_alerts_list
from alerts.services import assign_alert, change_status, lock_alert, unlock_alert
from alerts.status_transitions import get_allowed_transitions
from workspaces.selectors import get_workspace_members_for_assignment


def _ensure_workspace(request):
    """Forbid if no workspace."""
    if not getattr(request, "workspace", None):
        return HttpResponseForbidden("No active workspace.")
    return None


def _user_can_change_status(user, alert):
    """True if user can change alert status (considering lock: must be locker or manager)."""
    from alerts.permissions import can_change_status
    from alerts.role_hierarchy import get_role_code, is_manager
    if not can_change_status(user, alert):
        return False
    if alert.locked_by_id is not None and alert.locked_by_id != user.pk:
        role = get_role_code(user, alert.workspace)
        if not is_manager(role):
            return False
    return True


def _user_can_assign(user, alert):
    """True if user can assign alert (considering lock: must be locker or manager)."""
    from alerts.permissions import can_assign_alert
    from alerts.role_hierarchy import get_role_code, is_manager
    if not can_assign_alert(user, alert):
        return False
    if alert.locked_by_id is not None and alert.locked_by_id != user.pk:
        role = get_role_code(user, alert.workspace)
        if not is_manager(role):
            return False
    return True


def _user_can_lock(user, alert):
    """True if user can lock (when unlocked) or unlock (when locked by self). Analysts and above."""
    from alerts.locking_policy import can_lock, can_unlock
    from alerts.permissions import can_assign_alert
    if not can_assign_alert(user, alert):
        return False
    return can_lock(user, alert) or can_unlock(user, alert)


def _sla_flags_from_alert(alert):
    """Build SLA badge dict from annotated alert (selector adds sla_is_*)."""
    return {
        "is_resolved": getattr(alert, "sla_is_resolved", False),
        "is_overdue": getattr(alert, "sla_is_overdue", False),
        "is_near_breach": bool(getattr(alert, "sla_is_near_breach", False)),
    }


@login_required
def alert_list(request):
    """Filterable, paginated alerts list."""
    err = _ensure_workspace(request)
    if err:
        return err

    workspace = request.workspace

    q = request.GET.get("q", "").strip()
    severity = request.GET.get("severity", "")
    status = request.GET.get("status", "")
    assigned = request.GET.get("assigned", "")
    sla = request.GET.get("sla", "")
    ordering = request.GET.get("ordering", "-created_at")

    assigned_id = int(assigned) if assigned.isdigit() else None

    qs = get_workspace_alerts_list(
        workspace,
        search=q or None,
        severity=severity or None,
        status=status or None,
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
    alerts_page = paginator.get_page(page_num)

    # SLA flags from selector annotations
    alerts_with_sla = [
        (alert, _sla_flags_from_alert(alert)) for alert in alerts_page.object_list
    ]

    # Workspace members for assigned filter
    member_users = get_workspace_members_for_assignment(workspace)
    workspace_users = [(m.user_id, m.user.get_username()) for m in member_users]

    severity_choices = [{"value": "", "label": "All"}] + [
        {"value": c[0], "label": c[1]} for c in AlertSeverity.choices
    ]
    status_choices = [{"value": "", "label": "All"}] + [
        {"value": c[0], "label": c[1]} for c in AlertStatus.choices
    ]
    assigned_choices = [{"value": "", "label": "All"}] + [
        {"value": str(uid), "label": uname} for uid, uname in workspace_users
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
        "page_title": "Alerts",
        "alerts_page": alerts_page,
        "alerts_with_sla": alerts_with_sla,
        "filter_q": q,
        "filter_severity": severity,
        "filter_status": status,
        "filter_assigned": assigned,
        "filter_sla": sla,
        "filter_ordering": ordering,
        "severity_choices": severity_choices,
        "status_choices": status_choices,
        "assigned_choices": assigned_choices,
        "sla_choices": sla_choices,
        "query_string": query_string,
    }
    return render(request, "alerts/alert_list.html", context)


@login_required
def alert_detail(request, pk):
    """Alert detail page. Display only; no status/assignment changes."""
    err = _ensure_workspace(request)
    if err:
        return err

    alert = get_workspace_alert_detail(request.workspace, pk)

    assignment_candidates = get_workspace_members_for_assignment(request.workspace)
    all_events = list(alert.activity_logs.all())
    audit_events = all_events[:50]
    timeline_truncated = len(all_events) > 50
    first_ca = next(
        (ca for ca in alert.case_alerts.all() if ca.case and not ca.case.archived and ca.case.status != "CLOSED"),
        None,
    )
    related_case = first_ca.case if first_ca else None

    sla_flags = _sla_flags_from_alert(alert)
    created_str = timezone.localtime(alert.created_at).strftime("%b %d, %Y %H:%M")
    subtitle = f"Alert #{alert.pk} · {created_str}"

    role = get_role_code(request.user, alert.workspace)
    user_is_manager = is_manager(role)
    status_transitions = get_allowed_transitions(alert.status, is_manager=user_is_manager)
    locked_by_other = alert.locked_by_id is not None and alert.locked_by_id != request.user.pk
    locked_by_self = alert.locked_by_id == request.user.pk
    can_change_status_perm = _user_can_change_status(request.user, alert)
    can_assign_perm = _user_can_assign(request.user, alert)
    can_lock_perm = _user_can_lock(request.user, alert)

    context = {
        "page_title": alert.title,
        "alert": alert,
        "assignment_candidates": assignment_candidates,
        "audit_events": audit_events,
        "timeline_truncated": timeline_truncated,
        "related_case": related_case,
        "sla_flags": sla_flags,
        "subtitle": subtitle,
        "status_transitions": status_transitions,
        "locked_by_other": locked_by_other,
        "locked_by_self": locked_by_self,
        "can_change_status_perm": can_change_status_perm,
        "can_assign_perm": can_assign_perm,
        "can_lock_perm": can_lock_perm,
    }
    return render(request, "alerts/alert_detail.html", context)


@login_required
@require_POST
def alert_change_status(request, pk):
    """POST: Change alert status. Validates workspace, RBAC, lock. Calls service."""
    err = _ensure_workspace(request)
    if err:
        return err
    alert = get_workspace_alert_detail(request.workspace, pk)
    if not _user_can_change_status(request.user, alert):
        messages.error(request, "You cannot change status on this alert.")
        return redirect("alerts:detail", pk=pk)
    new_status = request.POST.get("status", "").strip()
    if not new_status or new_status not in [s.value for s in AlertStatus]:
        return redirect("alerts:detail", pk=pk)
    try:
        change_status(alert=alert, user=request.user, new_status=AlertStatus(new_status))
        messages.success(request, "Status updated.")
    except (PermissionError, ValueError) as e:
        messages.error(request, str(e) if str(e) else "Invalid status transition.")
    return redirect("alerts:detail", pk=pk)


@login_required
@require_POST
def alert_assign(request, pk):
    """POST: Assign alert to user. Validates workspace, RBAC, lock. Calls service."""
    err = _ensure_workspace(request)
    if err:
        return err
    alert = get_workspace_alert_detail(request.workspace, pk)
    if not _user_can_assign(request.user, alert):
        messages.error(request, "You cannot assign this alert.")
        return redirect("alerts:detail", pk=pk)
    user_id = request.POST.get("assigned_to", "").strip()
    if not user_id or not user_id.isdigit():
        return redirect("alerts:detail", pk=pk)
    target = get_user_model().objects.filter(pk=int(user_id)).first()
    if not target:
        return redirect("alerts:detail", pk=pk)
    members = get_workspace_members_for_assignment(request.workspace)
    member_ids = {m.user_id for m in members}
    if target.pk not in member_ids:
        messages.error(request, "Target user is not in this workspace.")
        return redirect("alerts:detail", pk=pk)
    try:
        assign_alert(alert=alert, assigner=request.user, target_user=target)
        messages.success(request, "Alert assigned.")
    except PermissionError as e:
        messages.error(request, str(e) if str(e) else "Assignment failed.")
    return redirect("alerts:detail", pk=pk)


@login_required
@require_POST
def alert_lock(request, pk):
    """POST: Lock alert. Validates workspace, RBAC. Calls service."""
    err = _ensure_workspace(request)
    if err:
        return err
    alert = get_workspace_alert_detail(request.workspace, pk)
    if not _user_can_lock(request.user, alert):
        messages.error(request, "You cannot lock this alert.")
        return redirect("alerts:detail", pk=pk)
    try:
        lock_alert(alert=alert, user=request.user)
        messages.success(request, "Alert locked.")
    except PermissionError as e:
        messages.error(request, str(e) if str(e) else "Lock failed.")
    return redirect("alerts:detail", pk=pk)


@login_required
@require_POST
def alert_unlock(request, pk):
    """POST: Unlock alert. Validates workspace, RBAC. Calls service."""
    err = _ensure_workspace(request)
    if err:
        return err
    alert = get_workspace_alert_detail(request.workspace, pk)
    if not _user_can_lock(request.user, alert):
        messages.error(request, "You cannot unlock this alert.")
        return redirect("alerts:detail", pk=pk)
    try:
        unlock_alert(alert=alert, user=request.user)
        messages.success(request, "Alert unlocked.")
    except PermissionError as e:
        messages.error(request, str(e) if str(e) else "Unlock failed.")
    return redirect("alerts:detail", pk=pk)

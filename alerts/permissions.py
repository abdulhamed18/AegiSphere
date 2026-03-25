"""
Centralized alert permission checks. Workspace isolation and role-based rules.

All checks use alert.workspace and role_hierarchy; no DB writes, no service calls.
Status values use AlertStatus enum.
"""

from alerts.enums import AlertStatus
from alerts.locking_policy import can_unlock
from alerts.role_hierarchy import get_role_code, is_manager


VIEWER_ROLE = "SOC_VIEWER"

FINAL_STATUSES = (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE)


def _user_in_workspace(user, workspace):
    """Return True if user has active membership in workspace."""
    role = get_role_code(user, workspace)
    return role is not None


def can_view_alert(user, alert):
    """
    Return True if user can view the alert. User must belong to alert.workspace.
    Viewers can only view (no other permissions).
    """
    if not user or not user.is_authenticated or alert is None:
        return False
    return _user_in_workspace(user, alert.workspace)


def can_assign_alert(user, alert):
    """
    Return True if user can assign this alert (to someone). User must be in
    alert.workspace and not a viewer.
    """
    if not user or not user.is_authenticated or alert is None:
        return False
    if not _user_in_workspace(user, alert.workspace):
        return False
    role = get_role_code(user, alert.workspace)
    return role is not None and role != VIEWER_ROLE


def can_change_status(user, alert):
    """
    Return True if user can change alert status. Only assigned analyst or manager.
    If alert is in final state (RESOLVED / FALSE_POSITIVE), only manager can change.
    """
    if not user or not user.is_authenticated or alert is None:
        return False
    if not _user_in_workspace(user, alert.workspace):
        return False
    role = get_role_code(user, alert.workspace)
    if role is None or role == VIEWER_ROLE:
        return False
    if alert.status in FINAL_STATUSES:
        return is_manager(role)
    is_assigned = alert.assigned_to_id == user.pk
    return is_assigned or is_manager(role)


def can_resolve_alert(user, alert):
    """
    Return True if user can resolve the alert (set to RESOLVED or FALSE_POSITIVE).
    Same rules as can_change_status for final transitions.
    """
    return can_change_status(user, alert)


def can_extend_sla(user, alert):
    """
    Return True if user can extend SLA. Only manager-level roles.
    """
    if not user or not user.is_authenticated or alert is None:
        return False
    if not _user_in_workspace(user, alert.workspace):
        return False
    role = get_role_code(user, alert.workspace)
    return is_manager(role)


def can_force_unlock(user, alert):
    """
    Return True if user can unlock the alert when it is locked by another user.
    Manager can override locks. No DB writes.
    """
    if not user or not user.is_authenticated or alert is None:
        return False
    if alert.locked_by_id is None or alert.locked_by_id == user.pk:
        return False
    return can_unlock(user, alert)

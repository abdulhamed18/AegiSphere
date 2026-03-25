"""
Phase 5 — Case Management
Step 2 — State Machine + Core Service Layer
Step 3 — SLA Engine

All case business logic lives here. Uses transaction.atomic() for all mutations.
Tenant isolation via case.workspace. Archived cases are locked.
"""

from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from alerts.assignment_policy import can_assign
from alerts.role_hierarchy import get_role_code, is_manager

from .models import (
    Case,
    CaseActivity,
    CaseAlert,
    CaseAttachment,
    CaseCollaborator,
    CaseIOC,
    CaseNote,
    CaseTag,
    CaseTask,
    CaseSeverity,
    CaseStatus,
    CaseIOCType,
)

# --- Activity Action Types (Step 4) ---

CASE_CREATED = "CASE_CREATED"
CASE_ASSIGNED = "CASE_ASSIGNED"
CASE_UNASSIGNED = "CASE_UNASSIGNED"
CASE_STATUS_CHANGED = "CASE_STATUS_CHANGED"
CASE_CLOSED = "CASE_CLOSED"
CASE_REOPENED = "CASE_REOPENED"
CASE_ARCHIVED = "CASE_ARCHIVED"
ALERT_ADDED = "ALERT_ADDED"
ALERT_REMOVED = "ALERT_REMOVED"
COLLABORATOR_ADDED = "COLLABORATOR_ADDED"
COLLABORATOR_REMOVED = "COLLABORATOR_REMOVED"
NOTE_ADDED = "NOTE_ADDED"
SLA_PAUSED = "SLA_PAUSED"
SLA_RESUMED = "SLA_RESUMED"
SLA_BREACHED = "SLA_BREACHED"
CASE_TASK_CREATED = "CASE_TASK_CREATED"
CASE_TASK_COMPLETED = "CASE_TASK_COMPLETED"
CASE_TASK_REOPENED = "CASE_TASK_REOPENED"
IOC_ADDED = "IOC_ADDED"
IOC_REMOVED = "IOC_REMOVED"
ATTACHMENT_ADDED = "ATTACHMENT_ADDED"
TAG_ADDED = "TAG_ADDED"
TAG_REMOVED = "TAG_REMOVED"
CASE_EXPORTED = "CASE_EXPORTED"

# --- Config ---

MAX_ATTACHMENT_SIZE_MB = 10
MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10MB in bytes

# --- SLA Policy (Step 3) ---

SLA_POLICY = {
    CaseSeverity.LOW: timedelta(days=5),
    CaseSeverity.MEDIUM: timedelta(days=3),
    CaseSeverity.HIGH: timedelta(days=1),
    CaseSeverity.CRITICAL: timedelta(hours=4),
}


# --- Custom Exceptions ---

class CasePermissionDenied(Exception):
    """Raised when actor lacks permission for the requested action."""

    pass


class CaseStateTransitionError(Exception):
    """Raised when invalid case status transition is attempted."""

    pass


class CaseValidationError(Exception):
    """Raised when case operation fails validation (e.g. close without alerts)."""

    pass


# --- Role mapping (L1/L2/L3/MANAGER) ---

L1_ROLES = ("SOC_TIER_1_ANALYST",)
L2_ROLES = ("SOC_TIER_2_ANALYST",)
L3_ROLES = ("SOC_TIER_3_ANALYST",)
MANAGER_ROLES = ("SOC_MANAGER", "ORG_OWNER", "PERSONAL_OWNER")


def _get_actor_role(actor, case):
    """Return role code for actor in case's workspace. None if not member."""
    if not actor or not actor.is_authenticated or case is None:
        return None
    return get_role_code(actor, case.workspace)


def _is_manager(role_code):
    """Return True if role is manager-level."""
    return is_manager(role_code) if role_code else False


def _user_in_workspace(user, workspace):
    """Return True if user has active membership in workspace."""
    return get_role_code(user, workspace) is not None


def _ensure_not_archived(case):
    """Raise CasePermissionDenied if case is archived."""
    if case.archived:
        raise CasePermissionDenied("Archived cases cannot be modified.")


def _ensure_case_modifiable(case):
    """Raise if case is archived or CLOSED. Use for task/IOC/attachment/tag/alert/collaborator mutations."""
    _ensure_not_archived(case)
    if case.status == CaseStatus.CLOSED:
        raise CasePermissionDenied("Closed cases cannot be modified.")


def _ensure_actor_in_workspace(actor, case):
    """Raise CasePermissionDenied if actor not in case workspace."""
    if not _user_in_workspace(actor, case.workspace):
        raise CasePermissionDenied("Actor is not a member of this workspace.")


# --- State Machine ---

VALID_TRANSITIONS = {
    CaseStatus.OPEN: [CaseStatus.IN_PROGRESS],
    CaseStatus.IN_PROGRESS: [CaseStatus.ON_HOLD, CaseStatus.RESOLVED],
    CaseStatus.ON_HOLD: [CaseStatus.IN_PROGRESS],
    CaseStatus.RESOLVED: [CaseStatus.CLOSED],
    CaseStatus.CLOSED: [],  # Immutable; reopen handled separately
}


def _can_transition(current_status, new_status, is_manager_user):
    """
    Return True if transition is valid.
    CLOSED is immutable for change_case_status; reopen uses reopen_case().
    """
    if current_status == new_status:
        return False
    current = (
        current_status
        if current_status in CaseStatus
        else CaseStatus(current_status)
        if isinstance(current_status, str) and current_status in [s.value for s in CaseStatus]
        else None
    )
    new = (
        new_status
        if new_status in CaseStatus
        else CaseStatus(new_status)
        if isinstance(new_status, str) and new_status in [s.value for s in CaseStatus]
        else None
    )
    if current is None or new is None:
        return False
    if current == CaseStatus.CLOSED:
        return False  # Reopen via reopen_case() only
    allowed = VALID_TRANSITIONS.get(current, [])
    return new in allowed


# --- Activity logging ---
#
# A single mutation may produce multiple audit entries.
# Each entry represents a distinct domain event.
# CASE_STATUS_CHANGED never includes SLA metadata.
# SLA_PAUSED / SLA_RESUMED never include status metadata.


def _log_case_activity(case, action_type, actor=None, metadata=None):
    """Create CaseActivity entry. Call only inside transaction."""
    CaseActivity.objects.create(
        case=case,
        actor=actor,
        action_type=action_type,
        metadata=metadata or {},
    )


# --- Permission: can change status ---

def _can_change_status(actor, case, actor_role):
    """L1/L2/L3: only if primary_assignee. MANAGER: always."""
    if actor_role == "SOC_VIEWER":
        return False
    if _is_manager(actor_role):
        return True
    return case.primary_assignee_id == actor.pk


# --- Permission: can add/remove alerts ---

def _can_add_remove_alerts(actor, case, actor_role):
    """Only primary_assignee or MANAGER."""
    if actor_role == "SOC_VIEWER":
        return False
    if _is_manager(actor_role):
        return True
    return case.primary_assignee_id == actor.pk


# --- Permission: can add collaborator ---

def _can_add_collaborator(actor, case, user_to_add, actor_role, target_role):
    """
    L1: cannot add.
    L2: can add L1 only, if primary_assignee.
    L3: can add L1 & L2, if primary_assignee.
    MANAGER: can add anyone.
    """
    if _is_manager(actor_role):
        return True
    if actor_role in L1_ROLES:
        return False
    if case.primary_assignee_id != actor.pk:
        return False
    if actor_role in L2_ROLES:
        return target_role in L1_ROLES
    if actor_role in L3_ROLES:
        return target_role in L1_ROLES or target_role in L2_ROLES
    return False


# --- Permission: can remove collaborator ---

def _can_modify_case_content(actor, case, actor_role):
    """Only primary_assignee or MANAGER. Used for tasks, IOCs, attachments, tags."""
    if actor_role == "SOC_VIEWER":
        return False
    if _is_manager(actor_role):
        return True
    return case.primary_assignee_id == actor.pk


def _can_remove_collaborator(actor, case, actor_role):
    """Only primary_assignee or MANAGER."""
    if actor_role == "SOC_VIEWER":
        return False
    if _is_manager(actor_role):
        return True
    return case.primary_assignee_id == actor.pk


# --- Service Functions ---

@transaction.atomic
def create_case(
    *,
    workspace,
    title,
    description,
    severity,
    priority,
    created_by,
):
    """
    Create a new case. All roles allowed. Status=OPEN.
    """
    if workspace is None:
        raise CaseValidationError("Workspace is required.")
    if not title or not title.strip():
        raise CaseValidationError("Title is required.")
    if created_by and not _user_in_workspace(created_by, workspace):
        raise CasePermissionDenied("Creator must be a member of the workspace.")

    now = timezone.now()
    severity_enum = severity if severity in CaseSeverity else CaseSeverity(severity)
    if severity_enum not in SLA_POLICY:
        raise CaseValidationError("Invalid severity for SLA calculation.")
    sla_delta = SLA_POLICY[severity_enum]
    sla_deadline = now + sla_delta

    case = Case.objects.create(
        workspace=workspace,
        title=title.strip(),
        description=description or "",
        severity=severity,
        priority=priority,
        status=CaseStatus.OPEN,
        created_by=created_by,
        sla_deadline=sla_deadline,
    )
    _log_case_activity(
        case,
        CASE_CREATED,
        actor=created_by,
        metadata={
            "actor_id": created_by.pk if created_by else None,
            "previous_value": None,
            "new_value": {"title": case.title},
            "extra": {},
        },
    )
    return case


@transaction.atomic
def assign_case(
    *,
    case,
    assigner,
    new_assignee,
):
    """
    Assign case to new_assignee. Validates L1/L2/L3/MANAGER assignment rules.
    Uses alerts.assignment_policy.can_assign.
    """
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(assigner, case.workspace)

    if new_assignee is not None:
        if not _user_in_workspace(new_assignee, case.workspace):
            raise CaseValidationError("Assignee must be a member of the workspace.")
            
        target_role = _get_actor_role(new_assignee, case)
        if target_role == "SOC_VIEWER":
            raise CaseValidationError("Viewer cannot be assigned to cases")
            
        if not can_assign(assigner, new_assignee, case.workspace):
            raise CasePermissionDenied("Assigner cannot assign to this user.")
    else:
        actor_role = _get_actor_role(assigner, case)
        if not _is_manager(actor_role):
            raise CasePermissionDenied("Only manager can unassign a case.")

    old_assignee_id = case.primary_assignee_id
    case.primary_assignee = new_assignee
    case.save(update_fields=["primary_assignee", "updated_at"])
    action = CASE_UNASSIGNED if new_assignee is None else CASE_ASSIGNED
    _log_case_activity(
        case,
        action,
        actor=assigner,
        metadata={
            "actor_id": assigner.pk,
            "previous_value": old_assignee_id,
            "new_value": new_assignee.pk if new_assignee else None,
            "extra": {},
        },
    )
    return case


@transaction.atomic
def change_case_status(
    *,
    case,
    actor,
    new_status,
):
    """
    Change case status. Validates state machine and permission.
    L1/L2/L3: only if primary_assignee. MANAGER: always.
    """
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    actor_role = _get_actor_role(actor, case)
    if actor_role is None:
        raise CasePermissionDenied("Actor is not a member of this workspace.")

    if not _can_change_status(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can change status.")

    current = case.status if case.status in CaseStatus else CaseStatus(case.status)
    new = new_status if new_status in CaseStatus else CaseStatus(new_status)
    if not _can_transition(current, new, _is_manager(actor_role)):
        raise CaseStateTransitionError(
            f"Invalid transition from {current} to {new}."
        )

    now = timezone.now()
    update_fields = ["status", "updated_at"]
    # CASE_STATUS_CHANGED: status transition only, no SLA metadata
    status_metadata = {
        "actor_id": actor.pk,
        "previous_value": current.value,
        "new_value": new.value,
        "extra": {},
    }

    if new == CaseStatus.CLOSED:
        case.closed_at = now
        update_fields.append("closed_at")

    if new == CaseStatus.ON_HOLD:
        if case.sla_deadline is not None:
            remaining_seconds = max(0, (case.sla_deadline - now).total_seconds())
            # SLA_PAUSED: SLA domain event only, no status metadata
            CaseActivity.objects.create(
                case=case,
                actor=actor,
                action_type=SLA_PAUSED,
                metadata={
                    "actor_id": actor.pk,
                    "previous_value": case.sla_deadline.isoformat(),
                    "new_value": None,
                    "extra": {"remaining_seconds": remaining_seconds},
                },
            )
            case.sla_deadline = None
            update_fields.append("sla_deadline")

    if current == CaseStatus.ON_HOLD and new == CaseStatus.IN_PROGRESS:
        last_pause = (
            case.activities.filter(action_type=SLA_PAUSED)
            .order_by("-created_at")
            .first()
        )
        remaining_seconds = None
        if last_pause and last_pause.metadata:
            raw = last_pause.metadata.get("remaining_seconds") or (
                last_pause.metadata.get("extra") or {}
            ).get("remaining_seconds")
            if raw is not None:
                try:
                    val = float(raw) if not isinstance(raw, (int, float)) else raw
                    if val >= 0:
                        remaining_seconds = val
                except (TypeError, ValueError):
                    pass
        # Fallback triggered due to missing or corrupt SLA_PAUSED metadata
        if remaining_seconds is None:
            pass  # will use severity-based recalculation below

        severity_enum = (
            case.severity if case.severity in CaseSeverity else CaseSeverity(case.severity)
        )
        if severity_enum not in SLA_POLICY:
            raise CaseValidationError("Invalid severity for SLA calculation.")
        if remaining_seconds is not None:
            case.sla_deadline = now + timedelta(seconds=remaining_seconds)
        else:
            case.sla_deadline = now + SLA_POLICY[severity_enum]
        case.sla_breached = False
        case.sla_breached_at = None
        update_fields.extend(["sla_deadline", "sla_breached", "sla_breached_at"])
        # SLA_RESUMED: SLA domain event only, no status metadata
        CaseActivity.objects.create(
            case=case,
            actor=actor,
            action_type=SLA_RESUMED,
            metadata={
                "actor_id": actor.pk,
                "previous_value": None,
                "new_value": case.sla_deadline.isoformat(),
                "extra": {},
            },
        )

    case.status = new
    case.save(update_fields=update_fields)
    _log_case_activity(case, CASE_STATUS_CHANGED, actor=actor, metadata=status_metadata)
    return case


@transaction.atomic
def close_case(
    *,
    case,
    actor,
    resolution_summary,
):
    """
    Close case. Requires: resolution_summary not empty, at least one alert,
    status=RESOLVED, assigned or manager.
    """
    _ensure_not_archived(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    if not resolution_summary or not str(resolution_summary).strip():
        raise CaseValidationError("Resolution summary is required to close a case.")

    actor_role = _get_actor_role(actor, case)
    if actor_role is None:
        raise CasePermissionDenied("Actor is not a member of this workspace.")

    if not _can_change_status(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can close.")

    if case.status != CaseStatus.RESOLVED:
        raise CaseValidationError("Case must be RESOLVED before closing.")

    alert_count = case.case_alerts.count()
    if alert_count < 1:
        raise CaseValidationError("Case must have at least one alert before closing.")

    now = timezone.now()
    old_status = case.status

    case.status = CaseStatus.CLOSED
    case.closed_at = now
    case.closed_by = actor
    case.resolution_summary = str(resolution_summary).strip()
    if case.reported_externally and case.reported_at is None:
        case.reported_at = now

    update_fields = [
        "status", "closed_at", "closed_by", "resolution_summary",
        "reported_at", "updated_at",
    ]
    case.save(update_fields=update_fields)

    _log_case_activity(
        case,
        CASE_STATUS_CHANGED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": old_status,
            "new_value": CaseStatus.CLOSED.value,
            "extra": {},
        },
    )
    _log_case_activity(
        case,
        CASE_CLOSED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": old_status,
            "new_value": CaseStatus.CLOSED.value,
            "extra": {"resolution_summary": case.resolution_summary},
        },
    )
    return case


@transaction.atomic
def reopen_case(
    *,
    case,
    actor,
):
    """
    Reopen closed case. Only MANAGER.
    """
    _ensure_not_archived(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    actor_role = _get_actor_role(actor, case)
    if not _is_manager(actor_role):
        raise CasePermissionDenied("Only manager can reopen a closed case.")

    if case.status != CaseStatus.CLOSED:
        raise CaseStateTransitionError("Only CLOSED cases can be reopened.")

    now = timezone.now()
    severity_enum = (
        case.severity if case.severity in CaseSeverity else CaseSeverity(case.severity)
    )
    if severity_enum not in SLA_POLICY:
        raise CaseValidationError("Invalid severity for SLA calculation.")
    sla_delta = SLA_POLICY[severity_enum]
    case.status = CaseStatus.IN_PROGRESS
    case.reopened_at = now
    case.sla_deadline = now + sla_delta
    case.sla_breached = False
    case.sla_breached_at = None
    case.save(
        update_fields=[
            "status",
            "reopened_at",
            "sla_deadline",
            "sla_breached",
            "sla_breached_at",
            "updated_at",
        ]
    )
    _log_case_activity(
        case,
        CASE_REOPENED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": None,
            "new_value": now.isoformat(),
            "extra": {},
        },
    )
    return case


@transaction.atomic
def add_alert_to_case(
    *,
    case,
    alert,
    actor,
):
    """
    Add alert to case. Workspace must match. Only assignee or manager.
    DB enforces one alert per case (unique on alert).
    """
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    if alert.workspace_id != case.workspace_id:
        raise CaseValidationError("Alert must belong to the same workspace as the case.")

    if CaseAlert.objects.filter(alert=alert).exists():
        raise CaseValidationError("Alert already linked to another case.")

    actor_role = _get_actor_role(actor, case)
    if not _can_add_remove_alerts(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can add alerts.")

    CaseAlert.objects.create(
        case=case,
        alert=alert,
        added_by=actor,
    )
    _log_case_activity(
        case,
        ALERT_ADDED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": None,
            "new_value": alert.pk,
            "extra": {},
        },
    )
    return case


@transaction.atomic
def remove_alert_from_case(
    *,
    case,
    alert,
    actor,
):
    """
    Remove alert from case. Only assignee or manager.
    """
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    actor_role = _get_actor_role(actor, case)
    if not _can_add_remove_alerts(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can remove alerts.")

    if case.case_alerts.count() <= 1:
        raise CaseValidationError("Case must always have at least one alert.")

    mapping = CaseAlert.objects.filter(case=case, alert=alert).first()
    if not mapping:
        raise CaseValidationError("Alert is not attached to this case.")

    mapping.delete()
    _log_case_activity(
        case,
        ALERT_REMOVED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": alert.pk,
            "new_value": None,
            "extra": {},
        },
    )
    return case


@transaction.atomic
def add_collaborator(
    *,
    case,
    actor,
    user_to_add,
):
    """
    Add collaborator. L1 cannot. L2/L3 limited by role hierarchy and assignee.
    MANAGER can add anyone.
    """
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)
    _ensure_actor_in_workspace(user_to_add, case.workspace)

    actor_role = _get_actor_role(actor, case)
    target_role = _get_actor_role(user_to_add, case)
    if not _can_add_collaborator(actor, case, user_to_add, actor_role, target_role):
        raise CasePermissionDenied("Actor cannot add this user as collaborator.")

    _, created = CaseCollaborator.objects.get_or_create(
        case=case,
        user=user_to_add,
        defaults={"added_by": actor},
    )
    if created:
        _log_case_activity(
            case,
            COLLABORATOR_ADDED,
            actor=actor,
            metadata={
                "actor_id": actor.pk,
                "previous_value": None,
                "new_value": user_to_add.pk,
                "extra": {},
            },
        )
    return case


@transaction.atomic
def remove_collaborator(
    *,
    case,
    actor,
    user_to_remove,
):
    """
    Remove collaborator. Only primary_assignee or MANAGER.
    """
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    actor_role = _get_actor_role(actor, case)
    if not _can_remove_collaborator(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can remove collaborators.")

    CaseCollaborator.objects.filter(case=case, user=user_to_remove).delete()
    _log_case_activity(
        case,
        COLLABORATOR_REMOVED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": user_to_remove.pk,
            "new_value": None,
            "extra": {},
        },
    )
    return case


@transaction.atomic
def add_note(
    *,
    case,
    actor,
    content,
    is_internal=True,
):
    """
    Add note to case. All workspace members can add notes.
    """
    _ensure_not_archived(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    if not content or not content.strip():
        raise CaseValidationError("Note content is required.")

    actor_role = _get_actor_role(actor, case)
    if actor_role == "SOC_VIEWER":
        raise CasePermissionDenied("Viewer cannot modify cases")

    CaseNote.objects.create(
        case=case,
        author=actor,
        content=content.strip(),
        is_internal=is_internal,
    )
    _log_case_activity(
        case,
        NOTE_ADDED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": None,
            "new_value": "note_created",
            "extra": {"is_internal": is_internal},
        },
    )
    return case


@transaction.atomic
def archive_case(
    *,
    case,
    actor,
):
    """
    Archive case. Only MANAGER. Archived cases are immutable.
    """
    _ensure_actor_in_workspace(actor, case.workspace)

    actor_role = _get_actor_role(actor, case)
    if not _is_manager(actor_role):
        raise CasePermissionDenied("Only manager can archive cases.")

    if case.archived:
        raise CaseValidationError("Case is already archived.")

    if case.status != CaseStatus.CLOSED:
        raise CaseValidationError("Case must be CLOSED before archiving.")

    now = timezone.now()
    case.archived = True
    case.archived_at = now
    case.save(update_fields=["archived", "archived_at", "updated_at"])
    _log_case_activity(
        case,
        CASE_ARCHIVED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": None,
            "new_value": now.isoformat(),
            "extra": {},
        },
    )
    return case


# --- Task governance (Step 5) ---

@transaction.atomic
def create_task(
    *,
    case,
    actor,
    title,
):
    """Create task. Only primary_assignee or MANAGER."""
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    actor_role = _get_actor_role(actor, case)
    if not _can_modify_case_content(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can create tasks.")

    if not title or not title.strip():
        raise CaseValidationError("Task title is required.")

    task = CaseTask.objects.create(
        case=case,
        title=title.strip(),
    )
    _log_case_activity(
        case,
        CASE_TASK_CREATED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": None,
            "new_value": {"task_id": task.pk, "title": task.title},
            "extra": {},
        },
    )
    return task


@transaction.atomic
def complete_task(
    *,
    case,
    actor,
    task,
):
    """Complete task. Only primary_assignee or MANAGER. Cannot complete already completed."""
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    if task.case_id != case.pk:
        raise CaseValidationError("Task does not belong to this case.")

    actor_role = _get_actor_role(actor, case)
    if not _can_modify_case_content(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can complete tasks.")

    if task.is_completed:
        raise CaseValidationError("Task is already completed.")

    now = timezone.now()
    task.is_completed = True
    task.completed_by = actor
    task.completed_at = now
    task.save(update_fields=["is_completed", "completed_by", "completed_at"])

    _log_case_activity(
        case,
        CASE_TASK_COMPLETED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": False,
            "new_value": True,
            "extra": {"task_id": task.pk, "completed_at": now.isoformat()},
        },
    )
    return task


@transaction.atomic
def reopen_task(
    *,
    case,
    actor,
    task,
):
    """Reopen completed task. Only primary_assignee or MANAGER. Reopen allowed only if completed."""
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    if task.case_id != case.pk:
        raise CaseValidationError("Task does not belong to this case.")

    actor_role = _get_actor_role(actor, case)
    if not _can_modify_case_content(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can reopen tasks.")

    if not task.is_completed:
        raise CaseValidationError("Only completed tasks can be reopened.")

    task.is_completed = False
    task.completed_by = None
    task.completed_at = None
    task.save(update_fields=["is_completed", "completed_by", "completed_at"])

    _log_case_activity(
        case,
        CASE_TASK_REOPENED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": True,
            "new_value": False,
            "extra": {"task_id": task.pk},
        },
    )
    return task


# --- IOC hardening (Step 5) ---

def _normalize_ioc_value(ioc_type, value):
    """Normalize IOC value: strip whitespace, lowercase for DOMAIN/EMAIL."""
    if not value:
        return value
    value = value.strip()
    if ioc_type in (CaseIOCType.DOMAIN, CaseIOCType.EMAIL):
        value = value.lower()
    return value


@transaction.atomic
def add_ioc(
    *,
    case,
    actor,
    type,
    value,
):
    """Add IOC. Only primary_assignee or MANAGER. Validates type, normalizes value."""
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    actor_role = _get_actor_role(actor, case)
    if not _can_modify_case_content(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can add IOCs.")

    try:
        type_enum = type if type in CaseIOCType else CaseIOCType(type)
    except (ValueError, TypeError):
        raise CaseValidationError("Invalid IOC type.")

    if not value or not str(value).strip():
        raise CaseValidationError("IOC value is required.")

    normalized = _normalize_ioc_value(type_enum, str(value))
    ioc = CaseIOC.objects.create(
        case=case,
        type=type_enum,
        value=normalized,
    )
    _log_case_activity(
        case,
        IOC_ADDED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": None,
            "new_value": {"ioc_id": ioc.pk, "type": type_enum, "value": normalized},
            "extra": {},
        },
    )
    return ioc


@transaction.atomic
def remove_ioc(
    *,
    case,
    actor,
    ioc,
):
    """Remove IOC. Only primary_assignee or MANAGER."""
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    if ioc.case_id != case.pk:
        raise CaseValidationError("IOC does not belong to this case.")

    actor_role = _get_actor_role(actor, case)
    if not _can_modify_case_content(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can remove IOCs.")

    ioc_data = {"ioc_id": ioc.pk, "type": ioc.type, "value": ioc.value}
    ioc.delete()
    _log_case_activity(
        case,
        IOC_REMOVED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": ioc_data,
            "new_value": None,
            "extra": {},
        },
    )
    return case


# --- Attachment hardening (Step 5) ---

@transaction.atomic
def add_attachment(
    *,
    case,
    actor,
    file,
    file_type="",
):
    """Add attachment. Only primary_assignee or MANAGER. Validates size (max 10MB)."""
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    actor_role = _get_actor_role(actor, case)
    if not _can_modify_case_content(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can add attachments.")

    if file is None:
        raise CaseValidationError("File is required.")
    if not hasattr(file, "size"):
        raise CaseValidationError("Invalid file object.")
    if file.size > MAX_ATTACHMENT_SIZE:
        raise CaseValidationError("File exceeds maximum allowed size (10MB).")

    attachment = CaseAttachment.objects.create(
        case=case,
        uploaded_by=actor,
        file=file,
        file_type=(file_type or "")[:100],
    )
    _log_case_activity(
        case,
        ATTACHMENT_ADDED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": None,
            "new_value": {"attachment_id": attachment.pk, "file_type": attachment.file_type},
            "extra": {},
        },
    )
    return attachment


# --- Tag enforcement (Step 5) ---

@transaction.atomic
def add_tag(
    *,
    case,
    actor,
    tag_name,
):
    """Add tag to case. Create tag if not exists. Only primary_assignee or MANAGER."""
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    actor_role = _get_actor_role(actor, case)
    if not _can_modify_case_content(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can add tags.")

    if not tag_name or not str(tag_name).strip():
        raise CaseValidationError("Tag name is required.")

    tag_name = str(tag_name).strip()
    tag, created = CaseTag.objects.get_or_create(
        workspace=case.workspace,
        name=tag_name,
    )
    if case.tags.filter(id=tag.id).exists():
        return case  # do not log duplicate event

    case.tags.add(tag)
    _log_case_activity(
        case,
        TAG_ADDED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": None,
            "new_value": {"tag_id": tag.pk, "tag_name": tag.name},
            "extra": {},
        },
    )
    return case


@transaction.atomic
def remove_tag(
    *,
    case,
    actor,
    tag_name,
):
    """Remove tag from case. Only primary_assignee or MANAGER."""
    _ensure_case_modifiable(case)
    _ensure_actor_in_workspace(actor, case.workspace)

    actor_role = _get_actor_role(actor, case)
    if not _can_modify_case_content(actor, case, actor_role):
        raise CasePermissionDenied("Only primary assignee or manager can remove tags.")

    tag = case.tags.filter(name=tag_name.strip()).first()
    if not tag:
        raise CaseValidationError("Tag is not assigned to this case.")

    case.tags.remove(tag)
    _log_case_activity(
        case,
        TAG_REMOVED,
        actor=actor,
        metadata={
            "actor_id": actor.pk,
            "previous_value": {"tag_id": tag.pk, "tag_name": tag.name},
            "new_value": None,
            "extra": {},
        },
    )
    return case


# --- SLA Breach Detection (Step 3) ---

@transaction.atomic
def check_case_sla_breaches():
    """
    Detect and mark SLA breaches for active cases.
    Returns count of newly breached cases.
    """
    now = timezone.now()
    from core.models import Workspace
    
    count = 0
    for workspace in Workspace.objects.all():
        breached = Case.objects.filter(
            workspace=workspace,
            archived=False,
        ).exclude(
            status=CaseStatus.CLOSED,
        ).filter(
            sla_breached=False,
            sla_deadline__isnull=False,
            sla_deadline__lt=now,
        )

        for case in breached:
            old_deadline = case.sla_deadline
            case.sla_breached = True
            case.sla_breached_at = now
            case.save(update_fields=["sla_breached", "sla_breached_at", "updated_at"])
            CaseActivity.objects.create(
                case=case,
                actor=None,
                action_type=SLA_BREACHED,
                metadata={
                    "actor_id": None,
                    "previous_value": old_deadline.isoformat(),
                    "new_value": now.isoformat(),
                    "extra": {},
                },
            )
            count += 1

    return count

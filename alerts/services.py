"""
Alert mutation service layer. All alert DB writes and activity logging live here.

Uses permission layer, assignment_policy, status_transitions, sla_utils, locking_policy.
All mutations run inside transaction.atomic(). Workspace isolation enforced.
"""

import hashlib
import uuid
import logging

from datetime import timedelta
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

logger = logging.getLogger(__name__)

from alerts.assignment_policy import can_assign
from alerts.enums import AlertActivityType, AlertCategory, AlertPriority, AlertSeverity, AlertStatus
from alerts.lock_utils import should_auto_unlock
from alerts.locking_policy import can_lock, can_unlock
from alerts.models import Alert, AlertActivityLog, AlertSuppressionRule
from alerts.permissions import can_assign_alert, can_change_status, can_extend_sla, can_force_unlock
from alerts.role_hierarchy import get_role_code, is_manager
from alerts.sla_utils import calculate_sla_deadline
from alerts.status_transitions import can_transition
from core.models import Workspace


def _log_activity(alert, action_type, actor=None, metadata=None):
    """Create AlertActivityLog entry. Call only inside transaction."""
    AlertActivityLog.objects.create(
        workspace=alert.workspace,
        alert=alert,
        actor=actor,
        action_type=action_type,
        metadata=metadata or {},
    )


def _calculate_risk_score(severity, asset_importance=None):
    """
    Base: CRITICAL=80, HIGH=60, MEDIUM=40, LOW=20.
    If asset_importance == 'HIGH' add 10. Clamp to max 100.
    """
    base = {
        AlertSeverity.CRITICAL: 80,
        AlertSeverity.HIGH: 60,
        AlertSeverity.MEDIUM: 40,
        AlertSeverity.LOW: 20,
    }.get(severity if severity in list(AlertSeverity) else AlertSeverity(severity), 40)
    score = base + (10 if asset_importance == "HIGH" else 0)
    return min(100, score)


def _calculate_priority(severity, risk_score):
    """Derive priority from risk_score: >=90 URGENT, >=70 HIGH, >=40 MEDIUM, else LOW."""
    if risk_score is None:
        risk_score = 40
    if risk_score >= 90:
        return AlertPriority.URGENT
    if risk_score >= 70:
        return AlertPriority.HIGH
    if risk_score >= 40:
        return AlertPriority.MEDIUM
    return AlertPriority.LOW


def create_alert(
    *,
    workspace,
    title,
    description,
    source,
    severity,
    created_by=None,
    source_event_id=None,
    correlation_id=None,
    category=None,
    mitre_technique=None,
    asset_importance=None,
    raw_event_payload=None,
    normalized_data=None,
    fingerprint=None,
    normalized_event=None,
):
    """
    Create a new alert in the workspace. Status=OPEN, SLA from severity.
    Applies risk/priority, fingerprint, duplicate detection, suppression, correlation_group_id.
    Returns existing alert if duplicate; None if suppressed; new alert otherwise.
    """
    if workspace is None or not isinstance(workspace, Workspace):
        raise ValueError("Invalid workspace")

    if severity in list(AlertSeverity):
        severity_enum = severity
    elif isinstance(severity, str) and severity in [s.value for s in AlertSeverity]:
        severity_enum = AlertSeverity(severity)
    else:
        raise ValueError(f"Invalid severity: {severity}")

    if fingerprint is None:
        payload = f"{workspace.pk}|{source}|{severity_enum.value}|{title}|{mitre_technique or ''}"
        fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    now = timezone.now()
    
    # Phase 6: Suppression Engine
    for rule in AlertSuppressionRule.objects.filter(workspace=workspace, enabled=True):
        # Match incoming alert to rule criteria
        if rule.rule_name and rule.rule_name not in source and rule.rule_name not in title:
            continue
        if rule.category and rule.category not in (category, getattr(category, "value", category)):
            continue
        
        group_val = None
        if raw_event_payload and isinstance(raw_event_payload, dict):
            if rule.event_type and raw_event_payload.get('event_type') != rule.event_type:
                continue
            if rule.group_by:
                group_val = raw_event_payload.get(rule.group_by) or raw_event_payload.get('group_value')
            
        window_start = now - timedelta(seconds=rule.suppression_window_seconds)
        
        query = Alert.objects.filter(
            workspace=workspace,
            created_at__gte=window_start
        ).order_by('-created_at')
        
        if rule.category:
            query = query.filter(category=rule.category)
            
        suppress = False
        for ex_alert in query:
            if rule.rule_name and rule.rule_name not in ex_alert.source and rule.rule_name not in ex_alert.title:
                continue
                
            if group_val:
                sim_payload = ex_alert.raw_event_payload or {}
                sim_val = sim_payload.get(rule.group_by) or sim_payload.get('group_value')
                if sim_val != group_val:
                    continue
                    
            suppress = True
            break
            
        if suppress:
            logger.info(f"suppressed alerts: Alert {title} suppressed by rule {rule.name}")
            return None

    existing = Alert.objects.filter(
        workspace=workspace,
        fingerprint=fingerprint,
        status__in=[AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.IN_PROGRESS],
        is_deleted=False,
    ).first()

    if existing:
        now = timezone.now()
        with transaction.atomic():
            existing.occurrence_count += 1
            existing.last_seen_at = now
            existing.updated_at = now
            existing.save(
                update_fields=[
                    "occurrence_count",
                    "last_seen_at",
                    "updated_at",
                ]
            )
            _log_activity(
                existing,
                AlertActivityType.DUPLICATE_MERGED,
                actor=created_by,
                metadata={"duplicate_incremented": True},
            )
        logger.info(f"deduplicated alerts: Alert {title} merged into existing alert {existing.id}. New count: {existing.occurrence_count}")
        return existing

    now = timezone.now()
    risk_score = _calculate_risk_score(severity_enum, asset_importance)
    priority = _calculate_priority(severity_enum, risk_score)
    correlation_group_id = uuid.uuid4()
    sla_deadline = calculate_sla_deadline(severity_enum)
    if category is not None and (
        category in list(AlertCategory)
        or (isinstance(category, str) and category in [c.value for c in AlertCategory])
    ):
        category_enum = category if category in list(AlertCategory) else AlertCategory(category)
    else:
        category_enum = AlertCategory.OTHER  # backward compatibility when category not provided

    with transaction.atomic():
        alert = Alert.objects.create(
            workspace=workspace,
            title=title,
            description=description,
            source=source,
            severity=severity_enum,
            status=AlertStatus.OPEN,
            source_event_id=source_event_id or None,
            correlation_id=correlation_id,
            sla_deadline=sla_deadline,
            priority=priority,
            risk_score=risk_score,
            category=category_enum,
            mitre_technique=mitre_technique or None,
            fingerprint=fingerprint,
            correlation_group_id=correlation_group_id,
            first_seen_at=now,
            last_seen_at=now,
            occurrence_count=1,
            normalized_event=normalized_event,
            raw_event_payload=raw_event_payload,
            normalized_data=normalized_data,
        )
        _log_activity(alert, AlertActivityType.CREATED, actor=created_by)
    return alert


def assign_alert(
    *,
    alert,
    assigner,
    target_user,
):
    """
    Assign alert to target_user. Validates assigner permission and assignment policy.
    Sets assigned_to, assigned_by, assigned_at. Logs ASSIGNED.
    """
    if alert is None or assigner is None or target_user is None:
        raise ValueError("alert, assigner, and target_user are required")

    if not can_assign_alert(assigner, alert):
        raise PermissionError("Assigner does not have permission to assign this alert")
    if not can_assign(assigner, target_user, alert.workspace):
        raise PermissionError("Assignment to this user is not allowed")
    if alert.locked_by_id is not None and alert.locked_by_id != assigner.pk:
        assigner_role = get_role_code(assigner, alert.workspace)
        if not is_manager(assigner_role):
            raise PermissionError("Cannot assign locked alert")

    now = timezone.now()
    with transaction.atomic():
        alert.assigned_to = target_user
        alert.assigned_by = assigner
        alert.assigned_at = now
        alert.save(update_fields=["assigned_to", "assigned_by", "assigned_at", "updated_at"])
        _log_activity(
            alert,
            AlertActivityType.ASSIGNED,
            actor=assigner,
            metadata={"assigned_to": target_user.pk},
        )
    return alert


def change_status(
    *,
    alert,
    user,
    new_status,
):
    """
    Change alert status. Validates permission and allowed transition.
    On RESOLVED/FALSE_POSITIVE sets resolved_at and clears lock. Logs STATUS_CHANGED.
    """
    if alert is None or user is None:
        raise ValueError("alert and user are required")
    if new_status not in list(AlertStatus):
        raise ValueError(f"Invalid status: {new_status}")

    if not can_change_status(user, alert):
        raise PermissionError("User does not have permission to change status on this alert")

    role = get_role_code(user, alert.workspace)
    manager = is_manager(role)
    if alert.locked_by_id is not None and alert.locked_by_id != user.pk and not manager:
        raise PermissionError("Alert is locked by another user")
    if alert.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE) and not manager:
        raise PermissionError("Final state alerts cannot be modified")

    current_status = (
        alert.status
        if alert.status in list(AlertStatus)
        else AlertStatus(alert.status)
        if isinstance(alert.status, str) and alert.status in [s.value for s in AlertStatus]
        else alert.status
    )
    if not can_transition(current_status, new_status, is_manager=manager):
        raise ValueError(f"Transition from {alert.status} to {new_status} is not allowed")

    now = timezone.now()
    update_fields = ["status", "updated_at"]
    if new_status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
        alert.resolved_at = now
        update_fields.append("resolved_at")
        if alert.locked_by_id is not None:
            alert.locked_by = None
            alert.locked_at = None
            update_fields.extend(["locked_by", "locked_at"])
    if new_status == AlertStatus.ACKNOWLEDGED:
        alert.acknowledged_at = now
        update_fields.append("acknowledged_at")
    if new_status == AlertStatus.REOPENED:
        alert.resolved_at = None
        update_fields.append("resolved_at")

    with transaction.atomic():
        alert.status = new_status
        alert.save(update_fields=update_fields)
        _log_activity(alert, AlertActivityType.STATUS_CHANGED, actor=user)
    return alert


def resolve_alert(
    *,
    alert,
    user,
):
    """Shortcut: set alert status to RESOLVED."""
    return change_status(alert=alert, user=user, new_status=AlertStatus.RESOLVED)


def mark_false_positive(
    *,
    alert,
    user,
):
    """Shortcut: set alert status to FALSE_POSITIVE."""
    return change_status(alert=alert, user=user, new_status=AlertStatus.FALSE_POSITIVE)


def acknowledge_alert(
    *,
    alert,
    user,
):
    """
    Acknowledge alert: OPEN → ACKNOWLEDGED. Sets acknowledged_at.
    Validates can_change_status; only allowed when current status is OPEN.
    """
    if alert is None or user is None:
        raise ValueError("alert and user are required")

    if not can_change_status(user, alert):
        raise PermissionError("User does not have permission to change status on this alert")

    current = (
        alert.status
        if alert.status in list(AlertStatus)
        else AlertStatus(alert.status)
        if isinstance(alert.status, str) and alert.status in [s.value for s in AlertStatus]
        else alert.status
    )
    if current != AlertStatus.OPEN:
        raise ValueError("Only OPEN alerts can be acknowledged")

    now = timezone.now()
    with transaction.atomic():
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_at = now
        alert.save(update_fields=["status", "acknowledged_at", "updated_at"])
        _log_activity(alert, AlertActivityType.STATUS_CHANGED, actor=user)
    return alert


def soft_delete_alert(
    *,
    alert,
    user,
):
    """
    Soft-delete alert (15-day bin foundation). Only manager or assigned analyst.
    Sets is_deleted=True, deleted_at=now(). Cannot delete already deleted.
    """
    if alert is None or user is None:
        raise ValueError("alert and user are required")

    if alert.is_deleted:
        raise ValueError("Alert is already deleted")

    role = get_role_code(user, alert.workspace)
    if role is None:
        raise PermissionError("User is not in this workspace")
    if not (is_manager(role) or alert.assigned_to_id == user.pk):
        raise PermissionError("Only manager or assigned analyst can soft-delete this alert")

    now = timezone.now()
    with transaction.atomic():
        alert.is_deleted = True
        alert.deleted_at = now
        alert.save(update_fields=["is_deleted", "deleted_at", "updated_at"])
        _log_activity(
            alert,
            AlertActivityType.STATUS_CHANGED,
            actor=user,
            metadata={"soft_deleted": True},
        )
    return alert


def restore_alert(
    *,
    alert,
    user,
):
    """
    Restore soft-deleted alert. Only manager. Sets is_deleted=False, deleted_at=None.
    """
    if alert is None or user is None:
        raise ValueError("alert and user are required")

    if not alert.is_deleted:
        raise ValueError("Alert is not deleted")

    role = get_role_code(user, alert.workspace)
    if role is None or not is_manager(role):
        raise PermissionError("Only manager can restore this alert")

    with transaction.atomic():
        alert.is_deleted = False
        alert.deleted_at = None
        alert.save(update_fields=["is_deleted", "deleted_at", "updated_at"])
        _log_activity(
            alert,
            AlertActivityType.STATUS_CHANGED,
            actor=user,
            metadata={"restored": True},
        )
    return alert


def suppress_alert(
    *,
    alert,
    user,
    until_datetime=None,
):
    """
    Temporarily suppress (mute) an existing alert. Only manager.
    Sets is_suppressed=True, suppressed_by=user, suppressed_until=until_datetime.
    """
    if alert is None or user is None:
        raise ValueError("alert and user are required")

    role = get_role_code(user, alert.workspace)
    if role is None or not is_manager(role):
        raise PermissionError("Only manager can suppress this alert")

    with transaction.atomic():
        alert.is_suppressed = True
        alert.suppressed_by = user
        alert.suppressed_until = until_datetime
        alert.save(
            update_fields=["is_suppressed", "suppressed_by", "suppressed_until", "updated_at"]
        )
        _log_activity(
            alert,
            AlertActivityType.STATUS_CHANGED,
            actor=user,
            metadata={"suppressed": True},
        )
    return alert


def unsuppress_alert(
    *,
    alert,
    user,
):
    """Clear suppression on alert. Only manager."""
    if alert is None or user is None:
        raise ValueError("alert and user are required")

    role = get_role_code(user, alert.workspace)
    if role is None or not is_manager(role):
        raise PermissionError("Only manager can unsuppress this alert")

    with transaction.atomic():
        alert.is_suppressed = False
        alert.suppressed_by = None
        alert.suppressed_until = None
        alert.save(
            update_fields=["is_suppressed", "suppressed_by", "suppressed_until", "updated_at"]
        )
        _log_activity(
            alert,
            AlertActivityType.STATUS_CHANGED,
            actor=user,
            metadata={"unsuppressed": True},
        )
    return alert


def escalate_alert(
    *,
    alert,
    user,
):
    """
    Escalate alert. Only manager. Increments escalation_level, sets escalated_at, escalated_by.
    """
    if alert is None or user is None:
        raise ValueError("alert and user are required")

    role = get_role_code(user, alert.workspace)
    if role is None or not is_manager(role):
        raise PermissionError("Only manager can escalate this alert")

    now = timezone.now()
    new_level = (alert.escalation_level or 0) + 1
    with transaction.atomic():
        alert.escalation_level = new_level
        alert.escalated_at = now
        alert.escalated_by = user
        alert.save(
            update_fields=["escalation_level", "escalated_at", "escalated_by", "updated_at"]
        )
        _log_activity(
            alert,
            AlertActivityType.STATUS_CHANGED,
            actor=user,
            metadata={"escalated_to": new_level},
        )
    return alert


def reopen_alert(
    *,
    alert,
    user,
):
    """
    Reopen a resolved/false-positive alert. Only manager.
    Sets status=REOPENED, clears resolved_at, recalculates SLA.
    Escalation metadata intentionally preserved. Reopening does not reset escalation history.
    """
    if alert is None or user is None:
        raise ValueError("alert and user are required")

    role = get_role_code(user, alert.workspace)
    if role is None or not is_manager(role):
        raise PermissionError("Only manager can reopen this alert")

    current = (
        alert.status
        if alert.status in list(AlertStatus)
        else AlertStatus(alert.status)
        if isinstance(alert.status, str) and alert.status in [s.value for s in AlertStatus]
        else alert.status
    )
    if current not in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
        raise ValueError("Only RESOLVED or FALSE_POSITIVE alerts can be reopened")

    # Escalation metadata intentionally preserved. Reopening does not reset escalation history.
    new_sla_deadline = calculate_sla_deadline(alert.severity)
    with transaction.atomic():
        alert.status = AlertStatus.REOPENED
        alert.resolved_at = None
        alert.sla_deadline = new_sla_deadline
        alert.save(update_fields=["status", "resolved_at", "sla_deadline", "updated_at"])
        _log_activity(
            alert,
            AlertActivityType.STATUS_CHANGED,
            actor=user,
            metadata={"reopened": True, "sla_reset": True, "escalation_preserved": True},
        )
    return alert


def permanently_delete_alert(
    *,
    alert,
    user,
):
    """
    Permanently delete a soft-deleted alert. Only manager. Logs then deletes.
    All mutations and deletion happen inside transaction.atomic().
    """
    if alert is None or user is None:
        raise ValueError("alert and user are required")

    if not alert.is_deleted:
        raise ValueError("Alert must be soft-deleted before permanent deletion")

    role = get_role_code(user, alert.workspace)
    if role is None or not is_manager(role):
        raise PermissionError("Only manager can permanently delete this alert")

    with transaction.atomic():
        _log_activity(
            alert,
            AlertActivityType.STATUS_CHANGED,
            actor=user,
            metadata={"permanently_deleted": True},
        )
        alert.delete()
    return None


def bulk_assign(
    *,
    alert_ids,
    assigner,
    target_user,
    workspace,
):
    """
    Assign multiple alerts. Reuses assign_alert. PermissionError per alert skips that alert.
    Returns {"success": [ids], "failed": [ids]}. Fetches alerts in one query for efficiency.
    """
    success = []
    failed = []
    ids = list(alert_ids or [])
    if not ids:
        return {"success": success, "failed": failed}
    alerts_by_id = {
        a.pk: a
        for a in Alert.objects.filter(id__in=ids, workspace=workspace).select_related("workspace")
    }
    with transaction.atomic():
        for aid in ids:
            try:
                alert = alerts_by_id.get(aid)
                if alert is None:
                    failed.append(aid)
                    continue
                assign_alert(alert=alert, assigner=assigner, target_user=target_user)
                success.append(aid)
            except PermissionError:
                failed.append(aid)
    return {"success": success, "failed": failed}


def bulk_resolve(
    *,
    alert_ids,
    user,
    workspace,
):
    """
    Resolve multiple alerts. Reuses resolve_alert. PermissionError per alert skips that alert.
    Returns {"success": [ids], "failed": [ids]}. Fetches alerts in one query for efficiency.
    """
    success = []
    failed = []
    ids = list(alert_ids or [])
    if not ids:
        return {"success": success, "failed": failed}
    alerts_by_id = {
        a.pk: a
        for a in Alert.objects.filter(id__in=ids, workspace=workspace).select_related("workspace")
    }
    with transaction.atomic():
        for aid in ids:
            try:
                alert = alerts_by_id.get(aid)
                if alert is None:
                    failed.append(aid)
                    continue
                resolve_alert(alert=alert, user=user)
                success.append(aid)
            except (PermissionError, ValueError):
                failed.append(aid)
    return {"success": success, "failed": failed}


def lock_alert(
    *,
    alert,
    user,
):
    """
    Lock alert for the user. If lock is expired (should_auto_unlock), clear it first.
    If locked by another user, raise PermissionError. Logs LOCKED.
    """
    if alert is None or user is None:
        raise ValueError("alert and user are required")

    if not can_lock(user, alert):
        raise PermissionError("User does not have permission to lock this alert")

    if alert.locked_by_id is not None and alert.locked_by_id != user.pk:
        if not should_auto_unlock(alert):
            raise PermissionError("Alert is locked by another user")

    now = timezone.now()
    with transaction.atomic():
        if should_auto_unlock(alert):
            previous_locker = alert.locked_by
            _log_activity(
                alert,
                AlertActivityType.UNLOCKED,
                actor=previous_locker,
                metadata={"auto_unlocked": True},
            )
            alert.locked_by = None
            alert.locked_at = None
        alert.locked_by = user
        alert.locked_at = now
        alert.save(update_fields=["locked_by", "locked_at", "updated_at"])
        _log_activity(alert, AlertActivityType.LOCKED, actor=user)
    return alert


def unlock_alert(
    *,
    alert,
    user,
    force=False,
):
    """
    Unlock the alert. If force=True, validate can_force_unlock; else can_unlock.
    Clears locked_by and locked_at. Logs UNLOCKED.
    """
    if alert is None or user is None:
        raise ValueError("alert and user are required")

    if force:
        if not can_force_unlock(user, alert):
            raise PermissionError("User does not have permission to force unlock this alert")
    else:
        if not can_unlock(user, alert):
            raise PermissionError("User does not have permission to unlock this alert")

    with transaction.atomic():
        alert.locked_by = None
        alert.locked_at = None
        alert.save(update_fields=["locked_by", "locked_at", "updated_at"])
        _log_activity(alert, AlertActivityType.UNLOCKED, actor=user)
    return alert


def extend_sla(
    *,
    alert,
    user,
    new_deadline,
):
    """
    Extend alert SLA deadline. Validates can_extend_sla and new_deadline > current.
    Logs SLA_EXTENDED with new_deadline in metadata.
    """
    if alert is None or user is None:
        raise ValueError("alert and user are required")
    if new_deadline is None:
        raise ValueError("new_deadline is required")

    if not can_extend_sla(user, alert):
        raise PermissionError("User does not have permission to extend SLA on this alert")

    current = alert.sla_deadline or timezone.now()
    if new_deadline <= current:
        raise ValueError("new_deadline must be after current deadline")

    with transaction.atomic():
        alert.sla_deadline = new_deadline
        alert.save(update_fields=["sla_deadline", "updated_at"])
        _log_activity(
            alert,
            AlertActivityType.SLA_EXTENDED,
            actor=user,
            metadata={"new_deadline": str(new_deadline)},
        )
    return alert



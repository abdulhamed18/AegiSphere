"""
Lock access rules for alerts. Defines who can lock/unlock and lock ownership.

Pure boolean decisions. No DB writes.
"""

from alerts.role_hierarchy import get_role_code, is_manager


def can_lock(user, alert):
    """
    Return True if user is allowed to lock the alert.
    If alert is not locked, allow. If locked by same user, allow (idempotent).
    If locked by another user, deny (unless manager can force-unlock; lock is separate).
    """
    if not user or not user.is_authenticated or alert is None:
        return False
    if alert.locked_by_id is None:
        return True
    return alert.locked_by_id == user.pk


def can_unlock(user, alert):
    """
    Return True if user is allowed to unlock the alert.
    If not locked, allow. If locked by same user, allow. If locked by other, only manager can unlock.
    """
    if not user or not user.is_authenticated or alert is None:
        return False
    if alert.locked_by_id is None:
        return True
    if alert.locked_by_id == user.pk:
        return True
    role = get_role_code(user, alert.workspace)
    return is_manager(role)


def is_locked_by_other(user, alert):
    """
    Return True if the alert is locked by someone other than user.
    """
    if alert is None or alert.locked_by_id is None:
        return False
    if user is None or not user.is_authenticated:
        return True
    return alert.locked_by_id != user.pk

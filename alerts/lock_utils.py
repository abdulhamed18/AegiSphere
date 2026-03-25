"""
Lock expiration infrastructure. Boolean helpers only; no DB writes or auto-unlock.

Used by future services to decide when a lock is expired or should be auto-unlocked.
"""

from datetime import timedelta

from django.utils import timezone


LOCK_TIMEOUT_MINUTES = 30


def is_lock_expired(alert, reference_time=None):
    """
    Return True only if a lock exists and has been held longer than LOCK_TIMEOUT_MINUTES.
    If no lock (locked_by_id or locked_at is None), return False.
    If reference_time is None, use timezone.now(). No DB writes.
    """
    if alert is None or alert.locked_by_id is None or alert.locked_at is None:
        return False
    if reference_time is None:
        reference_time = timezone.now()
    elapsed = reference_time - alert.locked_at
    return elapsed > timedelta(minutes=LOCK_TIMEOUT_MINUTES)


def should_auto_unlock(alert, reference_time=None):
    """
    Return True if the alert is locked (locked_by is set) and the lock is expired.
    Does not perform any unlock; callers use this to decide whether to unlock.
    No DB writes.
    """
    if alert is None or alert.locked_by_id is None:
        return False
    return is_lock_expired(alert, reference_time)

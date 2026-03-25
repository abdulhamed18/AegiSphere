"""
Allowed Alert status transitions. Pure validator for use by future services.

No DB writes. Uses AlertStatus enum.
"""

from alerts.enums import AlertStatus


ALLOWED_TRANSITIONS = {
    AlertStatus.OPEN: [AlertStatus.ACKNOWLEDGED],
    AlertStatus.ACKNOWLEDGED: [AlertStatus.IN_PROGRESS],
    AlertStatus.IN_PROGRESS: [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE],
    AlertStatus.RESOLVED: [AlertStatus.REOPENED],
    AlertStatus.FALSE_POSITIVE: [AlertStatus.REOPENED],
    AlertStatus.REOPENED: [AlertStatus.ACKNOWLEDGED],
}

FINAL_STATUSES = (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE)


def can_transition(current_status, new_status, is_manager=False):
    """
    Return True if transition from current_status to new_status is allowed.
    RESOLVED/FALSE_POSITIVE → REOPENED requires is_manager=True.
    RESOLVED/FALSE_POSITIVE → OPEN (legacy) requires is_manager=True.
    """
    if current_status == new_status:
        return False
    if new_status not in list(AlertStatus):
        return False
    allowed = ALLOWED_TRANSITIONS.get(current_status, [])
    if new_status in allowed:
        if new_status == AlertStatus.REOPENED and current_status in FINAL_STATUSES:
            return is_manager
        return True
    if current_status in FINAL_STATUSES and is_manager and new_status == AlertStatus.OPEN:
        return True
    return False


def get_allowed_transitions(current_status, is_manager=False):
    """
    Return list of (value, label) for valid target statuses.
    Used by UI to show only available transitions in dropdown.
    Accepts current_status as enum or string.
    """
    if isinstance(current_status, str) and current_status in [s.value for s in AlertStatus]:
        current_status = AlertStatus(current_status)
    result = []
    for s in list(AlertStatus):
        if can_transition(current_status, s, is_manager=is_manager):
            result.append((s.value, s.label))
    return result

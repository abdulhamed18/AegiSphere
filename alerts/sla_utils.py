"""
Central SLA definitions and calculations. Pure, stateless, no DB writes.

Used by future services for deadline calculation and breach detection.
"""

from datetime import timedelta

from django.utils import timezone

from alerts.enums import AlertSeverity, AlertStatus


SLA_RULES = {
    AlertSeverity.CRITICAL: timedelta(hours=1),
    AlertSeverity.HIGH: timedelta(hours=8),
    AlertSeverity.MEDIUM: timedelta(hours=24),
    AlertSeverity.LOW: timedelta(hours=72),
}

FINAL_STATUSES = (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE)


def calculate_sla_deadline(severity, reference_time=None):
    """
    Return reference_time + SLA duration for the given severity.
    If reference_time is None, use timezone.now().
    Raises ValueError if severity is not in SLA_RULES.
    No DB writes, no model mutation.
    """
    if severity not in SLA_RULES:
        raise ValueError(f"Unknown severity for SLA: {severity}")
    if reference_time is None:
        reference_time = timezone.now()
    return reference_time + SLA_RULES[severity]


def is_sla_breached(alert, reference_time=None):
    """
    Return True if the alert has passed its SLA deadline and is not in a final state.
    If alert.sla_deadline is None, return False. If status is RESOLVED or FALSE_POSITIVE, return False.
    If reference_time is None, use timezone.now(). Pure boolean.
    """
    if alert is None or alert.sla_deadline is None:
        return False
    if alert.status in FINAL_STATUSES:
        return False
    if reference_time is None:
        reference_time = timezone.now()
    return reference_time > alert.sla_deadline

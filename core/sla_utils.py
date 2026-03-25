"""
DB-agnostic SLA near-breach logic.
Uses remaining = sla_deadline - Now(), total = sla_deadline - created_at,
ratio = remaining / total < SLA_NEAR_BREACH_RATIO.
Works on SQLite and PostgreSQL via vendor-aware RawSQL.
"""

from django.db import connection
from django.db.models.expressions import RawSQL

from core.sla_constants import SLA_NEAR_BREACH_RATIO


# Resolved status literals (safe, not user input)
_ALERT_RESOLVED_SQL = "('RESOLVED','FALSE_POSITIVE')"
_CASE_RESOLVED_SQL = "('RESOLVED','CLOSED')"


def sla_near_breach_annotation_alerts(ratio=None):
    """RawSQL for alerts: sla_is_near_breach (1 or 0). DB-agnostic."""
    ratio = ratio or SLA_NEAR_BREACH_RATIO
    t = "alerts_alert"
    rs = _ALERT_RESOLVED_SQL
    vendor = connection.vendor

    if vendor == "postgresql":
        sql = f"""
        CASE WHEN {t}.sla_deadline IS NULL THEN 0
             WHEN {t}.status IN {rs} THEN 0
             WHEN {t}.sla_deadline < NOW() THEN 0
             WHEN EXTRACT(EPOCH FROM ({t}.sla_deadline - NOW())) /
                  NULLIF(EXTRACT(EPOCH FROM ({t}.sla_deadline - {t}.created_at)), 0) < %s THEN 1
             ELSE 0 END
        """
        return RawSQL(sql, [ratio])
    else:
        from django.utils import timezone
        now_str = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
        sql = f"""
        CASE WHEN {t}.sla_deadline IS NULL THEN 0
             WHEN {t}.status IN {rs} THEN 0
             WHEN julianday({t}.sla_deadline) < julianday(%s) THEN 0
             WHEN (julianday({t}.sla_deadline) - julianday(%s)) < %s * (julianday({t}.sla_deadline) - julianday({t}.created_at)) THEN 1
             ELSE 0 END
        """
        return RawSQL(sql, [now_str, now_str, ratio])

def sla_near_breach_annotation_cases(ratio=None):
    """RawSQL for cases: case_is_near_breach (1 or 0). DB-agnostic."""
    ratio = ratio or SLA_NEAR_BREACH_RATIO
    t = "cases_case"
    rs = _CASE_RESOLVED_SQL
    vendor = connection.vendor

    if vendor == "postgresql":
        sql = f"""
        CASE WHEN {t}.sla_deadline IS NULL THEN 0
             WHEN {t}.status IN {rs} THEN 0
             WHEN {t}.sla_deadline < NOW() THEN 0
             WHEN EXTRACT(EPOCH FROM ({t}.sla_deadline - NOW())) /
                  NULLIF(EXTRACT(EPOCH FROM ({t}.sla_deadline - {t}.created_at)), 0) < %s THEN 1
             ELSE 0 END
        """
        return RawSQL(sql, [ratio])
    else:
        from django.utils import timezone
        now_str = timezone.now().strftime("%Y-%m-%d %H:%M:%S")
        sql = f"""
        CASE WHEN {t}.sla_deadline IS NULL THEN 0
             WHEN {t}.status IN {rs} THEN 0
             WHEN julianday({t}.sla_deadline) < julianday(%s) THEN 0
             WHEN (julianday({t}.sla_deadline) - julianday(%s)) < %s * (julianday({t}.sla_deadline) - julianday({t}.created_at)) THEN 1
             ELSE 0 END
        """
        return RawSQL(sql, [now_str, now_str, ratio])

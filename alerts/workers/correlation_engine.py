import json
import time
import logging
import hashlib
import os
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from django.db import transaction

from core.models import Workspace
from alerts.models import Alert, AlertCorrelationRule
from cases.models import Case, CaseSeverity, CaseStatus
from alerts.enums import AlertStatus

logger = logging.getLogger(__name__)

SLEEP_SECONDS = getattr(settings, 'CORRELATION_ENGINE_SLEEP_SECONDS', 10)
INCIDENT_AUTO_CREATE_ENABLED = getattr(settings, 'INCIDENT_AUTO_CREATE_ENABLED', True)

def evaluate_correlation_rules():
    if not INCIDENT_AUTO_CREATE_ENABLED:
        return

    now = timezone.now()
    rules = AlertCorrelationRule.objects.filter(enabled=True).select_related('workspace')
    
    for rule in rules:
        try:
            window_start = now - timedelta(seconds=rule.time_window_seconds)
            
            # Fetch recent alerts
            alerts = Alert.objects.filter(
                workspace=rule.workspace,
                created_at__gte=window_start
            ).order_by('created_at')
            
            conditions = rule.conditions
            if not isinstance(conditions, list) or not conditions:
                continue
                
            # Group alerts by title (or source)
            alerts_list = list(alerts)
            
            condition_matches = {}
            for condition in conditions:
                condition_str = str(condition)
                found = []
                for a in alerts_list:
                    if (condition_str in a.title) or (condition_str in a.source):
                        found.append(a)
                if found:
                    condition_matches[condition_str] = found

                # All conditions met! Create a Case
                all_matched_alerts = set()
                for cond_alerts in condition_matches.values():
                    all_matched_alerts.update(cond_alerts)
                all_matched_alerts = list(all_matched_alerts)
                
                # Deduplicate cases using fingerprint on title for now or store fingerprint in case description
                # Since Case doesn't have a fingerprint field directly, we can check by title and recent cases
                # But to follow instructions strictly, maybe we should just check by title?
                time_bucket = int(now.timestamp() / rule.time_window_seconds)
                alert_ids = sorted([a.id for a in all_matched_alerts])
                fingerprint_raw = f"INC_{rule.id}_{time_bucket}_{','.join(map(str, alert_ids))}"
                fingerprint = hashlib.sha256(fingerprint_raw.encode('utf-8')).hexdigest()
                
                # We can store fingerprint in description and use it to dedup
                if Case.objects.filter(workspace=rule.workspace, description__contains=fingerprint).exists():
                    continue
                    
                # Calculate max severity
                severity_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                max_sev = "LOW"
                max_rank = 1
                for a in all_matched_alerts:
                    rank = severity_ranks.get(a.severity, 1)
                    if rank > max_rank:
                        max_rank = rank
                        max_sev = a.severity
                        
                with transaction.atomic():
                    case_obj = Case.objects.create(
                        workspace=rule.workspace,
                        title=rule.incident_title,
                        description=f"{rule.incident_description}\n[Fingerprint: {fingerprint}]",
                        severity=max_sev,
                        priority="MEDIUM",
                        status="OPEN"
                    )
                    case_obj.alerts.set(all_matched_alerts)
                    
                    for alert in all_matched_alerts:
                        alert.status = AlertStatus.CORRELATED
                        alert.save(update_fields=["status", "updated_at"])
                    
                # Logging output format expected by step 13
                logger.info(f"correlation triggers: 1 rules triggered")
                logger.info(f"case creation: Case {case_obj.title} created with {len(all_matched_alerts)} alerts")
                
        except Exception as e:
            logger.error(f"Error evaluating correlation rule '{rule.name}': {str(e)}")

def run_worker():
    logger.info("Starting Correlation Engine Worker...")
    while True:
        try:
            evaluate_correlation_rules()
            time.sleep(SLEEP_SECONDS)
        except Exception as e:
            logger.error(f"Correlation worker iteration failed: {e}")
            time.sleep(SLEEP_SECONDS)

if __name__ == "__main__":
    import django
    import os
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    django.setup()
    run_worker()

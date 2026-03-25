import json
import time
import logging
import hashlib
import os
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from django.db.models import Count, Q
from django.db import transaction
from django.core.exceptions import FieldDoesNotExist

from core.models import Workspace
from alerts.models import DetectionRule, Alert
from api.models import NormalizedEvent
from alerts.services import create_alert

logger = logging.getLogger(__name__)

BATCH_SIZE = getattr(settings, 'DETECTION_ENGINE_BATCH_SIZE', 100)
SLEEP_SECONDS = getattr(settings, 'DETECTION_ENGINE_SLEEP_SECONDS', 10)

def seed_default_rules(workspace):
    """Seed a workspace with default detection rules if none exist."""
    if DetectionRule.objects.filter(workspace=workspace).exists():
        return
    
    rule_pack_path = os.path.join(settings.BASE_DIR, 'alerts', 'rule_packs', 'default_rules.json')
    if not os.path.exists(rule_pack_path):
        logger.warning(f"Rule pack not found at {rule_pack_path}")
        return

    try:
        with open(rule_pack_path, 'r') as f:
            rules_data = json.load(f)
            
        rules_to_create = []
        for rd in rules_data:
            rules_to_create.append(DetectionRule(
                workspace=workspace,
                name=rd['name'],
                description=rd['description'],
                event_type=rd['event_type'],
                category=rd['category'],
                group_by=rd['group_by'],
                threshold_count=rd['threshold_count'],
                time_window_seconds=rd['time_window_seconds'],
                severity=rd['severity'],
                alert_title=rd['alert_title'],
                alert_description=rd['alert_description']
            ))
        
        DetectionRule.objects.bulk_create(rules_to_create)
        logger.info(f"Seeded {len(rules_to_create)} default rules for workspace {workspace.slug}")
    except Exception as e:
        logger.error(f"Failed to seed rules for workspace {workspace.slug}: {str(e)}")

def evaluate_rules():
    """Evaluate detection rules using DB aggregation and efficient window filtering."""
    # Periodic seeding - only check when evaluating
    for ws in Workspace.objects.all():
        seed_default_rules(ws)

    # 1. Fetch enabled rules
    rules = DetectionRule.objects.filter(enabled=True).select_related('workspace')
    now = timezone.now()
    
    logger.debug(f"Evaluating {rules.count()} rules at {now}")

    for rule in rules:
        try:
            # 2. Implement Time Window Filtering (Step 1)
            # Scan only events within the rule's specific window
            window_start = now - timedelta(seconds=rule.time_window_seconds)
            
            # Base query filtered by workspace, type, and window
            queryset = NormalizedEvent.objects.filter(
                workspace=rule.workspace,
                event_type=rule.event_type,
                event_time__gte=window_start
            )
            
            if rule.category:
                queryset = queryset.filter(category=rule.category)
            
            # 3. Use Database Aggregation for Grouping (Step 2 & 3)
            if rule.group_by:
                # Missing Field Safety (Step 3)
                try:
                    NormalizedEvent._meta.get_field(rule.group_by)
                except FieldDoesNotExist:
                    logger.warning(f"Detection rule '{rule.name}' refers to missing field '{rule.group_by}'. Skipping.")
                    continue

                # Exclude nulls and empty strings to avoid noise
                queryset = queryset.exclude(**{f"{rule.group_by}__isnull": True}).exclude(**{rule.group_by: ""})
                
                # DB delegation: Group, count, filter by threshold
                results = queryset.values(rule.group_by).annotate(
                    event_count=Count('id')
                ).filter(event_count__gte=rule.threshold_count)
                
                for res in results:
                    group_value = res.get(rule.group_by)
                    count = res.get('event_count')
                    sample_event = queryset.filter(**{rule.group_by: group_value}).order_by('-event_time').first()
                    trigger_alert_idempotent(rule, group_value, count, now, normalized_event=sample_event)
            else:
                # No grouping, just verify total volume in window
                count = queryset.count()
                if count >= rule.threshold_count:
                    sample_event = queryset.order_by('-event_time').first()
                    trigger_alert_idempotent(rule, "GLOBAL", count, now, normalized_event=sample_event)
                    
        except Exception as e:
            logger.error(f"Error evaluating rule '{rule.name}': {str(e)}")

def trigger_alert_idempotent(rule, group_value, count, evaluation_time, normalized_event=None):
    """Implement idempotent alert creation using time-bucketed fingerprinting (Step 4 & 5)."""
    # 4. Generate Alert Fingerprint
    # Bucketing window to ensure only one alert per window interval per group
    time_bucket = int(evaluation_time.timestamp() / rule.time_window_seconds)
    
    # rule_id + group_value + time_bucket leads to unique fingerprint per interval
    fingerprint_raw = f"DRUC_{rule.id}_{group_value}_{time_bucket}"
    alert_fingerprint = hashlib.sha256(fingerprint_raw.encode('utf-8')).hexdigest()
    
    # Check for existing alert with same fingerprint
    if Alert.objects.filter(workspace=rule.workspace, fingerprint=alert_fingerprint).exists():
        return

    # 5. Alert Creation using Service
    title = rule.alert_title.replace("{group_by}", str(group_value)).replace("{count}", str(count))
    description = rule.alert_description.replace("{group_by}", str(group_value)).replace("{count}", str(count))
    
    source_str = f"DetectionEngine:{rule.name}"
    
    # Hand off to service layer (idempotency handled by fingerprint)
    alert = create_alert(
        workspace=rule.workspace,
        title=title,
        description=description,
        source=source_str,
        severity=rule.severity,
        category=rule.category or 'OTHER',
        raw_event_payload={"rule_id": rule.id, "group_value": group_value, "count": count},
        fingerprint=alert_fingerprint,
        normalized_event=normalized_event
    )
    
    if alert:
        logger.info(f"Rule Triggered: '{rule.name}' for {group_value} (count: {count})")
        # Update metadata for rule visibility
        rule.last_triggered_at = timezone.now()
        rule.save(update_fields=['last_triggered_at'])

def run_worker():
    logger.info("Starting Hardened Detection Engine Worker...")
    while True:
        try:
            evaluate_rules()
            time.sleep(SLEEP_SECONDS)
        except Exception as e:
            logger.error(f"Detection worker iteration failed: {e}")
            time.sleep(SLEEP_SECONDS)

if __name__ == "__main__":
    import django
    import os
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    django.setup()
    run_worker()

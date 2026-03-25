import time
import logging
import hashlib
import importlib
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from django.db import transaction

from alerts.enums import EventCategory, EventSeverity
from api.models import IngestionEvent, EventSource, NormalizedEvent

logger = logging.getLogger(__name__)

BATCH_SIZE = getattr(settings, 'EVENT_PROCESSOR_BATCH_SIZE', 100)
RETRY_LIMIT = getattr(settings, 'EVENT_PROCESSOR_RETRY_LIMIT', 3)
SLEEP_SECONDS = getattr(settings, 'EVENT_PROCESSOR_SLEEP_SECONDS', 5)
STUCK_TIMEOUT = getattr(settings, 'EVENT_PROCESSOR_STUCK_TIMEOUT_SECONDS', 600)

def recover_stuck_events():
    """Reset events stuck in PROCESSING for more than STUCK_TIMEOUT seconds."""
    stuck_threshold = timezone.now() - timedelta(seconds=STUCK_TIMEOUT)
    stuck_events = IngestionEvent.objects.filter(
        processing_status=IngestionEvent.ProcessingStatus.PROCESSING,
        processing_started_at__lt=stuck_threshold
    )
    count = stuck_events.update(
        processing_status=IngestionEvent.ProcessingStatus.PENDING,
        processing_started_at=None
    )
    if count > 0:
        logger.warning(f"Recovered {count} stuck events back to PENDING.")

def update_event_failure(event, error_message):
    event.retry_count += 1
    event.parse_error = error_message
    if event.retry_count >= RETRY_LIMIT:
        event.processing_status = IngestionEvent.ProcessingStatus.FAILED
        logger.error(f"Event {event.id} permanently FAILED after {event.retry_count} retries. Error: {error_message}")
    else:
        event.processing_status = IngestionEvent.ProcessingStatus.PENDING
        logger.warning(f"Event {event.id} failed iteration {event.retry_count}. Retrying later. Error: {error_message}")
    
    event.save(update_fields=['retry_count', 'parse_error', 'processing_status'])

def build_normalized_event(event, parsed_data):
    # Ensure we use event.event_time if available, fall back to received_at
    event_time = event.event_time or event.received_at or timezone.now()
    
    # Safe extraction with defaults
    source_ip = parsed_data.get('source_ip') or parsed_data.get('src_ip')
    dest_ip = parsed_data.get('destination_ip') or parsed_data.get('dest_ip')
    
    event_type = parsed_data.get('event_type') or 'unknown'
    username = parsed_data.get('username') or ''
    
    # Deterministic time bucket (minute precision)
    time_bucket = event_time.replace(second=0, microsecond=0).isoformat()
        
    # SHA256 Fingerprint: source|event_type|source_ip|username|time_bucket
    fingerprint_raw = f"{event.source}|{event_type}|{source_ip or ''}|{username}|{time_bucket}"
    event_fingerprint = hashlib.sha256(fingerprint_raw.encode('utf-8')).hexdigest()
    
    # Validate and map enums
    raw_category = str(parsed_data.get('category', 'OTHER')).upper()
    category = raw_category if raw_category in [c.value for c in EventCategory] else EventCategory.OTHER

    raw_severity = str(parsed_data.get('severity', 'LOW')).upper()
    severity = raw_severity if raw_severity in [s.value for s in EventSeverity] else EventSeverity.LOW

    return NormalizedEvent(
        workspace=event.workspace,  # Enforce workspace isolation from raw event
        source=event.source,
        event_type=event_type,
        category=category,
        source_ip=source_ip,
        destination_ip=dest_ip,
        username=username or None,
        host=parsed_data.get('host'),
        process_name=parsed_data.get('process_name'),
        file_path=parsed_data.get('file_path'),
        event_time=event_time,
        severity=severity,
        raw_event=event,
        normalized_data=parsed_data,
        parser_version=parsed_data.get('parser_version', '1.0'),
        event_fingerprint=event_fingerprint
    )

def process_batch():
    """Fetch a batch of PENDING events and process them with atomic locking."""
    # Step 1: Fetch candidate IDs
    candidate_events = IngestionEvent.objects.filter(
        processing_status=IngestionEvent.ProcessingStatus.PENDING
    ).order_by('received_at')[:BATCH_SIZE]
    
    event_ids = list(candidate_events.values_list('id', flat=True))

    if not event_ids:
        return False

    # Step 2: Atomic Update to claim events
    # This prevents multiple workers from processing the same events
    updated_count = IngestionEvent.objects.filter(
        id__in=event_ids,
        processing_status=IngestionEvent.ProcessingStatus.PENDING
    ).update(
        processing_status=IngestionEvent.ProcessingStatus.PROCESSING,
        processing_started_at=timezone.now()
    )

    if updated_count == 0:
        return False

    # Step 3: Fetch only the events successfully claimed
    processing_events = IngestionEvent.objects.filter(
        id__in=event_ids,
        processing_status=IngestionEvent.ProcessingStatus.PROCESSING
    ).select_related('workspace')

    normalized_events_to_create = []
    events_to_mark_processed = []
    
    sources_cache = {}
    parsers_cache = {}

    for event in processing_events:
        try:
            source_name = getattr(event, 'source', '')
            
            # Step 4: EventSource Lookup Safety
            if source_name not in sources_cache:
                try:
                    sources_cache[source_name] = EventSource.objects.get(name=source_name)
                except EventSource.DoesNotExist:
                    sources_cache[source_name] = None
            
            source_obj = sources_cache[source_name]
            if not source_obj:
                update_event_failure(event, f"Event source '{source_name}' not found in registry")
                continue
            
            # Step 5: Parser Module Loading Safety
            parser_name = getattr(source_obj, 'parser_name', None)
            if not parser_name:
                update_event_failure(event, "No parser configured for source")
                continue

            if parser_name not in parsers_cache:
                try:
                    module_path = f"parsers.{parser_name}" if not parser_name.startswith("parsers.") else parser_name
                    parsers_cache[parser_name] = importlib.import_module(module_path)
                except Exception as e:
                    parsers_cache[parser_name] = e
            
            parser_module = parsers_cache[parser_name]
            if isinstance(parser_module, Exception):
                update_event_failure(event, f"Failed to load parser module {parser_name}: {str(parser_module)}")
                continue

            if not hasattr(parser_module, 'parse_event'):
                update_event_failure(event, f"Parser {parser_name} has no parse_event function")
                continue

            # Step 6: Parser Execution Safety
            try:
                parsed_data = parser_module.parse_event(event.raw_log)
                normalized_event = build_normalized_event(event, parsed_data)
                normalized_events_to_create.append(normalized_event)
                events_to_mark_processed.append(event)
            except Exception as e:
                update_event_failure(event, f"Parser execution error: {str(e)}")
        
        except Exception as e:
            # Catch-all for unexpected per-event failures to ensure loop continues
            logger.error(f"Unexpected error processing event {event.id}: {str(e)}")
            try:
                update_event_failure(event, f"Unexpected processing error: {str(e)}")
            except:
                pass

    # Step 7: Bulk Operations (Efficiency & Duplicate Safety)
    if normalized_events_to_create:
        # ignore_conflicts=True handles fingerprint uniqueness safely
        NormalizedEvent.objects.bulk_create(normalized_events_to_create, ignore_conflicts=True)

    if events_to_mark_processed:
        processed_ids = [e.id for e in events_to_mark_processed]
        IngestionEvent.objects.filter(id__in=processed_ids).update(
            processing_status=IngestionEvent.ProcessingStatus.PROCESSED
        )

    logger.info(f"Batch processed: {len(events_to_mark_processed)} success, {updated_count - len(events_to_mark_processed)} failed/skipped.")
    return True

def run_worker():
    logger.info("Starting Event Processor Worker...")
    while True:
        try:
            recover_stuck_events()
            processed_any = process_batch()
            if not processed_any:
                time.sleep(SLEEP_SECONDS)
        except Exception as e:
            logger.error(f"Worker iteration failed: {e}")
            time.sleep(SLEEP_SECONDS)

if __name__ == "__main__":
    import django
    import os
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    django.setup()
    run_worker()

if __name__ == "__main__":
    import django
    import os
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    django.setup()
    run_worker()

from django.db import models
from django.conf import settings
from alerts.enums import EventCategory, EventSeverity

class ApiKey(models.Model):
    workspace = models.ForeignKey(
        'core.Workspace',
        on_delete=models.CASCADE,
        related_name='api_keys_set'
    )
    name = models.CharField(max_length=255)
    key_prefix = models.CharField(max_length=10)
    public_id = models.CharField(max_length=32, unique=True, db_index=True)
    secret_hash = models.CharField(max_length=128)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='api_keys_created'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_used_ip = models.GenericIPAddressField(null=True, blank=True)
    usage_count = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)

    class Meta:
        indexes = [
            models.Index(fields=['workspace', 'is_active']),
        ]

    def __str__(self):
        return f"{self.name} ({self.key_prefix}_{self.public_id})"

class EventSource(models.Model):
    name = models.CharField(max_length=255, unique=True)
    display_name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    parser_name = models.CharField(max_length=255)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['enabled']),
        ]

    def __str__(self):
        return self.display_name

class IngestionEvent(models.Model):
    class ProcessingStatus(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        PROCESSING = 'PROCESSING', 'Processing'
        PROCESSED = 'PROCESSED', 'Processed'
        FAILED = 'FAILED', 'Failed'

    class IngestMethod(models.TextChoices):
        CONNECTOR = 'CONNECTOR', 'Connector'
        WEBHOOK = 'WEBHOOK', 'Webhook'
        SYSLOG = 'SYSLOG', 'Syslog'

    workspace = models.ForeignKey(
        'core.Workspace',
        on_delete=models.CASCADE,
        related_name='ingestion_events'
    )
    api_key = models.ForeignKey(
        ApiKey,
        on_delete=models.SET_NULL,
        null=True,
        related_name='ingestion_events'
    )
    source = models.CharField(max_length=255)
    ingest_method = models.CharField(
        max_length=50,
        choices=IngestMethod.choices,
        default=IngestMethod.WEBHOOK
    )
    raw_log = models.JSONField()
    event_time = models.DateTimeField(null=True, blank=True)
    received_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    processing_status = models.CharField(
        max_length=20,
        choices=ProcessingStatus.choices,
        default=ProcessingStatus.PENDING
    )
    processing_started_at = models.DateTimeField(null=True, blank=True)
    retry_count = models.IntegerField(default=0)
    parse_error = models.TextField(null=True, blank=True)
    parser_version = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['workspace']),
            models.Index(fields=['processing_status']),
            models.Index(fields=['source']),
            models.Index(fields=['received_at']),
        ]

    def __str__(self):
        return f"Event from {self.source} at {self.received_at}"

class NormalizedEvent(models.Model):
    workspace = models.ForeignKey(
        'core.Workspace',
        on_delete=models.CASCADE,
        related_name='normalized_events'
    )
    source = models.CharField(max_length=255)
    event_type = models.CharField(max_length=255)
    category = models.CharField(max_length=100, choices=EventCategory.choices)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    username = models.CharField(max_length=255, null=True, blank=True)
    host = models.CharField(max_length=255, null=True, blank=True)
    process_name = models.CharField(max_length=255, null=True, blank=True)
    file_path = models.TextField(null=True, blank=True)
    event_time = models.DateTimeField(null=True, blank=True)
    received_at = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=20, choices=EventSeverity.choices)
    raw_event = models.ForeignKey(
        IngestionEvent,
        on_delete=models.CASCADE,
        related_name='normalized_events'
    )
    normalized_data = models.JSONField()
    parser_version = models.CharField(max_length=50, null=True, blank=True)
    event_fingerprint = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=['workspace', 'event_time']),
            models.Index(fields=['workspace', 'category']),
            models.Index(fields=['workspace', 'event_type']),
            models.Index(fields=['workspace', 'severity']),
            models.Index(fields=['source_ip']),
            models.Index(fields=['username']),
            models.Index(fields=['event_fingerprint']),
        ]
        unique_together = ('workspace', 'event_fingerprint')

    def __str__(self):
        return f"{self.event_type} - {self.event_fingerprint}"

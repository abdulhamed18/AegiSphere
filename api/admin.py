from django.contrib import admin
from .models import ApiKey, EventSource, NormalizedEvent, IngestionEvent

@admin.register(IngestionEvent)
class IngestionEventAdmin(admin.ModelAdmin):
    list_display = (
        'workspace',
        'source',
        'ingest_method',
        'received_at',
        'processing_status',
        'retry_count',
        'processing_started_at',
    )
    list_filter = ('workspace', 'processing_status', 'source')
    search_fields = ('source', 'parse_error', 'workspace__name')
    readonly_fields = (
        'workspace', 
        'api_key', 
        'raw_log', 
        'received_at', 
        'created_at', 
        'processing_started_at',
        'parse_error',
        'retry_count'
    )

@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = (
        'workspace',
        'name',
        'key_prefix',
        'public_id',
        'created_by',
        'created_at',
        'is_active',
    )
    list_filter = ('is_active', 'key_prefix')
    search_fields = ('name', 'public_id', 'workspace__name', 'created_by__email')
    readonly_fields = ('key_prefix', 'public_id', 'created_at', 'last_used_at')
    
    def get_exclude(self, request, obj=None):
        """Exclude secret_hash from admin panel to prevent exposure."""
        return ('secret_hash',)

@admin.register(EventSource)
class EventSourceAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'display_name',
        'parser_name',
        'enabled',
        'created_at',
    )
    list_filter = ('enabled',)
    search_fields = ('name', 'display_name', 'parser_name')

@admin.register(NormalizedEvent)
class NormalizedEventAdmin(admin.ModelAdmin):
    list_display = (
        'workspace',
        'source',
        'event_type',
        'category',
        'severity',
        'event_time',
        'created_at',
    )
    list_filter = ('workspace', 'category', 'severity', 'source', 'event_type')
    search_fields = ('source', 'event_type', 'category', 'source_ip', 'username', 'event_fingerprint')
    readonly_fields = ('workspace', 'raw_event', 'event_fingerprint', 'created_at', 'received_at')

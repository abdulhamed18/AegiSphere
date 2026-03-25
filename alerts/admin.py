from django.contrib import admin
from .models import Alert, AlertTag, AlertActivityLog, AlertSuppressionRule, DetectionRule, AlertCorrelationRule, AlertNote

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = (
        'workspace',
        'title',
        'source',
        'severity',
        'status',
        'assigned_to',
        'normalized_event',
        'created_at',
    )
    list_filter = ('workspace', 'severity', 'status', 'source', 'category')
    search_fields = ('title', 'description', 'source', 'fingerprint', 'normalized_event__event_fingerprint')
    readonly_fields = ('created_at', 'updated_at', 'first_seen_at', 'last_seen_at', 'fingerprint')

@admin.register(AlertTag)
class AlertTagAdmin(admin.ModelAdmin):
    list_display = ('workspace', 'name', 'created_at')
    list_filter = ('workspace',)
    search_fields = ('name',)

@admin.register(AlertActivityLog)
class AlertActivityLogAdmin(admin.ModelAdmin):
    list_display = ('workspace', 'alert', 'actor', 'action_type', 'created_at')
    list_filter = ('workspace', 'action_type')
    readonly_fields = ('created_at',)

@admin.register(AlertSuppressionRule)
class AlertSuppressionRuleAdmin(admin.ModelAdmin):
    list_display = ('workspace', 'name', 'enabled', 'rule_name', 'event_type', 'category', 'group_by', 'created_at')
    list_filter = ('workspace', 'enabled', 'category')
    search_fields = ('name', 'rule_name')

@admin.register(AlertCorrelationRule)
class AlertCorrelationRuleAdmin(admin.ModelAdmin):
    list_display = ('workspace', 'name', 'enabled', 'incident_title', 'created_at')
    list_filter = ('workspace', 'enabled')
    search_fields = ('name', 'incident_title', 'incident_description')



@admin.register(AlertNote)
class AlertNoteAdmin(admin.ModelAdmin):
    list_display = ('workspace', 'alert', 'author', 'created_at')
    list_filter = ('workspace', 'author')
    search_fields = ('note',)



@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = (
        'workspace',
        'name',
        'enabled',
        'event_type',
        'threshold_count',
        'time_window_seconds',
        'severity',
        'last_triggered_at',
    )
    list_filter = ('workspace', 'enabled', 'event_type', 'severity', 'category')
    search_fields = ('name', 'description', 'alert_title')
    readonly_fields = ('created_at', 'updated_at', 'last_triggered_at')

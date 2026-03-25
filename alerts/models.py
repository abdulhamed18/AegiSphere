from django.conf import settings
from django.db import models

from core.models import Workspace

from .enums import (
    AlertActivityType,
    AlertCategory,
    AlertPriority,
    AlertSeverity,
    AlertStatus,
)


class AlertTag(models.Model):
    """Workspace-scoped tag for alerts. Unique per (workspace, name)."""

    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        db_index=True,
        related_name="alert_tags",
    )
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["workspace", "name"],
                name="alerttag_ws_name_unique",
            ),
        ]


class Alert(models.Model):
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        db_index=True,
        related_name="alerts",
    )
    title = models.CharField(max_length=255)
    description = models.TextField()
    source = models.CharField(max_length=100)
    source_event_id = models.CharField(max_length=255, null=True, blank=True)
    correlation_id = models.UUIDField(null=True, blank=True)
    severity = models.CharField(
        max_length=20,
        choices=AlertSeverity.choices,
    )
    status = models.CharField(
        max_length=20,
        choices=AlertStatus.choices,
        default=AlertStatus.OPEN,
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_alerts",
    )
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="alerts_assigned",
    )
    assigned_at = models.DateTimeField(null=True, blank=True)
    sla_deadline = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    locked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="locked_alerts",
    )
    locked_at = models.DateTimeField(null=True, blank=True)
    # SOC-level extensions (Phase 4.1)
    priority = models.CharField(
        max_length=20,
        choices=AlertPriority.choices,
        default=AlertPriority.MEDIUM,
        db_index=True,
    )
    risk_score = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    category = models.CharField(
        max_length=20,
        choices=AlertCategory.choices,
        default=AlertCategory.OTHER,
        db_index=True,
    )
    mitre_technique = models.CharField(
        max_length=20,
        null=True,
        blank=True,
        db_index=True,
    )
    is_deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True, db_index=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True, db_index=True)
    correlation_group_id = models.UUIDField(null=True, blank=True, db_index=True)
    fingerprint = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        db_index=True,
    )  # Not unique; deduplication handled in service layer per workspace
    # Deduplication metrics (Phase 4.2)
    first_seen_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_seen_at = models.DateTimeField(null=True, blank=True, db_index=True)
    occurrence_count = models.PositiveIntegerField(default=1)
    # Suppression metadata (alert-level temporary mute)
    is_suppressed = models.BooleanField(default=False, db_index=True)
    suppressed_until = models.DateTimeField(null=True, blank=True, db_index=True)
    suppressed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="suppressed_alerts",
    )
    # Escalation metadata
    escalation_level = models.PositiveIntegerField(default=0, db_index=True)
    escalated_at = models.DateTimeField(null=True, blank=True, db_index=True)
    escalated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="escalated_alerts",
    )
    # Structured event storage
    normalized_event = models.ForeignKey(
        "api.NormalizedEvent",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="alerts",
    )
    raw_event_payload = models.JSONField(null=True, blank=True)
    normalized_data = models.JSONField(null=True, blank=True)
    # Tagging
    tags = models.ManyToManyField(
        AlertTag,
        blank=True,
        related_name="alerts",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def duplicate_count(self):
        """duplicate_count is derived from occurrence_count. No DB column exists. Do not add it back."""
        return max((self.occurrence_count or 1) - 1, 0)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["workspace", "status"], name="alert_ws_status_idx"),
            models.Index(fields=["workspace", "severity"], name="alert_ws_severity_idx"),
            models.Index(fields=["workspace", "assigned_to"], name="alert_ws_assigned_idx"),
            models.Index(fields=["sla_deadline"], name="alert_sla_deadline_idx"),
            models.Index(fields=["created_at"], name="alert_created_at_idx"),
            models.Index(fields=["workspace", "is_deleted"], name="alert_ws_deleted_idx"),
            models.Index(fields=["workspace", "priority"], name="alert_ws_priority_idx"),
            models.Index(fields=["workspace", "risk_score"], name="alert_ws_risk_idx"),
            models.Index(
                fields=["workspace", "correlation_group_id"],
                name="alert_ws_correlation_idx",
            ),
            models.Index(fields=["workspace", "fingerprint"], name="alert_ws_fingerprint_idx"),
            models.Index(fields=["workspace", "is_suppressed"], name="alert_ws_suppressed_idx"),
            models.Index(fields=["workspace", "escalation_level"], name="alert_ws_escalation_idx"),
        ]


class AlertActivityLog(models.Model):
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        db_index=True,
        related_name="alert_activities",
    )
    alert = models.ForeignKey(
        Alert,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="activity_logs",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="alert_activities",
    )
    action_type = models.CharField(
        max_length=32,
        choices=AlertActivityType.choices,
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["workspace"], name="alert_activity_ws_idx"),
            models.Index(fields=["alert"], name="alert_activity_alert_idx"),
            models.Index(fields=["created_at"], name="alert_activity_created_idx"),
        ]


class AlertSuppressionRule(models.Model):
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        db_index=True,
        related_name="alert_suppression_rules",
    )
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    enabled = models.BooleanField(default=True)
    rule_name = models.CharField(max_length=255, null=True, blank=True)
    event_type = models.CharField(max_length=255, null=True, blank=True)
    category = models.CharField(
        max_length=20,
        choices=AlertCategory.choices,
        null=True,
        blank=True,
    )
    group_by = models.CharField(max_length=100, default='source_ip')
    suppression_window_seconds = models.IntegerField(default=300)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["workspace"], name="suppression_rule_ws_new_idx"),
            models.Index(fields=["enabled"], name="suppression_rule_en_new_idx"),
        ]

class AlertCorrelationRule(models.Model):
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        db_index=True,
        related_name="alert_correlation_rules",
    )
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    enabled = models.BooleanField(default=True)
    conditions = models.JSONField(default=list)
    time_window_seconds = models.IntegerField(default=300)
    incident_title = models.CharField(max_length=255)
    incident_description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["workspace", "enabled"], name="correlation_rule_ws_en_idx"),
        ]




class AlertNote(models.Model):
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="alert_notes",
    )
    alert = models.ForeignKey(
        Alert,
        on_delete=models.CASCADE,
        related_name="notes",
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="alert_notes",
    )
    note = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]




class DetectionRule(models.Model):
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        db_index=True,
        related_name="detection_rules"
    )
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    enabled = models.BooleanField(default=True)
    event_type = models.CharField(max_length=255, db_index=True)
    category = models.CharField(max_length=100, null=True, blank=True, db_index=True)
    group_by = models.CharField(max_length=100, null=True, blank=True)
    threshold_count = models.IntegerField(default=1)
    time_window_seconds = models.IntegerField(default=60)
    severity = models.CharField(max_length=20, choices=AlertSeverity.choices, default=AlertSeverity.MEDIUM)
    alert_title = models.CharField(max_length=255)
    alert_description = models.TextField()
    last_triggered_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=['workspace', 'enabled'], name='idx_det_rule_ws_en'),
            models.Index(fields=['workspace', 'event_type'], name='idx_det_rule_ws_et'),
            models.Index(fields=['workspace', 'category'], name='idx_det_rule_ws_cat'),
        ]

    def __str__(self):
        return self.name

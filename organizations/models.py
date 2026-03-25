"""
Organization Workspace Management — Database Models.

Only models that do NOT already exist in core/models.py are defined here.
Existing models reused from core: Workspace, WorkspaceMembership, WorkspaceRole,
WorkspacePermission, RolePermission, OrganizationJoinRequest, WorkspaceInvite,
OrganizationBlockList, RoleChangeAuditLog, OnboardingChecklistStatus.
"""

import uuid

from django.conf import settings
from django.db import models

from core.models import Workspace


class OrganizationSettings(models.Model):
    """Per-workspace organization configuration and security settings."""

    VISIBILITY_CHOICES = [
        ("public", "Public"),
        ("private", "Private"),
    ]

    workspace = models.OneToOneField(
        Workspace,
        on_delete=models.CASCADE,
        related_name="organization_settings",
    )
    description = models.TextField(blank=True, default="")
    visibility = models.CharField(
        max_length=20,
        choices=VISIBILITY_CHOICES,
        default="private",
    )

    # Security settings
    require_email_verification = models.BooleanField(default=True)
    session_timeout_minutes = models.PositiveIntegerField(default=480)
    allowed_email_domains = models.TextField(
        blank=True,
        default="",
        help_text="Comma-separated list of allowed email domains. Leave blank for all.",
    )
    api_access_enabled = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Organization Settings"
        verbose_name_plural = "Organization Settings"

    def __str__(self):
        return f"Settings for {self.workspace.name}"


class OrganizationAPIKey(models.Model):
    """API keys for SIEM integrations, log ingestion, and external services."""

    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    name = models.CharField(max_length=255)
    key_prefix = models.CharField(
        max_length=8,
        help_text="First 8 characters of the key for identification.",
    )
    key_hash = models.CharField(
        max_length=128,
        help_text="SHA-256 hash of the full key. Raw key is never stored.",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_api_keys",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["workspace", "is_active"], name="org_apikey_ws_active_idx"),
            models.Index(fields=["key_prefix"], name="org_apikey_prefix_idx"),
        ]

    def __str__(self):
        return f"{self.name} ({self.key_prefix}...)"


class OrganizationAuditLog(models.Model):
    """Persistent DB-backed audit log for organization governance events."""

    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="organization_audit_logs",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="organization_audit_actions",
    )
    action = models.CharField(max_length=255)
    target = models.CharField(max_length=255, blank=True, default="")
    timestamp = models.DateTimeField(auto_now_add=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["workspace", "timestamp"], name="org_audit_ws_ts_idx"),
            models.Index(fields=["workspace", "action"], name="org_audit_ws_action_idx"),
            models.Index(fields=["user"], name="org_audit_user_idx"),
        ]

    def __str__(self):
        username = self.user.username if self.user else "System"
        return f"[{self.timestamp}] {username}: {self.action}"


class OrganizationDataSource(models.Model):
    """Data source integrations connected to the workspace."""

    SOURCE_TYPE_CHOICES = [
        ("wazuh", "Wazuh"),
        ("sysmon", "Sysmon"),
        ("firewall", "Firewall Logs"),
        ("cloud", "Cloud Logs"),
        ("siem", "SIEM"),
        ("edr", "EDR"),
        ("custom", "Custom"),
    ]

    STATUS_CHOICES = [
        ("active", "Active"),
        ("inactive", "Inactive"),
        ("error", "Error"),
    ]

    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="data_sources",
    )
    name = models.CharField(max_length=255)
    source_type = models.CharField(
        max_length=50,
        choices=SOURCE_TYPE_CHOICES,
        default="custom",
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="inactive",
    )
    last_log_received = models.DateTimeField(null=True, blank=True)
    config = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["workspace", "status"], name="org_ds_ws_status_idx"),
        ]

    def __str__(self):
        return f"{self.name} ({self.get_source_type_display()})"

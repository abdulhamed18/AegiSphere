"""
Phase 5 — Case Management
Step 1 — Core Models + Database Constraints

Models only. No business logic, services, or permissions.
Multi-tenant: all models are workspace-scoped (except pure junction tables).
"""

from django.conf import settings
from django.db import models

from core.models import Workspace


# --- Enums (CharField choices) ---

class CaseSeverity(models.TextChoices):
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    CRITICAL = "CRITICAL", "Critical"


class CasePriority(models.TextChoices):
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    URGENT = "URGENT", "Urgent"


class CaseOutcome(models.TextChoices):
    TRUE_POSITIVE = "TRUE_POSITIVE", "True Positive"
    FALSE_POSITIVE = "FALSE_POSITIVE", "False Positive"
    BENIGN = "BENIGN", "Benign"
    POLICY_VIOLATION = "POLICY_VIOLATION", "Policy Violation"
    OTHER = "OTHER", "Other"


class CaseStatus(models.TextChoices):
    OPEN = "OPEN", "Open"
    IN_PROGRESS = "IN_PROGRESS", "In Progress"
    ON_HOLD = "ON_HOLD", "On Hold"
    RESOLVED = "RESOLVED", "Resolved"
    CLOSED = "CLOSED", "Closed"


class CaseIOCType(models.TextChoices):
    IP = "IP", "IP"
    DOMAIN = "DOMAIN", "Domain"
    HASH = "HASH", "Hash"
    EMAIL = "EMAIL", "Email"


# --- CaseTag (defined before Case for M2M) ---

class CaseTag(models.Model):
    """Workspace-scoped tag for cases. Unique per (workspace, name)."""

    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="case_tags",
    )
    name = models.CharField(max_length=100)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["workspace", "name"],
                name="casetag_ws_name_unique",
            ),
        ]


# --- Case ---

class Case(models.Model):
    """
    Root entity for case management.
    Cases must NEVER be deleted; use archived flag instead.
    workspace uses PROTECT so workspace deletion is blocked when cases exist.
    """

    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.PROTECT,
        db_index=True,
        related_name="cases",
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(
        max_length=20,
        choices=CaseSeverity.choices,
    )
    priority = models.CharField(
        max_length=20,
        choices=CasePriority.choices,
    )
    outcome = models.CharField(
        max_length=50,
        choices=CaseOutcome.choices,
        null=True,
        blank=True,
    )
    status = models.CharField(
        max_length=20,
        choices=CaseStatus.choices,
    )
    primary_assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_index=True,
        related_name="assigned_cases",
    )
    sla_deadline = models.DateTimeField(null=True, blank=True, db_index=True)
    sla_breached = models.BooleanField(default=False)
    sla_breached_at = models.DateTimeField(null=True, blank=True)
    archived = models.BooleanField(default=False, db_index=True)
    archived_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_cases",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    reopened_at = models.DateTimeField(null=True, blank=True)
    # Phase 7 — Compliance reporting
    resolution_summary = models.TextField(blank=True)
    external_reference_id = models.CharField(max_length=255, blank=True, null=True)
    reported_externally = models.BooleanField(default=False)
    reported_at = models.DateTimeField(null=True, blank=True)
    compliance_notes = models.TextField(blank=True)
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="closed_cases",
    )
    alerts = models.ManyToManyField(
        "alerts.Alert",
        related_name="cases",
        blank=True,
    )
    tags = models.ManyToManyField(
        CaseTag,
        blank=True,
        related_name="cases",
    )

    def delete(self, *args, **kwargs):
        raise Exception("Cases cannot be deleted. Use archive instead.")

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["workspace", "status"], name="case_ws_status_idx"),
            models.Index(fields=["workspace", "severity"], name="case_ws_severity_idx"),
            models.Index(
                fields=["workspace", "primary_assignee"],
                name="case_ws_assignee_idx",
            ),
            models.Index(fields=["workspace", "archived"], name="case_ws_archived_idx"),
            models.Index(fields=["sla_deadline"], name="case_sla_deadline_idx"),
        ]


# --- CaseAlert ---

class CaseAlert(models.Model):
    """Maps alerts to cases. One alert can belong to only one case."""

    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        related_name="case_alerts",
    )
    alert = models.ForeignKey(
        "alerts.Alert",
        on_delete=models.PROTECT,
        related_name="case_alerts",
    )
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="added_case_alerts",
    )
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["case", "alert"],
                name="casealert_case_alert_unique",
            ),
            models.UniqueConstraint(
                fields=["alert"],
                name="casealert_alert_unique",
            ),
        ]
        indexes = [
            models.Index(fields=["alert"], name="casealert_alert_idx"),
        ]


# --- CaseCollaborator ---

class CaseCollaborator(models.Model):
    """Users who collaborate on a case."""

    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        related_name="collaborators",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="case_collaborations",
    )
    added_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="added_case_collaborators",
    )
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["case", "user"],
                name="casecollab_case_user_unique",
            ),
        ]
        indexes = [
            models.Index(fields=["case"], name="casecollab_case_idx"),
        ]


# --- CaseNote ---

class CaseNote(models.Model):
    """Notes on a case. Can be internal or external."""

    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        related_name="notes",
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="case_notes",
    )
    content = models.TextField()
    is_internal = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["case"], name="casenote_case_idx"),
            models.Index(fields=["created_at"], name="casenote_created_idx"),
        ]


# --- CaseActivity ---

class CaseActivity(models.Model):
    """Immutable timeline of case events. No update/delete logic here."""

    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        related_name="activities",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="case_activities",
    )
    action_type = models.CharField(max_length=100)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["case"], name="caseactivity_case_idx"),
            models.Index(fields=["created_at"], name="caseactivity_created_idx"),
        ]


# --- CaseTask ---

class CaseTask(models.Model):
    """Tasks within a case."""

    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        related_name="tasks",
    )
    title = models.CharField(max_length=255)
    is_completed = models.BooleanField(default=False)
    completed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="completed_case_tasks",
    )
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["case", "title"],
                name="casetask_case_title_unique",
            ),
        ]
        indexes = [
            models.Index(fields=["case"], name="casetask_case_idx"),
        ]


# --- CaseAttachment ---

class CaseAttachment(models.Model):
    """File attachments on a case."""

    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        related_name="attachments",
    )
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="uploaded_case_attachments",
    )
    file = models.FileField(upload_to="case_attachments/")
    file_type = models.CharField(max_length=100, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["case"], name="caseattach_case_idx"),
        ]


# --- CaseIOC ---

class CaseIOC(models.Model):
    """Indicators of compromise associated with a case."""

    case = models.ForeignKey(
        Case,
        on_delete=models.CASCADE,
        related_name="iocs",
    )
    type = models.CharField(
        max_length=20,
        choices=CaseIOCType.choices,
    )
    value = models.CharField(max_length=255)
    enrichment_status = models.CharField(max_length=50, default="PENDING")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["case", "type", "value"],
                name="caseioc_case_type_value_unique",
            ),
        ]
        indexes = [
            models.Index(fields=["case"], name="caseioc_case_idx"),
            models.Index(fields=["type"], name="caseioc_type_idx"),
        ]

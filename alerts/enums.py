from django.db import models


class AlertStatus(models.TextChoices):
    """Alert lifecycle: OPEN → ACKNOWLEDGED → IN_PROGRESS → RESOLVED / FALSE_POSITIVE / REOPENED / CORRELATED."""
    OPEN = "OPEN", "Open"
    ACKNOWLEDGED = "ACKNOWLEDGED", "Acknowledged"
    IN_PROGRESS = "IN_PROGRESS", "In Progress"
    RESOLVED = "RESOLVED", "Resolved"
    FALSE_POSITIVE = "FALSE_POSITIVE", "False Positive"
    REOPENED = "REOPENED", "Reopened"
    CORRELATED = "CORRELATED", "Correlated"


class AlertPriority(models.TextChoices):
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    URGENT = "URGENT", "Urgent"


class AlertCategory(models.TextChoices):
    NETWORK = "NETWORK", "Network"
    ENDPOINT = "ENDPOINT", "Endpoint"
    IAM = "IAM", "IAM"
    APPLICATION = "APPLICATION", "Application"
    CLOUD = "CLOUD", "Cloud"
    OTHER = "OTHER", "Other"


class AlertSeverity(models.TextChoices):
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    CRITICAL = "CRITICAL", "Critical"


class AlertActivityType(models.TextChoices):
    CREATED = "CREATED", "Created"
    ASSIGNED = "ASSIGNED", "Assigned"
    STATUS_CHANGED = "STATUS_CHANGED", "Status Changed"
    DUPLICATE_MERGED = "DUPLICATE_MERGED", "Duplicate Merged"
    RESOLVED = "RESOLVED", "Resolved"
    FALSE_POSITIVE = "FALSE_POSITIVE", "False Positive"
    LOCKED = "LOCKED", "Locked"
    UNLOCKED = "UNLOCKED", "Unlocked"
    SLA_EXTENDED = "SLA_EXTENDED", "SLA Extended"


class EventCategory(models.TextChoices):
    AUTHENTICATION = "AUTHENTICATION", "Authentication"
    NETWORK = "NETWORK", "Network"
    PROCESS = "PROCESS", "Process"
    FILE = "FILE", "File"
    MALWARE = "MALWARE", "Malware"
    PRIVILEGE = "PRIVILEGE", "Privilege"
    OTHER = "OTHER", "Other"


class EventSeverity(models.TextChoices):
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    CRITICAL = "CRITICAL", "Critical"

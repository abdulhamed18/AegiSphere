"""
Organization selectors — read-only queries for the organization dashboard.
No mutations. All queries are workspace-scoped for tenant isolation.
"""

from django.db.models import Count, Q
from django.utils import timezone

from alerts.enums import AlertStatus
from alerts.models import Alert
from cases.models import Case, CaseStatus
from core.models import (
    OrganizationJoinRequest,
    RoleChangeAuditLog,
    RolePermission,
    WorkspaceInvite,
    WorkspaceMembership,
    WorkspacePermission,
    WorkspaceRole,
)

from .models import (
    OrganizationAPIKey,
    OrganizationAuditLog,
    OrganizationDataSource,
    OrganizationSettings,
)

# Active (non-resolved) alert statuses
_ACTIVE_ALERT_STATUSES = [
    AlertStatus.OPEN,
    AlertStatus.ACKNOWLEDGED,
    AlertStatus.IN_PROGRESS,
    AlertStatus.REOPENED,
]


def get_org_overview(workspace):
    """
    Return a dict of overview statistics for the organization.
    """
    member_count = WorkspaceMembership.objects.filter(
        workspace=workspace,
        is_active=True,
        is_archived=False,
    ).count()

    active_alerts = Alert.objects.filter(
        workspace=workspace,
        is_deleted=False,
        status__in=_ACTIVE_ALERT_STATUSES,
    ).count()

    active_cases = Case.objects.filter(
        workspace=workspace,
        status__in=[CaseStatus.OPEN, CaseStatus.IN_PROGRESS, CaseStatus.ON_HOLD],
        archived=False,
    ).count()

    # SLA breaches: alerts with sla_deadline in the past that are not resolved
    now = timezone.now()
    sla_breaches = Alert.objects.filter(
        workspace=workspace,
        is_deleted=False,
        sla_deadline__isnull=False,
        sla_deadline__lt=now,
        status__in=_ACTIVE_ALERT_STATUSES,
    ).count()

    return {
        "name": workspace.name,
        "id": workspace.id,
        "slug": workspace.slug,
        "created_at": workspace.created_at,
        "member_count": member_count,
        "active_alerts": active_alerts,
        "active_cases": active_cases,
        "sla_breaches": sla_breaches,
    }


def get_org_members(workspace):
    """
    Return active members of the workspace with user and role info.
    """
    return (
        WorkspaceMembership.objects.filter(
            workspace=workspace,
            is_active=True,
            is_archived=False,
        )
        .select_related("user", "role")
        .order_by("-role__level", "user__username")
    )


def get_pending_join_requests(workspace):
    """
    Return pending join requests for the workspace.
    """
    return (
        OrganizationJoinRequest.objects.filter(
            workspace=workspace,
            status="PENDING",
        )
        .select_related("user")
        .order_by("-created_at")
    )


def get_org_invites(workspace):
    """
    Return active (non-used) invites for the workspace.
    """
    return (
        WorkspaceInvite.objects.filter(
            workspace=workspace,
            is_used=False,
        )
        .select_related("invited_by", "invited_user")
        .order_by("-created_at")
    )


def get_analyst_workload(workspace):
    """
    Return analyst workload: open alerts and active cases per analyst.
    Only includes members with analyst-level or higher roles (excludes VIEWER).
    """
    members = (
        WorkspaceMembership.objects.filter(
            workspace=workspace,
            is_active=True,
            is_archived=False,
        )
        .exclude(role__code="SOC_VIEWER")
        .select_related("user", "role")
        .order_by("user__username")
    )

    workload = []
    for member in members:
        open_alerts = Alert.objects.filter(
            workspace=workspace,
            is_deleted=False,
            assigned_to=member.user,
            status__in=_ACTIVE_ALERT_STATUSES,
        ).count()

        active_cases = Case.objects.filter(
            workspace=workspace,
            primary_assignee=member.user,
            status__in=[CaseStatus.OPEN, CaseStatus.IN_PROGRESS],
            archived=False,
        ).count()

        workload.append({
            "user": member.user,
            "role": member.role,
            "open_alerts": open_alerts,
            "active_cases": active_cases,
        })

    return workload


def get_analyst_activity(workspace):
    """
    Return analyst activity: alerts resolved, cases closed, last active.
    Only includes members with analyst-level or higher roles (excludes VIEWER).
    """
    members = (
        WorkspaceMembership.objects.filter(
            workspace=workspace,
            is_active=True,
            is_archived=False,
        )
        .exclude(role__code="SOC_VIEWER")
        .select_related("user", "role")
        .order_by("user__username")
    )

    activity = []
    for member in members:
        alerts_resolved = Alert.objects.filter(
            workspace=workspace,
            is_deleted=False,
            assigned_to=member.user,
            status__in=[AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE],
        ).count()

        cases_closed = Case.objects.filter(
            workspace=workspace,
            primary_assignee=member.user,
            status__in=[CaseStatus.RESOLVED, CaseStatus.CLOSED],
            archived=False,
        ).count()

        last_active = member.user.last_login

        activity.append({
            "user": member.user,
            "role": member.role,
            "alerts_resolved": alerts_resolved,
            "cases_closed": cases_closed,
            "last_active": last_active,
        })

    return activity


def get_org_api_keys(workspace):
    """
    Return API keys for the workspace.
    """
    return (
        OrganizationAPIKey.objects.filter(workspace=workspace)
        .select_related("created_by")
        .order_by("-created_at")
    )


def get_org_audit_logs(workspace, limit=50):
    """
    Return recent audit log entries from the DB-backed audit log.
    """
    return (
        OrganizationAuditLog.objects.filter(workspace=workspace)
        .select_related("user")
        .order_by("-timestamp")[:limit]
    )


def get_org_settings(workspace):
    """
    Return settings for the workspace (create defaults if not exists).
    """
    settings_obj, _ = OrganizationSettings.objects.get_or_create(
        workspace=workspace,
        defaults={
            "description": "",
            "visibility": "private",
            "require_email_verification": True,
            "session_timeout_minutes": 480,
            "allowed_email_domains": "",
            "api_access_enabled": True,
        },
    )
    return settings_obj


def get_role_change_history(workspace, limit=20):
    """
    Return recent role change audit entries.
    """
    return (
        RoleChangeAuditLog.objects.filter(workspace=workspace)
        .select_related("user", "changed_by")
        .order_by("-changed_at")[:limit]
    )


def get_data_sources(workspace):
    """
    Return data sources for the workspace.
    """
    from django.utils import timezone
    from api.models import IngestionEvent
    
    sources = OrganizationDataSource.objects.filter(workspace=workspace).order_by("-created_at")
    today = timezone.now().date()
    
    # Calculate logs today for each source
    for source in sources:
        source.logs_today = IngestionEvent.objects.filter(
            workspace=workspace,
            source=source.source_type,
            created_at__date=today
        ).count()
        
    return sources


def get_ingestion_error_logs(workspace, limit=50):
    """
    Return recent ingestion error events.
    """
    from django.db.models import Q
    from api.models import IngestionEvent
    
    return IngestionEvent.objects.filter(
        Q(workspace=workspace) & 
        (Q(processing_status=IngestionEvent.ProcessingStatus.FAILED) | Q(parse_error__isnull=False))
    ).order_by("-received_at")[:limit]


def get_role_permissions_matrix():
    """
    Return a matrix of roles and their permissions for display.
    Returns a dict with:
      - roles: list of role names (excluding PERSONAL_OWNER)
      - permissions: list of dicts with 'name' and per-role booleans
    """
    # Organization-relevant roles in display order
    role_codes_ordered = [
        "ORG_OWNER",
        "SOC_MANAGER",
        "SOC_TIER_3_ANALYST",
        "SOC_TIER_2_ANALYST",
        "SOC_TIER_1_ANALYST",
        "SOC_VIEWER",
    ]

    roles = WorkspaceRole.objects.filter(code__in=role_codes_ordered)
    role_map = {r.code: r for r in roles}
    ordered_roles = [role_map[c] for c in role_codes_ordered if c in role_map]

    # Readable action names
    action_labels = {
        "can_assign_alert": "Assign Alerts",
        "can_escalate_alert": "Escalate Alerts",
        "can_close_case": "Close Cases",
        "can_reopen_case": "Reopen Cases",
        "can_unlock_alert": "Unlock Alerts",
        "can_edit_org_settings": "Manage Settings",
        "can_invite_members": "Invite Members",
        "can_remove_members": "Remove Members",
        "can_delete_workspace": "Delete Organization",
    }

    permissions = WorkspacePermission.objects.all()

    # Build permission -> set of role IDs
    rp_qs = RolePermission.objects.filter(
        role__in=ordered_roles,
    ).select_related("role", "permission")

    perm_role_map = {}
    for rp in rp_qs:
        perm_role_map.setdefault(rp.permission.code, set()).add(rp.role.code)

    rows = []
    for perm in permissions:
        if perm.code not in action_labels:
            continue
        granted = perm_role_map.get(perm.code, set())
        # Build a list of booleans matching ordered_roles for easy template iteration
        role_grants = [role.code in granted for role in ordered_roles]
        rows.append({
            "action": action_labels[perm.code],
            "grants": role_grants,
        })

    return {
        "roles": ordered_roles,
        "rows": rows,
    }


def get_workspace_api_usage(workspace):
    """
    Return workspace API usage statistics.
    Computed from actual data where available, with sensible defaults.
    """
    now = timezone.now()
    last_24h = now - timezone.timedelta(hours=24)

    # Count API keys used in last 24h
    api_calls_24h = OrganizationAPIKey.objects.filter(
        workspace=workspace,
        last_used_at__gte=last_24h,
    ).count()

    # Last ingestion: most recent alert created_at
    last_alert = Alert.objects.filter(
        workspace=workspace,
        is_deleted=False,
    ).order_by("-created_at").values_list("created_at", flat=True).first()

    last_ingestion = None
    if last_alert:
        diff = now - last_alert
        if diff.total_seconds() < 60:
            last_ingestion = "Just now"
        elif diff.total_seconds() < 3600:
            last_ingestion = f"{int(diff.total_seconds() // 60)} minutes ago"
        elif diff.total_seconds() < 86400:
            last_ingestion = f"{int(diff.total_seconds() // 3600)} hours ago"
        else:
            last_ingestion = f"{int(diff.days)} days ago"
    else:
        last_ingestion = "No data"

    # Data volume estimate: count of alerts as a rough proxy
    total_alerts = Alert.objects.filter(workspace=workspace).count()
    # Rough estimate: ~1KB per alert
    data_volume_kb = total_alerts * 1
    if data_volume_kb >= 1024 * 1024:
        data_volume = f"{data_volume_kb / (1024 * 1024):.1f} GB"
    elif data_volume_kb >= 1024:
        data_volume = f"{data_volume_kb / 1024:.1f} MB"
    else:
        data_volume = f"{data_volume_kb} KB"

    return {
        "api_calls_24h": api_calls_24h,
        "last_ingestion": last_ingestion,
        "data_volume": data_volume,
    }

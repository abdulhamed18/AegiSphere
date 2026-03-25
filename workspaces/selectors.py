"""
Workspace read queries. No mutations.
"""

from core.models import WorkspaceMembership


def get_workspace_members_for_assignment(workspace):
    """
    Return active workspace members for assignment dropdowns.
    Excludes soft-deleted (inactive) users and VIEWER role (cannot be assignee).
    """
    if workspace is None:
        return []
    return list(
        WorkspaceMembership.objects.filter(
            workspace=workspace,
            is_active=True,
            is_archived=False,
        )
        .exclude(role__code="SOC_VIEWER")
        .select_related("user", "role")
        .filter(user__is_active=True)
        .order_by("user__username")
    )

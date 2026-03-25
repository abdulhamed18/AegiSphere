"""
Organization-level RBAC enforcement.

Decorators and helpers for organization views. Reuses existing
workspaces.permissions for the core permission checks.
"""

from functools import wraps

from django.http import HttpResponseForbidden

from core.models import WorkspaceMembership

from workspaces.permissions import user_has_permission, user_role_level


# --- Role level constants (from workspaces/apps.py seed) ---
ROLE_LEVEL_OWNER = 90       # ORG_OWNER
ROLE_LEVEL_MANAGER = 80     # SOC_MANAGER
ROLE_LEVEL_ANALYST = 50     # SOC_TIER_1_ANALYST (lowest analyst)
ROLE_LEVEL_VIEWER = 10      # SOC_VIEWER

# --- Permission checks mapping to user spec ---
# Action                   | Owner | Manager | Analyst | Viewer
# View Organization        |  yes  |   yes   |   yes   |  yes
# Invite Members           |  yes  |   yes   |   no    |  no
# Approve Requests         |  yes  |   yes   |   no    |  no
# Change Roles             |  yes  |   yes   |   no    |  no
# Remove Members           |  yes  |   yes   |   no    |  no
# Manage Settings          |  yes  |   yes   |   no    |  no
# Delete Organization      |  yes  |   no    |   no    |  no


def get_membership(user, workspace):
    """Return the active membership for user in workspace, or None."""
    if not user or not user.is_authenticated or workspace is None:
        return None
    try:
        return WorkspaceMembership.objects.select_related("role").get(
            user=user,
            workspace=workspace,
            is_active=True,
            is_archived=False,
        )
    except WorkspaceMembership.DoesNotExist:
        return None


def get_user_org_role_code(user, workspace):
    """Return the role code string for the user's membership, or None."""
    membership = get_membership(user, workspace)
    return membership.role.code if membership else None


def is_org_member(user, workspace):
    """Check if user has an active membership in the workspace."""
    return get_membership(user, workspace) is not None


def can_manage_members(user, workspace):
    """Owner or Manager can invite, approve, change roles, remove members."""
    return user_has_permission(user, workspace, "can_invite_members")


def can_manage_settings(user, workspace):
    """Owner or Manager can edit organization settings."""
    return user_has_permission(user, workspace, "can_edit_org_settings")


def can_delete_organization(user, workspace):
    """Only Owner can delete the organization."""
    return user_has_permission(user, workspace, "can_delete_workspace")


def can_remove_members(user, workspace):
    """Owner or Manager can remove members."""
    return user_has_permission(user, workspace, "can_remove_members")


# --- Decorators ---

def require_org_workspace(view_func):
    """
    Decorator: ensure request.workspace is an organization or personal workspace
    and user has an active membership. Returns 403 otherwise.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        workspace = getattr(request, "workspace", None)
        if workspace is None:
            return HttpResponseForbidden("No active workspace.")
        if workspace.workspace_type not in ("organization", "personal"):
            return HttpResponseForbidden("This page is only available for organization and personal workspaces.")
        if not is_org_member(request.user, workspace):
            return HttpResponseForbidden("You are not a member of this workspace.")
        return view_func(request, *args, **kwargs)
    return wrapper


def require_manager_or_owner(view_func):
    """
    Decorator: require ORG_OWNER or SOC_MANAGER role.
    Must be used after @require_org_workspace.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        level = user_role_level(request.user, request.workspace)
        if level < ROLE_LEVEL_MANAGER:
            return HttpResponseForbidden("You do not have permission to perform this action.")
        return view_func(request, *args, **kwargs)
    return wrapper


def require_owner(view_func):
    """
    Decorator: require ORG_OWNER role.
    Must be used after @require_org_workspace.
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        level = user_role_level(request.user, request.workspace)
        if level < ROLE_LEVEL_OWNER:
            return HttpResponseForbidden("Only the organization owner can perform this action.")
        return view_func(request, *args, **kwargs)
    return wrapper

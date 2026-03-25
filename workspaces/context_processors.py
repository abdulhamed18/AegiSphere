"""Context processors for workspace-aware templates."""

from .utils import get_user_workspaces


def workspace_context(request):
    """Inject active_workspace and user_workspaces for navbar dropdown and breadcrumbs."""
    active_workspace = getattr(request, "active_workspace", None) or getattr(request, "workspace", None)
    if request.user.is_authenticated:
        user_workspaces = get_user_workspaces(request.user).order_by("name")
    else:
        user_workspaces = []
    return {
        "active_workspace": active_workspace,
        "user_workspaces": user_workspaces,
    }

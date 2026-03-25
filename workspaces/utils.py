from core.models import Workspace


def get_or_create_demo_workspace():
    """Return the single global demo workspace; create it if missing."""
    workspace, _ = Workspace.objects.get_or_create(
        slug="global-demo",
        defaults={
            "name": "Global Demo",
            "workspace_type": "demo",
        },
    )
    return workspace


def get_user_workspaces(user):
    """Return all workspaces the user belongs to (via active, non-archived membership only)."""
    if not user or not user.is_authenticated:
        return Workspace.objects.none()
    return Workspace.objects.filter(
        memberships__user=user,
        memberships__is_active=True,
        memberships__is_archived=False,
    ).distinct()


def set_active_workspace(request, workspace):
    """Store the active workspace id in session."""
    request.session["active_workspace_id"] = workspace.id


def get_active_workspace(request):
    """
    Return the active workspace if it exists and the user is a member.
    Otherwise return None.
    """
    if not request.user or not request.user.is_authenticated:
        return None
    workspace_id = request.session.get("active_workspace_id")
    if not workspace_id:
        return None
    user_workspaces = get_user_workspaces(request.user)
    try:
        workspace = user_workspaces.get(pk=workspace_id)
    except Workspace.DoesNotExist:
        return None
    return workspace


def filter_by_workspace(queryset, request):
    """Restrict queryset to the request's active workspace. Returns empty if no workspace."""
    if not request.workspace:
        return queryset.none()
    return queryset.filter(workspace=request.workspace)

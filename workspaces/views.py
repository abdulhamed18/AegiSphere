from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.views.decorators.http import require_POST

from core.models import Workspace

from .utils import get_user_workspaces, set_active_workspace


@require_POST
@login_required
def switch_workspace(request, workspace_id):
    """POST only; validate membership; set session active_workspace_id; redirect to dashboard. 403 if invalid."""
    user_workspaces = get_user_workspaces(request.user)
    try:
        workspace = user_workspaces.get(pk=workspace_id)
    except Workspace.DoesNotExist:
        return HttpResponseForbidden("You do not have access to this workspace.")
    request.session["active_workspace_id"] = workspace.id
    return redirect("dashboard")

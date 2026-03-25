from django.http import JsonResponse

from .utils import get_active_workspace, get_user_workspaces, set_active_workspace

# Paths exempt from workspace assignment and from demo read-only block (admin, auth, switch, static, api)
WORKSPACE_EXEMPT_PREFIXES = (
    "/admin/",
    "/accounts/login",
    "/accounts/logout",
    "/workspaces/switch/",
    "/switch-workspace/",
    "/static/",
    "/media/",
    "/api/",
)


def _is_workspace_exempt(path):
    return any(path.startswith(prefix) for prefix in WORKSPACE_EXEMPT_PREFIXES)


class WorkspaceMiddleware:
    """
    Session-based active workspace: read active_workspace_id from session,
    validate user is a member; if invalid or missing, select first valid
    membership workspace. Attach to request.active_workspace and request.workspace.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.user.is_authenticated:
            request.workspace = None
            request.active_workspace = None
        else:
            workspace = get_active_workspace(request)
            if workspace is None and not _is_workspace_exempt(request.path):
                user_workspaces = get_user_workspaces(request.user).order_by("name")
                first_workspace = user_workspaces.first()
                if first_workspace is not None:
                    set_active_workspace(request, first_workspace)
                    workspace = first_workspace
            
            if workspace is None and not _is_workspace_exempt(request.path):
                from django.http import HttpResponseForbidden
                return HttpResponseForbidden("No active workspace.")

            request.workspace = workspace
            request.active_workspace = workspace

            if request.user.is_superuser and workspace is not None and not _is_workspace_exempt(request.path):
                # Don't log static assets, HTMX polling, or favicon if they somehow slip through
                if request.method in ("GET", "POST") and not request.headers.get("x-hx-request"):
                    from organizations.models import OrganizationAuditLog
                    OrganizationAuditLog.objects.create(
                        workspace=workspace,
                        user=request.user,
                        action="ADMIN_WORKSPACE_ACCESS",
                        target=request.path,
                        metadata={
                            "method": request.method,
                        }
                    )

        # Demo workspace is read-only: block mutating methods outside exempt paths
        if (
            request.user.is_authenticated
            and request.workspace is not None
            and request.workspace.workspace_type == "demo"
            and request.method in ("POST", "PUT", "PATCH", "DELETE")
            and not _is_workspace_exempt(request.path)
        ):
            return JsonResponse(
                {"error": "Demo workspace is read-only"},
                status=403,
            )

        return self.get_response(request)

"""
Organization views — dashboard and action endpoints.
"""

import json

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from core.models import WorkspaceInvite, WorkspaceRole

from .permissions import (
    can_delete_organization,
    can_manage_members,
    can_manage_settings,
    get_user_org_role_code,
    require_manager_or_owner,
    require_org_workspace,
    require_owner,
)
from .selectors import (
    get_analyst_activity,
    get_analyst_workload,
    get_data_sources,
    get_org_api_keys,
    get_org_audit_logs,
    get_org_invites,
    get_org_members,
    get_org_overview,
    get_org_settings,
    get_pending_join_requests,
    get_role_permissions_matrix,
    get_workspace_api_usage,
    get_ingestion_error_logs,
)
from .services import (
    approve_join_request_service,
    change_member_role_service,
    create_invite_service,
    delete_organization_service,
    generate_api_key,
    leave_organization_service,
    reject_join_request_service,
    remove_member_service,
    revoke_api_key,
    revoke_invite_service,
    update_org_settings,
    update_workspace_info,
)


# --- Role choices for template dropdowns ---
ORG_ROLE_CHOICES = [
    ("ORG_OWNER", "Owner"),
    ("SOC_MANAGER", "Manager"),
    ("SOC_TIER_3_ANALYST", "Tier 3 Analyst"),
    ("SOC_TIER_2_ANALYST", "Tier 2 Analyst"),
    ("SOC_TIER_1_ANALYST", "Tier 1 Analyst"),
    ("SOC_VIEWER", "Viewer"),
]

INVITE_ROLE_CHOICES = [
    ("SOC_MANAGER", "Manager"),
    ("SOC_TIER_3_ANALYST", "Tier 3 Analyst"),
    ("SOC_TIER_2_ANALYST", "Tier 2 Analyst"),
    ("SOC_TIER_1_ANALYST", "Tier 1 Analyst"),
    ("SOC_VIEWER", "Viewer"),
]


@login_required
@require_org_workspace
def organization_dashboard(request):
    """Main organization control panel — renders tabbed UI."""
    workspace = request.workspace
    user = request.user
    role_code = get_user_org_role_code(user, workspace)

    context = {
        "page_title": "Organization",
        "overview": get_org_overview(workspace),
        "members": get_org_members(workspace),
        "join_requests": get_pending_join_requests(workspace),
        "invites": get_org_invites(workspace),
        "analyst_workload": get_analyst_workload(workspace),
        "analyst_activity": get_analyst_activity(workspace),
        "api_keys": get_org_api_keys(workspace) if can_manage_members(user, workspace) else [],
        "audit_logs": get_org_audit_logs(workspace) if role_code in ("ORG_OWNER", "PERSONAL_OWNER") else [],
        "org_settings": get_org_settings(workspace),
        "data_sources": get_data_sources(workspace),
        "ingestion_errors": get_ingestion_error_logs(workspace) if can_manage_settings(user, workspace) else [],
        "role_permissions_matrix": get_role_permissions_matrix(),
        "api_usage": get_workspace_api_usage(workspace),
        "workspace": workspace,
        "user_role": role_code,
        "can_manage": can_manage_members(user, workspace),
        "can_settings": can_manage_settings(user, workspace),
        "can_delete": can_delete_organization(user, workspace),
        "role_choices": ORG_ROLE_CHOICES,
        "invite_role_choices": INVITE_ROLE_CHOICES,
        "active_api_keys": get_org_api_keys(workspace).filter(is_active=True) if can_manage_members(user, workspace) else [],
    }
    return render(request, "organizations/organization_dashboard.html", context)


@login_required
@require_org_workspace
@require_manager_or_owner
@require_POST
def add_data_source(request):
    """Add a new data source from the wizard."""
    from .models import OrganizationDataSource
    
    source_type = request.POST.get("source_type", "custom")
    ingestion_method = request.POST.get("ingestion_method", "webhook")
    name = request.POST.get("name", f"{source_type.title()} Integration").strip()
    
    # Check for duplicates
    if OrganizationDataSource.objects.filter(workspace=request.workspace, name=name).exists():
        messages.error(request, "A data source with this name already exists in your workspace.")
        return redirect("organizations:dashboard")

    OrganizationDataSource.objects.create(
        workspace=request.workspace,
        name=name,
        source_type=source_type,
        status="active",
        config={
            "parser": f"{source_type}_parser",
            "ingestion_method": ingestion_method
        }
    )
    
    messages.success(request, "Data source added successfully.")
    return redirect("organizations:dashboard")


@login_required
@require_org_workspace
def organization_source_details(request, pk):
    """View details for a specific data source."""
    import json
    from django.shortcuts import get_object_or_404
    from .models import OrganizationDataSource
    from api.models import IngestionEvent
    
    workspace = request.workspace
    source = get_object_or_404(OrganizationDataSource, pk=pk, workspace=workspace)
    
    latest_event = IngestionEvent.objects.filter(
        workspace=workspace,
        source=source.source_type
    ).order_by('-received_at').first()
    
    if latest_event and latest_event.raw_log:
        try:
            raw_event_sample = json.dumps(latest_event.raw_log, indent=2)
        except Exception:
            raw_event_sample = str(latest_event.raw_log)
    else:
        raw_event_sample = "No events received yet"
    
    context = {
        "page_title": f"Source Details - {source.name}",
        "workspace": workspace,
        "source": source,
        "raw_event_sample": raw_event_sample,
    }
    return render(request, "organizations/source_details.html", context)


# --- Member Actions ---

@login_required
@require_org_workspace
@require_manager_or_owner
@require_POST
def change_role(request):
    """Change a member's role."""
    target_user_id = request.POST.get("user_id")
    new_role = request.POST.get("role")
    try:
        change_member_role_service(request.user, request.workspace, target_user_id, new_role)
        messages.success(request, "Role updated successfully.")
    except (ValidationError, Exception) as e:
        messages.error(request, str(e))
    return redirect("organizations:dashboard")


@login_required
@require_org_workspace
@require_manager_or_owner
@require_POST
def remove_member(request):
    """Remove a member from the organization."""
    target_user_id = request.POST.get("user_id")
    try:
        remove_member_service(request.user, request.workspace, target_user_id)
        messages.success(request, "Member removed successfully.")
    except (ValidationError, Exception) as e:
        messages.error(request, str(e))
    return redirect("organizations:dashboard")


# --- Join Request Actions ---

@login_required
@require_org_workspace
@require_manager_or_owner
@require_POST
def approve_request(request, pk):
    """Approve a join request."""
    try:
        approve_join_request_service(request.user, request.workspace, pk)
        messages.success(request, "Join request approved.")
    except (ValidationError, Exception) as e:
        messages.error(request, str(e))
    return redirect("organizations:dashboard")


@login_required
@require_org_workspace
@require_manager_or_owner
@require_POST
def reject_request(request, pk):
    """Reject a join request."""
    try:
        reject_join_request_service(request.user, request.workspace, pk)
        messages.success(request, "Join request rejected.")
    except (ValidationError, Exception) as e:
        messages.error(request, str(e))
    return redirect("organizations:dashboard")


# --- Invite Actions ---

@login_required
@require_org_workspace
@require_manager_or_owner
@require_POST
def create_invite(request):
    """Create a new invite link — returns JSON with invite URL."""
    role = request.POST.get("role", "SOC_VIEWER")
    try:
        invite = create_invite_service(request.user, request.workspace, role=role)
        # Build full invite URL
        invite_url = request.build_absolute_uri(f"/workspaces/join/invite/{invite.token}/")

        # Check if request expects JSON (AJAX)
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse({
                "success": True,
                "invite_url": invite_url,
                "token": str(invite.token),
            })

        # Fallback: set message and redirect
        messages.success(request, f"Invite created. Token: {invite.token}")
    except (ValidationError, Exception) as e:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse({"success": False, "error": str(e)}, status=400)
        messages.error(request, str(e))
    return redirect("organizations:dashboard")


@login_required
@require_org_workspace
@require_manager_or_owner
@require_POST
def revoke_invite(request, pk):
    """Revoke an invite."""
    try:
        revoke_invite_service(request.user, request.workspace, pk)
        messages.success(request, "Invite revoked.")
    except (ValidationError, Exception) as e:
        messages.error(request, str(e))
    return redirect("organizations:dashboard")


# --- API Key Actions ---

@login_required
@require_org_workspace
@require_manager_or_owner
@require_POST
def generate_key(request):
    """Generate a new API key — returns JSON with raw key for modal display."""
    name = request.POST.get("name", "").strip()
    if not name:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse({"success": False, "error": "API key name is required."}, status=400)
        messages.error(request, "API key name is required.")
        return redirect("organizations:dashboard")
    try:
        api_key, raw_key = generate_api_key(request.user, request.workspace, name)

        # Return JSON for AJAX
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse({
                "success": True,
                "raw_key": raw_key,
                "key_name": name,
                "key_prefix": api_key.key_prefix,
            })

        # Fallback
        messages.success(
            request,
            f"API key generated. Copy this key now — it will not be shown again: {raw_key}"
        )
    except (ValidationError, Exception) as e:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse({"success": False, "error": str(e)}, status=400)
        messages.error(request, str(e))
    return redirect("organizations:dashboard")


@login_required
@require_org_workspace
@require_manager_or_owner
@require_POST
def revoke_key(request, pk):
    """Revoke an API key."""
    try:
        revoke_api_key(request.user, request.workspace, pk)
        messages.success(request, "API key revoked.")
    except (ValidationError, Exception) as e:
        messages.error(request, str(e))
    # If the request comes from the API Keys page, redirect back there
    if "api-keys" in request.META.get("HTTP_REFERER", ""):
        return redirect("organizations:api-keys")
    return redirect("organizations:dashboard")


@login_required
@require_org_workspace
@require_manager_or_owner
def rotate_api_key(request, pk):
    """Rotate an existing API key."""
    from .models import OrganizationAPIKey
    import secrets
    import hashlib
    
    try:
        api_key = OrganizationAPIKey.objects.get(id=pk, workspace=request.workspace)
        
        # Check if the model has a rotate method, otherwise fallback to manual update
        if hasattr(api_key, 'rotate'):
            api_key.rotate()
        else:
            raw_key = secrets.token_urlsafe(48)
            api_key.key_prefix = raw_key[:8]
            api_key.key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            api_key.save(update_fields=["key_prefix", "key_hash"])
            # In a real scenario we'd want to show this to the user,
            # but for now we just return the raw_key in JSON as requested
        
        return JsonResponse({
            "success": True, 
            "message": "Key rotated successfully.",
            "raw_key": raw_key if 'raw_key' in locals() else None
        })
    except OrganizationAPIKey.DoesNotExist:
        return JsonResponse({"success": False, "error": "API key not found."}, status=404)
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=400)


@login_required
@require_org_workspace
@require_manager_or_owner
def api_keys_list(request):
    """See All API Keys management page."""
    from .models import OrganizationAPIKey
    api_keys = OrganizationAPIKey.objects.filter(workspace=request.workspace)
    return render(request, "organizations/api_keys.html", {
        "page_title": "API Keys",
        "workspace": request.workspace,
        "api_keys": api_keys,
    })


# --- Settings Actions ---

@login_required
@require_org_workspace
@require_manager_or_owner
@require_POST
def update_settings(request):
    """Update organization security settings."""
    try:
        data = {
            "require_email_verification": request.POST.get("require_email_verification") == "on",
            "session_timeout_minutes": int(request.POST.get("session_timeout_minutes", 480)),
            "allowed_email_domains": request.POST.get("allowed_email_domains", "").strip(),
            "api_access_enabled": request.POST.get("api_access_enabled") == "on",
        }
        update_org_settings(request.user, request.workspace, data)
        messages.success(request, "Security settings updated.")
    except (ValidationError, ValueError, Exception) as e:
        messages.error(request, str(e))
    return redirect("organizations:dashboard")


@login_required
@require_org_workspace
@require_manager_or_owner
@require_POST
def update_workspace(request):
    """Update workspace name and join configuration."""
    try:
        data = {
            "name": request.POST.get("name", "").strip(),
            "allow_join_by_id": request.POST.get("allow_join_by_id") == "on",
            "invite_only": request.POST.get("invite_only") == "on",
        }

        # Also update description and visibility in org settings
        settings_data = {
            "description": request.POST.get("description", "").strip(),
            "visibility": request.POST.get("visibility", "private"),
        }
        update_workspace_info(request.user, request.workspace, data)
        update_org_settings(request.user, request.workspace, settings_data)
        messages.success(request, "Organization settings updated.")
    except (ValidationError, Exception) as e:
        messages.error(request, str(e))
    return redirect("organizations:dashboard")


# --- Danger Zone ---

@login_required
@require_org_workspace
@require_POST
def leave_org(request):
    """Leave the organization."""
    try:
        leave_organization_service(request.user, request.workspace)
        messages.success(request, "You have left the organization.")
        return redirect("dashboard")
    except (ValidationError, Exception) as e:
        messages.error(request, str(e))
    return redirect("organizations:dashboard")


@login_required
@require_org_workspace
@require_owner
@require_POST
def delete_org(request):
    """Delete the organization. Owner only."""
    try:
        delete_organization_service(request.user, request.workspace)
        messages.success(request, "Organization has been deleted.")
        return redirect("dashboard")
    except (ValidationError, Exception) as e:
        messages.error(request, str(e))
    return redirect("organizations:dashboard")

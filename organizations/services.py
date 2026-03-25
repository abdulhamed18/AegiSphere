"""
Organization services — mutation operations.
Delegates to existing workspaces services where possible,
adds new logic for API keys and DB-backed audit logging.
"""

import hashlib
import secrets

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from core.models import WorkspaceMembership, WorkspaceInvite

from .models import OrganizationAPIKey, OrganizationAuditLog, OrganizationSettings
from .permissions import (
    can_delete_organization,
    can_manage_members,
    can_manage_settings,
    can_remove_members,
    get_membership,
)


# --- Audit Logging ---

def log_org_action(workspace, user, action, target="", metadata=None):
    """
    Write a persistent audit log entry to the database.
    Never raises; wrapped in try/except for safety.
    """
    try:
        OrganizationAuditLog.objects.create(
            workspace=workspace,
            user=user if user and user.is_authenticated else None,
            action=action,
            target=target,
            metadata=metadata or {},
        )
    except Exception:
        pass


# --- API Key Management ---

def generate_api_key(actor, workspace, name):
    """
    Generate a new API key for the workspace.
    Returns (api_key_object, raw_key) — raw_key is shown once and never stored.
    """
    if not can_manage_settings(actor, workspace):
        raise ValidationError("You do not have permission to generate API keys.")

    raw_key = secrets.token_urlsafe(48)
    key_prefix = raw_key[:8]
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    with transaction.atomic():
        api_key = OrganizationAPIKey.objects.create(
            workspace=workspace,
            name=name,
            key_prefix=key_prefix,
            key_hash=key_hash,
            created_by=actor,
            is_active=True,
        )
        log_org_action(
            workspace, actor,
            "API key generated",
            target=name,
            metadata={"key_id": api_key.pk, "key_prefix": key_prefix},
        )

    return api_key, raw_key


def revoke_api_key(actor, workspace, key_id):
    """
    Revoke (deactivate) an API key.
    """
    if not can_manage_settings(actor, workspace):
        raise ValidationError("You do not have permission to revoke API keys.")

    try:
        api_key = OrganizationAPIKey.objects.get(
            pk=key_id,
            workspace=workspace,
        )
    except OrganizationAPIKey.DoesNotExist:
        raise ValidationError("API key not found.")

    if not api_key.is_active:
        raise ValidationError("API key is already revoked.")

    with transaction.atomic():
        api_key.is_active = False
        api_key.save(update_fields=["is_active"])
        log_org_action(
            workspace, actor,
            "API key revoked",
            target=api_key.name,
            metadata={"key_id": api_key.pk, "key_prefix": api_key.key_prefix},
        )

    return api_key


# --- Organization Settings ---

def update_org_settings(actor, workspace, data):
    """
    Update organization settings. Only owners and managers can do this.
    `data` is a dict of field_name -> value.
    """
    if not can_manage_settings(actor, workspace):
        raise ValidationError("You do not have permission to update settings.")

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

    changed_fields = []
    allowed_fields = [
        "description", "visibility", "require_email_verification",
        "session_timeout_minutes", "allowed_email_domains", "api_access_enabled",
    ]

    with transaction.atomic():
        for field in allowed_fields:
            if field in data:
                old_val = getattr(settings_obj, field)
                new_val = data[field]
                if old_val != new_val:
                    setattr(settings_obj, field, new_val)
                    changed_fields.append(field)

        if changed_fields:
            settings_obj.save(update_fields=changed_fields + ["updated_at"])
            log_org_action(
                workspace, actor,
                "Organization settings updated",
                target=", ".join(changed_fields),
                metadata={"changed_fields": changed_fields},
            )

    return settings_obj


def update_workspace_info(actor, workspace, data):
    """
    Update workspace name and join configuration.
    """
    if not can_manage_settings(actor, workspace):
        raise ValidationError("You do not have permission to update workspace info.")

    changed = []
    with transaction.atomic():
        if "name" in data and data["name"] and data["name"] != workspace.name:
            workspace.name = data["name"]
            changed.append("name")

        if "allow_join_by_id" in data:
            val = bool(data["allow_join_by_id"])
            if val != workspace.allow_join_by_id:
                workspace.allow_join_by_id = val
                changed.append("allow_join_by_id")

        if "invite_only" in data:
            val = bool(data["invite_only"])
            if val != workspace.invite_only:
                workspace.invite_only = val
                changed.append("invite_only")

        if changed:
            # Bypass workspace.save() which calls full_clean; use update instead
            from core.models import Workspace as WS
            WS.objects.filter(pk=workspace.pk).update(
                **{f: getattr(workspace, f) for f in changed}
            )
            log_org_action(
                workspace, actor,
                "Workspace info updated",
                target=", ".join(changed),
                metadata={"changed_fields": changed},
            )

    return workspace


# --- Member Management (delegates to existing services) ---

def change_member_role_service(actor, workspace, target_user_id, new_role_code):
    """
    Change a member's role. Delegates to workspaces.join_governance_service.
    """
    from workspaces.join_governance_service import change_member_role

    if not can_manage_members(actor, workspace):
        raise ValidationError("You do not have permission to change roles.")

    try:
        membership = WorkspaceMembership.objects.select_related("role").get(
            user_id=target_user_id,
            workspace=workspace,
            is_active=True,
        )
    except WorkspaceMembership.DoesNotExist:
        raise ValidationError("Member not found.")

    result = change_member_role(actor, membership, new_role_code)
    log_org_action(
        workspace, actor,
        "Member role changed",
        target=membership.user.username,
        metadata={"new_role": new_role_code},
    )
    return result


def remove_member_service(actor, workspace, target_user_id):
    """
    Remove a member from the workspace. Delegates to workspaces.membership_service.
    """
    from core.models import CustomUser
    from workspaces.membership_service import remove_member

    if not can_remove_members(actor, workspace):
        raise ValidationError("You do not have permission to remove members.")

    try:
        target_user = CustomUser.objects.get(pk=target_user_id)
    except CustomUser.DoesNotExist:
        raise ValidationError("User not found.")

    result = remove_member(actor, workspace, target_user)
    log_org_action(
        workspace, actor,
        "Member removed",
        target=target_user.username,
        metadata={"user_id": target_user_id},
    )
    return result


def approve_join_request_service(actor, workspace, request_id):
    """
    Approve a join request. Delegates to workspaces.join_governance_service.
    """
    from core.models import OrganizationJoinRequest
    from workspaces.join_governance_service import approve_join_request

    try:
        join_req = OrganizationJoinRequest.objects.get(
            pk=request_id,
            workspace=workspace,
        )
    except OrganizationJoinRequest.DoesNotExist:
        raise ValidationError("Join request not found.")

    result = approve_join_request(actor, join_req)
    log_org_action(
        workspace, actor,
        "Join request approved",
        target=join_req.user.username,
        metadata={"request_id": request_id},
    )
    return result


def reject_join_request_service(actor, workspace, request_id):
    """
    Reject a join request. Delegates to workspaces.join_governance_service.
    """
    from core.models import OrganizationJoinRequest
    from workspaces.join_governance_service import reject_join_request

    try:
        join_req = OrganizationJoinRequest.objects.get(
            pk=request_id,
            workspace=workspace,
        )
    except OrganizationJoinRequest.DoesNotExist:
        raise ValidationError("Join request not found.")

    result = reject_join_request(actor, join_req)
    log_org_action(
        workspace, actor,
        "Join request rejected",
        target=join_req.user.username,
        metadata={"request_id": request_id},
    )
    return result


def create_invite_service(actor, workspace, role="SOC_VIEWER"):
    """
    Create a workspace invite link. Delegates to workspaces.join_governance_service.
    """
    from workspaces.join_governance_service import create_invite

    result = create_invite(actor, workspace, role=role)
    log_org_action(
        workspace, actor,
        "Invite link created",
        target=f"Role: {role}",
        metadata={"invite_id": result.pk, "role": role},
    )
    return result


def revoke_invite_service(actor, workspace, invite_id):
    """
    Revoke an invite by marking it as used.
    """
    if not can_manage_members(actor, workspace):
        raise ValidationError("You do not have permission to revoke invites.")

    try:
        invite = WorkspaceInvite.objects.get(
            pk=invite_id,
            workspace=workspace,
        )
    except WorkspaceInvite.DoesNotExist:
        raise ValidationError("Invite not found.")

    if invite.is_used:
        raise ValidationError("Invite is already used/revoked.")

    with transaction.atomic():
        invite.is_used = True
        invite.save(update_fields=["is_used"])
        log_org_action(
            workspace, actor,
            "Invite revoked",
            target=f"Token: {invite.token[:8]}...",
            metadata={"invite_id": invite.pk},
        )

    return invite


def leave_organization_service(actor, workspace):
    """
    User leaves the organization. Delegates to workspaces.join_governance_service.
    """
    from workspaces.join_governance_service import leave_workspace

    username = actor.username
    leave_workspace(actor, workspace)
    log_org_action(
        workspace, actor,
        "Member left organization",
        target=username,
        metadata={"user_id": actor.pk},
    )


def delete_organization_service(actor, workspace):
    """
    Delete the organization workspace. Only owner can do this.
    """
    from workspaces.membership_service import delete_workspace

    if not can_delete_organization(actor, workspace):
        raise ValidationError("Only the organization owner can delete this workspace.")

    log_org_action(
        workspace, actor,
        "Organization deleted",
        target=workspace.name,
        metadata={"workspace_id": workspace.pk},
    )
    delete_workspace(actor, workspace)

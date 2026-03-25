"""
Safe membership management: add/remove members with permission and role checks.
Uses soft-deactivate for removal (is_active=False); does not delete rows.
Workspace deletion and ownership transfer must go through this service.
"""

from django.core.exceptions import ValidationError
from django.db import models as db_models
from django.db import transaction
from django.utils import timezone

from core.models import Workspace, WorkspaceMembership, WorkspaceRole

from .permissions import user_has_permission


def add_member(actor_user, workspace, target_user, role_code):
    """
    Add target_user to workspace with the given role. Validates actor permission,
    workspace type, and prevents assigning owner roles manually.
    Returns the created or existing membership.
    """
    if not user_has_permission(actor_user, workspace, "can_invite_members"):
        raise ValidationError("You do not have permission to invite members.")

    if workspace.workspace_type == "demo":
        raise ValidationError("No memberships are allowed for demo workspaces.")

    if workspace.workspace_type == "personal":
        raise ValidationError(
            "Personal workspaces allow only the owner; cannot add other members."
        )

    if role_code in WorkspaceMembership.OWNER_ROLE_CODES:
        raise ValidationError("Owner roles cannot be assigned manually.")

    try:
        role = WorkspaceRole.objects.get(code=role_code)
    except WorkspaceRole.DoesNotExist:
        raise ValidationError(f"Unknown role code: {role_code}.")

    membership, _ = WorkspaceMembership.objects.get_or_create(
        user=target_user,
        workspace=workspace,
        defaults={"role": role, "is_active": True},
    )
    if not membership.is_active:
        membership.is_active = True
        membership.role = role
        membership.save(update_fields=["is_active", "role"])
    return membership


def remove_member(actor_user, workspace, target_user):
    """
    Soft-deactivate the target user's membership (set is_active=False).
    Does not delete the row. Validates actor permission and protects owner roles.
    """
    if not user_has_permission(actor_user, workspace, "can_remove_members"):
        raise ValidationError("You do not have permission to remove members.")

    try:
        target_membership = WorkspaceMembership.objects.select_related("role").get(
            user=target_user,
            workspace=workspace,
            is_active=True,
        )
    except WorkspaceMembership.DoesNotExist:
        raise ValidationError("No active membership found for this user in the workspace.")

    allow_owner_self_removal = False
    if (
        target_user == actor_user
        and target_membership.role.code == "ORG_OWNER"
        and workspace.workspace_type == "organization"
    ):
        org_owner_count = WorkspaceMembership.objects.filter(
            workspace=workspace,
            is_active=True,
            role__code="ORG_OWNER",
        ).count()
        if org_owner_count <= 1:
            raise ValidationError(
                "You must assign another Organization Owner before leaving."
            )
        allow_owner_self_removal = True

    if (
        target_membership.role.code in WorkspaceMembership.OWNER_ROLE_CODES
        and not allow_owner_self_removal
    ):
        raise ValidationError("Owner role cannot be removed.")

    now = timezone.now()
    target_membership.is_active = False
    target_membership.deactivated_at = now
    if actor_user == target_user:
        target_membership.left_at = now
        target_membership.save(update_fields=["is_active", "deactivated_at", "left_at"])
    else:
        target_membership.save(update_fields=["is_active", "deactivated_at"])
    return target_membership


def delete_workspace(actor_user, workspace):
    """
    Safely delete a workspace. Only allowed for non-demo workspaces when the
    actor has can_delete_workspace and is the appropriate owner (ORG_OWNER or
    PERSONAL_OWNER). Do not call workspace.delete() directly elsewhere.
    """
    if workspace.workspace_type == "demo":
        raise ValidationError("Demo workspaces cannot be deleted.")

    if not user_has_permission(actor_user, workspace, "can_delete_workspace"):
        raise ValidationError("You do not have permission to delete this workspace.")

    try:
        actor_membership = WorkspaceMembership.objects.select_related("role").get(
            user=actor_user,
            workspace=workspace,
            is_active=True,
        )
    except WorkspaceMembership.DoesNotExist:
        raise ValidationError("You do not have an active membership in this workspace.")

    role_code = actor_membership.role.code
    if workspace.workspace_type == "organization":
        if role_code != "ORG_OWNER":
            raise ValidationError(
                "Only the organization owner can delete this workspace."
            )
    elif workspace.workspace_type == "personal":
        if role_code != "PERSONAL_OWNER":
            raise ValidationError(
                "Only the personal workspace owner can delete this workspace."
            )

    try:
        db_models.Model.delete(workspace)
    except db_models.ProtectedError:
        raise ValidationError(
            "Cannot delete workspace. Existing cases must be resolved or archived first."
        )


def purge_expired_memberships():
    """
    Archive memberships that have been soft-deactivated for more than 30 days.
    Sets is_archived=True and archived_at=timezone.now(). Does not delete rows.
    """
    cutoff = timezone.now() - timezone.timedelta(days=30)
    to_archive = WorkspaceMembership.objects.filter(
        is_active=False,
        deactivated_at__isnull=False,
        deactivated_at__lte=cutoff,
        is_archived=False,
    )
    count = to_archive.count()
    now = timezone.now()
    to_archive.update(is_archived=True, archived_at=now)
    return count


def hard_delete_archived_memberships(retention_days=365):
    """
    Permanently delete memberships that have been archived for longer than
    retention_days. Use for compliance retention cleanup.
    """
    cutoff = timezone.now() - timezone.timedelta(days=retention_days)
    to_delete = WorkspaceMembership.all_objects.filter(
        is_archived=True,
        archived_at__isnull=False,
        archived_at__lte=cutoff,
    )
    count = to_delete.count()
    to_delete.delete()
    return count


def transfer_ownership(actor_user, workspace, new_owner_user, downgrade_previous_owner=True):
    """
    Add ORG_OWNER role to new_owner_user in the organization. Optionally
    downgrade the previous owner (actor) to SOC_MANAGER. Multiple ORG_OWNER
    memberships are allowed; no single-owner requirement.
    """
    if workspace.workspace_type == "personal":
        raise ValidationError("Ownership of personal workspaces cannot be transferred.")

    if workspace.workspace_type != "organization":
        raise ValidationError("Ownership transfer is only allowed for organization workspaces.")

    try:
        actor_membership = WorkspaceMembership.objects.select_related("role").get(
            user=actor_user,
            workspace=workspace,
            is_active=True,
        )
    except WorkspaceMembership.DoesNotExist:
        raise ValidationError("You do not have an active membership in this workspace.")

    if actor_membership.role.code != "ORG_OWNER":
        raise ValidationError("Only the organization owner can transfer ownership.")

    try:
        new_owner_membership = WorkspaceMembership.objects.select_related("role").get(
            user=new_owner_user,
            workspace=workspace,
            is_active=True,
        )
    except WorkspaceMembership.DoesNotExist:
        raise ValidationError(
            "The new owner must already have an active membership in this workspace."
        )

    if new_owner_user == actor_user:
        raise ValidationError("The new owner must be a different user.")

    try:
        org_owner_role = WorkspaceRole.objects.get(code="ORG_OWNER")
    except WorkspaceRole.DoesNotExist:
        raise ValidationError("Required roles are not configured.")

    with transaction.atomic():
        if downgrade_previous_owner:
            try:
                soc_manager_role = WorkspaceRole.objects.get(code="SOC_MANAGER")
            except WorkspaceRole.DoesNotExist:
                raise ValidationError("Required roles are not configured.")
            actor_membership.role = soc_manager_role
            actor_membership.save(update_fields=["role"])

        new_owner_membership.role = org_owner_role
        new_owner_membership.save(update_fields=["role"])

        # No workspace.owner update; ownership is determined by ORG_OWNER membership only.

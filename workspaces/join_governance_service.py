"""
Phase 3 – Organization Join & Governance services.
All membership mutations go through this module or membership_service.
Uses existing RBAC (user_has_permission); no model changes.
"""

import logging
import secrets
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from core.models import (
    OnboardingChecklistStatus,
    OrganizationBlockList,
    OrganizationJoinRequest,
    RoleChangeAuditLog,
    Workspace,
    WorkspaceInvite,
    WorkspaceMembership,
    WorkspaceRole,
)

from .audit import log_governance_action
from .exceptions import (
    AlreadyMember,
    CooldownViolation,
    InviteInvalid,
    PermissionDenied,
    RequestExpired,
)
from .notifications import (
    NotificationEvent,
    notify_user,
    notify_workspace_admins,
)
from .permissions import user_has_permission


# Cooldown / config
JOIN_REQUEST_REJECTION_COOLDOWN_DAYS = 7
LEFT_ORG_COOLDOWN_DAYS = 3
INVITE_EXPIRY_DAYS = 7
JOIN_REQUEST_EXPIRY_DAYS = 7

# Allowed admin roles for governance actions (in addition to permission checks)
GOVERNANCE_ADMIN_ROLES = ("ORG_OWNER", "SOC_MANAGER")


def submit_join_request(user, workspace, reason=None):
    """
    Submit a join request for an organization workspace.
    Enforces email verification, workspace type, block list, cooldowns, single pending.
    """
    if not user or not user.is_authenticated:
        raise PermissionDenied("Authentication required.")
    if not getattr(user, "is_verified", False):
        raise PermissionDenied("Email must be verified to request access.")

    if workspace.workspace_type != "organization":
        raise PermissionDenied("Join requests are only for organization workspaces.")
    if workspace.invite_only:
        raise PermissionDenied("This organization is invite-only; join by invite only.")

    if OrganizationBlockList.objects.filter(
        workspace=workspace, blocked_user=user
    ).exists():
        raise PermissionDenied("You are blocked from this organization.")

    if WorkspaceMembership.objects.filter(
        user=user, workspace=workspace, is_active=True
    ).exists():
        raise AlreadyMember("You are already a member.")

    now = timezone.now()
    rejection_cutoff = now - timedelta(days=JOIN_REQUEST_REJECTION_COOLDOWN_DAYS)
    last_rejected = (
        OrganizationJoinRequest.objects.filter(
            user=user,
            workspace=workspace,
            status="REJECTED",
            reviewed_at__gte=rejection_cutoff,
        )
        .order_by("-reviewed_at")
        .first()
    )
    if last_rejected:
        raise CooldownViolation(
            "You cannot submit a new request yet due to a recent rejection."
        )

    # Cooldown: use explicit left_at (governance-safe; invite-based join bypasses this)
    left_cutoff = now - timedelta(days=LEFT_ORG_COOLDOWN_DAYS)
    former = WorkspaceMembership.all_objects.filter(
        user=user,
        workspace=workspace,
        is_active=False,
        left_at__isnull=False,
        left_at__gte=left_cutoff,
    ).first()
    if former:
        raise CooldownViolation(
            "You must wait before requesting to rejoin after leaving."
        )

    if OrganizationJoinRequest.objects.filter(
        user=user, workspace=workspace, status="PENDING"
    ).exists():
        raise PermissionDenied("You already have a pending request for this workspace.")

    with transaction.atomic():
        expires_at = now + timedelta(days=JOIN_REQUEST_EXPIRY_DAYS)
        request = OrganizationJoinRequest.objects.create(
            user=user,
            workspace=workspace,
            requested_role="SOC_VIEWER",
            status="PENDING",
            reason=reason or "",
            expires_at=expires_at,
        )
        try:
            log_governance_action(user, workspace, NotificationEvent.JOIN_REQUEST_SUBMITTED, target_user=user, metadata={"request_id": request.pk})
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
        try:
            notify_workspace_admins(NotificationEvent.JOIN_REQUEST_SUBMITTED, workspace, metadata={"request_id": request.pk})
        except Exception:
            pass
    return request


def withdraw_join_request(user, join_request):
    """Withdraw a PENDING join request. Only the request owner can withdraw."""
    if not user or not user.is_authenticated:
        raise PermissionDenied("Authentication required.")
    if join_request.user_id != user.pk:
        raise PermissionDenied("Only the request owner can withdraw.")
    if join_request.status != "PENDING":
        raise PermissionDenied("Only pending requests can be withdrawn.")

    with transaction.atomic():
        join_request.status = "WITHDRAWN"
        join_request.save(update_fields=["status"])
        # No notification sent intentionally.
        # Withdraw is user-initiated and does not require admin alert.
        try:
            log_governance_action(user, join_request.workspace, NotificationEvent.JOIN_REQUEST_WITHDRAWN, target_user=user, metadata={"request_id": join_request.pk})
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
    return join_request


def approve_join_request(approver, join_request, approval_comment=None):
    """
    Approve a PENDING join request: create/reactivate membership as SOC_VIEWER,
    update request, create onboarding checklist. Returns membership.
    """
    workspace = join_request.workspace
    target_user = join_request.user
    now = timezone.now()

    if not user_has_permission(approver, workspace, "can_invite_members"):
        raise PermissionDenied("You do not have permission to approve join requests.")
    try:
        approver_membership = WorkspaceMembership.objects.select_related("role").get(
            user=approver, workspace=workspace, is_active=True
        )
    except WorkspaceMembership.DoesNotExist:
        raise PermissionDenied("You do not have an active membership in this workspace.")
    if approver_membership.role.code not in GOVERNANCE_ADMIN_ROLES:
        raise PermissionDenied("Only organization owners or SOC managers can approve join requests.")

    if join_request.status != "PENDING":
        raise PermissionDenied("Only pending requests can be approved.")
    if join_request.expires_at < now:
        raise RequestExpired("This join request has expired.")
    if join_request.user_id == approver.pk:
        raise PermissionDenied("Self-approval is not allowed.")

    try:
        soc_viewer_role = WorkspaceRole.objects.get(code="SOC_VIEWER")
    except WorkspaceRole.DoesNotExist:
        raise PermissionDenied("Required roles are not configured.")

    with transaction.atomic():
        if OrganizationBlockList.objects.filter(
            workspace=workspace, blocked_user=target_user
        ).exists():
            raise PermissionDenied("User is blocked from this organization.")

        membership = WorkspaceMembership.all_objects.filter(
            user=target_user, workspace=workspace
        ).first()
        if membership:
            if membership.is_active:
                raise AlreadyMember("User is already an active member.")
            membership.is_active = True
            membership.deactivated_at = None
            membership.left_at = None
            membership.role = soc_viewer_role
            membership.save(update_fields=["is_active", "deactivated_at", "left_at", "role"])
        else:
            membership = WorkspaceMembership.objects.create(
                user=target_user,
                workspace=workspace,
                role=soc_viewer_role,
                is_active=True,
            )

        join_request.status = "APPROVED"
        join_request.reviewed_by = approver
        join_request.reviewed_at = now
        join_request.approval_comment = approval_comment or ""
        join_request.save(update_fields=["status", "reviewed_by", "reviewed_at", "approval_comment"])

        OnboardingChecklistStatus.objects.get_or_create(
            user=target_user,
            workspace=workspace,
            defaults={"profile_completed": False, "policy_read": False, "skipped": False},
        )
        try:
            log_governance_action(approver, workspace, NotificationEvent.JOIN_REQUEST_APPROVED, target_user=target_user, metadata={"request_id": join_request.pk})
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
        try:
            notify_user(NotificationEvent.JOIN_REQUEST_APPROVED, workspace, target_user, metadata={"request_id": join_request.pk})
        except Exception:
            pass
    return membership


def reject_join_request(approver, join_request, approval_comment=None):
    """Reject a PENDING join request. Updates status and reviewed fields."""
    workspace = join_request.workspace
    target_user = join_request.user
    if not user_has_permission(approver, workspace, "can_invite_members"):
        raise PermissionDenied("You do not have permission to reject join requests.")
    try:
        approver_membership = WorkspaceMembership.objects.select_related("role").get(
            user=approver, workspace=workspace, is_active=True
        )
    except WorkspaceMembership.DoesNotExist:
        raise PermissionDenied("You do not have an active membership in this workspace.")
    if approver_membership.role.code not in GOVERNANCE_ADMIN_ROLES:
        raise PermissionDenied("Only organization owners or SOC managers can reject join requests.")
    if join_request.status != "PENDING":
        raise PermissionDenied("Only pending requests can be rejected.")

    now = timezone.now()
    with transaction.atomic():
        join_request.status = "REJECTED"
        join_request.reviewed_by = approver
        join_request.reviewed_at = now
        join_request.approval_comment = approval_comment or ""
        join_request.save(update_fields=["status", "reviewed_by", "reviewed_at", "approval_comment"])
        try:
            log_governance_action(approver, workspace, NotificationEvent.JOIN_REQUEST_REJECTED, target_user=target_user, metadata={"request_id": join_request.pk})
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
        try:
            notify_user(NotificationEvent.JOIN_REQUEST_REJECTED, workspace, target_user, metadata={"request_id": join_request.pk})
        except Exception:
            pass
    return join_request


def create_invite(inviter, workspace, invited_user=None, role="SOC_VIEWER", expiry_days=None):
    """
    Create a workspace invite. Inviter must have can_invite_members.
    Returns WorkspaceInvite. expiry_days defaults to INVITE_EXPIRY_DAYS.
    """
    if not user_has_permission(inviter, workspace, "can_invite_members"):
        raise PermissionDenied("You do not have permission to create invites.")
    if workspace.workspace_type != "organization":
        raise PermissionDenied("Invites are only for organization workspaces.")

    days = expiry_days if expiry_days is not None else INVITE_EXPIRY_DAYS
    expires_at = timezone.now() + timedelta(days=days)
    token = secrets.token_urlsafe(32)
    if len(token) > 128:
        token = token[:128]

    with transaction.atomic():
        invite = WorkspaceInvite.objects.create(
            workspace=workspace,
            invited_user=invited_user,
            invited_by=inviter,
            role=role,
            token=token,
            expires_at=expires_at,
            is_used=False,
        )
        try:
            log_governance_action(inviter, workspace, NotificationEvent.INVITE_CREATED, target_user=invited_user, metadata={"invite_id": invite.pk, "role": role})
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
        if invited_user is not None:
            try:
                notify_user(NotificationEvent.INVITE_CREATED, workspace, invited_user, metadata={"invite_id": invite.pk})
            except Exception:
                pass
    return invite


def accept_invite(user, token):
    """
    Accept an invite by token. If invite has invited_user, it must match.
    Creates or reactivates membership, marks invite used, creates onboarding.
    """
    if not user or not user.is_authenticated:
        raise PermissionDenied("Authentication required.")

    invite = WorkspaceInvite.objects.filter(token=token).select_related("workspace").first()
    if not invite:
        raise InviteInvalid("Invite not found.")
    if invite.expires_at < timezone.now():
        raise InviteInvalid("Invite has expired.")
    if invite.is_used:
        raise InviteInvalid("Invite has already been used.")
    if invite.invited_user_id is not None and invite.invited_user_id != user.pk:
        raise InviteInvalid("This invite was sent to another user.")

    workspace = invite.workspace
    try:
        role = WorkspaceRole.objects.get(code=invite.role)
    except WorkspaceRole.DoesNotExist:
        role = WorkspaceRole.objects.get(code="SOC_VIEWER")

    with transaction.atomic():
        membership = WorkspaceMembership.all_objects.filter(
            user=user, workspace=workspace
        ).first()
        if membership:
            if membership.is_active:
                raise AlreadyMember("You are already a member of this workspace.")
            membership.is_active = True
            membership.deactivated_at = None
            membership.left_at = None
            membership.role = role
            membership.save(update_fields=["is_active", "deactivated_at", "left_at", "role"])
        else:
            membership = WorkspaceMembership.objects.create(
                user=user,
                workspace=workspace,
                role=role,
                is_active=True,
            )

        invite.is_used = True
        invite.save(update_fields=["is_used"])

        OnboardingChecklistStatus.objects.get_or_create(
            user=user,
            workspace=workspace,
            defaults={"profile_completed": False, "policy_read": False, "skipped": False},
        )
        try:
            log_governance_action(user, workspace, NotificationEvent.INVITE_ACCEPTED, target_user=user, metadata={"invite_id": invite.pk})
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
        try:
            notify_workspace_admins(NotificationEvent.INVITE_ACCEPTED, workspace, metadata={"user_id": user.pk})
        except Exception:
            pass
    return membership


def block_user(admin, workspace, target_user, reason=None):
    """
    Block a user from the workspace. Requires can_remove_members and ORG_OWNER or SOC_MANAGER.
    Auto-rejects any PENDING join request from target_user.
    """
    if not user_has_permission(admin, workspace, "can_remove_members"):
        raise PermissionDenied("You do not have permission to block members.")
    try:
        admin_membership = WorkspaceMembership.objects.select_related("role").get(
            user=admin, workspace=workspace, is_active=True
        )
    except WorkspaceMembership.DoesNotExist:
        raise PermissionDenied("You do not have an active membership in this workspace.")
    if admin_membership.role.code not in GOVERNANCE_ADMIN_ROLES:
        raise PermissionDenied("Only organization owners or SOC managers can block users.")
    if workspace.workspace_type != "organization":
        raise PermissionDenied("Block list is only for organization workspaces.")

    now = timezone.now()
    with transaction.atomic():
        OrganizationBlockList.objects.get_or_create(
            workspace=workspace,
            blocked_user=target_user,
            defaults={"blocked_by": admin, "reason": reason or ""},
        )
        pending = OrganizationJoinRequest.objects.filter(
            workspace=workspace,
            user=target_user,
            status="PENDING",
        )
        for req in pending:
            req.status = "REJECTED"
            req.reviewed_by = admin
            req.reviewed_at = now
            req.save(update_fields=["status", "reviewed_by", "reviewed_at"])
        try:
            log_governance_action(admin, workspace, NotificationEvent.USER_BLOCKED, target_user=target_user, metadata={"reason": reason})
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
    return None


def unblock_user(admin, workspace, target_user):
    """Remove a user from the workspace block list. Requires can_remove_members and ORG_OWNER or SOC_MANAGER."""
    if not user_has_permission(admin, workspace, "can_remove_members"):
        raise PermissionDenied("You do not have permission to unblock members.")
    try:
        admin_membership = WorkspaceMembership.objects.select_related("role").get(
            user=admin, workspace=workspace, is_active=True
        )
    except WorkspaceMembership.DoesNotExist:
        raise PermissionDenied("You do not have an active membership in this workspace.")
    if admin_membership.role.code not in GOVERNANCE_ADMIN_ROLES:
        raise PermissionDenied("Only organization owners or SOC managers can unblock users.")

    with transaction.atomic():
        OrganizationBlockList.objects.filter(
            workspace=workspace,
            blocked_user=target_user,
        ).delete()
        try:
            log_governance_action(admin, workspace, NotificationEvent.USER_UNBLOCKED, target_user=target_user, metadata={})
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
    return None


def change_member_role(admin, membership, new_role_code):
    """
    Change a member's role. Only ORG_OWNER or SOC_MANAGER. Cannot downgrade last ORG_OWNER.
    Creates RoleChangeAuditLog. Returns updated membership.
    """
    workspace = membership.workspace
    try:
        admin_membership = WorkspaceMembership.objects.select_related("role").get(
            user=admin, workspace=workspace, is_active=True
        )
    except WorkspaceMembership.DoesNotExist:
        raise PermissionDenied("You do not have an active membership in this workspace.")

    if admin_membership.role.code not in ("ORG_OWNER", "SOC_MANAGER"):
        raise PermissionDenied("Only organization owners or SOC managers can change roles.")

    try:
        new_role = WorkspaceRole.objects.get(code=new_role_code)
    except WorkspaceRole.DoesNotExist:
        raise PermissionDenied(f"Unknown role: {new_role_code}.")

    if new_role_code in WorkspaceMembership.OWNER_ROLE_CODES and membership.role.code not in WorkspaceMembership.OWNER_ROLE_CODES:
        if not user_has_permission(admin, workspace, "can_invite_members"):
            raise PermissionDenied("You cannot assign owner roles.")

    old_code = membership.role.code
    if old_code == "ORG_OWNER" and admin_membership.role.code != "ORG_OWNER":
        raise PermissionDenied("Managers cannot change the role of an organization owner.")

    if old_code == "ORG_OWNER" and new_role_code != "ORG_OWNER":
        other_owners = WorkspaceMembership.objects.filter(
            workspace=workspace,
            is_active=True,
            role__code="ORG_OWNER",
        ).exclude(user=membership.user)
        if not other_owners.exists():
            raise PermissionDenied("Cannot downgrade the last organization owner.")

    with transaction.atomic():
        membership.role = new_role
        membership.save(update_fields=["role"])
        RoleChangeAuditLog.objects.create(
            workspace=workspace,
            user=membership.user,
            changed_by=admin,
            old_role=old_code,
            new_role=new_role_code,
        )
        try:
            log_governance_action(admin, workspace, NotificationEvent.ROLE_CHANGED, target_user=membership.user, metadata={"old_role": old_code, "new_role": new_role_code})
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
        try:
            notify_user(NotificationEvent.ROLE_CHANGED, workspace, membership.user, metadata={"new_role": new_role_code})
        except Exception:
            pass
    return membership


def expire_old_join_requests():
    """
    Mark PENDING join requests past expires_at as EXPIRED. For use in cron/job.
    Idempotent and safe under concurrent runs: uses select_for_update(skip_locked=True).
    Returns count of expired requests.
    """
    now = timezone.now()
    with transaction.atomic():
        expired_requests = list(
            OrganizationJoinRequest.objects.filter(
                status="PENDING",
                expires_at__lt=now,
            )
            .select_for_update(skip_locked=True)
            .select_related("workspace", "user")
        )
        if not expired_requests:
            return 0
        request_ids = [req.pk for req in expired_requests]
        OrganizationJoinRequest.objects.filter(pk__in=request_ids).update(status="EXPIRED")
    for req in expired_requests:
        try:
            log_governance_action(None, req.workspace, NotificationEvent.JOIN_REQUEST_EXPIRED, target_user=req.user, metadata={"request_id": req.pk})
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
        try:
            notify_user(NotificationEvent.JOIN_REQUEST_EXPIRED, req.workspace, req.user, metadata={"request_id": req.pk})
        except Exception:
            pass
    return len(expired_requests)


def leave_workspace(user, workspace):
    """
    User leaves the organization (soft deactivate). Sets deactivated_at and left_at.
    Last ORG_OWNER cannot leave. Cooldown for re-join uses left_at.
    """
    from .membership_service import remove_member

    with transaction.atomic():
        remove_member(user, workspace, user)
        try:
            log_governance_action(user, workspace, NotificationEvent.USER_LEFT_WORKSPACE, target_user=user, metadata={})
        except Exception:
            logging.getLogger("aegisphere.audit").exception("audit_failed")
    return None

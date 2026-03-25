import uuid

from django.conf import settings
from django.contrib.auth.models import AbstractUser, UserManager
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q

# Role codes for CharField choices (aligned with WorkspaceRole seed in workspaces.apps).
ROLE_CODE_CHOICES = [
    ("PERSONAL_OWNER", "Personal Owner"),
    ("ORG_OWNER", "Organization Owner"),
    ("SOC_MANAGER", "SOC Manager"),
    ("SOC_TIER_3_ANALYST", "SOC Tier 3 Analyst"),
    ("SOC_TIER_2_ANALYST", "SOC Tier 2 Analyst"),
    ("SOC_TIER_1_ANALYST", "SOC Tier 1 Analyst"),
    ("SOC_VIEWER", "SOC Viewer"),
]


class CustomUserQuerySet(models.QuerySet):
    def delete(self):
        raise ValidationError(
            "Bulk delete is not allowed. Deactivate users individually."
        )


class CustomUserManager(UserManager.from_queryset(CustomUserQuerySet)):
    """Auth-aware manager: UserManager methods + CustomUserQuerySet behavior."""


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = CustomUserManager()

    def delete(self, *args, **kwargs):
        """
        Safe user deletion: no cascade delete. If user is last ORG_OWNER in any
        organization, raise. Otherwise soft-deactivate (is_active=False) only.
        """
        from django.apps import apps

        WorkspaceMembership = apps.get_model("core", "WorkspaceMembership")
        active = WorkspaceMembership.objects.filter(
            user=self,
            is_active=True,
        ).select_related("role", "workspace")
        for membership in active:
            if (
                membership.role.code == "ORG_OWNER"
                and membership.workspace.workspace_type == "organization"
            ):
                other_owners = WorkspaceMembership.objects.filter(
                    workspace=membership.workspace,
                    is_active=True,
                    role__code="ORG_OWNER",
                ).exclude(user=self)
                if not other_owners.exists():
                    raise ValidationError(
                        "Transfer ownership before deleting account."
                    )
        self.is_active = False
        self.save(update_fields=["is_active"])


class Workspace(models.Model):
    WORKSPACE_TYPE_CHOICES = [
        ("personal", "Personal"),
        ("demo", "Demo"),
        ("organization", "Organization"),
    ]

    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    workspace_type = models.CharField(
        max_length=20,
        choices=WORKSPACE_TYPE_CHOICES,
        default="personal",
    )
    invite_code = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False,
        null=True,
        blank=True,
    )
    allow_join_by_id = models.BooleanField(default=False)
    invite_only = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        super().clean()
        if self.workspace_type != "personal":
            return
        if not self.pk:
            return
        # Enforce exactly one personal workspace per user (ownership by PERSONAL_OWNER only).
        owner_user_ids = list(
            WorkspaceMembership.objects.filter(
                workspace=self,
                is_active=True,
                role__code="PERSONAL_OWNER",
            ).values_list("user_id", flat=True).distinct()
        )
        for user_id in owner_user_ids:
            if (
                Workspace.objects.filter(workspace_type="personal")
                .exclude(pk=self.pk)
                .filter(
                    memberships__user_id=user_id,
                    memberships__is_active=True,
                    memberships__role__code="PERSONAL_OWNER",
                )
                .exists()
            ):
                raise ValidationError("User can have only one personal workspace.")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """
        Direct deletion is not allowed. Use membership_service.delete_workspace()
        so permission and owner checks are enforced.
        """
        raise ValidationError(
            "Direct workspace.delete() is not allowed. "
            "Use membership_service.delete_workspace() instead."
        )


class OrganizationJoinRequest(models.Model):
    STATUS_CHOICES = [
        ("PENDING", "Pending"),
        ("APPROVED", "Approved"),
        ("REJECTED", "Rejected"),
        ("EXPIRED", "Expired"),
        ("WITHDRAWN", "Withdrawn"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="organization_join_requests",
    )
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="join_requests",
    )
    requested_role = models.CharField(
        max_length=100,
        choices=ROLE_CODE_CHOICES,
        default="SOC_VIEWER",
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="PENDING",
    )
    reason = models.TextField(blank=True, null=True)
    approval_comment = models.TextField(blank=True, null=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_join_requests",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "workspace"],
                condition=Q(status="PENDING"),
                name="unique_pending_join_request_per_user_workspace",
            )
        ]
        indexes = [
            models.Index(fields=["workspace", "status"], name="org_join_req_ws_status_idx"),
            models.Index(fields=["expires_at"], name="org_join_req_exp_at_idx"),
            models.Index(fields=["user"], name="org_join_req_user_idx"),
            models.Index(fields=["workspace", "user", "status"], name="org_join_req_ws_user_st_idx"),
            models.Index(fields=["status", "expires_at"], name="org_join_req_st_exp_idx"),
        ]


class OrganizationBlockList(models.Model):
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="block_list_entries",
    )
    blocked_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="blocked_in_workspaces",
    )
    blocked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="blocked_users_entries",
    )
    reason = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["workspace", "blocked_user"],
                name="unique_workspace_blocked_user",
            )
        ]
        indexes = [
            models.Index(
                fields=["workspace", "blocked_user"],
                name="org_blocklist_ws_user_idx",
            ),
        ]


class WorkspaceInvite(models.Model):
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="invites",
    )
    invited_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="workspace_invites_received",
    )
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="workspace_invites_sent",
    )
    role = models.CharField(
        max_length=100,
        choices=ROLE_CODE_CHOICES,
        default="SOC_VIEWER",
    )
    token = models.CharField(max_length=128, unique=True, db_index=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["token"], name="ws_invite_token_idx"),
            models.Index(fields=["workspace"], name="ws_invite_workspace_idx"),
            models.Index(fields=["expires_at"], name="ws_invite_exp_at_idx"),
            models.Index(fields=["workspace", "is_used"], name="ws_invite_ws_used_idx"),
        ]


class OnboardingChecklistStatus(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="onboarding_checklist_statuses",
    )
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="onboarding_checklist_statuses",
    )
    profile_completed = models.BooleanField(default=False)
    policy_read = models.BooleanField(default=False)
    skipped = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "workspace"],
                name="unique_user_workspace_onboarding",
            )
        ]
        indexes = [
            models.Index(
                fields=["workspace", "user"],
                name="onboarding_ws_user_idx",
            ),
        ]


class RoleChangeAuditLog(models.Model):
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="role_change_audit_logs",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="role_change_audit_logs",
    )
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="role_changes_performed",
    )
    old_role = models.CharField(max_length=100, choices=ROLE_CODE_CHOICES)
    new_role = models.CharField(max_length=100, choices=ROLE_CODE_CHOICES)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(
                fields=["workspace", "user"],
                name="role_audit_ws_user_idx",
            ),
            models.Index(fields=["changed_at"], name="role_audit_changed_at_idx"),
        ]


class WorkspaceRole(models.Model):
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=100, unique=True)
    level = models.IntegerField()
    is_system = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class WorkspacePermission(models.Model):
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name


class RolePermission(models.Model):
    role = models.ForeignKey(
        WorkspaceRole,
        on_delete=models.CASCADE,
        related_name="role_permissions",
    )
    permission = models.ForeignKey(
        WorkspacePermission,
        on_delete=models.CASCADE,
        related_name="permission_roles",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["role", "permission"],
                name="unique_role_permission",
            )
        ]


class ActiveMembershipManager(models.Manager):
    """Default manager: exclude archived rows so normal queries are compliance-safe."""

    def get_queryset(self):
        return super().get_queryset().filter(is_archived=False)


class WorkspaceMembership(models.Model):
    OWNER_ROLE_CODES = ("PERSONAL_OWNER", "ORG_OWNER")

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="workspace_memberships",
    )
    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    role = models.ForeignKey(
        WorkspaceRole,
        on_delete=models.PROTECT,
        related_name="memberships",
    )
    joined_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    deactivated_at = models.DateTimeField(null=True, blank=True)
    left_at = models.DateTimeField(null=True, blank=True)
    is_archived = models.BooleanField(default=False)
    archived_at = models.DateTimeField(null=True, blank=True)

    objects = ActiveMembershipManager()
    all_objects = models.Manager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "workspace"],
                name="unique_user_workspace_membership",
            )
        ]

    def clean(self):
        if not self.workspace_id or not self.role_id:
            return
        workspace = self.workspace
        role_code = self.role.code

        if workspace.workspace_type == "demo":
            raise ValidationError(
                {"role": "No memberships are allowed for demo workspaces."}
            )

        if workspace.workspace_type == "personal":
            if role_code != "PERSONAL_OWNER":
                raise ValidationError(
                    {"role": "Personal workspaces allow only the PERSONAL_OWNER role."}
                )
            # Exactly one PERSONAL_OWNER per personal workspace (excluding self when updating).
            other_owners = WorkspaceMembership.objects.filter(
                workspace=workspace,
                is_active=True,
                role__code="PERSONAL_OWNER",
            ).exclude(pk=self.pk)
            if other_owners.exists():
                raise ValidationError(
                    {"role": "Personal workspace can have only one owner."}
                )
            # No shared members: personal workspace can have only one member (the owner).
            other_members = WorkspaceMembership.objects.filter(
                workspace=workspace,
                is_active=True,
            ).exclude(pk=self.pk)
            if other_members.exists():
                raise ValidationError(
                    {"role": "Personal workspace can have only one member (the owner)."}
                )
            return

        if workspace.workspace_type == "organization":
            if role_code == "PERSONAL_OWNER":
                raise ValidationError(
                    {"role": "PERSONAL_OWNER is not allowed for organization workspaces."}
                )
            # Multiple ORG_OWNER memberships are allowed for organization workspaces.

    def save(self, *args, **kwargs):
        self.full_clean()
        if self.pk is not None:
            try:
                old = WorkspaceMembership.all_objects.get(pk=self.pk)
            except WorkspaceMembership.DoesNotExist:
                pass
            else:
                old_owner = old.role.code in self.OWNER_ROLE_CODES
                new_owner = self.role.code in self.OWNER_ROLE_CODES
                if old_owner and not new_owner:
                    # Allow ORG_OWNER downgrade in organization workspaces (e.g. transfer_ownership).
                    if old.role.code != "ORG_OWNER" or self.workspace.workspace_type != "organization":
                        raise ValidationError(
                            {"role": "Owner role cannot be downgraded."}
                        )
                if old_owner and new_owner and self.role.level < old.role.level:
                    raise ValidationError(
                        {"role": "Owner role cannot be downgraded."}
                    )
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if self.role.code in self.OWNER_ROLE_CODES:
            raise ValidationError("Owner role cannot be removed.")
        super().delete(*args, **kwargs)

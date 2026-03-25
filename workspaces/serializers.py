"""
Phase 3 – Join governance API serializers.
Structural validation only; no service calls.
"""

from rest_framework import serializers

from core.models import Workspace, WorkspaceRole
from django.contrib.auth import get_user_model

User = get_user_model()

# Role codes allowed for invites/organization (excluding PERSONAL_OWNER)
ORG_ROLE_CODES = [
    "ORG_OWNER",
    "SOC_MANAGER",
    "SOC_TIER_3_ANALYST",
    "SOC_TIER_2_ANALYST",
    "SOC_TIER_1_ANALYST",
    "SOC_VIEWER",
]


class JoinRequestCreateSerializer(serializers.Serializer):
    """Submit join request: workspace_id required; reason optional."""

    workspace_id = serializers.IntegerField(required=True)
    reason = serializers.CharField(required=False, allow_blank=True, max_length=2000)

    def validate_workspace_id(self, value):
        try:
            workspace = Workspace.objects.get(pk=value)
        except Workspace.DoesNotExist:
            raise serializers.ValidationError("Workspace does not exist.")
        if workspace.workspace_type != "organization":
            raise serializers.ValidationError(
                "Join requests are only for organization workspaces."
            )
        return value


class JoinRequestReviewSerializer(serializers.Serializer):
    """Approve/reject join request: optional comment."""

    approval_comment = serializers.CharField(
        required=False, allow_blank=True, max_length=2000
    )


class InviteCreateSerializer(serializers.Serializer):
    """Create invite: optional invited_user_id; role defaults to SOC_VIEWER."""

    invited_user_id = serializers.IntegerField(required=False, allow_null=True)
    role = serializers.CharField(default="SOC_VIEWER", max_length=100)

    def validate_invited_user_id(self, value):
        if value is None:
            return value
        if not User.objects.filter(pk=value).exists():
            raise serializers.ValidationError("User does not exist.")
        return value

    def validate_role(self, value):
        if value not in ORG_ROLE_CODES:
            raise serializers.ValidationError(
                f"Invalid role. Must be one of: {', '.join(ORG_ROLE_CODES)}."
            )
        return value


class RoleChangeSerializer(serializers.Serializer):
    """Change member role: new_role_code required."""

    new_role_code = serializers.CharField(max_length=100)

    def validate_new_role_code(self, value):
        if not WorkspaceRole.objects.filter(code=value).exists():
            raise serializers.ValidationError("Role does not exist.")
        if value not in ORG_ROLE_CODES:
            raise serializers.ValidationError(
                f"Invalid role for organization. Must be one of: {', '.join(ORG_ROLE_CODES)}."
            )
        return value


class BlockUserSerializer(serializers.Serializer):
    """Block user: target_user_id required; reason optional."""

    target_user_id = serializers.IntegerField(required=True)
    reason = serializers.CharField(required=False, allow_blank=True, max_length=2000)

    def validate_target_user_id(self, value):
        if not User.objects.filter(pk=value).exists():
            raise serializers.ValidationError("User does not exist.")
        return value


class UnblockUserSerializer(serializers.Serializer):
    """Unblock user: target_user_id required."""

    target_user_id = serializers.IntegerField(required=True)

    def validate_target_user_id(self, value):
        if not User.objects.filter(pk=value).exists():
            raise serializers.ValidationError("User does not exist.")
        return value


class AcceptInviteSerializer(serializers.Serializer):
    """Accept invite by token."""

    token = serializers.CharField(required=True, max_length=128)

    def validate_token(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("Token is required.")
        return value.strip()


# ---------------------------------------------------------------------------
# List / read-only serializers (no service calls)
# ---------------------------------------------------------------------------

class JoinRequestListSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    user_id = serializers.IntegerField(source="user_id")
    workspace_id = serializers.IntegerField(source="workspace_id")
    status = serializers.CharField()
    reason = serializers.CharField(allow_null=True)
    created_at = serializers.DateTimeField()
    expires_at = serializers.DateTimeField()


class MemberListSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    user_id = serializers.IntegerField(source="user_id")
    role = serializers.CharField(source="role.code")
    joined_at = serializers.DateTimeField()


class BlockListEntrySerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    blocked_user_id = serializers.IntegerField(source="blocked_user_id")
    reason = serializers.CharField(allow_null=True)
    created_at = serializers.DateTimeField()


class InviteListSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    invited_user_id = serializers.IntegerField(source="invited_user_id", allow_null=True)
    role = serializers.CharField()
    expires_at = serializers.DateTimeField()
    is_used = serializers.BooleanField()
    created_at = serializers.DateTimeField()

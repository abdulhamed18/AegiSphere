"""
Phase 3 – Step 3: API integration layer for join governance.
Exposes join_governance_service via DRF; enforces workspace isolation and response format.
"""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.models import (
    OrganizationBlockList,
    OrganizationJoinRequest,
    Workspace,
    WorkspaceInvite,
    WorkspaceMembership,
)

from workspaces.exceptions import (
    AlreadyMember,
    CooldownViolation,
    InviteInvalid,
    JoinGovernanceError,
    PermissionDenied,
    RequestExpired,
)
from workspaces.join_governance_service import (
    accept_invite,
    approve_join_request,
    block_user,
    change_member_role,
    create_invite,
    expire_old_join_requests,
    leave_workspace,
    reject_join_request,
    submit_join_request,
    unblock_user,
    withdraw_join_request,
)
from workspaces.serializers import (
    AcceptInviteSerializer,
    BlockListEntrySerializer,
    BlockUserSerializer,
    InviteCreateSerializer,
    InviteListSerializer,
    JoinRequestCreateSerializer,
    JoinRequestListSerializer,
    JoinRequestReviewSerializer,
    MemberListSerializer,
    RoleChangeSerializer,
    UnblockUserSerializer,
)
from workspaces.api.throttles import InviteThrottle, JoinRequestThrottle

# Governance admin roles for list endpoints (join-requests, block-list, invites)
GOVERNANCE_ADMIN_ROLE_CODES = ("ORG_OWNER", "SOC_MANAGER")


class StandardPageNumberPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100


def _paginated_data(paginator, page, serializer):
    """Build consistent list response: results, count, next, previous. Empty state: results=[], count=0, next=null, previous=null."""
    results = serializer.data if page is not None else []
    count = paginator.page.paginator.count if getattr(paginator, "page", None) else 0
    next_link = paginator.get_next_link() if getattr(paginator, "get_next_link", None) else None
    prev_link = paginator.get_previous_link() if getattr(paginator, "get_previous_link", None) else None
    return {
        "results": results,
        "count": count,
        "next": next_link if next_link else None,
        "previous": prev_link if prev_link else None,
    }


User = get_user_model()


def _success(data=None, message="OK", status_code=200):
    return Response(
        {"success": True, "message": message, "data": data if data is not None else {}},
        status=status_code,
    )


def _error(message, status_code=400, data=None):
    if data is not None:
        return Response(
            {"success": False, "message": message, "data": data},
            status=status_code,
        )
    return Response(
        {"success": False, "message": message, "data": {}},
        status=status_code,
    )


def join_governance_exception_handler(exc, context):
    """
    Map workspace join governance exceptions to HTTP responses.
    No raw stack traces. Throttled → 429.
    """
    if isinstance(exc, PermissionDenied):
        return _error(str(exc), status.HTTP_403_FORBIDDEN)
    if isinstance(exc, (CooldownViolation, AlreadyMember, InviteInvalid, RequestExpired)):
        return _error(str(exc), status.HTTP_400_BAD_REQUEST)
    if isinstance(exc, JoinGovernanceError):
        return _error(str(exc), status.HTTP_400_BAD_REQUEST)
    from rest_framework.exceptions import Throttled
    if isinstance(exc, Throttled):
        return _error("Too many requests. Try again later.", status.HTTP_429_TOO_MANY_REQUESTS)
    return None


def custom_drf_exception_handler(exc, context):
    """DRF EXCEPTION_HANDLER: try join governance mapping first, then DRF default."""
    from rest_framework.views import exception_handler

    response = join_governance_exception_handler(exc, context)
    if response is not None:
        return response
    return exception_handler(exc, context)


def _require_workspace(request):
    """Strict workspace context: raise PermissionDenied if missing. Use in all endpoints that need workspace."""
    workspace = getattr(request, "workspace", None)
    if not workspace:
        raise PermissionDenied("Workspace context is required.")
    return workspace


def _get_join_request_or_404(request, pk, workspace=None):
    """Fetch join request by id; if workspace given, enforce join_request.workspace == workspace."""
    try:
        join_request = OrganizationJoinRequest.objects.select_related("workspace", "user").get(pk=pk)
    except OrganizationJoinRequest.DoesNotExist:
        return None, _error("Join request not found.", status.HTTP_404_NOT_FOUND)
    if workspace is not None and join_request.workspace_id != workspace.pk:
        return None, _error("Join request does not belong to this workspace.", status.HTTP_403_FORBIDDEN)
    return join_request, None


def _get_membership_or_404(request, pk, workspace=None):
    """Fetch membership by id; enforce membership.workspace == workspace."""
    try:
        membership = WorkspaceMembership.objects.select_related("workspace", "user", "role").get(pk=pk)
    except WorkspaceMembership.DoesNotExist:
        return None, _error("Membership not found.", status.HTTP_404_NOT_FOUND)
    if workspace is not None and membership.workspace_id != workspace.pk:
        return None, _error("Membership does not belong to this workspace.", status.HTTP_403_FORBIDDEN)
    return membership, None


# ---------------------------------------------------------------------------
# A. Submit Join Request
# ---------------------------------------------------------------------------
class SubmitJoinRequestView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [JoinRequestThrottle]

    def post(self, request):
        serializer = JoinRequestCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return _error("Validation failed.", status.HTTP_400_BAD_REQUEST, data=serializer.errors)
        workspace_id = serializer.validated_data["workspace_id"]
        reason = serializer.validated_data.get("reason") or ""

        workspace = Workspace.objects.filter(pk=workspace_id).first()
        if not workspace:
            return _error("Workspace does not exist.", status.HTTP_404_NOT_FOUND)
        if workspace.workspace_type != "organization":
            return _error("Join requests are only for organization workspaces.", status.HTTP_400_BAD_REQUEST)
        # Join-by-ID logic: invite_only always blocks; else allow_join_by_id or same workspace context
        if workspace.invite_only:
            return _error("This organization is invite-only; join by invite only.", status.HTTP_403_FORBIDDEN)
        if workspace.allow_join_by_id:
            pass  # allow submit_join_request
        else:
            current = getattr(request, "workspace", None)
            if not current or current.pk != workspace.pk:
                return _error(
                    "This workspace does not allow join by ID. Switch to this workspace to request access.",
                    status.HTTP_403_FORBIDDEN,
                )

        try:
            join_request = submit_join_request(request.user, workspace, reason=reason or None)
        except (PermissionDenied, AlreadyMember, CooldownViolation) as e:
            return join_governance_exception_handler(e, {"request": request})

        return _success(
            {"request_id": join_request.pk, "workspace_id": workspace.pk},
            "Join request submitted.",
            status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# B. Withdraw Join Request
# ---------------------------------------------------------------------------
class WithdrawJoinRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        join_request, err = _get_join_request_or_404(request, id, workspace=workspace)
        if err:
            return err
        # Redundant safety check – object already filtered by workspace in _get_join_request_or_404
        if join_request.workspace_id != workspace.pk:
            return join_governance_exception_handler(
                PermissionDenied("Workspace mismatch."), {"request": request}
            )
        if join_request.user_id != request.user.pk:
            return _error("Only the request owner can withdraw.", status.HTTP_403_FORBIDDEN)
        try:
            withdraw_join_request(request.user, join_request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        return _success({"request_id": join_request.pk}, "Join request withdrawn.")


# ---------------------------------------------------------------------------
# C. Approve Join Request
# ---------------------------------------------------------------------------
class ApproveJoinRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        if not WorkspaceMembership.objects.filter(
            user=request.user, workspace=workspace, is_active=True
        ).exists():
            return _error("You must be an active member of this workspace.", status.HTTP_403_FORBIDDEN)
        join_request, err = _get_join_request_or_404(request, id, workspace=workspace)
        if err:
            return err
        serializer = JoinRequestReviewSerializer(data=request.data)
        if not serializer.is_valid():
            return _error("Validation failed.", status.HTTP_400_BAD_REQUEST, data=serializer.errors)
        approval_comment = serializer.validated_data.get("approval_comment") or ""

        try:
            approve_join_request(request.user, join_request, approval_comment=approval_comment or None)
        except (
            PermissionDenied,
            RequestExpired,
            AlreadyMember,
        ) as e:
            return join_governance_exception_handler(e, {"request": request})
        return _success({"request_id": join_request.pk}, "Join request approved.")


# ---------------------------------------------------------------------------
# D. Reject Join Request
# ---------------------------------------------------------------------------
class RejectJoinRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        if not WorkspaceMembership.objects.filter(
            user=request.user, workspace=workspace, is_active=True
        ).exists():
            return _error("You must be an active member of this workspace.", status.HTTP_403_FORBIDDEN)
        join_request, err = _get_join_request_or_404(request, id, workspace=workspace)
        if err:
            return err
        serializer = JoinRequestReviewSerializer(data=request.data)
        if not serializer.is_valid():
            return _error("Validation failed.", status.HTTP_400_BAD_REQUEST, data=serializer.errors)
        approval_comment = serializer.validated_data.get("approval_comment") or ""

        try:
            reject_join_request(request.user, join_request, approval_comment=approval_comment or None)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        return _success({"request_id": join_request.pk}, "Join request rejected.")


# ---------------------------------------------------------------------------
# E. Create Invite
# ---------------------------------------------------------------------------
class CreateInviteView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [InviteThrottle]

    def post(self, request):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        serializer = InviteCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return _error("Validation failed.", status.HTTP_400_BAD_REQUEST, data=serializer.errors)
        invited_user_id = serializer.validated_data.get("invited_user_id")
        role = serializer.validated_data.get("role", "SOC_VIEWER")
        invited_user = User.objects.filter(pk=invited_user_id).first() if invited_user_id else None

        try:
            invite = create_invite(request.user, workspace, invited_user=invited_user, role=role)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})

        return _success(
            {
                "invite_id": invite.pk,
                "token": invite.token,
                "expires_at": invite.expires_at.isoformat(),
            },
            "Invite created.",
            status.HTTP_201_CREATED,
        )


# ---------------------------------------------------------------------------
# F. Accept Invite
# ---------------------------------------------------------------------------
class AcceptInviteView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [JoinRequestThrottle]

    def post(self, request):
        serializer = AcceptInviteSerializer(data=request.data)
        if not serializer.is_valid():
            return _error("Validation failed.", status.HTTP_400_BAD_REQUEST, data=serializer.errors)
        token = serializer.validated_data["token"]

        try:
            membership = accept_invite(request.user, token)
        except (InviteInvalid, AlreadyMember) as e:
            return join_governance_exception_handler(e, {"request": request})

        return _success(
            {
                "membership_id": membership.pk,
                "workspace_id": membership.workspace_id,
                "role": membership.role.code,
            },
            "Invite accepted.",
        )


# ---------------------------------------------------------------------------
# G. Block User
# ---------------------------------------------------------------------------
class BlockUserView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        if not WorkspaceMembership.objects.filter(
            user=request.user, workspace=workspace, is_active=True
        ).exists():
            return _error("You must be an active member of this workspace.", status.HTTP_403_FORBIDDEN)
        serializer = BlockUserSerializer(data=request.data)
        if not serializer.is_valid():
            return _error("Validation failed.", status.HTTP_400_BAD_REQUEST, data=serializer.errors)
        target_user_id = serializer.validated_data["target_user_id"]
        reason = serializer.validated_data.get("reason") or ""
        try:
            target_user = User.objects.get(pk=target_user_id)
        except User.DoesNotExist:
            return _error("User does not exist.", status.HTTP_404_NOT_FOUND)

        try:
            block_user(request.user, workspace, target_user, reason=reason or None)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        return _success({"target_user_id": target_user_id}, "User blocked.")


# ---------------------------------------------------------------------------
# H. Unblock User
# ---------------------------------------------------------------------------
class UnblockUserView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        if not WorkspaceMembership.objects.filter(
            user=request.user, workspace=workspace, is_active=True
        ).exists():
            return _error("You must be an active member of this workspace.", status.HTTP_403_FORBIDDEN)
        serializer = UnblockUserSerializer(data=request.data)
        if not serializer.is_valid():
            return _error("Validation failed.", status.HTTP_400_BAD_REQUEST, data=serializer.errors)
        target_user_id = serializer.validated_data["target_user_id"]
        try:
            target_user = User.objects.get(pk=target_user_id)
        except User.DoesNotExist:
            return _error("User does not exist.", status.HTTP_404_NOT_FOUND)

        try:
            unblock_user(request.user, workspace, target_user)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        return _success({"target_user_id": target_user_id}, "User unblocked.")


# ---------------------------------------------------------------------------
# I. Change Member Role
# ---------------------------------------------------------------------------
class ChangeMemberRoleView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        membership, err = _get_membership_or_404(request, id, workspace=workspace)
        if err:
            return err
        serializer = RoleChangeSerializer(data=request.data)
        if not serializer.is_valid():
            return _error("Validation failed.", status.HTTP_400_BAD_REQUEST, data=serializer.errors)
        new_role_code = serializer.validated_data["new_role_code"]

        try:
            membership = change_member_role(request.user, membership, new_role_code)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        return _success(
            {"membership_id": membership.pk, "new_role_code": membership.role.code},
            "Role updated.",
        )


# ---------------------------------------------------------------------------
# J. Leave Workspace
# ---------------------------------------------------------------------------
class LeaveWorkspaceView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        if not WorkspaceMembership.objects.filter(
            user=request.user, workspace=workspace, is_active=True
        ).exists():
            return _error("You must be an active member of this workspace.", status.HTTP_403_FORBIDDEN)
        try:
            leave_workspace(request.user, workspace)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        return _success({"workspace_id": workspace.pk}, "Left workspace.")


# ---------------------------------------------------------------------------
# LIST ENDPOINTS (GET, read-only)
# ---------------------------------------------------------------------------

def _user_is_governance_admin(user, workspace):
    """True if user has ORG_OWNER or SOC_MANAGER in this workspace."""
    try:
        m = WorkspaceMembership.objects.select_related("role").get(
            user=user, workspace=workspace, is_active=True
        )
        return m.role.code in GOVERNANCE_ADMIN_ROLE_CODES
    except WorkspaceMembership.DoesNotExist:
        return False


class ListJoinRequestsView(APIView):
    permission_classes = [IsAuthenticated]
    pagination_class = StandardPageNumberPagination

    def get(self, request):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        if not _user_is_governance_admin(request.user, workspace):
            return _error("Only organization owners or SOC managers can list join requests.", status.HTTP_403_FORBIDDEN)
        status_filter = request.query_params.get("status", "PENDING")
        if status_filter not in ("PENDING", "APPROVED", "REJECTED", "EXPIRED", "WITHDRAWN"):
            status_filter = "PENDING"
        qs = OrganizationJoinRequest.objects.filter(workspace=workspace, status=status_filter).select_related("user").order_by("-created_at")
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(qs, request)
        serializer = JoinRequestListSerializer(page or [], many=True)
        return _success(_paginated_data(paginator, page, serializer), "OK")


class ListMembersView(APIView):
    permission_classes = [IsAuthenticated]
    pagination_class = StandardPageNumberPagination

    def get(self, request):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        if not WorkspaceMembership.objects.filter(user=request.user, workspace=workspace, is_active=True).exists():
            return _error("You must be a member of this workspace.", status.HTTP_403_FORBIDDEN)
        qs = WorkspaceMembership.objects.filter(workspace=workspace, is_active=True).select_related("role").order_by("joined_at")
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(qs, request)
        serializer = MemberListSerializer(page or [], many=True)
        return _success(_paginated_data(paginator, page, serializer), "OK")


class ListBlockListView(APIView):
    permission_classes = [IsAuthenticated]
    pagination_class = StandardPageNumberPagination

    def get(self, request):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        if not _user_is_governance_admin(request.user, workspace):
            return _error("Only organization owners or SOC managers can list block list.", status.HTTP_403_FORBIDDEN)
        qs = OrganizationBlockList.objects.filter(workspace=workspace).select_related("blocked_user").order_by("-created_at")
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(qs, request)
        serializer = BlockListEntrySerializer(page or [], many=True)
        return _success(_paginated_data(paginator, page, serializer), "OK")


class ListInvitesView(APIView):
    permission_classes = [IsAuthenticated]
    pagination_class = StandardPageNumberPagination

    def get(self, request):
        try:
            workspace = _require_workspace(request)
        except PermissionDenied as e:
            return join_governance_exception_handler(e, {"request": request})
        if not _user_is_governance_admin(request.user, workspace):
            return _error("Only organization owners or SOC managers can list invites.", status.HTTP_403_FORBIDDEN)
        qs = WorkspaceInvite.objects.filter(workspace=workspace).order_by("-created_at")
        paginator = self.pagination_class()
        page = paginator.paginate_queryset(qs, request)
        serializer = InviteListSerializer(page or [], many=True)
        return _success(_paginated_data(paginator, page, serializer), "OK")


# ---------------------------------------------------------------------------
# K. Expire Join Requests (ADMIN ONLY)
# ---------------------------------------------------------------------------
class ExpireJoinRequestsView(APIView):
    """Global admin-only: no workspace. Does NOT use _require_workspace or request.workspace."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not (request.user.is_staff or request.user.is_superuser):
            return _error("Only system administrators can perform this operation.", status.HTTP_403_FORBIDDEN)
        count = expire_old_join_requests()
        return _success({"expired_count": count}, "Expired join requests processed.")


# ---------------------------------------------------------------------------
# Secure schema view (staff-only)
# ---------------------------------------------------------------------------
def _get_schema_view():
    from rest_framework.schemas import get_schema_view as _gsv
    return _gsv(
        title="AegiSphere API",
        description="Enterprise SOC SaaS Governance API",
        version="1.0.0",
    )


_schema_view = _get_schema_view()


class SecureSchemaView(APIView):
    """Schema endpoint: OpenAPI JSON, restricted to staff/superuser."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.is_staff and not request.user.is_superuser:
            raise PermissionDenied("Schema access restricted to administrators.")
        return _schema_view(request)

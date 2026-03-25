from core.models import RolePermission, WorkspaceMembership


def user_has_permission(user, workspace, permission_code: str) -> bool:
    if not user or not user.is_authenticated:
        return False
    if workspace is None:
        return False

    try:
        membership = WorkspaceMembership.objects.select_related("role").get(
            user=user,
            workspace=workspace,
            is_active=True,
            is_archived=False,
        )
    except WorkspaceMembership.DoesNotExist:
        return False

    role = membership.role

    return RolePermission.objects.filter(
        role=role,
        permission__code=permission_code,
    ).exists()


def user_role_level(user, workspace) -> int:
    if not user or not user.is_authenticated or workspace is None:
        return 0

    try:
        membership = WorkspaceMembership.objects.select_related("role").get(
            user=user,
            workspace=workspace,
            is_active=True,
            is_archived=False,
        )
    except WorkspaceMembership.DoesNotExist:
        return 0

    return membership.role.level


"""
Assignment policy: whether an assigner can assign an alert to a target user.

Pure decision logic only. No DB writes, no alert mutation.
"""

from alerts.role_hierarchy import can_assign_to_role, get_role_code


VIEWER_ROLE = "SOC_VIEWER"


def can_assign(assigner, target_user, workspace):
    """
    Return True if assigner can assign an alert to target_user in workspace.

    Rules:
    1. Both users must belong to the same workspace.
    2. Both must have active membership.
    3. Viewers cannot assign.
    4. Assigner must be allowed by ROLE_ASSIGNMENT_SCOPE for target's role.
    5. Cannot assign user from different workspace (ensured by same workspace check).
    """
    if not assigner or not assigner.is_authenticated:
        return False
    if not target_user or not target_user.is_authenticated:
        return False
    if workspace is None:
        return False

    assigner_role = get_role_code(assigner, workspace)
    target_role = get_role_code(target_user, workspace)

    if assigner_role is None or target_role is None:
        return False
    if assigner_role == VIEWER_ROLE:
        return False
    return can_assign_to_role(assigner_role, target_role)

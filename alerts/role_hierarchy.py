"""
Centralized role assignment scope logic for Alert workflow.

All hierarchy and role-based assignment rules live here. No business logic
in models; no DB writes. Used by assignment_policy and permissions.
"""

from core.models import WorkspaceMembership


ROLE_ASSIGNMENT_SCOPE = {
    "SOC_TIER_1_ANALYST": ["SOC_TIER_1_ANALYST"],
    "SOC_TIER_2_ANALYST": ["SOC_TIER_1_ANALYST", "SOC_TIER_2_ANALYST"],
    "SOC_TIER_3_ANALYST": ["SOC_TIER_1_ANALYST", "SOC_TIER_2_ANALYST", "SOC_TIER_3_ANALYST"],
    "SOC_MANAGER": ["SOC_TIER_1_ANALYST", "SOC_TIER_2_ANALYST", "SOC_TIER_3_ANALYST", "SOC_MANAGER"],
    "ORG_OWNER": ["SOC_TIER_1_ANALYST", "SOC_TIER_2_ANALYST", "SOC_TIER_3_ANALYST", "SOC_MANAGER", "ORG_OWNER"],
    "PERSONAL_OWNER": ["SOC_TIER_1_ANALYST", "SOC_TIER_2_ANALYST", "SOC_TIER_3_ANALYST", "SOC_MANAGER", "PERSONAL_OWNER"],
}


def get_role_code(user, workspace):
    """
    Return the role code for user in workspace, or None if no active membership.
    Uses WorkspaceMembership; read-only.
    """
    if not user or not user.is_authenticated or workspace is None:
        return None
    try:
        membership = WorkspaceMembership.objects.select_related("role").get(
            user=user,
            workspace=workspace,
            is_active=True,
        )
        return membership.role.code
    except WorkspaceMembership.DoesNotExist:
        return None
    except WorkspaceMembership.MultipleObjectsReturned:
        return None


def can_assign_to_role(assigner_role_code, target_role_code):
    """
    Return True if assigner_role_code is allowed to assign alerts to users
    with target_role_code, according to ROLE_ASSIGNMENT_SCOPE.
    """
    if not assigner_role_code or not target_role_code:
        return False
    allowed = ROLE_ASSIGNMENT_SCOPE.get(assigner_role_code)
    if not allowed:
        return False
    return target_role_code in allowed


def is_manager(role_code):
    """
    Return True if role_code is manager-level (can extend SLA, force unlock).
    """
    if not role_code:
        return False
    return role_code in ("SOC_MANAGER", "ORG_OWNER", "PERSONAL_OWNER")

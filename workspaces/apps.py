from django.apps import AppConfig
from django.db.utils import OperationalError, ProgrammingError


class WorkspacesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "workspaces"

    def ready(self):
        # Seed core workspace RBAC primitives (roles, permissions, mappings).
        try:
            from core.models import RolePermission, WorkspacePermission, WorkspaceRole

            self._seed_roles(WorkspaceRole)
            self._seed_permissions(WorkspacePermission)
            self._seed_role_permissions(WorkspaceRole, WorkspacePermission, RolePermission)
        except (OperationalError, ProgrammingError):
            # Database might not be ready (e.g. during initial migrate); skip seeding.
            return

    def _seed_roles(self, WorkspaceRole):
        roles = [
            ("Personal Owner", "PERSONAL_OWNER", 100),
            ("Organization Owner", "ORG_OWNER", 90),
            ("SOC Manager", "SOC_MANAGER", 80),
            ("SOC Tier 3 Analyst", "SOC_TIER_3_ANALYST", 70),
            ("SOC Tier 2 Analyst", "SOC_TIER_2_ANALYST", 60),
            ("SOC Tier 1 Analyst", "SOC_TIER_1_ANALYST", 50),
            ("SOC Viewer", "SOC_VIEWER", 10),
        ]
        for name, code, level in roles:
            WorkspaceRole.objects.get_or_create(
                code=code,
                defaults={
                    "name": name,
                    "level": level,
                    "is_system": True,
                },
            )

    def _seed_permissions(self, WorkspacePermission):
        permissions = [
            ("Can assign alert", "can_assign_alert"),
            ("Can escalate alert", "can_escalate_alert"),
            ("Can close case", "can_close_case"),
            ("Can reopen case", "can_reopen_case"),
            ("Can unlock alert", "can_unlock_alert"),
            ("Can edit organization settings", "can_edit_org_settings"),
            ("Can invite members", "can_invite_members"),
            ("Can remove members", "can_remove_members"),
            ("Can delete workspace", "can_delete_workspace"),
        ]
        for name, code in permissions:
            WorkspacePermission.objects.get_or_create(
                code=code,
                defaults={"name": name},
            )

    def _seed_role_permissions(
        self,
        WorkspaceRole,
        WorkspacePermission,
        RolePermission,
    ):
        # Map from role code to list of permission codes.
        role_permissions = {
            "SOC_VIEWER": [],
            "SOC_TIER_1_ANALYST": [
                "can_assign_alert",
            ],
            "SOC_TIER_2_ANALYST": [
                "can_assign_alert",
                "can_escalate_alert",
            ],
            "SOC_TIER_3_ANALYST": [
                "can_assign_alert",
                "can_escalate_alert",
                "can_close_case",
            ],
            "SOC_MANAGER": [
                "can_assign_alert",
                "can_escalate_alert",
                "can_close_case",
                "can_reopen_case",
                "can_unlock_alert",
                "can_edit_org_settings",
                "can_invite_members",
                "can_remove_members",
            ],
            "ORG_OWNER": [
                "can_assign_alert",
                "can_escalate_alert",
                "can_close_case",
                "can_reopen_case",
                "can_unlock_alert",
                "can_edit_org_settings",
                "can_invite_members",
                "can_remove_members",
                "can_delete_workspace",
            ],
            "PERSONAL_OWNER": [
                "can_assign_alert",
                "can_escalate_alert",
                "can_close_case",
                "can_reopen_case",
                "can_unlock_alert",
                "can_edit_org_settings",
                "can_invite_members",
                "can_remove_members",
                "can_delete_workspace",
            ],
        }

        for role_code, permission_codes in role_permissions.items():
            try:
                role = WorkspaceRole.objects.get(code=role_code)
            except WorkspaceRole.DoesNotExist:
                continue

            for perm_code in permission_codes:
                try:
                    permission = WorkspacePermission.objects.get(code=perm_code)
                except WorkspacePermission.DoesNotExist:
                    continue

                RolePermission.objects.get_or_create(
                    role=role,
                    permission=permission,
                )

#!/usr/bin/env python
"""
Standalone seed script for a "Test Organization" workspace.
Creates workspace, users, memberships, alerts, and cases for UI/RBAC testing.
Does NOT modify schema, services, or business logic.
Supports --reset to delete and recreate cleanly (respects Case.workspace PROTECT).
"""

import argparse
import sys
from pathlib import Path
from datetime import timedelta

# Project root and Django setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import warnings
warnings.filterwarnings("ignore", message="Accessing the database during app initialization", category=RuntimeWarning)

import django
django.setup()

from django.utils import timezone
from django.db import transaction

# Models
User = __import__("django.contrib.auth", fromlist=["get_user_model"]).get_user_model()
Workspace = __import__("core.models", fromlist=["Workspace"]).Workspace
WorkspaceRole = __import__("core.models", fromlist=["WorkspaceRole"]).WorkspaceRole
WorkspaceMembership = __import__("core.models", fromlist=["WorkspaceMembership"]).WorkspaceMembership
Alert = __import__("alerts.models", fromlist=["Alert"]).Alert
Case = __import__("cases.models", fromlist=["Case"]).Case
CaseAlert = __import__("cases.models", fromlist=["CaseAlert"]).CaseAlert

# Enums
AlertSeverity = __import__("alerts.enums", fromlist=["AlertSeverity"]).AlertSeverity
AlertStatus = __import__("alerts.enums", fromlist=["AlertStatus"]).AlertStatus
AlertPriority = __import__("alerts.enums", fromlist=["AlertPriority"]).AlertPriority
AlertCategory = __import__("alerts.enums", fromlist=["AlertCategory"]).AlertCategory
CaseSeverity = __import__("cases.models", fromlist=["CaseSeverity"]).CaseSeverity
CaseStatus = __import__("cases.models", fromlist=["CaseStatus"]).CaseStatus
CasePriority = __import__("cases.models", fromlist=["CasePriority"]).CasePriority
CaseOutcome = __import__("cases.models", fromlist=["CaseOutcome"]).CaseOutcome

# Constants
WORKSPACE_NAME = "Test Organization"
WORKSPACE_SLUG = "test-organization"
PASSWORD = "StrongPassword123!"

# User specs: (username, email, role_code)
USER_SPECS = [
    ("test_owner", "owner@testorg.com", "ORG_OWNER"),
    ("test_manager", "manager@testorg.com", "SOC_MANAGER"),
    ("test_analyst1", "analyst1@testorg.com", "SOC_TIER_1_ANALYST"),
    ("test_analyst2", "analyst2@testorg.com", "SOC_TIER_2_ANALYST"),
    ("test_analyst3", "analyst3@testorg.com", "SOC_TIER_3_ANALYST"),
    ("test_viewer", "viewer@testorg.com", "SOC_VIEWER"),
]

# SLA hours by severity (for alerts)
SLA_HOURS = {"LOW": 72, "MEDIUM": 24, "HIGH": 8, "CRITICAL": 1}


def _get_workspace():
    return Workspace.objects.filter(slug=WORKSPACE_SLUG).first()


def _get_or_create_workspace():
    ws, created = Workspace.objects.get_or_create(
        slug=WORKSPACE_SLUG,
        defaults={
            "name": WORKSPACE_NAME,
            "workspace_type": "organization",
        },
    )
    if not created:
        ws.name = WORKSPACE_NAME
        ws.workspace_type = "organization"
        ws.save(update_fields=["name", "workspace_type"])
    return ws


def _get_or_create_users():
    users = {}
    for username, email, _ in USER_SPECS:
        user, created = User.objects.get_or_create(
            username=username,
            defaults={"email": email},
        )
        if created:
            user.set_password(PASSWORD)
            user.save(update_fields=["password"])
        else:
            if getattr(user, "email", None) != email:
                user.email = email
                user.save(update_fields=["email"])
        users[username] = user
    return users


def _create_memberships(workspace, users):
    count = 0
    for username, email, role_code in USER_SPECS:
        user = users[username]
        role = WorkspaceRole.objects.get(code=role_code)
        membership, created = WorkspaceMembership.objects.get_or_create(
            user=user,
            workspace=workspace,
            defaults={"role": role, "is_active": True},
        )
        if not created and not membership.is_active:
            membership.is_active = True
            membership.role = role
            membership.save(update_fields=["is_active", "role"])
        if created:
            count += 1
    return count


def _create_alerts(workspace, users, count_target=18):
    now = timezone.now()
    severity_list = [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
    status_list = [AlertStatus.OPEN, AlertStatus.IN_PROGRESS, AlertStatus.RESOLVED, AlertStatus.ACKNOWLEDGED]
    priorities = [AlertPriority.LOW, AlertPriority.MEDIUM, AlertPriority.HIGH, AlertPriority.URGENT]
    categories = [AlertCategory.NETWORK, AlertCategory.ENDPOINT, AlertCategory.IAM, AlertCategory.APPLICATION, AlertCategory.OTHER]
    sources = ["EDR", "SIEM", "Firewall", "IDS", "CloudTrail", "Azure AD"]
    titles = [
        "Suspicious PowerShell execution",
        "Multiple failed login attempts",
        "Unusual outbound connection to unknown IP",
        "Sensitive file access spike",
        "New scheduled task on server",
        "Lateral movement attempt detected",
        "Privilege escalation alert",
        "Data exfiltration pattern",
        "Malware signature match",
        "Anomalous DNS query volume",
        "Disabled security logging",
        "New admin account created",
        "RDP connection from unusual geography",
        "Certificate tampering attempt",
        "Kernel driver loaded",
        "Suspicious child process",
        "Registry persistence mechanism",
        "Encrypted channel to C2",
    ]
    descriptions = [
        "Automated detection of script execution with encoded payload.",
        "Brute-force pattern from single source IP.",
        "Connection to non-RFC1918 address on high port.",
        "Access to confidential share from new host.",
        "Task registered by service account.",
        "SMB session from previously compromised host.",
        "Process token manipulation observed.",
        "Large outbound transfer to external host.",
        "AV engine matched known hash.",
        "Query rate 10x baseline.",
        "Audit policy change on critical server.",
        "Account created outside change window.",
        "RDP from country with no business presence.",
        "Invalid signature on system binary.",
        "Unsigned driver load attempt.",
        "Office spawning cmd.exe.",
        "Run key modified for auto-start.",
        "TLS to IP with no reverse DNS.",
    ]
    created_count = 0
    assignees = [users["test_analyst1"], users["test_manager"], users["test_owner"], None]
    for i in range(count_target):
        sev = severity_list[i % len(severity_list)]
        status = status_list[i % len(status_list)]
        hrs = SLA_HOURS.get(sev, 24)
        sla_deadline = now - timedelta(hours=1) if i % 4 == 0 else now + timedelta(hours=hrs)
        created_at = now - timedelta(days=i % 7, hours=i % 24)
        resolved_at = (now - timedelta(hours=2)) if status == AlertStatus.RESOLVED else None
        _, created = Alert.objects.get_or_create(
            workspace=workspace,
            title=titles[i % len(titles)] + f" #{i+1}",
            defaults={
                "description": descriptions[i % len(descriptions)],
                "source": sources[i % len(sources)],
                "severity": sev,
                "status": status,
                "priority": priorities[i % len(priorities)],
                "category": categories[i % len(categories)],
                "sla_deadline": sla_deadline,
                "resolved_at": resolved_at,
                "assigned_to": assignees[i % len(assignees)],
                "created_at": created_at,
            },
        )
        if created:
            created_count += 1
    return created_count


def _create_cases_and_links(workspace, users, alerts_in_workspace):
    now = timezone.now()
    CaseSeverityChoices = [CaseSeverity.LOW, CaseSeverity.MEDIUM, CaseSeverity.HIGH, CaseSeverity.CRITICAL]
    CaseStatusChoices = [CaseStatus.OPEN, CaseStatus.IN_PROGRESS, CaseStatus.RESOLVED, CaseStatus.CLOSED]
    CasePriorityChoices = [CasePriority.LOW, CasePriority.MEDIUM, CasePriority.HIGH, CasePriority.URGENT]
    titles = [
        "Q1 Insider threat investigation",
        "Phishing campaign response",
        "Ransomware containment",
        "Data breach assessment",
        "Compliance audit support",
    ]
    descriptions = [
        "Investigation of unusual access to confidential data by internal user.",
        "Response to reported phishing emails and credential harvesting.",
        "Containment and recovery for ransomware incident.",
        "Assessment of potential data exposure and notification requirements.",
        "Support for external audit and evidence collection.",
    ]
    case_list = []
    alert_qs = list(Alert.objects.filter(workspace=workspace).order_by("id"))
    if not alert_qs:
        return 0
    for i in range(min(5, len(alert_qs) // 2)):
        created_at = now - timedelta(days=i + 1)
        case, _ = Case.objects.get_or_create(
            workspace=workspace,
            title=titles[i],
            defaults={
                "description": descriptions[i],
                "severity": CaseSeverityChoices[i % len(CaseSeverityChoices)],
                "status": CaseStatusChoices[i % len(CaseStatusChoices)],
                "priority": CasePriorityChoices[i % len(CasePriorityChoices)],
                "created_by": users["test_manager"],
                "primary_assignee": users["test_analyst1"] if i % 2 else users["test_manager"],
                "created_at": created_at,
            },
        )
        case_list.append(case)
    # Link 2-4 distinct alerts per case (each alert can belong to at most one case).
    used_alert_ids = set()
    for idx, case in enumerate(case_list):
        to_link = min(4, len(alert_qs) - len(used_alert_ids))
        linked_this = 0
        for alert in alert_qs:
            if alert.id in used_alert_ids:
                continue
            _, created = CaseAlert.objects.get_or_create(
                case=case,
                alert=alert,
                defaults={"added_by": users["test_analyst1"]},
            )
            if created:
                used_alert_ids.add(alert.id)
                linked_this += 1
            if linked_this >= max(2, to_link):
                break
    return len(case_list)


def _reset(workspace):
    from workspaces.membership_service import delete_workspace
    owner = User.objects.filter(username="test_owner").first()
    if not owner:
        print("  (test_owner not found; cannot call delete_workspace; skipping workspace delete.)")
        return
    # Case.workspace is PROTECT: delete cases first (QuerySet.delete bypasses Case.delete() override).
    case_count, _ = Case.objects.filter(workspace=workspace).delete()
    print(f"  Deleted {case_count} case-related row(s).")
    delete_workspace(owner, workspace)
    print("  Workspace deleted via membership_service.delete_workspace().")


def run_seed():
    with transaction.atomic():
        workspace = _get_or_create_workspace()
        print(f"Workspace: {workspace.name}")
        print(f"Workspace ID: {workspace.id}")
        users = _get_or_create_users()
        _create_memberships(workspace, users)
        alert_count = Alert.objects.filter(workspace=workspace).count()
        if alert_count < 15:
            created = _create_alerts(workspace, users, count_target=18)
            print(f"Alerts created: {created} (total in workspace: {Alert.objects.filter(workspace=workspace).count()})")
        else:
            print(f"Alerts (existing): {alert_count}")
        case_count_before = Case.objects.filter(workspace=workspace).count()
        if case_count_before < 4:
            cases_created = _create_cases_and_links(workspace, users, None)
            print(f"Cases created: {cases_created} (total: {Case.objects.filter(workspace=workspace).count()})")
        else:
            print(f"Cases (existing): {case_count_before}")
        membership_count = WorkspaceMembership.objects.filter(workspace=workspace, is_active=True).count()
    print()
    print("--- Summary ---")
    print(f"  Workspace ID: {workspace.id}")
    print(f"  User count (this org): {len(users)}")
    print(f"  Membership count: {membership_count}")
    print(f"  Alert count: {Alert.objects.filter(workspace=workspace).count()}")
    print(f"  Case count: {Case.objects.filter(workspace=workspace).count()}")
    print()
    print("--- Credentials (all password: " + PASSWORD + ") ---")
    for username, email, role_code in USER_SPECS:
        print(f"  {username} ({role_code}): {email}")


def run_reset():
    workspace = _get_workspace()
    if not workspace:
        print("Test Organization workspace not found. Nothing to reset.")
        return
    print("Resetting Test Organization...")
    with transaction.atomic():
        _reset(workspace)
    print("Reset complete. Run without --reset to recreate.")


def main():
    parser = argparse.ArgumentParser(description="Seed Test Organization workspace for UI/RBAC testing.")
    parser.add_argument("--reset", action="store_true", help="Delete Test Organization and all its data, then exit.")
    args = parser.parse_args()
    if args.reset:
        run_reset()
    else:
        run_seed()


if __name__ == "__main__":
    main()

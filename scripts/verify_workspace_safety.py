#!/usr/bin/env python
"""
Read-only workspace safety audit script.

Verifies that deleting a single Workspace will NOT break the system.
Does NOT modify database, models, or any data. Analysis only.
"""
# Use ASCII-safe markers for Windows console compatibility
SAFE = "[SAFE]"
RISK = "[RISK]"
REVIEW = "[REVIEW]"

import os
import re
import sys
from pathlib import Path

# Add project root to path and initialize Django
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import warnings
warnings.filterwarnings("ignore", message="Accessing the database during app initialization", category=RuntimeWarning)

import django

django.setup()

from django.apps import apps
from django.db import models

# Resolve Workspace model once
Workspace = apps.get_model("core", "Workspace")


def get_workspace_fk_fields(model):
    """Return list of (field_name, field) for FKs pointing to Workspace."""
    result = []
    for f in model._meta.get_fields():
        if not hasattr(f, "remote_field") or f.remote_field is None:
            continue
        remote_model = getattr(f.remote_field, "model", None)
        if remote_model is None:
            continue
        if remote_model == Workspace:
            result.append((f.name, f))
    return result


def on_delete_label(field):
    """Return string label for on_delete (e.g. CASCADE, PROTECT)."""
    if not hasattr(field, "remote_field") or field.remote_field is None:
        return "N/A"
    behavior = field.remote_field.on_delete
    return behavior.__name__ if behavior else "N/A"


def check_1_workspace_scoped_models():
    """List models with FK to Workspace; flag non-CASCADE as RISK."""
    print("\n--- CHECK 1: Workspace-scoped models (FK to Workspace) ---")
    risks = []
    for model in apps.get_models():
        if model._meta.abstract:
            continue
        for fname, field in get_workspace_fk_fields(model):
            on_del = on_delete_label(field)
            status = "RISK" if on_del != "CASCADE" else "SAFE"
            label = f"  {model._meta.label}: field '{fname}' -> on_delete={on_del}"
            if status == "RISK":
                risks.append(label)
                print(f"  {RISK}  {label}")
            else:
                print(f"  {SAFE}  {label}")
    if not any(get_workspace_fk_fields(m) for m in apps.get_models() if not m._meta.abstract):
        print("  (No concrete workspace-scoped models found.)")
    return len(risks) == 0, risks


def check_2_reverse_relations():
    """Inspect reverse relations from Workspace; flag PROTECT/SET_NULL on workspace FK as RISK."""
    print("\n--- CHECK 2: Reverse relations from Workspace ---")
    risks = []
    for rel in Workspace._meta.related_objects:
        # rel.field is the FK field on the related model (Django's RelatedObject)
        field = getattr(rel, "field", None)
        if field is None or not hasattr(field, "remote_field") or field.remote_field is None:
            related_model = getattr(rel, "related_model", None)
            if related_model is None:
                continue
            for f in related_model._meta.get_fields():
                if not hasattr(f, "remote_field") or f.remote_field is None:
                    continue
                if getattr(f.remote_field, "model", None) != Workspace:
                    continue
                field = f
                break
            else:
                continue
        related_model = rel.related_model
        on_del = on_delete_label(field)
        rel_name = getattr(rel, "related_name", None) or getattr(field, "remote_field", None) and getattr(field.remote_field, "related_name", None) or rel.name
        label = f"  {related_model._meta.label}.{field.name} (related_name={rel_name}) -> on_delete={on_del}"
        if on_del in ("PROTECT", "SET_NULL"):
            risks.append(label)
            print(f"  {RISK}  {label}")
        else:
            print(f"  {SAFE}  {label}")
    return len(risks) == 0, risks


def _model_has_workspace_fk(model):
    return len(get_workspace_fk_fields(model)) > 0


def _model_references_workspace_scoped(model):
    """True if model has a forward FK to a model that has workspace FK (workspace-scoped)."""
    for f in model._meta.get_fields():
        if not hasattr(f, "remote_field") or f.remote_field is None:
            continue
        # Only forward FKs (many_to_one or one_to_one), not reverse relations
        if not (getattr(f, "many_to_one", False) or getattr(f, "one_to_one", False)):
            continue
        remote = f.remote_field.model
        if remote is model:
            continue
        if _model_has_workspace_fk(remote):
            return True
    return False


def check_3_cross_workspace_fks():
    """Models that reference workspace-scoped models but have no workspace FK."""
    print("\n--- CHECK 3: Cross-workspace FKs (reference workspace-scoped but no workspace FK) ---")
    workspace_scoped = {m for m in apps.get_models() if not m._meta.abstract and _model_has_workspace_fk(m)}
    review = []
    for model in apps.get_models():
        if model._meta.abstract:
            continue
        if _model_has_workspace_fk(model):
            continue
        if _model_references_workspace_scoped(model):
            review.append(f"  {model._meta.label}")
    for r in review:
        print(f"  {REVIEW}  {r}")
    if not review:
        print(f"  {SAFE}  No cross-workspace FK models found.")
    return review


def check_4_hardcoded_workspace_ids():
    """Scan project Python files for hardcoded workspace id patterns."""
    print("\n--- CHECK 4: Hardcoded Workspace IDs ---")
    patterns = [
        (re.compile(r"workspace_id\s*=\s*(\d+)"), "workspace_id=<literal>"),
        (re.compile(r"Workspace\.objects\.get\s*\(\s*id\s*=\s*(\d+)"), "Workspace.objects.get(id=<literal>)"),
        (re.compile(r"Workspace\.objects\.get\s*\(\s*pk\s*=\s*(\d+)"), "Workspace.objects.get(pk=<literal>)"),
    ]
    found = []
    for py_path in PROJECT_ROOT.rglob("*.py"):
        if "venv" in py_path.parts or "__pycache__" in py_path.parts or ".venv" in py_path.parts or "migrations" in py_path.parts:
            continue
        try:
            text = py_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = py_path.relative_to(PROJECT_ROOT)
        for i, line in enumerate(text.splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            for pat, desc in patterns:
                if pat.search(line):
                    # Allow pk=value (variable) in validation code
                    if "pk=value)" in line or "pk=value " in line:
                        continue
                    found.append((str(rel), i, line.strip()[:80], desc))
                    break
    if found:
        for path, line_no, snippet, desc in found:
            print(f"  {RISK}  {path}:{line_no}  ({desc})  -> {snippet}...")
        return False, found
    print(f"  {SAFE}  No hardcoded workspace ID patterns found.")
    return True, []


def check_5_signals():
    """Inspect Django signals affecting Workspace or Membership."""
    print("\n--- CHECK 5: Signals (Workspace / Membership) ---")
    review = []
    # Scan project files for @receiver / .connect( with Workspace or WorkspaceMembership
    for py_path in PROJECT_ROOT.rglob("*.py"):
        if "venv" in py_path.parts or "__pycache__" in py_path.parts or ".venv" in py_path.parts or py_path.name == "verify_workspace_safety.py":
            continue
        try:
            text = py_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        rel = py_path.relative_to(PROJECT_ROOT)
        if "@receiver" in text or ".connect(" in text:
            for i, line in enumerate(text.splitlines(), 1):
                if ("Workspace" in line or "WorkspaceMembership" in line) and ("receiver" in line or "connect" in line or "post_save" in line or "pre_delete" in line):
                    review.append((str(rel), i, line.strip()[:90]))
    # Known core signal: create_personal_workspace_for_user
    try:
        import core.signals as core_sigs
        if hasattr(core_sigs, "create_personal_workspace_for_user"):
            print(f"  {REVIEW}  core.signals.create_personal_workspace_for_user (post_save, sender=CustomUser)")
            print("             -> Creates one personal workspace + membership per new user (not cross-workspace).")
            review.append("core.signals.create_personal_workspace_for_user")
    except Exception:
        pass
    for r in review:
        if isinstance(r, tuple):
            print(f"  {REVIEW}  {r[0]}:{r[1]}  {r[2]}")
    if not review:
        print(f"  {SAFE}  No project signal handlers found for Workspace/Membership.")
    return review


def check_6_singleton_or_global():
    """Models without workspace FK that might be tenant-dependent (e.g. AlertConfig, SLAConfig)."""
    print("\n--- CHECK 6: Singleton / global (no workspace FK, possibly tenant-dependent) ---")
    # Names that suggest tenant-scoped config
    tenant_like = ("config", "sla", "alertconfig", "slaconfig", "setting", "preference")
    review = []
    for model in apps.get_models():
        if model._meta.abstract:
            continue
        if _model_has_workspace_fk(model):
            continue
        name_lower = model.__name__.lower()
        if any(t in name_lower for t in tenant_like):
            review.append(f"  {model._meta.label} (name suggests tenant scope)")
    # Also list global RBAC that is not workspace-scoped
    for model in apps.get_models():
        if model._meta.abstract:
            continue
        if _model_has_workspace_fk(model):
            continue
        if model.__name__ in ("WorkspaceRole", "WorkspacePermission", "RolePermission"):
            review.append(f"  {model._meta.label} (global RBAC - not workspace-scoped)")
    if review:
        for r in review:
            print(f"  {REVIEW}  {r}")
    else:
        print(f"  {SAFE}  No obvious tenant-dependent models without workspace FK.")
    return review


def check_7_protected_foreign_keys():
    """List all FKs with on_delete=PROTECT in the project."""
    print("\n--- CHECK 7: Protected foreign keys (on_delete=PROTECT) ---")
    found = []
    for model in apps.get_models():
        if model._meta.abstract:
            continue
        for f in model._meta.get_fields():
            if not hasattr(f, "remote_field") or f.remote_field is None:
                continue
            if not hasattr(f.remote_field, "on_delete"):
                continue  # e.g. ManyToManyField has no on_delete
            if getattr(f.remote_field.on_delete, "__name__", "") == "PROTECT":
                found.append((model._meta.label, f.name, getattr(f.remote_field.model, "_meta", None)))
    for label, fname, meta in found:
        remote = meta.label if meta else "?"
        print(f"  {REVIEW}  {label}.{fname} -> on_delete=PROTECT (target: {remote})")
    if not found:
        print(f"  {SAFE}  No PROTECT FKs found.")
    return found


def check_8_membership_safety():
    """Verify Membership has FK to Workspace (CASCADE) and User (CASCADE)."""
    print("\n--- CHECK 8: Membership safety ---")
    Membership = apps.get_model("core", "WorkspaceMembership")
    ok_workspace = ok_user = False
    for f in Membership._meta.get_fields():
        if not hasattr(f, "remote_field") or f.remote_field is None:
            continue
        if getattr(f.remote_field.model, "__name__", None) == "Workspace":
            on_del = on_delete_label(f)
            ok_workspace = on_del == "CASCADE"
            print(f"  {SAFE if ok_workspace else RISK}  Membership.workspace -> on_delete={on_del}")
        if getattr(f.remote_field.model, "__name__", None) == "CustomUser" and f.name == "user":
            on_del = on_delete_label(f)
            ok_user = on_del == "CASCADE"
            print(f"  {SAFE if ok_user else RISK}  Membership.user -> on_delete={on_del}")
    safe = ok_workspace and ok_user
    if safe:
        print(f"  {SAFE}  Membership uses CASCADE on Workspace and User.")
    return safe


def main():
    print("=== WORKSPACE SAFETY AUDIT ===")
    print("(Read-only. No database or code modifications.)")

    results = {}
    results["check1"], _ = check_1_workspace_scoped_models()
    results["check2"], _ = check_2_reverse_relations()
    results["check3"] = len(check_3_cross_workspace_fks()) == 0
    results["check4"], _ = check_4_hardcoded_workspace_ids()
    check_5_signals()
    results["check5"] = True  # Signals are REVIEW, not hard RISK for delete
    check_6_singleton_or_global()
    results["check6"] = True  # REVIEW only
    check_7_protected_foreign_keys()
    results["check7"] = True  # REVIEW only
    results["check8"] = check_8_membership_safety()

    # Final verdict: RISK if any hard failure
    risk_checks = ["check1", "check2", "check4", "check8"]
    has_risk = not all(results.get(c, True) for c in risk_checks)

    print("\n" + "=" * 50)
    if has_risk:
        print("FINAL VERDICT: RISKS DETECTED - REVIEW REQUIRED")
        print("  Address CHECK 1/2/4/8 risks before deleting workspaces.")
    else:
        print("FINAL VERDICT: SAFE TO DELETE WORKSPACE")
        print("  (From model/schema perspective. Still use membership_service.delete_workspace().)")
    print("=" * 50)


if __name__ == "__main__":
    main()

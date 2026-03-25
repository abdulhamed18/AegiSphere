"""
Signals for core app. Auto-creates a personal workspace for each new user.
Ownership is determined only by PERSONAL_OWNER membership (no workspace.owner).
"""

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.text import slugify

from .models import CustomUser, Workspace, WorkspaceMembership, WorkspaceRole


@receiver(post_save, sender=CustomUser)
def create_personal_workspace_for_user(sender, instance, created, **kwargs):
    """
    When a new user is created, ensure they have exactly one personal workspace
    and PERSONAL_OWNER membership. Uses get_or_create; no workspace.owner.
    """
    if not created:
        return
    if getattr(instance, "is_superuser", False):
        return

    # One personal workspace per user: ownership by PERSONAL_OWNER membership only.
    if WorkspaceMembership.objects.filter(
        user=instance,
        is_active=True,
        role__code="PERSONAL_OWNER",
        workspace__workspace_type="personal",
    ).exists():
        return

    slug_base = slugify(instance.username) or f"user-{instance.pk}"
    slug = f"{slug_base}-{instance.pk}-personal"
    name = f"{instance.username}'s Workspace"
    workspace = Workspace.objects.create(
        name=name,
        slug=slug,
        workspace_type="personal",
    )
    try:
        role = WorkspaceRole.objects.get(code="PERSONAL_OWNER")
    except WorkspaceRole.DoesNotExist:
        return
    WorkspaceMembership.objects.create(
        user=instance,
        workspace=workspace,
        role=role,
        is_active=True,
    )

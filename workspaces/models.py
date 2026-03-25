from django.db import models

from core.models import Workspace


class WorkspaceScopedModel(models.Model):
    """Abstract base for models that belong to a single workspace (tenant isolation)."""

    workspace = models.ForeignKey(
        Workspace,
        on_delete=models.CASCADE,
        related_name="%(class)s_objects",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        abstract = True

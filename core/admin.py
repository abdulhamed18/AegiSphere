from django.contrib import admin

from .models import OrganizationJoinRequest, Workspace


@admin.register(Workspace)
class WorkspaceAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "workspace_type", "created_at")
    list_filter = ("workspace_type", "created_at")
    search_fields = ("name", "slug")


@admin.register(OrganizationJoinRequest)
class OrganizationJoinRequestAdmin(admin.ModelAdmin):
    list_display = ("user", "workspace", "status", "created_at")
    list_filter = ("status", "created_at")
    search_fields = ("user__username", "workspace__name")


from django.contrib.auth.admin import UserAdmin
from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ("username", "email", "is_verified", "is_active", "is_staff")
    list_filter = ("is_verified", "is_active", "is_staff", "is_superuser")
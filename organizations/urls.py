from django.urls import path

from . import views

app_name = "organizations"

urlpatterns = [
    # Dashboard
    path("", views.organization_dashboard, name="dashboard"),
    
    # Data Sources
    path("data-sources/add/", views.add_data_source, name="add-source"),
    path("data-sources/<int:pk>/", views.organization_source_details, name="source-details"),

    # Member management
    path("members/change-role/", views.change_role, name="change-role"),
    path("members/remove/", views.remove_member, name="remove-member"),

    # Join requests
    path("join-requests/<int:pk>/approve/", views.approve_request, name="approve-request"),
    path("join-requests/<int:pk>/reject/", views.reject_request, name="reject-request"),

    # Invites
    path("invites/create/", views.create_invite, name="create-invite"),
    path("invites/<int:pk>/revoke/", views.revoke_invite, name="revoke-invite"),

    # API keys
    path("api-keys/", views.api_keys_list, name="api-keys"),
    path("api-keys/generate/", views.generate_key, name="generate-key"),
    path("api-keys/<int:pk>/revoke/", views.revoke_key, name="revoke-key"),
    path("api-keys/<int:pk>/rotate/", views.rotate_api_key, name="rotate-key"),

    # Settings
    path("settings/security/", views.update_settings, name="update-settings"),
    path("settings/workspace/", views.update_workspace, name="update-workspace"),

    # Danger zone
    path("leave/", views.leave_org, name="leave"),
    path("delete/", views.delete_org, name="delete"),
]

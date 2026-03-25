"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path

from core.auth_views import register
from core.views import dashboard
from workspaces.api.join_governance_views import SecureSchemaView
from workspaces.views import switch_workspace

urlpatterns = [
    path("", dashboard, name="dashboard"),
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),
    path("accounts/register/", register, name="register"),
    path("alerts/", include("alerts.urls")),
    path("workspaces/", include("workspaces.urls")),
    path("switch-workspace/<int:workspace_id>/", switch_workspace, name="switch_workspace"),
    path("api/schema/", SecureSchemaView.as_view(), name="openapi-schema"),
    path("api/workspaces/", include("workspaces.api.urls")),
    path("api/internal/", include("workspaces.api.internal_urls")),
    path("api/v1/", include("api.urls")),
    path("cases/", include("cases.urls")),
    path("metrics/", include("metrics.urls")),
    path("organization/", include("organizations.urls")),
]

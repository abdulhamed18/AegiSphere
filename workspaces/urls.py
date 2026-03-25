from django.urls import path

from . import views

app_name = "workspaces"

urlpatterns = [
    path("switch/<int:workspace_id>/", views.switch_workspace, name="switch_workspace"),
]

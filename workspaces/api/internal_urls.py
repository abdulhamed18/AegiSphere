"""
Internal/admin-only API routes (e.g. expire join requests).
Namespace: api/internal/
"""

from django.urls import path

from . import join_governance_views as views

urlpatterns = [
    path("expire-join-requests/", views.ExpireJoinRequestsView.as_view(), name="expire-join-requests"),
]

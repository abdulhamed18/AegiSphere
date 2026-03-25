"""
Phase 8 — App Shell: Alerts placeholder routes.
"""

from django.urls import path

from . import views

app_name = "alerts"

urlpatterns = [
    path("", views.alert_list, name="list"),
    path("<int:pk>/", views.alert_detail, name="detail"),
    path("<int:pk>/change-status/", views.alert_change_status, name="change-status"),
    path("<int:pk>/assign/", views.alert_assign, name="assign"),
    path("<int:pk>/lock/", views.alert_lock, name="lock"),
    path("<int:pk>/unlock/", views.alert_unlock, name="unlock"),
]

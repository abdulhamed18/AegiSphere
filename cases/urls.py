"""
Phase 7 — Case API URLs
"""

from django.urls import path

from . import views

app_name = "cases"

urlpatterns = [
    path("", views.case_list, name="list"),
    path("<int:pk>/", views.case_detail, name="case-detail"),
    path("<int:pk>/export/", views.CaseExportView.as_view(), name="case-export"),
]

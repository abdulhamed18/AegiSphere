from django.urls import path

from . import views

app_name = "metrics"

urlpatterns = [
    path("workload/", views.workload_dashboard, name="workload"),
]

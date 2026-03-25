from django.urls import path
from api.views.ingestion import IngestEventsView

app_name = 'api'

urlpatterns = [
    path("ingest/", IngestEventsView.as_view(), name="ingest_events"),
]

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils.dateparse import parse_datetime

from api.authentication import ApiKeyAuthentication
from api.permissions import HasValidApiKey
from api.throttles import ApiKeyRateThrottle
from api.serializers import IngestionRequestSerializer
from api.models import IngestionEvent
from api.utils import log_api_security_event

class IngestEventsView(APIView):
    authentication_classes = [ApiKeyAuthentication]
    permission_classes = [HasValidApiKey]
    throttle_classes = [ApiKeyRateThrottle]

    def post(self, request, *args, **kwargs):
        # We try to determine event count for received log if it's available and a list
        event_count = 0
        if isinstance(request.data, dict) and isinstance(request.data.get('events'), list):
            event_count = len(request.data.get('events'))
            
        # Log payload received attempt
        log_api_security_event(
            workspace=request.workspace,
            api_key_public_id=request.api_key.public_id,
            request=request,
            event_str="INGESTION_RECEIVED",
            event_count=event_count
        )

        serializer = IngestionRequestSerializer(data=request.data)
        if not serializer.is_valid():
            log_api_security_event(
                workspace=request.workspace,
                api_key_public_id=request.api_key.public_id,
                request=request,
                event_str="INVALID_PAYLOAD",
                event_count=event_count
            )
            return Response(
                {"status": "error", "error": "INVALID_PAYLOAD", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        validated_data = serializer.validated_data
        source = validated_data['source'].lower()
        events_data = validated_data['events']
        
        # Build event model instances for bulk creation
        event_instances = []
        for event in events_data:
            event_time = None
            if isinstance(event, dict):
                time_str = event.get('event_time') or event.get('timestamp') or event.get('@timestamp')
                if isinstance(time_str, str):
                    try:
                        parsed_time = parse_datetime(time_str)
                        if parsed_time:
                            event_time = parsed_time
                    except Exception:
                        pass

            event_instances.append(
                IngestionEvent(
                    workspace=request.workspace,
                    api_key=request.api_key,
                    source=source,
                    raw_log=event,
                    event_time=event_time,
                    ingest_method=IngestionEvent.IngestMethod.WEBHOOK,
                    processing_status=IngestionEvent.ProcessingStatus.PENDING
                )
            )

        # Bulk create all valid events
        IngestionEvent.objects.bulk_create(event_instances)

        # Update matching data source
        from django.utils import timezone
        from organizations.models import OrganizationDataSource
        OrganizationDataSource.objects.filter(
            workspace=request.workspace,
            source_type=source
        ).update(last_log_received=timezone.now())

        # Log completion
        log_api_security_event(
            workspace=request.workspace,
            api_key_public_id=request.api_key.public_id,
            request=request,
            event_str="INGESTION_STORED",
            event_count=len(event_instances)
        )

        return Response(
            {"status": "success", "received": len(event_instances)},
            status=status.HTTP_200_OK
        )

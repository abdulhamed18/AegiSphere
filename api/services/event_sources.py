from api.models import EventSource

def get_source_by_name(source_name):
    """
    Find EventSource record by the source string stored in IngestionEvent.
    Returns None if the source does not exist.
    """
    try:
        return EventSource.objects.get(name=source_name)
    except EventSource.DoesNotExist:
        return None

import json
from rest_framework import serializers

class IngestionRequestSerializer(serializers.Serializer):
    source = serializers.CharField(required=True)
    events = serializers.ListField(
        child=serializers.DictField(),
        allow_empty=False,
        max_length=500
    )

    def validate_source(self, value):
        if not value:
            raise serializers.ValidationError("Source must not be empty.")
        
        stripped = value.strip()
        if not stripped:
            raise serializers.ValidationError("Source must not be whitespace-only.")
            
        if len(stripped) > 100:
            raise serializers.ValidationError("Source must be 100 characters or less.")
            
        return stripped

    def validate_events(self, value):
        for event in value:
            if not isinstance(event, dict):
                raise serializers.ValidationError("Each event must be a dictionary.")
            event_size = len(json.dumps(event).encode('utf-8'))
            if event_size > 10 * 1024:
                raise serializers.ValidationError("Event size exceeds the 10 KB limit.")
        return value


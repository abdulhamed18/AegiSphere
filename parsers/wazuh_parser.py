def parse_event(raw_log):
    # Dummy implementation for tests
    return {
        "event_type": "failed_login",
        "category": "authentication",
        "source_ip": "192.168.1.10",
        "username": raw_log.get("user", "admin"),
        "host": "server01",
        "severity": "LOW"
    }

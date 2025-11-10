def detect_new_service(events):
    alerts = []
    for event in events:
        if event.get("event_id") == 7045:
            alerts.append(f"[MEDIUM] New Service Installed: {event.get('command')}")
    return alerts

def detect_suspicious_powershell(events):
    alerts = []
    for event in events:
        if event.get("event_id") == 4688:
            cmd = event.get("command", "")
            if "powershell" in cmd.lower() and ("-enc" in cmd.lower() or "iex" in cmd.lower()):
                alerts.append(f"[HIGH] Suspicious PowerShell command: {cmd}")
    return alerts

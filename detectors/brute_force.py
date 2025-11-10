def detect_bruteforce(events):
    failed_attempts = {}

    for event in events:
        if event.get("event_id") == 4625:  
            ip = event.get("ip", "")
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    alerts = []

    for ip, count in failed_attempts.items():
        if count >= 3:
            alerts.append(f"[HIGH] Possible Brute Force Attack from IP {ip} ({count} failed logins)")

    return alerts

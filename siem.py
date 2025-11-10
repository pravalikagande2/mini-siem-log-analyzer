from parser.windows_parser import parse_log_line
from detectors.brute_force import detect_bruteforce
from detectors.powershell import detect_suspicious_powershell
from detectors.log_cleared import detect_log_clear
from detectors.new_service import detect_new_service

from colorama import Fore, Style, init
from datetime import datetime, timezone
import os

init(autoreset=True)

LOG_FILE = "logs/security.txt"
HTML_OUT = "report/alerts_report.html"
TXT_OUT = "alerts_report.txt"



def read_logs(file):
    with open(file, "r", encoding="utf-8") as f:
        blocks = f.read().strip().split("\n\n")

    events = []
    for block in blocks:
        ev = parse_log_line(block)
        if ev:
            events.append(ev)
    return events



def write_text_report(alerts):
    with open(TXT_OUT, "w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(alert + "\n")



def write_html_report(alerts):
    high = sum(1 for a in alerts if "[HIGH]" in a)
    medium = sum(1 for a in alerts if "[MEDIUM]" in a)
    low = sum(1 for a in alerts if "[LOW]" in a)

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Mini SIEM Report</title>
    <style>
        body {{
            font-family: Arial, Helvetica, sans-serif;
            padding: 20px;
            background: #f5f6fa;
        }}
        h1 {{
            color: #2c3e50;
        }}
        .meta {{
            color: #555;
            margin-bottom: 20px;
        }}
        .summary {{
            padding: 12px;
            background: #ecf0f1;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .high {{ color: #c0392b; font-weight: bold; }}
        .medium {{ color: #e67e22; font-weight: bold; }}
        .low {{ color: #27ae60; font-weight: bold; }}
        ul {{ list-style: none; padding-left: 0; }}
        li {{
            margin: 10px 0;
            padding: 12px;
            background: white;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>

<h1>Mini SIEM Alert Report</h1>
<div class="meta">
Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')} (UTC)
</div>

<div class="summary">
    <strong>Summary:</strong><br><br>
    <span class="high">High: {high}</span> &nbsp;|&nbsp;
    <span class="medium">Medium: {medium}</span> &nbsp;|&nbsp;
    <span class="low">Low: {low}</span>
</div>

<ul>
"""

   
    for alert in alerts:
        if "[HIGH]" in alert:
            html += f"<li class='high'>{alert}</li>\n"
        elif "[MEDIUM]" in alert:
            html += f"<li class='medium'>{alert}</li>\n"
        else:
            html += f"<li class='low'>{alert}</li>\n"

    html += """
</ul>
</body>
</html>
"""

    
    folder = os.path.dirname(HTML_OUT)
    if folder and not os.path.exists(folder):
        os.makedirs(folder)

    with open(HTML_OUT, "w", encoding="utf-8") as f:
        f.write(html)
    
   




# Console Output
def pretty_print(alerts):
    print(Fore.CYAN + "\n==== ALERTS ====\n" + Style.RESET_ALL)

    for alert in alerts:
        if "[HIGH]" in alert:
            print(Fore.RED + alert + Style.RESET_ALL)
        elif "[MEDIUM]" in alert:
            print(Fore.YELLOW + alert + Style.RESET_ALL)
        else:
            print(Fore.GREEN + alert + Style.RESET_ALL)



# Main Function
def main():
    events = read_logs(LOG_FILE)

    alerts = []
    alerts += detect_bruteforce(events)
    alerts += detect_suspicious_powershell(events)
    alerts += detect_log_clear(events)
    alerts += detect_new_service(events)

    pretty_print(alerts)
    write_text_report(alerts)
    write_html_report(alerts)

    print(Fore.CYAN + f"\nReports created: {TXT_OUT} and {HTML_OUT}\n" + Style.RESET_ALL)

    import webbrowser
    webbrowser.open(os.path.abspath(HTML_OUT))


if __name__ == "__main__":
    main()

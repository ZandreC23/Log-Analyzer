import sys
import json
from datetime import datetime

THRESHOLD = 3
WINDOW_SECONDS = 60

failed_counts = {}

if len(sys.argv) < 2:
    print("Usage: python analyzer.py <logfile>")
    sys.exit(1)

log_file = sys.argv[1]
current_year = str(datetime.now().year)


# ---- 1. READ the log and group failures by IP ----

with open(log_file) as f:
    for line in f:
        if "Failed" in line:
            parts = line.split()
            ip = parts[parts.index("from") + 1]

            timestamp = parts[0] + " " + parts[1] + " " + parts[2] + " " + current_year
            time_obj = datetime.strptime(timestamp, "%b %d %H:%M:%S %Y")

            if ip in failed_counts:
                failed_counts[ip].append(time_obj)
            else:
                failed_counts[ip] = [time_obj]


# ---- 2. RANK the IPs, most failures first ----

ranked = sorted(failed_counts.items(), key=lambda pair: len(pair[1]), reverse=True)


# ---- 3. WRITE the text report and collect the findings ----

findings = []

with open("report.txt", "w") as report:
    for ip, times in ranked:
        count = len(times)
        span = (times[-1] - times[0]).total_seconds()
        is_alert = count >= THRESHOLD and span <= WINDOW_SECONDS

        if is_alert:
            report_line = f"[ALERT] {ip} -> {count} failed attempts in {int(span)} seconds - possible brute-force"
        else:
            report_line = f"{ip} -> {count} failed attempts"

        print(report_line)
        report.write(report_line + "\n")

        findings.append({
            "ip": ip,
            "failed_attempts": count,
            "span_seconds": int(span),
            "first_attempt": str(times[0]),
            "last_attempt": str(times[-1]),
            "alert": is_alert
        })


# ---- 4. WRITE the JSON report ----

with open("report.json", "w") as json_report:
    json.dump(findings, json_report, indent=2)


# ---- 5. BUILD the HTML dashboard ----
# Python only hands over the data. The JavaScript in template.html draws the page.

with open("template.html") as template_file:
    template = template_file.read()

template = template.replace("LOG_NAME", log_file)
template = template.replace("GENERATED_AT", datetime.now().strftime("%Y-%m-%d %H:%M"))
template = template.replace("THRESHOLD_VALUE", str(THRESHOLD))
template = template.replace("WINDOW_VALUE", str(WINDOW_SECONDS))
template = template.replace("DATA_GOES_HERE", json.dumps(findings))

with open("index.html", "w") as dashboard:
    dashboard.write(template)
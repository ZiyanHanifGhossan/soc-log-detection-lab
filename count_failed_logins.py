import csv
from collections import defaultdict
from pathlib import Path

# Find the data file relative to this script.
data_file = Path(__file__).parent / "data" / "sample_log.csv"

with data_file.open(newline="", encoding="utf-8-sig") as file:
    events = list(csv.DictReader(file))

# Keep a separate failure count for each username and source IP.
failures_by_identity = defaultdict(int)

for event in events:
    if event["event_type"] == "login_failed":
        identity = (event["username"], event["source_ip"])
        failures_by_identity[identity] += 1

for (username, source_ip), count in failures_by_identity.items():
    print(f"{username} @ {source_ip}: {count} failed logins")

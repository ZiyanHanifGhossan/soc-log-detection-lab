import csv
import json
from collections import Counter
from pathlib import Path


data_directory = Path(__file__).parent / "data"
source_file = data_directory / "cowrie.json.2025-04-03.anon"
output_file = data_directory / "cowrie_login_events.csv"

# Keep authentication events only. Success events are retained for Rule 2,
# even though this particular sample file contains no successful logins.
event_type_map = {
    "cowrie.login.failed": "login_failed",
    "cowrie.login.success": "login_success",
}
fieldnames = ["timestamp", "username", "source_ip", "event_type"]
event_counts = Counter()
missing_field_counts = Counter()
skipped_incomplete_events = 0
unique_usernames = set()
unique_source_ips = set()

with source_file.open(encoding="utf-8") as source, output_file.open(
    "w", newline="", encoding="utf-8"
) as destination:
    writer = csv.DictWriter(destination, fieldnames=fieldnames)
    writer.writeheader()

    for line_number, line in enumerate(source, start=1):
        event = json.loads(line)
        event_type = event_type_map.get(event.get("eventid"))

        if event_type is None:
            continue

        required_fields = ["timestamp", "username", "src_ip"]
        missing_fields = [field for field in required_fields if not event.get(field)]
        if missing_fields:
            skipped_incomplete_events += 1
            missing_field_counts.update(missing_fields)
            continue

        # Intentionally do not copy Cowrie's password or message fields.
        writer.writerow(
            {
                "timestamp": event["timestamp"],
                "username": event["username"],
                "source_ip": event["src_ip"],
                "event_type": event_type,
            }
        )
        event_counts[event_type] += 1
        unique_usernames.add(event["username"])
        unique_source_ips.add(event["src_ip"])

print(f"Saved normalized authentication events to: {output_file}")
print(f"Failed logins: {event_counts['login_failed']}")
print(f"Successful logins: {event_counts['login_success']}")
print(f"Distinct usernames: {len(unique_usernames)}")
print(f"Distinct source IPs: {len(unique_source_ips)}")
print(f"Skipped incomplete authentication events: {skipped_incomplete_events}")
if missing_field_counts:
    print(f"Missing required fields: {dict(missing_field_counts)}")

import argparse
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


def parse_timestamp(value):
    """Read either the simulation's clock time or a full ISO 8601 timestamp."""
    if "T" in value:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return datetime.strptime(value, "%H:%M:%S")


def display_timestamp(value):
    if value.tzinfo is not None:
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return value.strftime("%H:%M:%S")


parser = argparse.ArgumentParser(
    description="Detect repeated and distributed failed logins."
)
parser.add_argument(
    "data_file",
    nargs="?",
    type=Path,
    default=Path(__file__).parent / "data" / "sample_log.csv",
    help="CSV file to analyze (defaults to the synthetic sample).",
)
data_file = parser.parse_args().data_file

with data_file.open(newline="", encoding="utf-8-sig") as file:
    events = list(csv.DictReader(file))

# Keep every event grouped by username and source IP.
events_by_identity = defaultdict(list)
# Also group failed logins by source IP to look for attempts across accounts.
failed_by_ip = defaultdict(list)

for event in events:
    event_time = parse_timestamp(event["timestamp"])
    username = event["username"]
    source_ip = event["source_ip"]
    event_type = event["event_type"]

    identity = (username, source_ip)
    events_by_identity[identity].append((event_time, event_type))

    if event_type == "login_failed":
        failed_by_ip[source_ip].append((event_time, username))

failure_threshold = 5
failure_window = timedelta(minutes=10)
success_follow_up_window = timedelta(minutes=2)

# Rule 1: repeated failures for the same username from the same IP.
for (username, source_ip), identity_events in events_by_identity.items():
    identity_events.sort(key=lambda item: item[0])
    failure_times = [
        event_time
        for event_time, event_type in identity_events
        if event_type == "login_failed"
    ]
    alert_found = False

    for window_start in failure_times:
        window_end = window_start + failure_window
        attempts_in_window = [
            event_time
            for event_time in failure_times
            if window_start <= event_time <= window_end
        ]

        if len(attempts_in_window) >= failure_threshold:
            last_failed_attempt = attempts_in_window[-1]
            print(
                f"RULE 1 ALERT: {username} @ {source_ip} had "
                f"{len(attempts_in_window)} failed logins "
                f"from {display_timestamp(attempts_in_window[0])} "
                f"to {display_timestamp(last_failed_attempt)}"
            )

            follow_up_end = last_failed_attempt + success_follow_up_window
            follow_up_events = [
                (event_time, event_type)
                for event_time, event_type in identity_events
                if last_failed_attempt < event_time <= follow_up_end
            ]

            for event_time, event_type in follow_up_events:
                seconds_after = int(
                    (event_time - last_failed_attempt).total_seconds()
                )
                if event_type == "login_success":
                    print(
                        f"RULE 2 ESCALATION: successful login at "
                        f"{display_timestamp(event_time)} "
                        f"({seconds_after} seconds after the last failure)"
                    )
                elif event_type == "account_locked":
                    print(
                        f"CONTEXT: account_locked at "
                        f"{display_timestamp(event_time)} "
                        f"({seconds_after} seconds after the last failure)"
                    )

            alert_found = True
            break

    if not alert_found:
        print(f"No Rule 1 alert: {username} @ {source_ip}")

# Rule 3 candidate: one source IP has failed logins for many distinct accounts.
unique_account_threshold = 5

for source_ip, attempts in failed_by_ip.items():
    attempts.sort(key=lambda item: item[0])
    alert_found = False

    for window_start, _ in attempts:
        window_end = window_start + failure_window
        attempts_in_window = [
            (event_time, username)
            for event_time, username in attempts
            if window_start <= event_time <= window_end
        ]
        distinct_usernames = {username for _, username in attempts_in_window}

        if len(distinct_usernames) >= unique_account_threshold:
            first_attempt = display_timestamp(attempts_in_window[0][0])
            last_attempt = display_timestamp(attempts_in_window[-1][0])
            print(
                f"RULE 3 CANDIDATE: {source_ip} had failed logins for "
                f"{len(distinct_usernames)} distinct accounts "
                f"from {first_attempt} to {last_attempt}; "
                "possible password-spraying pattern"
            )
            alert_found = True
            break

    if not alert_found:
        print(f"No Rule 3 candidate: {source_ip}")

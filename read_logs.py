import csv
from pathlib import Path

# Find the data file relative to this script, so it works from any folder.
data_file = Path(__file__).parent / "data" / "sample_log.csv"

with data_file.open(newline="", encoding="utf-8-sig") as file:
    events = csv.DictReader(file)

    for event in events:
        print(event)

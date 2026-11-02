"""Schema-v4 job records: a CSV identity column and canonical JSON record."""

import csv
import json


def read_jobs(path):
    with path.open(encoding="utf-8", newline="") as stream:
        return [json.loads(row["record"]) for row in csv.DictReader(stream)]

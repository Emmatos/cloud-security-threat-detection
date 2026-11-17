
"""
AWS Cloud Security Threat Detection
Module: Security Log Ingestion

Purpose:
Read simulated AWS CloudTrail events and VPC Flow Logs.
"""

import json
from pathlib import Path


# Locate the main project directory
PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Define security data file locations
CLOUDTRAIL_FILE = (
    PROJECT_ROOT / "data" / "cloudtrail" / "sample_cloudtrail.json"
)

VPC_FLOW_FILE = (
    PROJECT_ROOT / "data" / "vpc-flow-logs" / "sample_vpc_flow.log"
)


def load_cloudtrail():
    """Read AWS CloudTrail JSON events."""

    with open(CLOUDTRAIL_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    events = data.get("Records", [])

    return events


def load_vpc_flow_logs():
    """Read and process VPC Flow Log records."""

    events = []

    with open(VPC_FLOW_FILE, "r", encoding="utf-8") as file:

        lines = file.readlines()

    header = None

    for line in lines:

        line = line.strip()

        # Ignore blank lines
        if not line:
            continue

        # Identify the column names
        if line.startswith("version "):
            header = line.split()
            continue

        # Ignore records if no header exists
        if header is None:
            continue

        values = line.split()

        # Check that the record matches the header
        if len(values) != len(header):
            continue

        event = dict(zip(header, values))

        events.append(event)

    return events


def main():

    print("=" * 55)
    print("AWS CLOUD SECURITY LOG INGESTION")
    print("=" * 55)

    cloudtrail_events = load_cloudtrail()

    vpc_events = load_vpc_flow_logs()

    print("\nCLOUDTRAIL RESULTS")
    print("-" * 55)

    print("Total CloudTrail events:", len(cloudtrail_events))

    for event in cloudtrail_events:

        print(
            event.get("eventName"),
            "|",
            event.get("sourceIPAddress")
        )

    print("\nVPC FLOW LOG RESULTS")
    print("-" * 55)

    print("Total VPC Flow Log events:", len(vpc_events))

    for event in vpc_events:

        print(
            event.get("srcaddr"),
            "->",
            event.get("dstaddr"),
            "|",
            event.get("action"),
            "| Port:",
            event.get("dstport")
        )

    print("\nLOG INGESTION COMPLETED SUCCESSFULLY.")


if __name__ == "__main__":
    main()

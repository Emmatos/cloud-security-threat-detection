
"""
AWS Cloud Security Threat Detection

Module: detection_engine.py

Purpose:
Analyze CloudTrail and VPC Flow Logs
and identify suspicious security events.
"""

from src.ingestion import load_cloudtrail, load_vpc_flow_logs
from src.storage import save_findings


def create_finding(rule_id, event_type, severity,
                   source_ip, description, recommendation):

    """Create a standardized security finding."""

    return {
        "rule_id": rule_id,
        "event_type": event_type,
        "severity": severity,
        "source_ip": source_ip,
        "description": description,
        "recommendation": recommendation
    }


def detect_cloudtrail_events(events):

    """Detect suspicious AWS CloudTrail activities."""

    findings = []

    for event in events:

        event_name = event.get("eventName")

        source_ip = event.get("sourceIPAddress", "Unknown")

        response = event.get("responseElements") or {}

        # SEC-001: Detect failed console logins
        if (
            event_name == "ConsoleLogin"
            and response.get("ConsoleLogin") == "Failure"
        ):

            findings.append(
                create_finding(
                    "SEC-001",
                    "Failed Console Login",
                    "Medium",
                    source_ip,
                    "An AWS console login attempt failed.",
                    "Review the account, source IP and authentication history."
                )
            )

        # SEC-002: Detect IAM access-key creation
        if event_name == "CreateAccessKey":

            findings.append(
                create_finding(
                    "SEC-002",
                    "IAM Access Key Creation",
                    "Medium",
                    source_ip,
                    "An IAM access key was created.",
                    "Verify the actor, authorization and intended use of the key."
                )
            )

    return findings


def detect_vpc_flow_logs(events):

    """Detect rejected connections to sensitive network ports."""

    findings = []

    for event in events:

        action = event.get("action", "").upper()

        destination_port = event.get("dstport")

        source_ip = event.get("srcaddr", "Unknown")

        # Only investigate rejected connections
        if action != "REJECT":
            continue

        # SEC-003: Rejected SSH connections
        if destination_port == "22":

            findings.append(
                create_finding(
                    "SEC-003",
                    "Rejected SSH Connection",
                    "Low",
                    source_ip,
                    "A network connection to SSH port 22 was rejected.",
                    "Review the source IP and network access rules."
                )
            )

        # SEC-004: Rejected RDP connections
        elif destination_port == "3389":

            findings.append(
                create_finding(
                    "SEC-004",
                    "Rejected RDP Connection",
                    "Low",
                    source_ip,
                    "A network connection to RDP port 3389 was rejected.",
                    "Review the source IP and investigate unexpected RDP traffic."
                )
            )

    return findings


def main():

    """Run the complete security detection engine."""

    print("=" * 60)
    print("AWS CLOUD SECURITY THREAT DETECTION ENGINE")
    print("=" * 60)

    # Load security events
    cloudtrail_events = load_cloudtrail()

    vpc_events = load_vpc_flow_logs()

    # Run detection rules
    cloudtrail_findings = detect_cloudtrail_events(
        cloudtrail_events
    )

    vpc_findings = detect_vpc_flow_logs(vpc_events)

    # Combine all findings
    all_findings = cloudtrail_findings + vpc_findings
    
    # Save security findings into SQLite
    saved_count = save_findings(all_findings)

    print("\nDATABASE STORAGE")
    print("-" * 60)

    print("Findings saved to database:", saved_count)
    print("\nSECURITY DETECTION SUMMARY")
    print("-" * 60)

    print("CloudTrail events:", len(cloudtrail_events))

    print("VPC Flow Log events:", len(vpc_events))

    print("Security findings:", len(all_findings))

    print("\nDETECTED SECURITY FINDINGS")
    print("-" * 60)

    for finding in all_findings:

        print("\nRule ID:", finding["rule_id"])

        print("Event:", finding["event_type"])

        print("Severity:", finding["severity"])

        print("Source IP:", finding["source_ip"])

        print("Description:", finding["description"])

        print("Recommendation:", finding["recommendation"])

        print("-" * 60)

    print("\nTHREAT DETECTION COMPLETED.")


if __name__ == "__main__":
    main()

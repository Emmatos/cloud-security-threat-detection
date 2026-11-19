
from src.detection_engine import detect_cloudtrail_events, detect_vpc_flow_logs


def test_failed_console_login_detection():
    events = [
        {
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "203.0.113.15",
            "responseElements": {
                "ConsoleLogin": "Failure"
            }
        }
    ]

    findings = detect_cloudtrail_events(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-001"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["source_ip"] == "203.0.113.15"


def test_iam_access_key_creation_detection():
    events = [
        {
            "eventName": "CreateAccessKey",
            "sourceIPAddress": "192.0.2.25"
        }
    ]

    findings = detect_cloudtrail_events(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-002"
    assert findings[0]["severity"] == "Medium"


def test_rejected_ssh_connection_detection():
    events = [
        {
            "action": "REJECT",
            "dstport": "22",
            "srcaddr": "203.0.113.15"
        }
    ]

    findings = detect_vpc_flow_logs(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-003"
    assert findings[0]["severity"] == "Low"


def test_rejected_rdp_connection_detection():
    events = [
        {
            "action": "REJECT",
            "dstport": "3389",
            "srcaddr": "203.0.113.15"
        }
    ]

    findings = detect_vpc_flow_logs(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SEC-004"
    assert findings[0]["severity"] == "Low"


def test_accepted_ssh_connection_is_not_flagged():
    events = [
        {
            "action": "ACCEPT",
            "dstport": "22",
            "srcaddr": "198.51.100.23"
        }
    ]

    findings = detect_vpc_flow_logs(events)

    assert len(findings) == 0


def test_rejected_unmonitored_port_is_not_flagged():
    events = [
        {
            "action": "REJECT",
            "dstport": "443",
            "srcaddr": "203.0.113.15"
        }
    ]

    findings = detect_vpc_flow_logs(events)

    assert len(findings) == 0

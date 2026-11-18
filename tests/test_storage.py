
from src import storage


def test_save_and_retrieve_security_findings(tmp_path, monkeypatch):

    # Use a temporary database for testing.
    test_database_dir = tmp_path / "database"
    test_database_file = test_database_dir / "test_security.db"

    # Redirect storage to the temporary database.
    monkeypatch.setattr(storage, "DATABASE_DIR", test_database_dir)
    monkeypatch.setattr(storage, "DATABASE_FILE", test_database_file)

    findings = [
        {
            "rule_id": "SEC-001",
            "event_type": "Failed Console Login",
            "severity": "Medium",
            "source_ip": "203.0.113.15",
            "description": "Test failed login.",
            "recommendation": "Review the source IP."
        }
    ]

    # Save the finding.
    saved_count = storage.save_findings(findings)

    # Retrieve the finding.
    retrieved_findings = storage.get_findings()

    assert saved_count == 1
    assert len(retrieved_findings) == 1
    assert retrieved_findings[0]["rule_id"] == "SEC-001"
    assert retrieved_findings[0]["severity"] == "Medium"

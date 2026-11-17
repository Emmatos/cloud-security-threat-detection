
"""
AWS Cloud Security Threat Detection
Module: storage.py

Purpose:
Create and manage the SQLite security findings database.
"""

import sqlite3
from pathlib import Path


# Locate the project directory
PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Define the database location
DATABASE_DIR = PROJECT_ROOT / "database"

DATABASE_FILE = DATABASE_DIR / "security_findings.db"


def initialize_database():
    """Create the database and security findings table."""

    # Create database folder if it does not exist
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)

    # Connect to SQLite
    with sqlite3.connect(DATABASE_FILE) as connection:

        cursor = connection.cursor()

        # Create security findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_findings (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                rule_id TEXT NOT NULL,

                event_type TEXT NOT NULL,

                severity TEXT NOT NULL,

                source_ip TEXT,

                description TEXT,

                recommendation TEXT,

                detected_at TEXT DEFAULT CURRENT_TIMESTAMP

            )
        """)

        connection.commit()

    print("Security database initialized successfully.")


def save_findings(findings):
    """Save detected security findings into SQLite."""

    initialize_database()

    with sqlite3.connect(DATABASE_FILE) as connection:

        cursor = connection.cursor()

        for finding in findings:

            cursor.execute("""
                INSERT INTO security_findings (
                    rule_id,
                    event_type,
                    severity,
                    source_ip,
                    description,
                    recommendation
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                finding.get("rule_id"),
                finding.get("event_type"),
                finding.get("severity"),
                finding.get("source_ip"),
                finding.get("description"),
                finding.get("recommendation")
            ))

        connection.commit()

        return len(findings)


def get_findings():
    """Retrieve all stored security findings."""

    initialize_database()

    with sqlite3.connect(DATABASE_FILE) as connection:

        connection.row_factory = sqlite3.Row

        cursor = connection.cursor()

        cursor.execute("""
            SELECT *
            FROM security_findings
            ORDER BY id DESC
        """)

        findings = cursor.fetchall()

        return [dict(row) for row in findings]


def main():

    """Test the SQLite database."""

    print("=" * 55)
    print("AWS CLOUD SECURITY DATABASE")
    print("=" * 55)

    initialize_database()

    findings = get_findings()

    print("\nDatabase location:", DATABASE_FILE)

    print("Stored security findings:", len(findings))

    print("\nDATABASE TEST COMPLETED.")


if __name__ == "__main__":
    main()

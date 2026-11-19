
"""
PROJECT 01: AWS CLOUD SECURITY THREAT DETECTION

Streamlit Security Operations Dashboard

Data sources:
1. SQLite security findings database
2. Local VPC Flow Log sample
"""

import sqlite3
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# --------------------------------------------------
# PROJECT PATH CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# --------------------------------------------------
# PROJECT MODULE IMPORTS
# --------------------------------------------------

from src.ingestion import load_vpc_flow_logs
from src.storage import get_findings

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="Cloud Security Operations Center",
    page_icon="🛡️",
    layout="wide",
)

# --------------------------------------------------
# LOAD PROJECT DATA
# --------------------------------------------------


@st.cache_data(ttl=10)
def load_dashboard_data():
    findings = get_findings()
    network_events = load_vpc_flow_logs()

    return findings, network_events


# --------------------------------------------------
# DASHBOARD HEADER
# --------------------------------------------------

st.title("🛡️ Cloud Security Operations Center")

st.caption(
    "Project 01 | Python | SQLite | Streamlit | AWS Security Analytics"
)

st.markdown("---")

# --------------------------------------------------
# DASHBOARD DATA AND VISUALIZATIONS
# --------------------------------------------------

try:
    findings, network_events = load_dashboard_data()

    findings_df = pd.DataFrame(findings)
    network_df = pd.DataFrame(network_events)

    # --------------------------------------------------
    # SECURITY METRICS
    # --------------------------------------------------

    st.subheader("Security Overview")

    total_findings = len(findings_df)

    medium_findings = 0
    low_findings = 0
    high_findings = 0
    critical_findings = 0

    if not findings_df.empty:
        severity_counts = (
            findings_df["severity"]
            .str.lower()
            .value_counts()
        )

        medium_findings = severity_counts.get("medium", 0)
        low_findings = severity_counts.get("low", 0)
        high_findings = severity_counts.get("high", 0)
        critical_findings = severity_counts.get("critical", 0)

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Total Findings", total_findings)
    col2.metric("Critical", int(critical_findings))
    col3.metric("High", int(high_findings))
    col4.metric("Medium", int(medium_findings))
    col5.metric("Low", int(low_findings))

    st.markdown("---")

    # --------------------------------------------------
    # NETWORK TRAFFIC ANALYSIS
    # --------------------------------------------------

    st.subheader("Network Traffic Analysis")

    if not network_df.empty:
        network_df["action"] = (
            network_df["action"]
            .astype(str)
            .str.upper()
        )

        traffic_counts = network_df["action"].value_counts()

        accepted = int(traffic_counts.get("ACCEPT", 0))
        rejected = int(traffic_counts.get("REJECT", 0))

        col1, col2, col3 = st.columns(3)

        col1.metric("Total Network Events", len(network_df))
        col2.metric("Accepted Connections", accepted)
        col3.metric("Rejected Connections", rejected)

        traffic_chart = pd.DataFrame(
            {
                "Decision": ["ACCEPT", "REJECT"],
                "Events": [accepted, rejected],
            }
        )

        st.bar_chart(
            traffic_chart,
            x="Decision",
            y="Events",
        )

    else:
        st.info("No VPC Flow Log events available.")

    st.markdown("---")

    # --------------------------------------------------
    # SECURITY FINDINGS
    # --------------------------------------------------

    st.subheader("Detected Security Findings")

    if not findings_df.empty:
        selected_severity = st.selectbox(
            "Filter findings by severity",
            ["All", "Critical", "High", "Medium", "Low"],
        )

        filtered_df = findings_df.copy()

        if selected_severity != "All":
            filtered_df = filtered_df[
                filtered_df["severity"].str.lower()
                == selected_severity.lower()
            ]

        display_columns = [
            "rule_id",
            "event_type",
            "severity",
            "source_ip",
            "description",
            "recommendation",
        ]

        st.dataframe(
            filtered_df[display_columns],
            width="stretch",
            hide_index=True,
        )

    else:
        st.info("No security findings have been recorded yet.")

    st.markdown("---")

    # --------------------------------------------------
    # SOURCE IP ANALYSIS
    # --------------------------------------------------

    st.subheader("Source IP Analysis")

    if not findings_df.empty:
        ip_counts = (
            findings_df["source_ip"]
            .value_counts()
            .reset_index()
        )

        ip_counts.columns = ["Source IP", "Findings"]

        st.bar_chart(
            ip_counts,
            x="Source IP",
            y="Findings",
        )

    else:
        st.info("No source IP findings available.")

    st.markdown("---")

    # --------------------------------------------------
    # DETECTION RULES
    # --------------------------------------------------

    st.subheader("Active Detection Rules")

    rules = pd.DataFrame(
        [
            {
                "Rule ID": "SEC-001",
                "Detection": "Failed Console Login",
                "Severity": "Medium",
            },
            {
                "Rule ID": "SEC-002",
                "Detection": "IAM Access Key Creation",
                "Severity": "Medium",
            },
            {
                "Rule ID": "SEC-003",
                "Detection": "Rejected SSH Connection",
                "Severity": "Low",
            },
            {
                "Rule ID": "SEC-004",
                "Detection": "Rejected RDP Connection",
                "Severity": "Low",
            },
        ]
    )

    st.dataframe(
        rules,
        width="stretch",
        hide_index=True,
    )

    st.markdown("---")

# --------------------------------------------------
# ERROR HANDLING
# --------------------------------------------------

except (sqlite3.Error, OSError, UnicodeError) as error:
    st.error("Unable to load dashboard data.")

    st.exception(error)

    st.info(
        "Check that the database exists and the ingestion "
        "module can read your sample VPC Flow Logs."
    )

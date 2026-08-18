from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from hunter import ModelAbuseHunter

ROOT = Path(__file__).resolve().parent
ARCHIVE_PATH = ROOT / "sample_cases.json"

SAMPLE_REPORTS = {
    "Phishing + prompt abuse": (
        "A fake payroll portal asks employees to log in through helpdesk@secure-payroll.co and https://payroll-login-secure.co/portal. "
        "The adversary also asks the model to ignore policies, reveal secrets, and generate phishing scripts. "
        "The malicious IP is 185.220.101.42."
    ),
    "Ransomware + malware": (
        "An attacker references lockfiles-update.net and a malware hash 9f1c4a2e5b6d7a88d0e9f9b2c1d3a4f5. "
        "The adversary asks the model to produce ransomware deployment scripts and bypass system prompt guardrails."
    ),
    "Jailbreak workflow": (
        "The actor attempts to get the model to ignore restrictions and provide instructions for credential theft. "
        "The prompt includes a fake login page and uses the domain secure-payroll.co as part of a social engineering lure."
    ),
}


@st.cache_data
def load_cases(path: str = str(ARCHIVE_PATH)):
    data_path = Path(path)
    if not data_path.exists():
        return []
    try:
        payload = json.loads(data_path.read_text(encoding="utf-8"))
        cases = payload.get("cases", []) if isinstance(payload, dict) else []
        return cases if isinstance(cases, list) else []
    except Exception:
        return []


@st.cache_data
def analyze_text(text: str, assignee: str | None = None, notes: list[str] | None = None):
    hunter = ModelAbuseHunter(storage_path=ARCHIVE_PATH)
    return hunter.analyze(text, assignee=assignee, notes=notes or [])


st.set_page_config(page_title="Adversarial Model Abuse Hunter", page_icon="🛡️", layout="wide")
st.title("🛡️ Adversarial Model Abuse Hunter")
st.caption("Threat hunting and case triage for adversarial model abuse, phishing, and malicious prompt workflows")

with st.sidebar:
    st.header("Sample reports")
    for label, sample in SAMPLE_REPORTS.items():
        if st.button(label, use_container_width=True):
            st.session_state["input_text"] = sample

    st.markdown("---")
    st.subheader("Case queue")
    cases = load_cases()
    if cases:
        for case in cases[:5]:
            title = case.get("title") or case.get("case_id") or "Historical case"
            severity = case.get("severity") or "Unknown"
            priority = case.get("priority") or "P3"
            st.markdown(f"[{priority}] {title} — {severity}")
    else:
        st.write("No saved cases yet.")

text_input = st.text_area(
    "Threat / abuse report",
    value=st.session_state.get("input_text", SAMPLE_REPORTS["Phishing + prompt abuse"]),
    height=220,
)

assignee = st.selectbox("Assign analyst", ["unassigned", "Analyst A", "Analyst B", "Analyst C"])
case_note = st.text_input("Analyst note", value="")

if st.button("Analyze report", type="primary"):
    if text_input.strip():
        with st.spinner("Assessing model abuse behavior and risk..."):
            notes = [case_note] if case_note.strip() else []
            result = analyze_text(text_input, assignee=assignee, notes=notes)
        st.session_state["report"] = result

report = st.session_state.get("report")
if report:
    risk = report.get("risk", {})
    indicators = report.get("indicators", [])
    alerts = report.get("alerts", [])
    summary = report.get("summary", "")
    related_cases = report.get("related_cases", [])
    case_id = report.get("case_id", "N/A")
    priority = report.get("priority", "P3")
    status = report.get("status", "new")
    assignee_value = report.get("assignee", "unassigned")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Risk score", f"{risk.get('score', 0)}/100")
    col2.metric("Severity", risk.get("severity", "Low"))
    col3.metric("Indicators", len(indicators))
    col4.metric("Priority", priority)

    st.subheader("Case investigation")
    st.markdown(f"**Case ID:** {case_id} | **Status:** {status} | **Assignee:** {assignee_value} | **Priority:** {priority}")

    st.subheader("Analyst summary")
    st.code(summary, language="text")

    tab1, tab2, tab3 = st.tabs(["Alerts", "Indicators", "Queue"])

    with tab1:
        if alerts:
            for alert in alerts:
                st.markdown(f"- **{alert.get('title')}** [{alert.get('severity', 'Unknown')}] — {alert.get('summary', '')}")
        else:
            st.info("No alerts were generated.")

    with tab2:
        if indicators:
            df = pd.DataFrame(indicators)
            display = df[["type", "value", "confidence", "tags", "mitre"]].copy()
            display["tags"] = display["tags"].apply(lambda values: ", ".join(values) if isinstance(values, list) else values)
            display["mitre"] = display["mitre"].apply(lambda values: ", ".join(values) if isinstance(values, list) else values)
            st.dataframe(display, use_container_width=True)
        else:
            st.info("No indicators were extracted.")

    with tab3:
        queue = report.get("case_queue", [])
        if queue:
            queue_df = pd.DataFrame(queue)
            display_queue = queue_df[["case_id", "title", "priority", "severity", "status", "risk_score"]].copy()
            st.dataframe(display_queue, use_container_width=True)
        else:
            st.info("No cases in the queue yet.")

    st.subheader("Related cases")
    if related_cases:
        st.json(related_cases)
    else:
        st.info("No related cases were detected.")

    st.subheader("Raw JSON")
    st.json(report)
else:
    st.info("Paste a threat report or choose a sample to start an investigation.")

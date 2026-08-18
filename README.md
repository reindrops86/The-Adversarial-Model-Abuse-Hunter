# Adversarial Model Abuse Hunter

A lightweight threat-intel and investigation workflow for adversarial use of generative AI models, abuse campaigns, and malicious prompt activity.

## What it does

- extracts indicators from raw threat and abuse text
- detects prompt abuse patterns such as jailbreaks, phishing, malware, credential theft, and social engineering
- scores severity and confidence for each case
- correlates related incidents across a local case archive
- produces a structured analyst report and enforcement recommendations
- exposes a Streamlit dashboard for analyst review

## Project structure

- `hunter.py` — core analysis engine and case management
- `app.py` — Streamlit dashboard
- `sample_cases.json` — example data

## Run the app

```powershell
cd "C:\Users\downi\OneDrive\Documents\08metricsdemos_1786575674023\08_metrics_demos\artifacts\adversarial_model_abuse_hunter"
& "C:\Users\downi\crewai-venv\Scripts\python.exe" -m streamlit run app.py --server.headless true --server.port 8503 --server.address 127.0.0.1

& "C:\Users\downi\crewai-venv\Scripts\python.exe" -c "from hunter import ModelAbuseHunter; sample = 'A phishing lure from helpdesk@secure-payroll.co directs employees to https://payroll-login-secure.co/portal. The attacker asks the model to bypass safeguards and produce a credential theft script. The malicious IP is 185.220.101.42.'; print(ModelAbuseHunter().analyze(sample, assignee='Analyst A')['risk'])"

Notes
This is a lightweight prototype built for local investigation workflows. It uses a local intelligence feed and JSON-based case archive so it works offline without external services.

Example threat text
Threat notice: a malicious campaign is targeting employees with a fake payroll portal.
The lure impersonates a payroll portal and includes a link to https://payroll-login-secure[.]co/portal.
The sender address helpdesk@secure-payroll[.]co is used to pass a convincing phishing request.
The campaign also references a malicious IP 185.220.101.42 and a suspicious hash 9f1c4a2e5b6d7a88d0e9f9b2c1d3a4f5.
The adversary asks the model to ignore prior instructions, reveal secrets, and provide a credential harvesting workflow.

Dependencies
streamlit>=1.40.0
pandas>=2.2.0

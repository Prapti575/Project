# NetShield — Rule-Based Network Intrusion Detection System

**Bootcamp project:** BharatCares | IBM SkillsBuild Cybersecurity Bootcamp  
**Approach:** Python rule-based detection — **no machine learning**

## Overview
NetShield reads network-flow records from a CSV file, validates the data, applies simple explainable rules, and displays potential indicators in a Streamlit dashboard. It is intended as a beginner-friendly educational project.

## Features
- CSV upload and required-column validation
- Possible port-scan indicator
- High source flow-count indicator
- High bytes-per-flow indicator
- High/Medium/Low severity labels with explanations
- Dashboard charts, source-IP filters, and CSV exports
- Synthetic demo traffic generator

## Requirements
- Python 3.10 or later recommended
- pip

## Run locally
1. Extract the project ZIP and open a terminal in the `NetShield` folder.
2. (Recommended) Create a virtual environment:
   ```bash
   python -m venv .venv
   ```
   Windows:
   ```bash
   .venv\Scripts\activate
   ```
   macOS/Linux:
   ```bash
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the dashboard:
   ```bash
   streamlit run app.py
   ```
5. In the browser, select **Use sample traffic** and click **Analyze traffic**.

## CSV format
The CSV must include these columns:

| Column | Meaning | Example |
|---|---|---|
| `src_ip` | Source IP address | `192.168.1.10` |
| `dst_ip` | Destination IP address | `10.0.0.20` |
| `dst_port` | Destination port (0–65535) | `443` |
| `protocol` | Protocol label | `TCP` |
| `bytes` | Bytes recorded for the flow | `1200` |
| `packets` | Packets recorded for the flow | `12` |

An optional `timestamp` column is supported. Extra columns are preserved.

## Detection rules
1. **Possible port scan — High:** a source IP contacts at least the selected number of distinct destination ports.
2. **High source flow count — Medium:** a source IP produces at least the selected number of flow records.
3. **High bytes per flow — Medium:** an individual flow reaches the selected byte threshold.
4. **Low:** no configured rule triggers.

Thresholds are adjustable in the sidebar. Severity follows a simple precedence: High if the port-scan rule matches; otherwise Medium if either volume rule matches; otherwise Low.

## Testing
- Use sample traffic to verify that scan-like traffic from `203.0.113.77` triggers the port-scan rule.
- Check that a row with large `bytes` triggers the high-bytes rule when its source does not trigger a higher-severity rule.
- Upload a CSV with a missing required column; the app should show a clear validation error.
- Upload a CSV containing invalid numeric values; unusable rows should be removed and validation notes displayed.
- Export results and confirm that the output contains `severity` and `alert_reason`.

## Limitations and ethical use
- This tool analyzes static CSV flow records; it does not capture live packets.
- It uses no ML and does not train a model.
- Rules can create false positives or miss real attacks. Alerts are indicators, not proof.
- Only analyze traffic and datasets you have permission to use. Do not use findings to access or disrupt systems.

## Project files
- `app.py` — Streamlit interface and workflow
- `detector.py` — rule-based detection logic
- `preprocessing.py` — CSV validation and cleaning
- `generate_data.py` — synthetic demo data
- `requirements.txt` — Python dependencies
- `data/sample_traffic.csv` — example CSV dataset
- `project_report.docx` — project report

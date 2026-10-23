import pandas as pd

def analyze_traffic(df, port_threshold=10, flow_threshold=100, bytes_threshold=1_000_000):
    """Apply explainable, rule-based indicators to cleaned network-flow data."""
    out = df.copy()
    out["bytes"] = pd.to_numeric(out["bytes"], errors="coerce").fillna(0)
    out["dst_port"] = pd.to_numeric(out["dst_port"], errors="coerce").fillna(-1).astype(int)
    source_port_counts = out.groupby("src_ip")["dst_port"].nunique().to_dict()
    source_flow_counts = out.groupby("src_ip")["src_ip"].transform("size")

    severities, reasons = [], []
    for idx, row in out.iterrows():
        alerts = []
        severity = "Low"
        src = row["src_ip"]
        if source_port_counts.get(src, 0) >= port_threshold:
            alerts.append(f"Possible port scan: source contacted {source_port_counts[src]} distinct destination ports")
            severity = "High"
        if int(source_flow_counts.loc[idx]) >= flow_threshold:
            alerts.append(f"High source flow count: {int(source_flow_counts.loc[idx])} flows")
            if severity != "High":
                severity = "Medium"
        if float(row["bytes"]) >= bytes_threshold:
            alerts.append(f"High bytes per flow: {int(row['bytes']):,} bytes")
            if severity == "Low":
                severity = "Medium"
        severities.append(severity)
        reasons.append("; ".join(alerts) if alerts else "No configured rule triggered")
    out["severity"] = severities
    out["alert_reason"] = reasons
    return out

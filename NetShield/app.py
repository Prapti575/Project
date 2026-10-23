import streamlit as st
import pandas as pd
import plotly.express as px
from detector import analyze_traffic
from preprocessing import validate_and_clean
from generate_data import generate_sample_data

st.set_page_config(page_title="NetShield NIDS", page_icon="🛡️", layout="wide")

st.title("🛡️ NetShield — Network Intrusion Detection System")
st.caption("Rule-based network traffic analysis • No machine learning")

with st.sidebar:
    st.header("Traffic source")
    source = st.radio("Choose input", ["Use sample traffic", "Upload CSV"])
    uploaded = None
    if source == "Upload CSV":
        uploaded = st.file_uploader("Upload network traffic CSV", type=["csv"])
    st.divider()
    st.subheader("Detection rules")
    port_threshold = st.slider("Distinct destination ports for possible scan", 5, 50, 10)
    flow_threshold = st.slider("Flows per source IP", 10, 500, 100)
    bytes_threshold = st.slider("High bytes per flow", 100_000, 10_000_000, 1_000_000, step=100_000)
    run_scan = st.button("Analyze traffic", type="primary", use_container_width=True)

st.markdown("""
NetShield checks CSV network-flow records against simple, explainable rules.
It does **not** capture live packets and does **not** use machine learning.
Use only network data you are authorized to analyze.
""")

if "traffic" not in st.session_state:
    st.session_state.traffic = generate_sample_data()
if "results" not in st.session_state:
    st.session_state.results = None
if "cleaned" not in st.session_state:
    st.session_state.cleaned = None

if run_scan:
    try:
        if source == "Upload CSV":
            if uploaded is None:
                st.error("Please upload a CSV file first.")
                st.stop()
            raw = pd.read_csv(uploaded)
        else:
            raw = generate_sample_data()
        cleaned, issues = validate_and_clean(raw)
        if cleaned.empty:
            st.error("No valid rows remain after validation. Check the required columns and values.")
            if issues:
                st.write(issues)
            st.stop()
        results = analyze_traffic(
            cleaned,
            port_threshold=port_threshold,
            flow_threshold=flow_threshold,
            bytes_threshold=bytes_threshold,
        )
        st.session_state.traffic = cleaned
        st.session_state.cleaned = cleaned
        st.session_state.results = results
        st.session_state.issues = issues
        st.success(f"Analysis complete: checked {len(cleaned):,} valid flow records.")
    except Exception as exc:
        st.error(f"Could not analyze this file: {exc}")

results = st.session_state.results
traffic = st.session_state.traffic

if results is None:
    st.info("Select a traffic source and click **Analyze traffic** to run the rules.")
    st.subheader("Expected CSV columns")
    st.code("src_ip,dst_ip,dst_port,protocol,bytes,packets")
    st.write("Optional columns are allowed. Extra columns are preserved.")
else:
    issues = st.session_state.get("issues", [])
    if issues:
        with st.expander(f"Data validation notes ({len(issues)})"):
            for issue in issues:
                st.write(f"- {issue}")

    total = len(results)
    alerts = results[results["severity"] != "Low"]
    high = int((results["severity"] == "High").sum())
    medium = int((results["severity"] == "Medium").sum())
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Flow records", f"{total:,}")
    c2.metric("Alerts", f"{len(alerts):,}")
    c3.metric("High severity", f"{high:,}")
    c4.metric("Medium severity", f"{medium:,}")

    st.subheader("Alert review")
    filter_severity = st.multiselect("Filter by severity", ["High", "Medium", "Low"], default=["High", "Medium"])
    filtered = results[results["severity"].isin(filter_severity)].copy()
    if "src_ip" in filtered.columns:
        ip_options = sorted(filtered["src_ip"].dropna().astype(str).unique().tolist())
        chosen_ips = st.multiselect("Filter by source IP (optional)", ip_options)
        if chosen_ips:
            filtered = filtered[filtered["src_ip"].astype(str).isin(chosen_ips)]
    display_cols = [c for c in ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes", "packets", "severity", "alert_reason"] if c in filtered.columns]
    st.dataframe(filtered[display_cols], use_container_width=True, hide_index=True)

    st.download_button(
        "Download filtered results (CSV)",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="netshield_alerts.csv",
        mime="text/csv",
    )
    st.download_button(
        "Download all analysis results (CSV)",
        data=results.to_csv(index=False).encode("utf-8"),
        file_name="netshield_all_results.csv",
        mime="text/csv",
    )

    left, right = st.columns(2)
    with left:
        st.subheader("Severity distribution")
        sev_counts = results["severity"].value_counts().reindex(["High", "Medium", "Low"], fill_value=0).reset_index()
        sev_counts.columns = ["Severity", "Count"]
        st.plotly_chart(px.bar(sev_counts, x="Severity", y="Count", title="Records by severity"), use_container_width=True)
    with right:
        st.subheader("Protocol distribution")
        proto_counts = traffic["protocol"].astype(str).value_counts().rename_axis("Protocol").reset_index(name="Flows")
        st.plotly_chart(px.pie(proto_counts, names="Protocol", values="Flows", title="Traffic protocols"), use_container_width=True)

    st.subheader("Top source IPs by flow count")
    top_sources = traffic["src_ip"].astype(str).value_counts().head(10).rename_axis("Source IP").reset_index(name="Flows")
    st.plotly_chart(px.bar(top_sources, x="Source IP", y="Flows", title="Top 10 source IPs"), use_container_width=True)

    st.subheader("Detection rules")
    st.markdown("""
    - **Possible port scan (High):** a source IP contacts at least the configured number of distinct destination ports.
    - **High source flow count (Medium):** a source IP produces at least the configured number of flow records.
    - **High bytes per flow (Medium):** a flow reaches the configured byte threshold.
    - **No rule triggered (Low):** no configured rule matched that flow.

    These are educational heuristics. Review alerts alongside trusted network logs before taking action.
    """)

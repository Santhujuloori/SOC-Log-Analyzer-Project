import streamlit as st
import pandas as pd
from analyzer import analyze_logs

# =========================
# 🔧 PAGE CONFIG
# =========================
st.set_page_config(page_title="SOC Log Analyzer", page_icon="🛡️", layout="wide")

# =========================
# 🎨 STYLE
# =========================
st.markdown("""
<style>
.block-container {padding-top: 2rem;}
h1 {text-align: center;}
</style>
""", unsafe_allow_html=True)

# =========================
# 🧠 TITLE
# =========================
st.markdown("<h1>🛡️ SOC Log Analyzer Dashboard</h1>", unsafe_allow_html=True)
st.markdown("### 🔍 Detect threats from security logs")

# =========================
# 📂 FILE UPLOAD
# =========================
uploaded_file = st.file_uploader("📂 Upload CSV log file")

if uploaded_file is not None:

    df = pd.read_csv(uploaded_file)

    # =========================
    # 🔎 SIDEBAR FILTERS
    # =========================
    st.sidebar.header("🔎 Filters")

    ip_filter = st.sidebar.selectbox(
        "Select IP",
        ["All"] + list(df["ip"].unique())
    )

    user_filter = st.sidebar.selectbox(
        "Select User",
        ["All"] + list(df["user"].unique())
    )

    # =========================
    # 🔄 APPLY FILTERS
    # =========================
    filtered_df = df.copy()

    if ip_filter != "All":
        filtered_df = filtered_df[filtered_df["ip"] == ip_filter]

    if user_filter != "All":
        filtered_df = filtered_df[filtered_df["user"] == user_filter]

    # =========================
    # 🔍 ANALYSIS
    # =========================
    alerts = analyze_logs(filtered_df)
    alerts_df = pd.DataFrame(alerts)

    # =========================
    # 📑 TABS
    # =========================
    tab1, tab2, tab3 = st.tabs(["📊 Logs", "🚨 Alerts", "📈 Dashboard"])

    # =========================
    # 📊 TAB 1: LOGS
    # =========================
    with tab1:
        st.subheader("📊 Log Data")
        st.dataframe(filtered_df, use_container_width=True)

    # =========================
    # 🚨 TAB 2: ALERTS
    # =========================
    with tab2:
        st.subheader("🚨 Detected Alerts")

        def color_severity(val):
            if val == "High":
                return "background-color: red; color: white"
            elif val == "Low":
                return "background-color: yellow"
            return ""

        if not alerts_df.empty:

            # 🔎 Severity filter
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["All", "High", "Low"]
            )

            filtered_alerts = alerts_df.copy()

            if severity_filter != "All":
                filtered_alerts = filtered_alerts[
                    filtered_alerts["severity"] == severity_filter
                ]

            styled_df = filtered_alerts.style.map(
                color_severity, subset=["severity"]
            )

            st.dataframe(styled_df, use_container_width=True)

            # 📥 Download
            st.download_button(
                "📥 Download Alerts",
                filtered_alerts.to_csv(index=False),
                file_name="alerts_report.csv"
            )

        else:
            st.success("✅ No suspicious activity detected")

    # =========================
    # 📈 TAB 3: DASHBOARD
    # =========================
    with tab3:

        if not alerts_df.empty:

            st.subheader("📊 Threat Overview")

            # Risk Score
            high_count = (alerts_df["severity"] == "High").sum()
            low_count = (alerts_df["severity"] == "Low").sum()
            risk_score = high_count * 10 + low_count * 2

            col1, col2, col3 = st.columns(3)
            col1.metric("🚨 High Alerts", high_count)
            col2.metric("⚠️ Low Alerts", low_count)
            col3.metric("🔥 Risk Score", risk_score)

            # Suspicious IPs
            st.subheader("🚨 Suspicious IPs")
            suspicious_ips = alerts_df["ip"].value_counts().reset_index()
            suspicious_ips.columns = ["IP", "Alert Count"]
            st.dataframe(suspicious_ips, use_container_width=True)

            # Charts
            st.subheader("📈 Alert Distribution")
            summary = alerts_df["type"].value_counts()
            st.bar_chart(summary)

            st.subheader("📊 IP Activity Trend")
            st.line_chart(suspicious_ips.set_index("IP"))

        else:
            st.info("No data available for dashboard")
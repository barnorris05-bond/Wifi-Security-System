import streamlit as st
import pandas as pd
from reports.pdf_report import generate_pdf_report
from reports.csv_export import generate_csv_report
from reports.json_export import generate_json_report

def render_networks_tab(scan_session):
    st.header("Detected Networks")
    if not scan_session or not scan_session.networks:
        st.info("No network records found.")
        return

    data = []
    for n in scan_session.networks:
        asm = scan_session.assessments.get(n.bssid)
        data.append({
            "SSID": n.ssid,
            "BSSID": n.bssid,
            "Channel": n.channel,
            "Frequency": f"{n.frequency_mhz} MHz",
            "Band": n.band,
            "Signal (dBm)": n.signal_dbm,
            "Encryption": n.encryption,
            "Authentication": n.authentication,
            "Risk Level": asm.risk_level if asm else "UNKNOWN",
            "Risk Score": asm.risk_score if asm else 0
        })

    df = pd.DataFrame(data)
    st.dataframe(df, use_container_width=True)

    st.subheader("Export Security Reports")
    col1, col2, col3 = st.columns(3)
    with col1:
        pdf_bytes = generate_pdf_report(scan_session)
        st.download_button("PDF Report", data=pdf_bytes, file_name=f"wifi_report_{scan_session.scan_id}.pdf", mime="application/pdf", type="secondary")
    with col2:
        csv_data = generate_csv_report(scan_session)
        st.download_button("CSV Data", data=csv_data, file_name=f"wifi_data_{scan_session.scan_id}.csv", mime="text/csv", type="secondary")
    with col3:
        json_data = generate_json_report(scan_session)
        st.download_button("JSON Export", data=json_data, file_name=f"wifi_session_{scan_session.scan_id}.json", mime="application/json", type="secondary")

    st.divider()
    st.subheader("Detailed Security Assessment")

    selected_bssid = st.selectbox(
        "Select Network BSSID for In-Depth Risk Findings:",
        options=[n.bssid for n in scan_session.networks],
        format_func=lambda x: f"{x} - {[n.ssid for n in scan_session.networks if n.bssid == x][0]}"
    )

    if selected_bssid:
        net = next((n for n in scan_session.networks if n.bssid == selected_bssid), None)
        asm = scan_session.assessments.get(selected_bssid)

        if net and asm:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Risk Score", f"{asm.risk_score} / 100")
            with col2:
                st.metric("Risk Level", asm.risk_level)
            with col3:
                st.metric("Security Status", asm.security_level)

            st.markdown("#### Security Findings & Recommendations")
            if asm.findings:
                for f in asm.findings:
                    severity_color = "CRITICAL" if f.severity in ["CRITICAL", "HIGH"] else "MEDIUM" if f.severity == "MEDIUM" else "INFO"
                    with st.expander(f"[{severity_color}] {f.severity}: {f.title}"):
                        st.write(f"**Description:** {f.description}")
                        st.write(f"**Recommendation:** {f.recommendation}")
            else:
                st.success("No security findings detected for this network.")

import streamlit as st
import pandas as pd

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

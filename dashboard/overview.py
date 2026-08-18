import streamlit as st
import plotly.express as px
import pandas as pd
from dashboard.components import render_metric_cards

def render_overview(scan_session):
    st.header("Scan Overview")
    if not scan_session or not scan_session.networks:
        st.info("No scan data available. Load sample data or trigger a scan.")
        return

    nets = scan_session.networks
    assessments = scan_session.assessments

    risk_counts = {}
    for asm in assessments.values():
        risk_counts[asm.risk_level] = risk_counts.get(asm.risk_level, 0) + 1

    valid_signals = [n.signal_dbm for n in nets if n.signal_dbm is not None]
    avg_signal = round(sum(valid_signals) / len(valid_signals), 1) if valid_signals else 0.0

    render_metric_cards(len(nets), avg_signal, risk_counts)
    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Security Risk Distribution")
        if risk_counts:
            df_risk = pd.DataFrame(list(risk_counts.items()), columns=["Risk Level", "Count"])
            fig_risk = px.pie(df_risk, values="Count", names="Risk Level", hole=0.4,
                              color="Risk Level",
                              color_discrete_map={"CRITICAL": "red", "HIGH": "orange", "MODERATE": "yellow", "LOW": "green"})
            st.plotly_chart(fig_risk, use_container_width=True)

    with col2:
        st.subheader("Frequency Band Allocation")
        bands = {}
        for n in nets:
            bands[n.band] = bands.get(n.band, 0) + 1
        df_band = pd.DataFrame(list(bands.items()), columns=["Band", "Count"])
        fig_band = px.bar(df_band, x="Band", y="Count", color="Band")
        st.plotly_chart(fig_band, use_container_width=True)

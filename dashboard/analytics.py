import streamlit as st
import plotly.express as px
import pandas as pd

def render_analytics_tab(scan_session):
    st.header("Spectrum & Channel Congestion")
    if not scan_session or not scan_session.networks:
        st.info("No scan data available.")
        return

    nets = scan_session.networks
    df = pd.DataFrame([n.to_dict() for n in nets])

    st.subheader("Channel Occupancy")
    fig_chan = px.histogram(df, x="channel", color="band", nbins=20, labels={"channel": "Channel Number"})
    st.plotly_chart(fig_chan, use_container_width=True)

    st.subheader("Signal Strength vs. Channel")
    fig_scatter = px.scatter(df, x="channel", y="signal_dbm", color="encryption",
                             hover_data=["ssid", "bssid"], size_max=15)
    st.plotly_chart(fig_scatter, use_container_width=True)

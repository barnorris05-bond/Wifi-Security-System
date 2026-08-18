import streamlit as st

def render_metric_cards(total_nets: int, avg_signal: float, risk_counts: dict):
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Networks", total_nets)
    with col2:
        st.metric("Avg Signal", f"{avg_signal} dBm" if avg_signal else "N/A")
    with col3:
        st.metric("Critical/High Risk", risk_counts.get("CRITICAL", 0) + risk_counts.get("HIGH", 0))
    with col4:
        st.metric("Secure Networks", risk_counts.get("LOW", 0))

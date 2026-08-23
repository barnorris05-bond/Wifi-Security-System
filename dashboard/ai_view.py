import streamlit as st
import os
from analyzer.ai_assistant import NemotronAnalyzer

def render_ai_view():
    st.title("🤖 Nemotron AI Security Insights")

    # Provider toggle: Local Ollama (4B) vs NVIDIA Cloud API
    provider = st.radio("Select Execution Mode", ["Local (Ollama 4B)", "Cloud (NVIDIA API)"])
    mode = "local" if "Local" in provider else "cloud"

    if mode == "cloud" and not os.getenv("NVIDIA_API_KEY"):
        st.warning("Please set the NVIDIA_API_KEY environment variable to use Cloud mode.")
        return

    st.subheader("Analyze Selected Network")
    ssid = st.text_input("SSID", value="Guest_WiFi")
    security = st.selectbox("Security Protocol", ["Open", "WEP", "WPA2-Personal", "WPA3-Personal"])
    signal = st.slider("Signal Strength (dBm)", -100, -30, -65)
    channel = st.number_input("Channel", min_value=1, max_value=165, value=6)

    if st.button("Generate Security Assessment"):
        with st.spinner(f"Nemotron ({mode}) is analyzing network vectors..."):
            try:
                analyzer = NemotronAnalyzer(mode=mode)
                report = analyzer.analyze_network_security(ssid, security, signal, channel)
                st.success("Analysis Complete")
                st.markdown(report)
            except Exception as e:
                st.error(f"Failed to generate analysis: {e}")

if __name__ == "__main__":
    render_ai_view()

import streamlit as st
from analyzer.ai_assistant import NemotronAnalyzer

def render_network_details(df):
    st.title("Detected Networks")
    
    # Render main table
    st.dataframe(df, use_container_width=True)

    st.subheader("Export Security Reports")
    col1, col2, col3 = st.columns(3)
    col1.button("PDF Report")
    col2.button("CSV Data")
    col3.button("JSON Export")

    st.divider()

    st.subheader("Detailed Security Assessment")
    
    # Dropdown for network selection
    options = [f"{row['BSSID']} - {row['SSID']}" for _, row in df.iterrows()]
    selected_option = st.selectbox("Select Network BSSID for In-Depth Risk Findings:", options)
    
    if selected_option:
        # Extract selected network row
        selected_bssid = selected_option.split(" - ")[0]
        net_data = df[df['BSSID'] == selected_bssid].iloc[0]

        # Display basic metric cards
        m1, m2, m3 = st.columns(3)
        m1.metric("Risk Score", f"{net_data['Risk Score']} / 100")
        m2.metric("Risk Level", net_data['Risk Level'])
        m3.metric("Security Status", "SECURE" if net_data['Risk Score'] < 30 else "VULNERABLE")

        st.markdown("### 🤖 Nemotron AI Analysis")
        
        # Select execution mode (Local Ollama vs NVIDIA Cloud API)
        provider = st.radio("AI Engine:", ["Local (Ollama 4B)", "Cloud (NVIDIA API)"], horizontal=True)
        mode = "local" if "Local" in provider else "cloud"

        if st.button("Run AI Risk Audit"):
            with st.spinner("Nemotron is analyzing network parameters..."):
                try:
                    analyzer = NemotronAnalyzer(mode=mode)
                    report = analyzer.analyze_network_security(
                        ssid=str(net_data['SSID']),
                        security_type=f"{net_data['Encryption']} / {net_data['Authentication']}",
                        signal_dbm=int(net_data['Signal (dBm)']),
                        channel=int(net_data['Channel'])
                    )
                    st.info(report)
                except Exception as e:
                    st.error(f"Analysis Error: {e}")

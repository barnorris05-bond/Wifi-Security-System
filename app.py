import streamlit as st
import json
from datetime import datetime
from models.scan import ScanSession
from models.network import NetworkModel
from analyzer.security import SecurityAnalyzer
from database.database import DatabaseManager
from scanner.scanner_factory import ScannerFactory
from dashboard.overview import render_overview
from dashboard.networks import render_networks_tab
from dashboard.analytics import render_analytics_tab

st.set_page_config(page_title="WiFi Security Analytics", layout="wide", page_icon="??")

db = DatabaseManager()

@st.cache_data
def load_sample_data():
    try:
        with open("data/sample_scan.json", "r") as f:
            raw_nets = json.load(f)
        
        session = ScanSession(scan_id="sample_001", interface="wlan0", backend_used="mock_file")
        for item in raw_nets:
            net = NetworkModel(**item)
            session.networks.append(net)
            session.assessments[net.bssid] = SecurityAnalyzer.analyze(net)
        return session
    except Exception as e:
        st.error(f"Failed to load sample dataset: {e}")
        return None

st.sidebar.title("Controls")

data_source = st.sidebar.radio("Data Source", ["Live Wi-Fi Scan", "Database History", "Sample Mock Data"])

session = None

if data_source == "Live Wi-Fi Scan":
    st.sidebar.subheader("Live Scanner")
    interface_name = st.sidebar.text_input("Interface Name", value="Wi-Fi")
    
    if st.sidebar.button("SCAN NOW", type="primary"):
        with st.spinner(f"Scanning airwaves on interface '{interface_name}'..."):
            try:
                scanner = ScannerFactory.get_scanner(interface_name)
                session = scanner.execute_scan()
                
                for net in session.networks:
                    session.assessments[net.bssid] = SecurityAnalyzer.analyze(net)
                
                db.save_session(session)
                st.sidebar.success(f"Scan complete! Detected {len(session.networks)} networks.")
            except Exception as e:
                st.sidebar.error(f"Scan failed: {str(e)}")
                session = load_sample_data()

elif data_source == "Database History":
    recent_scans = db.get_recent_scans()
    if recent_scans:
        scan_options = {f"{r['scan_id']} ({r['timestamp'][:19]}) - {r['network_count']} nets": r['scan_id'] for r in recent_scans}
        selected_label = st.sidebar.selectbox("Select Historic Scan", list(scan_options.keys()))
        selected_scan_id = scan_options[selected_label]
        
        session = db.load_scan_session(selected_scan_id)
        if session:
            st.sidebar.info(f"Loaded historic scan: {session.scan_id}")
        else:
            st.sidebar.error("Failed to load session from database.")
            session = load_sample_data()
    else:
        st.sidebar.warning("No historic scans stored in SQLite database yet.")
        session = load_sample_data()

else:
    session = load_sample_data()

if not session:
    session = load_sample_data()

tab1, tab2, tab3 = st.tabs(["Overview", "Network Details", "Spectrum Analytics"])

with tab1:
    render_overview(session)

with tab2:
    render_networks_tab(session)

with tab3:
    render_analytics_tab(session)

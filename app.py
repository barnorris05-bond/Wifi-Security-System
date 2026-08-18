import streamlit as st
import json
from datetime import datetime
from models.scan import ScanSession
from models.network import NetworkModel
from analyzer.security import SecurityAnalyzer
from database.database import DatabaseManager
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

st.sidebar.title("?? Controls")
data_source = st.sidebar.radio("Data Source", ["Sample Mock Data", "Database Scans"])

if data_source == "Sample Mock Data":
    session = load_sample_data()
else:
    recent = db.get_recent_scans()
    if recent:
        selected_scan_id = st.sidebar.selectbox("Select Historic Scan", [r["scan_id"] for r in recent])
        session = load_sample_data() # Placeholder fallback
    else:
        st.sidebar.warning("No historic scans found in SQLite database.")
        session = load_sample_data()

tab1, tab2, tab3 = st.tabs(["Overview", "Network Details", "Spectrum Analytics"])

with tab1:
    render_overview(session)

with tab2:
    render_networks_tab(session)

with tab3:
    render_analytics_tab(session)

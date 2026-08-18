import os
from models.scan import ScanSession
from models.network import NetworkModel
from analyzer.security import SecurityAnalyzer
from database.database import DatabaseManager

def test_database_persistence(tmp_path):
    db_file = tmp_path / "test_wifi.db"
    db = DatabaseManager(str(db_file))
    
    session = ScanSession(scan_id="test_001", interface="wlan0", backend_used="mock")
    net = NetworkModel(ssid="TestNet", bssid="11:22:33:44:55:66", channel=6, frequency_mhz=2437, band="2.4 GHz", encryption="OPEN")
    session.networks.append(net)
    session.assessments[net.bssid] = SecurityAnalyzer.analyze(net)
    
    db.save_session(session)
    recent = db.get_recent_scans()
    
    assert len(recent) == 1
    assert recent[0]["scan_id"] == "test_001"
    assert recent[0]["network_count"] == 1

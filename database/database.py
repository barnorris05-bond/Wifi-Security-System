import sqlite3, json
from typing import List, Optional, Dict, Any
from models.scan import ScanSession
from models.network import NetworkModel
from models.assessment import SecurityAssessment, Finding

class DatabaseManager:
    def __init__(self, db_path: str = "data/wifi.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executescript('''
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    interface TEXT,
                    backend_used TEXT,
                    timestamp TEXT,
                    duration_seconds REAL,
                    network_count INTEGER
                );

                CREATE TABLE IF NOT EXISTS networks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    ssid TEXT,
                    bssid TEXT,
                    channel INTEGER,
                    frequency_mhz REAL,
                    band TEXT,
                    signal_dbm INTEGER,
                    signal_percent INTEGER,
                    encryption TEXT,
                    authentication TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
                );

                CREATE TABLE IF NOT EXISTS assessments (
                    scan_id TEXT,
                    bssid TEXT,
                    security_level TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    findings_json TEXT,
                    PRIMARY KEY(scan_id, bssid),
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
                );
            ''')
            conn.commit()

    def save_session(self, session: ScanSession):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO scans (scan_id, interface, backend_used, timestamp, duration_seconds, network_count) VALUES (?, ?, ?, ?, ?, ?)",
                (session.scan_id, session.interface, session.backend_used,
                 session.timestamp.isoformat(), session.duration_seconds, len(session.networks))
            )

            for net in session.networks:
                cursor.execute('''
                    INSERT INTO networks 
                    (scan_id, ssid, bssid, channel, frequency_mhz, band, signal_dbm, signal_percent, encryption, authentication)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (session.scan_id, net.ssid, net.bssid, net.channel, net.frequency_mhz,
                      net.band, net.signal_dbm, net.signal_percent, net.encryption, net.authentication))

            for bssid, asm in session.assessments.items():
                findings_str = json.dumps([f.__dict__ for f in asm.findings])
                cursor.execute('''
                    INSERT OR REPLACE INTO assessments (scan_id, bssid, security_level, risk_score, risk_level, findings_json) 
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (session.scan_id, bssid, asm.security_level, asm.risk_score, asm.risk_level, findings_str))

            conn.commit()

    def get_recent_scans(self, limit: int = 15) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def load_scan_session(self, scan_id: str) -> Optional[ScanSession]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            scan_row = cursor.fetchone()
            if not scan_row:
                return None

            cursor.execute("SELECT * FROM networks WHERE scan_id = ?", (scan_id,))
            net_rows = cursor.fetchall()
            networks = []
            for r in net_rows:
                networks.append(NetworkModel(
                    ssid=r["ssid"], bssid=r["bssid"], channel=r["channel"],
                    frequency_mhz=r["frequency_mhz"], band=r["band"],
                    signal_dbm=r["signal_dbm"], signal_percent=r["signal_percent"],
                    encryption=r["encryption"], authentication=r["authentication"]
                ))

            cursor.execute("SELECT * FROM assessments WHERE scan_id = ?", (scan_id,))
            asm_rows = cursor.fetchall()
            assessments = {}
            for r in asm_rows:
                findings_raw = json.loads(r["findings_json"])
                findings = [Finding(**f) for f in findings_raw]
                assessments[r["bssid"]] = SecurityAssessment(
                    bssid=r["bssid"], security_level=r["security_level"],
                    risk_score=r["risk_score"], risk_level=r["risk_level"],
                    findings=findings
                )

            from datetime import datetime
            return ScanSession(
                scan_id=scan_row["scan_id"], interface=scan_row["interface"],
                backend_used=scan_row["backend_used"],
                timestamp=datetime.fromisoformat(scan_row["timestamp"]),
                duration_seconds=scan_row["duration_seconds"],
                networks=networks, assessments=assessments
            )

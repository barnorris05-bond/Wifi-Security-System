import sqlite3, json
from typing import List, Dict, Any
from models.scan import ScanSession

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
                    bssid TEXT PRIMARY KEY,
                    security_level TEXT,
                    risk_score INTEGER,
                    risk_level TEXT,
                    findings_json TEXT
                );
            ''')
            conn.commit()

    def save_session(self, session: ScanSession):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?, ?, ?)",
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
                    INSERT OR REPLACE INTO assessments VALUES (?, ?, ?, ?, ?)
                ''', (bssid, asm.security_level, asm.risk_score, asm.risk_level, findings_str))

            conn.commit()

    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

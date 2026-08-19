import pandas as pd

def generate_csv_report(scan_session) -> str:
    data = []
    for net in scan_session.networks:
        asm = scan_session.assessments.get(net.bssid)
        data.append({
            "Scan ID": scan_session.scan_id,
            "SSID": net.ssid,
            "BSSID": net.bssid,
            "Channel": net.channel,
            "Frequency MHz": net.frequency_mhz,
            "Band": net.band,
            "Signal DBM": net.signal_dbm,
            "Encryption": net.encryption,
            "Authentication": net.authentication,
            "Risk Level": asm.risk_level if asm else "UNKNOWN",
            "Risk Score": asm.risk_score if asm else 0
        })
    return pd.DataFrame(data).to_csv(index=False)

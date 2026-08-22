from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class NetworkChange:
    bssid: str
    ssid: str
    change_type: str
    details: str

class HistoricalAnalyzer:
    @staticmethod
    def compare_scans(previous_networks: List[Dict[str, Any]], current_networks: List[Dict[str, Any]]) -> List[NetworkChange]:
        changes = []
        prev_map = {n['bssid']: n for n in previous_networks}
        curr_map = {n['bssid']: n for n in current_networks}

        for bssid, curr in curr_map.items():
            if bssid not in prev_map:
                changes.append(NetworkChange(bssid, curr['ssid'], "NEW_NETWORK", "Network detected for the first time."))
            else:
                prev = prev_map[bssid]
                if prev.get('encryption') != curr.get('encryption'):
                    changes.append(NetworkChange(
                        bssid, curr['ssid'], "SECURITY_CHANGED", 
                        f"Encryption modified: {prev.get('encryption')} -> {curr.get('encryption')}"
                    ))
                if prev.get('channel') != curr.get('channel'):
                    changes.append(NetworkChange(
                        bssid, curr['ssid'], "CHANNEL_CHANGED", 
                        f"Channel shifted: {prev.get('channel')} -> {curr.get('channel')}"
                    ))

        for bssid, prev in prev_map.items():
            if bssid not in curr_map:
                changes.append(NetworkChange(bssid, prev['ssid'], "REMOVED_NETWORK", "Network no longer within range."))

        return changes

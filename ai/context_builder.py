from typing import Dict, Any, List

class AIContextBuilder:
    @staticmethod
    def build_scan_context(scan_session: Any, networks: List[Any], assessments: List[Any]) -> Dict[str, Any]:
        assessment_map = {a.bssid: a for a in assessments}
        
        context_networks = []
        for net in networks:
            eval_data = assessment_map.get(net.bssid)
            masked_bssid = f"{net.bssid[:8]}:XX:XX:{net.bssid[-2:]}" if len(net.bssid) >= 17 else net.bssid
            
            context_networks.append({
                "ssid": net.ssid,
                "bssid": masked_bssid,
                "band": net.band,
                "channel": net.channel,
                "signal_dbm": net.signal_dbm,
                "encryption": net.encryption,
                "authentication": net.authentication,
                "heuristic_risk_score": eval_data.risk_score if eval_data else 0,
                "risk_level": eval_data.risk_level if eval_data else "UNKNOWN",
                "deterministic_findings": eval_data.findings if eval_data else []
            })

        return {
            "scan_metadata": {
                "total_networks": len(networks),
                "platform": getattr(scan_session, "platform", "Unknown"),
                "backend": getattr(scan_session, "backend", "Unknown")
            },
            "networks": context_networks
        }

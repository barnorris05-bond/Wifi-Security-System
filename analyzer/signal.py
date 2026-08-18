from typing import Dict, List, Any
from models.network import NetworkModel

class SignalAnalyzer:
    @staticmethod
    def summarize(networks: List[NetworkModel]) -> Dict[str, Any]:
        if not networks:
            return {"avg_dbm": None, "distribution": {}}
        valid_signals = [n.signal_dbm for n in networks if n.signal_dbm is not None]
        avg_dbm = sum(valid_signals) / len(valid_signals) if valid_signals else -100

        distribution = {"Excellent (>-50)": 0, "Good (-50 to -67)": 0, "Fair (-68 to -75)": 0, "Weak (<-75)": 0}
        for dbm in valid_signals:
            if dbm > -50:
                distribution["Excellent (>-50)"] += 1
            elif -67 <= dbm <= -50:
                distribution["Good (-50 to -67)"] += 1
            elif -75 <= dbm < -67:
                distribution["Fair (-68 to -75)"] += 1
            else:
                distribution["Weak (<-75)"] += 1

        return {
            "avg_dbm": round(avg_dbm, 1),
            "strongest": max(networks, key=lambda n: n.signal_dbm or -100, default=None),
            "distribution": distribution
        }

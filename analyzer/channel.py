from collections import Counter
from typing import Dict, List, Any
from models.network import NetworkModel

class ChannelAnalyzer:
    @staticmethod
    def analyze_congestion(networks: List[NetworkModel]) -> Dict[str, Any]:
        channel_counts = Counter(n.channel for n in networks if n.channel > 0)
        congestion_levels = {}
        for chan, count in channel_counts.items():
            if count >= 8:
                congestion_levels[chan] = "HIGH"
            elif count >= 4:
                congestion_levels[chan] = "MODERATE"
            else:
                congestion_levels[chan] = "LOW"

        return {
            "channel_counts": dict(channel_counts),
            "congestion_levels": congestion_levels,
            "most_congested": channel_counts.most_common(3)
        }

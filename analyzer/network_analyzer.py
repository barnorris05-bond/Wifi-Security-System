from __future__ import annotations

from collections import Counter
from typing import Iterable, List, Dict, Any

from models.network import NetworkModel


class NetworkAnalyzer:
    """High-level summary helpers for Wi-Fi scan results."""

    @staticmethod
    def summarize(networks: Iterable[NetworkModel]) -> Dict[str, Any]:
        networks = list(networks)
        if not networks:
            return {
                "total_networks": 0,
                "security_mix": {},
                "band_mix": {},
                "strongest_signal_dbm": None,
            }

        sec_counts = Counter(net.encryption for net in networks)
        band_counts = Counter(net.band for net in networks)
        strongest = max(networks, key=lambda n: n.signal_dbm if n.signal_dbm is not None else float("-inf"))

        return {
            "total_networks": len(networks),
            "security_mix": dict(sec_counts),
            "band_mix": dict(band_counts),
            "strongest_signal_dbm": strongest.signal_dbm,
        }
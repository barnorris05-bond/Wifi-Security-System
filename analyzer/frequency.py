from __future__ import annotations

from typing import Optional


class BandResolver:
    """Resolve Wi-Fi frequency bands from either a channel or a frequency value."""

    @staticmethod
    def resolve_band(channel: Optional[int] = None, frequency_mhz: Optional[float] = None) -> str:
        if frequency_mhz is not None:
            if 2400 <= frequency_mhz <= 2500:
                return "2.4 GHz"
            if 4900 <= frequency_mhz <= 5899:
                return "5 GHz"
            if 5900 <= frequency_mhz <= 7115:
                return "6 GHz"
            return "Unknown"

        if channel is None:
            return "Unknown"

        if 1 <= channel <= 14:
            return "2.4 GHz"
        if 36 <= channel <= 177:
            return "5 GHz"
        if 1 <= channel <= 233:
            return "6 GHz"
        return "Unknown"

    @staticmethod
    def resolve_frequency(channel: Optional[int] = None, band: Optional[str] = None) -> float:
        if channel is None:
            return 0.0

        normalized = (band or BandResolver.resolve_band(channel=channel)).upper()
        if "2.4" in normalized:
            return 2407.0 + (channel * 5.0) if channel != 14 else 2484.0
        if "5" in normalized:
            return 5000.0 + (channel * 5.0)
        if "6" in normalized:
            return 5955.0 + ((channel - 1) * 20.0)
        return 0.0


class FrequencyAnalyzer:
    @staticmethod
    def summarize_by_band(networks):
        summary = {"2.4 GHz": 0, "5 GHz": 0, "6 GHz": 0, "Unknown": 0}
        for net in networks:
            band = BandResolver.resolve_band(net.channel, net.frequency_mhz)
            summary.setdefault(band, 0)
            summary[band] += 1
        return summary
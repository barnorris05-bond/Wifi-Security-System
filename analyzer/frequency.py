from dataclasses import dataclass

@dataclass
class BandInfo:
    frequency_mhz: float
    band: str

class FrequencyResolver:
    @staticmethod
    def resolve_from_frequency(freq_mhz: float) -> str:
        if 2400 <= freq_mhz <= 2500:
            return "2.4 GHz"
        elif 4900 <= freq_mhz <= 5899:
            return "5 GHz"
        elif 5925 <= freq_mhz <= 7125:
            return "6 GHz"
        return "Unknown"

    @staticmethod
    def resolve_from_channel(channel: int) -> BandInfo:
        if 1 <= channel <= 14:
            freq = 2407.0 + (channel * 5.0) if channel != 14 else 2484.0
            return BandInfo(freq, "2.4 GHz")
        elif 36 <= channel <= 177:
            freq = 5000.0 + (channel * 5.0)
            return BandInfo(freq, "5 GHz")
        elif 1 <= channel <= 233 and (channel - 1) % 4 == 0:
            freq = 5950.0 + (channel * 5.0)
            return BandInfo(freq, "6 GHz")
        return BandInfo(0.0, "Unknown")

    @classmethod
    def resolve_band(cls, channel: int = 0, frequency_mhz: float = 0.0) -> str:
        if frequency_mhz > 0:
            return cls.resolve_from_frequency(frequency_mhz)
        return cls.resolve_from_channel(channel).band

    @classmethod
    def resolve_frequency(cls, channel: int = 0, band: str = "") -> float:
        return cls.resolve_from_channel(channel).frequency_mhz

# Backward compatibility alias
BandResolver = FrequencyResolver

from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class NetworkModel:
    ssid: str
    bssid: str
    channel: int
    frequency_mhz: float
    band: str
    signal_dbm: Optional[int] = None
    signal_quality_raw: Optional[str] = None
    signal_percent: int = 0
    encryption: str = "UNKNOWN"
    authentication: str = "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()

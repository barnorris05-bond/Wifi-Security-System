from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any
from models.network import NetworkModel
from models.assessment import SecurityAssessment

@dataclass
class ScanSession:
    scan_id: str
    interface: str
    backend_used: str
    timestamp: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0
    networks: List[NetworkModel] = field(default_factory=list)
    assessments: Dict[str, SecurityAssessment] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "interface": self.interface,
            "backend_used": self.backend_used,
            "timestamp": self.timestamp.isoformat(),
            "duration_seconds": self.duration_seconds,
            "network_count": len(self.networks),
            "networks": [net.to_dict() for net in self.networks],
            "assessments": {bssid: asm.to_dict() for bssid, asm in self.assessments.items()}
        }

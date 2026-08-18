from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class Finding:
    severity: str
    title: str
    description: str
    recommendation: str

@dataclass
class SecurityAssessment:
    bssid: str
    security_level: str
    risk_score: int
    risk_level: str
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid,
            "security_level": self.security_level,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "findings": [f.__dict__ for f in self.findings]
        }

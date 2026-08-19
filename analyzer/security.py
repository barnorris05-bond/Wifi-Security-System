"""Security assessment helpers.

The scoring used here is intentionally heuristic and project-specific, not an
industry-standard Wi-Fi security rating. It is intended for teaching/demo use.
"""

from typing import List

from config.risk_rules import AUTHENTICATION_WEIGHTS, ENCRYPTION_WEIGHTS, RISK_LEVEL_THRESHOLDS
from models.assessment import Finding, SecurityAssessment
from models.network import NetworkModel

HEURISTIC_RISK_NOTE = (
    "Risk scores are heuristic project estimates for demonstration and learning, "
    "not formal security certifications or vendor-grade ratings."
)


class SecurityAnalyzer:
    @classmethod
    def analyze(cls, network: NetworkModel) -> SecurityAssessment:
        risk_score = 0
        findings: List[Finding] = []

        enc = network.encryption.upper()
        enc_risk = ENCRYPTION_WEIGHTS.get(enc, ENCRYPTION_WEIGHTS["UNKNOWN"])
        risk_score += enc_risk

        if enc == "OPEN":
            findings.append(Finding("HIGH", "Unencrypted Network", "Communicates without wireless encryption.", "Enable WPA2/WPA3."))
        elif enc == "WEP":
            findings.append(Finding("HIGH", "Legacy WEP Encryption", "Vulnerable to rapid key recovery attacks.", "Upgrade to WPA2/WPA3."))
        elif enc == "WPA":
            findings.append(Finding("MEDIUM", "Deprecated WPA Security", "TKIP cipher is vulnerable to collision attacks.", "Use WPA2-AES or WPA3."))
        elif enc == "WPA2":
            findings.append(Finding("INFO", "Established WPA2 Security", "Provides standard wireless protection.", "Consider modern WPA3 transition."))
        elif enc == "WPA3":
            findings.append(Finding("INFO", "Modern WPA3 Security", "Employs SAE to defeat offline dictionary attacks.", "Maintain firmware updates."))

        auth = network.authentication.upper()
        auth_risk = AUTHENTICATION_WEIGHTS.get(auth, AUTHENTICATION_WEIGHTS["UNKNOWN"])
        risk_score += auth_risk

        if auth == "ENTERPRISE":
            findings.append(Finding("INFO", "802.1X Enterprise Authentication", "Uses centralized identity verification.", "Enforce RADIUS certificate checking."))

        final_risk = max(0, min(100, risk_score))
        assigned_risk_level = "LOW"
        assigned_sec_level = "SECURE"

        for threshold, risk_lvl, sec_lvl in RISK_LEVEL_THRESHOLDS:
            if final_risk >= threshold:
                assigned_risk_level = risk_lvl
                assigned_sec_level = sec_lvl
                break

        return SecurityAssessment(
            bssid=network.bssid, security_level=assigned_sec_level,
            risk_score=final_risk, risk_level=assigned_risk_level, findings=findings
        )

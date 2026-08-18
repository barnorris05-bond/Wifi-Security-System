ENCRYPTION_WEIGHTS = {
    "OPEN": 70,
    "WEP": 65,
    "WPA": 35,
    "WPA2": 15,
    "WPA3": 0,
    "UNKNOWN": 20
}

AUTHENTICATION_WEIGHTS = {
    "NONE": 0,
    "PERSONAL": 0,
    "ENTERPRISE": -10,
    "UNKNOWN": 10
}

RISK_LEVEL_THRESHOLDS = [
    (70, "CRITICAL", "UNSECURED"),
    (40, "HIGH", "WEAK"),
    (15, "MODERATE", "ACCEPTABLE"),
    (0,  "LOW", "SECURE")
]

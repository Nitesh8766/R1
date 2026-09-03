"""
schemas.py
----------
Structured data shapes for the Malware Static Analysis Workbench.

Everything the analysis engine produces is expressed as plain dicts built
from these helpers, so the CLI (--json), the Flask API, and the SQLite
history layer all consume exactly the same shape.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Severity is derived from a finding's weight. This is a presentation-layer
# grouping only -- the underlying weighted score is what actually drives
# the LOW/MEDIUM/HIGH verdict.
# ---------------------------------------------------------------------------
def severity_for_weight(weight: int) -> str:
    if weight >= 8:
        return "critical"
    elif weight >= 5:
        return "high"
    elif weight >= 3:
        return "medium"
    else:
        return "low"


# ---------------------------------------------------------------------------
# Category display names. Internal category keys (used throughout the
# engine, e.g. "process_injection") map to the human-readable labels the
# spec asked for.
# ---------------------------------------------------------------------------
CATEGORY_LABELS = {
    "process_injection": "Process Injection",
    "process_hollowing": "Process Hollowing",
    "memory_manipulation": "Memory Manipulation",
    "persistence": "Persistence",
    "anti_debug": "Anti-Debug",
    "anti_sandbox": "Anti-Sandbox",
    "crypto": "Cryptography API Use",
    "keylogging": "Keylogging Indicators",
    "file_discovery": "File Discovery",
    "network": "Network Activity",
    "network_download": "Network Download",
    "file_write": "File Manipulation",
    "file_manipulation": "File Manipulation",
    "priv_escalation": "Privilege Escalation",
    "termination": "Process Termination",
    "execution": "Execution",
    "packing": "Packing / Obfuscation",
    "structural": "PE Structural Anomaly",
    "signing": "Code Signing",
    "string_indicator": "String-Based Indicator",
    "ransomware": "Ransomware Indicators",
}


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping. Only asserted where there is a direct, defensible
# link between the static indicator and the technique. This is intentionally
# small and conservative -- a mini-project should not overclaim.
# ---------------------------------------------------------------------------
MITRE_MAP = {
    "process_injection": [("T1055", "Process Injection")],
    "process_hollowing": [("T1055.012", "Process Hollowing")],
    "persistence": [("T1547.001", "Registry Run Keys / Startup Folder"),
                     ("T1543.003", "Windows Service")],
    "anti_debug": [("T1622", "Debugger Evasion")],
    "anti_sandbox": [("T1497", "Virtualization/Sandbox Evasion")],
    "keylogging": [("T1056.001", "Keylogging")],
    "network_download": [("T1105", "Ingress Tool Transfer")],
    "network": [("T1071", "Application Layer Protocol")],
    "priv_escalation": [("T1134", "Access Token Manipulation")],
    "execution": [("T1059", "Command and Scripting Interpreter")],
    "packing": [("T1027", "Obfuscated Files or Information")],
    "ransomware": [("T1490", "Inhibit System Recovery"),
                    ("T1486", "Data Encrypted for Impact")],
    "string_indicator_powershell": [("T1059.001", "PowerShell")],
    "string_indicator_shell": [("T1059.003", "Windows Command Shell")],
}


def mitre_for_category(category: str, indicator_key: str = None):
    """Returns MITRE technique tuples for a category, checking a more
    specific indicator_key first (e.g. 'string_indicator_powershell')."""
    if indicator_key and indicator_key in MITRE_MAP:
        return MITRE_MAP[indicator_key]
    return MITRE_MAP.get(category, [])


@dataclass
class Finding:
    id: str
    category: str
    severity: str
    score: int
    indicator: str
    message: str
    explanation: str
    evidence: str
    mitre: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def make_finding(id_, category, weight, indicator, message, explanation, evidence,
                  indicator_key=None):
    return Finding(
        id=id_,
        category=category,
        severity=severity_for_weight(weight),
        score=weight,
        indicator=indicator,
        message=message,
        explanation=explanation,
        evidence=evidence,
        mitre=[{"technique_id": t, "technique_name": n}
               for t, n in mitre_for_category(category, indicator_key)],
    ).to_dict()


# ---------------------------------------------------------------------------
# Risk thresholds -- kept as plain module-level constants so they are easy
# to point to and change in a viva ("thresholds are configurable here").
# ---------------------------------------------------------------------------
RISK_THRESHOLDS = {
    "LOW_MAX": 14,     # 0-14   -> LOW
    "MEDIUM_MAX": 34,  # 15-34  -> MEDIUM
    # 35+ -> HIGH
}

NORMALIZED_SCORE_CAP = 100


def classify_risk(raw_score: int) -> str:
    if raw_score >= RISK_THRESHOLDS["MEDIUM_MAX"] + 1:
        return "HIGH"
    elif raw_score >= RISK_THRESHOLDS["LOW_MAX"] + 1:
        return "MEDIUM"
    return "LOW"


def normalize_score(raw_score: int) -> int:
    return min(raw_score, NORMALIZED_SCORE_CAP)

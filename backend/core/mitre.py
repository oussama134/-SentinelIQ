"""
SentinelIQ — MITRE ATT&CK Mapping
Maps your 15 CICIDS2017 classes → MITRE tactics & techniques
This is what makes your project look enterprise-grade
Reference: https://attack.mitre.org
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class MitreMapping:
    attack_label: str          # Your model's output label
    tactic: str                # MITRE Tactic name
    tactic_id: str             # e.g. "TA0001"
    technique_id: str          # e.g. "T1110"
    technique_name: str        # e.g. "Brute Force"
    sub_technique: Optional[str] = None   # e.g. "T1110.001"
    kill_chain_stage: str = "" # Simplified kill chain stage
    severity_base: str = "MEDIUM"  # Default severity


# ============================================================
# YOUR 15 CICIDS2017 CLASSES → MITRE ATT&CK
# ============================================================
MITRE_MAPPINGS: dict[str, MitreMapping] = {

    "BENIGN": MitreMapping(
        attack_label="BENIGN",
        tactic="None",
        tactic_id="",
        technique_id="",
        technique_name="Normal Traffic",
        kill_chain_stage="None",
        severity_base="LOW"
    ),

    "FTP-Patator": MitreMapping(
        attack_label="FTP-Patator",
        tactic="Credential Access",
        tactic_id="TA0006",
        technique_id="T1110",
        technique_name="Brute Force",
        sub_technique="T1110.001",  # Password Guessing
        kill_chain_stage="Exploitation",
        severity_base="HIGH"
    ),

    "SSH-Patator": MitreMapping(
        attack_label="SSH-Patator",
        tactic="Credential Access",
        tactic_id="TA0006",
        technique_id="T1110",
        technique_name="Brute Force",
        sub_technique="T1110.001",
        kill_chain_stage="Exploitation",
        severity_base="HIGH"
    ),

    "DoS slowloris": MitreMapping(
        attack_label="DoS slowloris",
        tactic="Impact",
        tactic_id="TA0040",
        technique_id="T1499",
        technique_name="Endpoint Denial of Service",
        sub_technique="T1499.001",  # OS Exhaustion Flood
        kill_chain_stage="Actions on Objectives",
        severity_base="HIGH"
    ),

    "DoS Slowhttptest": MitreMapping(
        attack_label="DoS Slowhttptest",
        tactic="Impact",
        tactic_id="TA0040",
        technique_id="T1499",
        technique_name="Endpoint Denial of Service",
        sub_technique="T1499.002",  # Service Exhaustion Flood
        kill_chain_stage="Actions on Objectives",
        severity_base="HIGH"
    ),

    "DoS Hulk": MitreMapping(
        attack_label="DoS Hulk",
        tactic="Impact",
        tactic_id="TA0040",
        technique_id="T1499",
        technique_name="Endpoint Denial of Service",
        sub_technique="T1499.002",
        kill_chain_stage="Actions on Objectives",
        severity_base="CRITICAL"
    ),

    "DoS GoldenEye": MitreMapping(
        attack_label="DoS GoldenEye",
        tactic="Impact",
        tactic_id="TA0040",
        technique_id="T1499",
        technique_name="Endpoint Denial of Service",
        sub_technique="T1499.002",
        kill_chain_stage="Actions on Objectives",
        severity_base="CRITICAL"
    ),

    "Heartbleed": MitreMapping(
        attack_label="Heartbleed",
        tactic="Credential Access",
        tactic_id="TA0006",
        technique_id="T1552",
        technique_name="Unsecured Credentials",
        sub_technique="T1552.004",  # Private Keys
        kill_chain_stage="Exploitation",
        severity_base="CRITICAL"
    ),

    "Web Attack – Brute Force": MitreMapping(
        attack_label="Web Attack – Brute Force",
        tactic="Credential Access",
        tactic_id="TA0006",
        technique_id="T1110",
        technique_name="Brute Force",
        sub_technique="T1110.001",
        kill_chain_stage="Exploitation",
        severity_base="HIGH"
    ),

    "Web Attack – XSS": MitreMapping(
        attack_label="Web Attack – XSS",
        tactic="Initial Access",
        tactic_id="TA0001",
        technique_id="T1189",
        technique_name="Drive-by Compromise",
        kill_chain_stage="Delivery",
        severity_base="MEDIUM"
    ),

    "Web Attack – Sql Injection": MitreMapping(
        attack_label="Web Attack – Sql Injection",
        tactic="Initial Access",
        tactic_id="TA0001",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        kill_chain_stage="Exploitation",
        severity_base="CRITICAL"
    ),

    "Infiltration": MitreMapping(
        attack_label="Infiltration",
        tactic="Lateral Movement",
        tactic_id="TA0008",
        technique_id="T1210",
        technique_name="Exploitation of Remote Services",
        kill_chain_stage="Lateral Movement",
        severity_base="CRITICAL"
    ),

    "Bot": MitreMapping(
        attack_label="Bot",
        tactic="Command and Control",
        tactic_id="TA0011",
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        sub_technique="T1071.001",  # Web Protocols
        kill_chain_stage="Command & Control",
        severity_base="HIGH"
    ),

    "PortScan": MitreMapping(
        attack_label="PortScan",
        tactic="Reconnaissance",
        tactic_id="TA0043",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        kill_chain_stage="Reconnaissance",
        severity_base="MEDIUM"
    ),

    "DDoS": MitreMapping(
        attack_label="DDoS",
        tactic="Impact",
        tactic_id="TA0040",
        technique_id="T1498",
        technique_name="Network Denial of Service",
        sub_technique="T1498.001",  # Direct Network Flood
        kill_chain_stage="Actions on Objectives",
        severity_base="CRITICAL"
    ),
}


def get_mitre_mapping(attack_label: str) -> MitreMapping:
    """
    Get MITRE mapping for a model prediction label.
    Handles minor label variations (case, spacing, dashes).
    """
    # Direct match
    if attack_label in MITRE_MAPPINGS:
        return MITRE_MAPPINGS[attack_label]

    # Fuzzy match — handle label variations from different datasets
    label_lower = attack_label.lower().strip()
    for key, mapping in MITRE_MAPPINGS.items():
        if key.lower().strip() == label_lower:
            return mapping
        # Partial match for DoS variants
        if label_lower in key.lower() or key.lower() in label_lower:
            return mapping

    # Unknown attack — return generic mapping
    return MitreMapping(
        attack_label=attack_label,
        tactic="Unknown",
        tactic_id="",
        technique_id="T0000",
        technique_name="Unknown Technique",
        kill_chain_stage="Unknown",
        severity_base="MEDIUM"
    )


def get_all_tactics() -> list[str]:
    """Return all unique tactics in our mappings"""
    return list(set(
        m.tactic for m in MITRE_MAPPINGS.values()
        if m.tactic != "None"
    ))
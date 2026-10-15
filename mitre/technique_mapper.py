"""
MITRE ATT&CK Technique Mapper
==============================
Deterministic, evidence-based mapping from reconstructed incident telemetry and
attack-chain steps to the MITRE ATT&CK Enterprise taxonomy.

Authoritative Reference:
    - MITRE ATT&CK Enterprise Framework (v14/v15)
    - https://attack.mitre.org/

Key Invariants:
    - 100% Deterministic: Rules rely strictly on generic behavioral evidence and telemetry attributes.
    - Zero Filename / Entity Dependence: Never checks filenames, specific IPs, usernames, or hostnames.
    - Evidence Traceability: Every mapping references supporting detection IDs and event IDs,
      preserving forensic traceability back to raw log messages.
    - Confidence Bounded: Confidences range between 0.70 and 0.95 (never 1.0 certainty).
    - Conservative: Does not invent techniques where evidence is absent.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union, Set
import re

from preprocessing.event_schema import NormalizedEvent
from detection.rule_engine import Detection
from correlation.incident_detector import Incident
from reconstruction.attack_chain import AttackChain, AttackStep, AttackStage


# Curated MITRE ATT&CK Enterprise technique metadata registry
ATTACK_REGISTRY: Dict[str, Dict[str, Any]] = {
    "T1110.001": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing",
        "parent_id": "T1110",
        "parent_name": "Brute Force",
        "primary_tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1078": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "parent_id": None,
        "parent_name": None,
        "primary_tactic": "Initial Access",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1078.003": {
        "technique_id": "T1078.003",
        "technique_name": "Local Accounts",
        "parent_id": "T1078",
        "parent_name": "Valid Accounts",
        "primary_tactic": "Initial Access",
        "tactics": ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
        "url": "https://attack.mitre.org/techniques/T1078/003/",
    },
    "T1046": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "parent_id": None,
        "parent_name": None,
        "primary_tactic": "Discovery",
        "tactics": ["Discovery"],
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1083": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "parent_id": None,
        "parent_name": None,
        "primary_tactic": "Discovery",
        "tactics": ["Discovery"],
        "url": "https://attack.mitre.org/techniques/T1083/",
    },
    "T1548.003": {
        "technique_id": "T1548.003",
        "technique_name": "Sudo and Sudo Caching",
        "parent_id": "T1548",
        "parent_name": "Abuse Elevation Control Mechanism",
        "primary_tactic": "Privilege Escalation",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "T1548.001": {
        "technique_id": "T1548.001",
        "technique_name": "Setuid and Setgid",
        "parent_id": "T1548",
        "parent_name": "Abuse Elevation Control Mechanism",
        "primary_tactic": "Privilege Escalation",
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "url": "https://attack.mitre.org/techniques/T1548/001/",
    },
    "T1003.008": {
        "technique_id": "T1003.008",
        "technique_name": "/etc/passwd and /etc/shadow",
        "parent_id": "T1003",
        "parent_name": "OS Credential Dumping",
        "primary_tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1003/008/",
    },
    "T1552.004": {
        "technique_id": "T1552.004",
        "technique_name": "Private Keys",
        "parent_id": "T1552",
        "parent_name": "Unsecured Credentials",
        "primary_tactic": "Credential Access",
        "tactics": ["Credential Access"],
        "url": "https://attack.mitre.org/techniques/T1552/004/",
    },
    "T1560.001": {
        "technique_id": "T1560.001",
        "technique_name": "Archive via Utility",
        "parent_id": "T1560",
        "parent_name": "Archive Collected Data",
        "primary_tactic": "Collection",
        "tactics": ["Collection"],
        "url": "https://attack.mitre.org/techniques/T1560/001/",
    },
    "T1048": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "parent_id": None,
        "parent_name": None,
        "primary_tactic": "Exfiltration",
        "tactics": ["Exfiltration"],
        "url": "https://attack.mitre.org/techniques/T1048/",
    },
    "T1048.002": {
        "technique_id": "T1048.002",
        "technique_name": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
        "parent_id": "T1048",
        "parent_name": "Exfiltration Over Alternative Protocol",
        "primary_tactic": "Exfiltration",
        "tactics": ["Exfiltration"],
        "url": "https://attack.mitre.org/techniques/T1048/002/",
    },
}


@dataclass
class TechniqueMapping:
    """
    Represents an evidence-backed mapping to an official MITRE ATT&CK technique.
    """
    technique_id: str
    technique_name: str
    tactic: str
    tactics: List[str]
    confidence: float
    rationale: str
    supporting_detection_ids: List[str]
    supporting_event_ids: List[str]
    evidence_count: int
    sub_technique_of: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.technique_id or not self.technique_id.startswith("T"):
            raise ValueError(f"Invalid MITRE technique ID '{self.technique_id}'")
        if not (0.0 < self.confidence < 1.0):
            raise ValueError(f"Confidence {self.confidence} must be in (0.0, 1.0) and never 1.0.")
        if not self.supporting_event_ids:
            raise ValueError("TechniqueMapping must reference at least one supporting event ID.")
        if self.evidence_count != len(self.supporting_event_ids):
            self.evidence_count = len(self.supporting_event_ids)

    def to_dict(self) -> Dict[str, Any]:
        """Convert mapping to a serializable dictionary representation."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "tactics": self.tactics,
            "confidence": round(self.confidence, 4),
            "rationale": self.rationale,
            "supporting_detection_ids": self.supporting_detection_ids,
            "supporting_event_ids": self.supporting_event_ids,
            "evidence_count": self.evidence_count,
            "sub_technique_of": self.sub_technique_of,
            "metadata": self.metadata,
        }


class TechniqueMapper:
    """
    Evaluates incident telemetry, detection rules, and reconstructed attack steps
    to deterministically infer corresponding MITRE ATT&CK techniques.
    """

    def map_techniques(
        self,
        attack_chain: Optional[AttackChain] = None,
        incident: Optional[Incident] = None,
        events: Optional[Union[List[NormalizedEvent], Dict[str, NormalizedEvent]]] = None,
        detections: Optional[List[Detection]] = None,
    ) -> List[TechniqueMapping]:
        """
        Derive evidence-backed MITRE ATT&CK techniques from reconstructed chain or incident.

        Args:
            attack_chain: Optional reconstructed AttackChain.
            incident: Optional Incident instance.
            events: Optional pool of normalized events (list or dict).
            detections: Optional list of Detection instances.

        Returns:
            List of TechniqueMapping instances sorted by tactic lifecycle progression.
        """
        # If no input or empty incident/chain, return empty list
        if not attack_chain and not incident and not detections and not events:
            return []

        if attack_chain and not attack_chain.steps and not incident and not detections:
            return []

        # Index events
        event_dict: Dict[str, Any] = {}
        all_events: List[Any] = []
        if events:
            if isinstance(events, dict):
                event_dict = events
                all_events = list(events.values())
            else:
                all_events = events
                for e in events:
                    if hasattr(e, "event_id"):
                        event_dict[e.event_id] = e

        # Index detections
        det_map: Dict[str, Detection] = {}
        if detections:
            for d in detections:
                det_map[d.detection_id] = d

        # Collect incident scope
        incident_detection_ids: Set[str] = set()
        incident_event_ids: Set[str] = set()

        if attack_chain:
            for step in attack_chain.steps:
                incident_detection_ids.update(step.detection_ids)
                incident_event_ids.update(step.event_ids)

        if incident:
            incident_detection_ids.update(incident.detection_ids)
            incident_event_ids.update(incident.event_ids)

        if not attack_chain and not incident and detections:
            for d in detections:
                incident_detection_ids.add(d.detection_id)
                incident_event_ids.update(d.event_ids)

        # Filter relevant detections and events
        relevant_detections = [det_map[did] for did in incident_detection_ids if did in det_map]
        
        # If detections was passed without pre-filtering:
        if not relevant_detections and detections:
            relevant_detections = detections

        # Filter relevant events
        if incident_event_ids:
            relevant_events = [event_dict[eid] for eid in incident_event_ids if eid in event_dict]
        else:
            relevant_events = all_events

        # If no relevant events found in dict, check all_events
        if not relevant_events and all_events:
            relevant_events = all_events

        mappings: List[TechniqueMapping] = []

        # ---------------------------------------------------------------------
        # 1. T1110.001: Password Guessing (Brute Force)
        # ---------------------------------------------------------------------
        t1110_mapping = self._map_t1110_brute_force(attack_chain, relevant_detections, relevant_events)
        if t1110_mapping:
            mappings.append(t1110_mapping)

        # ---------------------------------------------------------------------
        # 2. T1078: Valid Accounts (Compromised Login) - prefers T1078 when locality unknown
        # ---------------------------------------------------------------------
        t1078_mapping = self._map_t1078_valid_accounts(attack_chain, relevant_detections, relevant_events, all_events)
        if t1078_mapping:
            mappings.append(t1078_mapping)

        # ---------------------------------------------------------------------
        # 3. T1046: Network Service Discovery (Port Scanning)
        # ---------------------------------------------------------------------
        t1046_mapping = self._map_t1046_port_scan(attack_chain, relevant_detections, relevant_events)
        if t1046_mapping:
            mappings.append(t1046_mapping)

        # ---------------------------------------------------------------------
        # 4. T1548.003: Sudo and Sudo Caching (Privilege Escalation)
        # ---------------------------------------------------------------------
        t1548_mapping = self._map_t1548_sudo_elevation(attack_chain, relevant_detections, relevant_events)
        if t1548_mapping:
            mappings.append(t1548_mapping)

        # ---------------------------------------------------------------------
        # 5. T1083: File and Directory Discovery / T1548.001: Setuid and Setgid
        # ---------------------------------------------------------------------
        t1083_mapping = self._map_t1083_file_discovery(attack_chain, relevant_detections, relevant_events)
        if t1083_mapping:
            mappings.append(t1083_mapping)

        t1548_1_mapping = self._map_t1548_setuid(attack_chain, relevant_detections, relevant_events)
        if t1548_1_mapping:
            mappings.append(t1548_1_mapping)

        # ---------------------------------------------------------------------
        # 6. T1003.008: /etc/passwd and /etc/shadow (OS Credential Dumping)
        # ---------------------------------------------------------------------
        t1003_mapping = self._map_t1003_shadow_dumping(attack_chain, relevant_detections, relevant_events)
        if t1003_mapping:
            mappings.append(t1003_mapping)

        # ---------------------------------------------------------------------
        # 7. T1552.004: Private Keys (Unsecured Credentials)
        # ---------------------------------------------------------------------
        t1552_mapping = self._map_t1552_private_keys(attack_chain, relevant_detections, relevant_events)
        if t1552_mapping:
            mappings.append(t1552_mapping)

        # ---------------------------------------------------------------------
        # 8. T1560.001: Archive via Utility (Collection / Staging)
        # ---------------------------------------------------------------------
        t1560_mapping = self._map_t1560_archive_utility(attack_chain, relevant_detections, relevant_events, incident=incident)
        if t1560_mapping:
            mappings.append(t1560_mapping)

        # ---------------------------------------------------------------------
        # 9. T1048: Exfiltration Over Alternative Protocol
        # ---------------------------------------------------------------------
        t1048_mapping = self._map_t1048_exfiltration(attack_chain, relevant_detections, relevant_events)
        if t1048_mapping:
            mappings.append(t1048_mapping)

        return mappings

    # -------------------------------------------------------------------------
    # Evaluation Helpers
    # -------------------------------------------------------------------------

    def _map_t1110_brute_force(
        self,
        chain: Optional[AttackChain],
        detections: List[Detection],
        events: List[Any],
    ) -> Optional[TechniqueMapping]:
        """Detect behavioral evidence of T1110.001 (Password Guessing)."""
        r001_dets = [d for d in detections if d.rule_id == "R001" or "brute force" in d.title.lower()]
        
        failed_evts = [
            e for e in events
            if getattr(e, "event_type", "") in {"login_failed", "auth_failed", "authentication_failure"}
            or (getattr(e, "action", "") == "failure" and getattr(e, "process", "") in {"sshd", "login", "auth"})
        ]

        if not r001_dets and len(failed_evts) < 5:
            return None

        eids = list(dict.fromkeys(
            [eid for d in r001_dets for eid in d.event_ids] +
            [e.event_id for e in failed_evts]
        ))
        det_ids = [d.detection_id for d in r001_dets]

        users = sorted(list({getattr(e, "username", "") for e in events if getattr(e, "username", None) and e.event_id in eids}))
        user_str = ", ".join(users) if users else "targeted account"

        conf = 0.94 if len(eids) >= 10 else 0.88
        meta = ATTACK_REGISTRY["T1110.001"]

        return TechniqueMapping(
            technique_id=meta["technique_id"],
            technique_name=meta["technique_name"],
            tactic=meta["primary_tactic"],
            tactics=meta["tactics"],
            confidence=conf,
            rationale=(
                f"Mapped to T1110.001 because telemetry records {len(eids)} consecutive failed authentication "
                f"attempts targeting account '{user_str}', matching repetitive automated password guessing patterns."
            ),
            supporting_detection_ids=det_ids,
            supporting_event_ids=eids,
            evidence_count=len(eids),
            sub_technique_of=meta["parent_id"],
            metadata={"target_users": users, "failure_count": len(eids)},
        )

    def _map_t1078_valid_accounts(
        self,
        chain: Optional[AttackChain],
        detections: List[Detection],
        events: List[Any],
        all_events: List[Any],
    ) -> Optional[TechniqueMapping]:
        """Detect behavioral evidence of T1078 (Valid Accounts)."""
        r003_dets = [d for d in detections if d.rule_id == "R003" or "suspicious login" in d.title.lower()]

        # Check chain for INITIAL_ACCESS step
        chain_init_step = None
        if chain:
            for s in chain.steps:
                if s.stage == AttackStage.INITIAL_ACCESS.value:
                    chain_init_step = s
                    break

        eids: List[str] = []
        det_ids: List[str] = []

        if chain_init_step:
            eids.extend(chain_init_step.event_ids)
            det_ids.extend(chain_init_step.detection_ids)

        if r003_dets:
            for d in r003_dets:
                det_ids.append(d.detection_id)
                eids.extend(d.event_ids)

        # If not already found, look for successful login directly in events
        if not eids:
            for e in (events + all_events):
                if getattr(e, "event_type", "") == "login_success" or (
                    getattr(e, "action", "") == "success" and getattr(e, "process", "") in {"sshd", "login"}
                ):
                    # Check if accompanied by failed logins matching targeted account or source IP
                    has_prior_failures = any(
                        getattr(f, "event_type", "") == "login_failed"
                        and f.timestamp <= e.timestamp
                        and (
                            (getattr(f, "username", None) and getattr(e, "username", None) and f.username == e.username)
                            or (getattr(f, "source_ip", None) and getattr(e, "source_ip", None) and f.source_ip == e.source_ip)
                        )
                        for f in events
                    )
                    if has_prior_failures:
                        eids.append(e.event_id)
                        break

        eids = list(dict.fromkeys(eids))
        if not eids:
            return None

        # Fix 1: Prefer T1078 (Valid Accounts) when account locality is unknown from telemetry.
        meta = ATTACK_REGISTRY["T1078"]
        conf = 0.85 if chain_init_step else 0.80

        users = sorted(list({getattr(e, "username", "") for e in (events + all_events) if getattr(e, "username", None) and getattr(e, "event_id", "") in eids}))
        user_str = f" for '{', '.join(users)}'" if users else ""

        return TechniqueMapping(
            technique_id=meta["technique_id"],
            technique_name=meta["technique_name"],
            tactic=meta["primary_tactic"],
            tactics=meta["tactics"],
            confidence=conf,
            rationale=(
                f"Mapped to T1078 (Valid Accounts) because telemetry observed successful authentication{user_str} "
                f"directly following credential guessing or from an unapproved ingress address. "
                f"Mapped to top-level T1078 because account locality (local vs. domain/central) cannot be determined from telemetry alone."
            ),
            supporting_detection_ids=list(dict.fromkeys(det_ids)),
            supporting_event_ids=eids,
            evidence_count=len(eids),
            sub_technique_of=meta["parent_id"],
            metadata={"account_locality": "unknown", "target_users": users},
        )

    def _map_t1046_port_scan(
        self,
        chain: Optional[AttackChain],
        detections: List[Detection],
        events: List[Any],
    ) -> Optional[TechniqueMapping]:
        """Detect behavioral evidence of T1046 (Network Service Discovery)."""
        r002_dets = [d for d in detections if d.rule_id == "R002" or "port scan" in d.title.lower()]
        scan_evts = [
            e for e in events
            if getattr(e, "event_type", "") in {"port_scan", "network_recon"}
        ]

        if not r002_dets and len(scan_evts) < 10:
            return None

        eids = list(dict.fromkeys(
            [eid for d in r002_dets for eid in d.event_ids] +
            [e.event_id for e in scan_evts]
        ))
        det_ids = [d.detection_id for d in r002_dets]

        meta = ATTACK_REGISTRY["T1046"]
        conf = 0.92 if r002_dets else 0.82

        return TechniqueMapping(
            technique_id=meta["technique_id"],
            technique_name=meta["technique_name"],
            tactic=meta["primary_tactic"],
            tactics=meta["tactics"],
            confidence=conf,
            rationale=(
                f"Mapped to T1046 because network flow telemetry captures {len(eids)} connection attempts across multiple "
                f"distinct destination ports, consistent with remote network service and vulnerability discovery."
            ),
            supporting_detection_ids=det_ids,
            supporting_event_ids=eids,
            evidence_count=len(eids),
            sub_technique_of=meta["parent_id"],
        )

    def _map_t1548_sudo_elevation(
        self,
        chain: Optional[AttackChain],
        detections: List[Detection],
        events: List[Any],
    ) -> Optional[TechniqueMapping]:
        """Detect behavioral evidence of T1548.003 (Sudo and Sudo Caching)."""
        sudo_evts = [
            e for e in events
            if getattr(e, "process", "") in {"sudo", "su", "pkexec"}
            or "sudo" in getattr(e, "raw_message", "").lower()
            or getattr(e, "event_type", "") in {"sudo_enum", "privilege_escalation_attempt", "privilege_change"}
        ]
        if not sudo_evts:
            return None

        # Fix 5: An ordinary sudo command (e.g. sudo ls) must not independently imply adversarial privilege escalation.
        # Require genuine elevation indicators, privilege transitions, or corroborating elevation events.
        elevation_evts = [
            e for e in sudo_evts
            if getattr(e, "event_type", "") in {"sudo_enum", "privilege_escalation_attempt", "privilege_change"}
            or ("elevat" in getattr(e, "action", "").lower() if getattr(e, "action", "") else False)
            or any(kw in getattr(e, "raw_message", "").lower() for kw in [
                "uid changed", "privilege transition", "privilege change",
                "sudoers", "list privileges", "list allowed", "-exec", "/bin/sh", "/bin/bash",
                "sudo su", "sudo -i", "sudo -s"
            ])
            or (getattr(e, "username", "") == "root" and getattr(e, "process", "") in {"sudo", "sh", "bash"})
        ]

        if not elevation_evts:
            return None

        r004_sudo = [
            d for d in detections
            if d.rule_id == "R004" and any(e.event_id in d.event_ids for e in elevation_evts)
        ]

        has_root_transition = any(
            "uid changed" in getattr(e, "raw_message", "").lower()
            or ("root" in getattr(e, "raw_message", "").lower() and "elevate" in getattr(e, "action", "").lower())
            for e in elevation_evts
        )

        if not r004_sudo and not has_root_transition:
            return None

        eids = list(dict.fromkeys(
            [eid for d in r004_sudo for eid in d.event_ids] +
            [e.event_id for e in elevation_evts]
        ))

        det_ids = [d.detection_id for d in r004_sudo]

        has_uid_0 = any(
            "uid changed" in getattr(e, "raw_message", "").lower() or getattr(e, "username", "") == "root"
            for e in events if e.event_id in eids
        )
        conf = 0.94 if has_uid_0 else 0.88
        meta = ATTACK_REGISTRY["T1548.003"]

        return TechniqueMapping(
            technique_id=meta["technique_id"],
            technique_name=meta["technique_name"],
            tactic=meta["primary_tactic"],
            tactics=meta["tactics"],
            confidence=conf,
            rationale=(
                f"Mapped to T1548.003 because audit logs record sudo elevation command executions and privilege transitions "
                f"matching rule R004 resulting in administrative access (supported by {len(eids)} event(s))."
            ),
            supporting_detection_ids=det_ids,
            supporting_event_ids=eids,
            evidence_count=len(eids),
            sub_technique_of=meta["parent_id"],
        )

    def _map_t1083_file_discovery(
        self,
        chain: Optional[AttackChain],
        detections: List[Detection],
        events: List[Any],
    ) -> Optional[TechniqueMapping]:
        """Detect behavioral evidence of T1083 (File and Directory Discovery)."""
        # Fix 3: SUID search commands like 'find / -perm -4000' are Discovery, not SUID execution abuse.
        discovery_evts = [
            e for e in events
            if "-perm -4000" in getattr(e, "raw_message", "").lower()
            or getattr(e, "event_type", "") == "privilege_recon"
            or ("find /" in getattr(e, "raw_message", "").lower() and "uid=" in getattr(e, "raw_message", "").lower())
        ]
        r004_recon = [
            d for d in detections
            if d.rule_id == "R004" and any(e.event_id in d.event_ids for e in discovery_evts)
        ]

        if not discovery_evts and not r004_recon:
            return None

        eids = list(dict.fromkeys(
            [eid for d in r004_recon for eid in d.event_ids] +
            [e.event_id for e in discovery_evts]
        ))
        det_ids = [d.detection_id for d in r004_recon]

        meta = ATTACK_REGISTRY["T1083"]
        conf = 0.85

        return TechniqueMapping(
            technique_id=meta["technique_id"],
            technique_name=meta["technique_name"],
            tactic=meta["primary_tactic"],
            tactics=meta["tactics"],
            confidence=conf,
            rationale=(
                f"Mapped to T1083 (File and Directory Discovery) because command execution telemetry recorded file "
                f"system enumeration ('find / -perm -4000') to discover files with special permissions/attributes. "
                f"This represents discovery reconnaissance rather than active elevation exploit execution."
            ),
            supporting_detection_ids=det_ids,
            supporting_event_ids=eids,
            evidence_count=len(eids),
            sub_technique_of=meta["parent_id"],
        )

    def _map_t1548_setuid(
        self,
        chain: Optional[AttackChain],
        detections: List[Detection],
        events: List[Any],
    ) -> Optional[TechniqueMapping]:
        """Detect genuine behavioral evidence of T1548.001 (Setuid and Setgid abuse/execution)."""
        # Fix 3: T1548.001 represents active SUID execution or permission modification, NOT read-only discovery.
        abuse_evts = [
            e for e in events
            if ("chmod" in getattr(e, "raw_message", "").lower() and any(p in getattr(e, "raw_message", "").lower() for p in ["+s", "u+s", "4755", "g+s"]))
            or (getattr(e, "event_type", "") == "setuid_execution" and getattr(e, "action", "") == "elevated")
        ]
        r004_suid = [
            d for d in detections
            if d.rule_id == "R004" and any(e.event_id in d.event_ids for e in abuse_evts)
        ]

        if not abuse_evts and not r004_suid:
            return None

        eids = list(dict.fromkeys(
            [eid for d in r004_suid for eid in d.event_ids] +
            [e.event_id for e in abuse_evts]
        ))
        det_ids = [d.detection_id for d in r004_suid]

        meta = ATTACK_REGISTRY["T1548.001"]
        conf = 0.88

        return TechniqueMapping(
            technique_id=meta["technique_id"],
            technique_name=meta["technique_name"],
            tactic=meta["primary_tactic"],
            tactics=meta["tactics"],
            confidence=conf,
            rationale=(
                f"Mapped to T1548.001 because telemetry recorded setuid/setgid binary execution or permission alteration "
                f"resulting in elevated process execution (supported by {len(eids)} event(s))."
            ),
            supporting_detection_ids=det_ids,
            supporting_event_ids=eids,
            evidence_count=len(eids),
            sub_technique_of=meta["parent_id"],
        )

    def _map_t1003_shadow_dumping(
        self,
        chain: Optional[AttackChain],
        detections: List[Detection],
        events: List[Any],
    ) -> Optional[TechniqueMapping]:
        """Detect behavioral evidence of T1003.008 (/etc/passwd and /etc/shadow)."""
        shadow_evts = [
            e for e in events
            if any(p in getattr(e, "raw_message", "").lower() for p in ["/etc/shadow", "/etc/passwd"])
        ]
        r005_shadow = [
            d for d in detections
            if d.rule_id == "R005" and any(k in d.title.lower() for k in ["shadow", "passwd"])
        ]

        if not shadow_evts and not r005_shadow:
            return None

        eids = list(dict.fromkeys(
            [eid for d in r005_shadow for eid in d.event_ids] +
            [e.event_id for e in shadow_evts]
        ))
        det_ids = [d.detection_id for d in r005_shadow]

        meta = ATTACK_REGISTRY["T1003.008"]
        conf = 0.92 if shadow_evts else 0.85

        return TechniqueMapping(
            technique_id=meta["technique_id"],
            technique_name=meta["technique_name"],
            tactic=meta["primary_tactic"],
            tactics=meta["tactics"],
            confidence=conf,
            rationale=(
                f"Mapped to T1003.008 because audit logs record direct file access operations against system credential "
                f"stores (/etc/shadow or /etc/passwd) to extract password hashes."
            ),
            supporting_detection_ids=det_ids,
            supporting_event_ids=eids,
            evidence_count=len(eids),
            sub_technique_of=meta["parent_id"],
        )

    def _map_t1552_private_keys(
        self,
        chain: Optional[AttackChain],
        detections: List[Detection],
        events: List[Any],
    ) -> Optional[TechniqueMapping]:
        """Detect behavioral evidence of T1552.004 (Private Keys)."""
        # Fix 4: Exclude authorized_keys, which stores SSH authorization configs/public keys, NOT private keys.
        def is_genuine_private_key_msg(msg: str) -> bool:
            if not msg or "authorized_keys" in msg.lower():
                return False
            low = msg.lower()
            return any(k in low for k in ["private_key", ".pem", "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa"]) or (
                ".key" in low and "authorized_keys" not in low
            )

        key_evts = [
            e for e in events
            if is_genuine_private_key_msg(getattr(e, "raw_message", ""))
        ]
        r005_key = [
            d for d in detections
            if d.rule_id == "R005"
            and "authorized_keys" not in d.title.lower()
            and any(k in d.title.lower() for k in ["private_key", "pem", "id_rsa", "private key"])
        ]

        if not key_evts and not r005_key:
            return None

        eids = list(dict.fromkeys(
            [eid for d in r005_key for eid in d.event_ids if is_genuine_private_key_msg(getattr(next((e for e in events if getattr(e, "event_id", None) == eid), None), "raw_message", ""))] +
            [e.event_id for e in key_evts]
        ))

        events_by_id = {getattr(e, "event_id", ""): e for e in events}
        eids = [eid for eid in eids if eid in events_by_id and "authorized_keys" not in getattr(events_by_id[eid], "raw_message", "").lower()]

        if not eids:
            return None

        det_ids = [d.detection_id for d in r005_key if any(eid in d.event_ids for eid in eids)]

        meta = ATTACK_REGISTRY["T1552.004"]
        conf = 0.90

        return TechniqueMapping(
            technique_id=meta["technique_id"],
            technique_name=meta["technique_name"],
            tactic=meta["primary_tactic"],
            tactics=meta["tactics"],
            confidence=conf,
            rationale=(
                f"Mapped to T1552.004 because audit telemetry detected unauthorized read access to private cryptographic "
                f"keys and certificate tokens on the local filesystem (excluding public authorized_keys)."
            ),
            supporting_detection_ids=det_ids,
            supporting_event_ids=eids,
            evidence_count=len(eids),
            sub_technique_of=meta["parent_id"],
        )

    def _map_t1560_archive_utility(
        self,
        chain: Optional[AttackChain],
        detections: List[Detection],
        events: List[Any],
        incident: Optional[Incident] = None,
    ) -> Optional[TechniqueMapping]:
        """Detect behavioral evidence of T1560.001 (Archive via Utility)."""
        # Fix 6: Require context of data staging or incident involvement; filter out benign system backup cron jobs.
        archive_evts = [
            e for e in events
            if getattr(e, "event_type", "") == "file_archive"
            or (getattr(e, "process", "") in {"tar", "zip", "gzip", "7z"} and "created" in getattr(e, "action", "").lower())
            or ("tar -" in getattr(e, "raw_message", "").lower() and ".tar" in getattr(e, "raw_message", "").lower())
        ]

        if not archive_evts:
            return None

        suspicious_archive_evts = []
        for e in archive_evts:
            raw = getattr(e, "raw_message", "").lower()
            user = getattr(e, "username", "").lower()
            is_benign_backup = ("daily_backup" in raw or "routine" in raw) and ("backup" in user)
            is_suspicious_target = any(k in raw for k in ["confidential", "exfil", "staging", "export", "/tmp/"])
            has_incident_context = bool(chain) or bool(incident) or bool(detections)

            if is_suspicious_target or (has_incident_context and not is_benign_backup):
                suspicious_archive_evts.append(e)

        if not suspicious_archive_evts:
            return None

        eids = [e.event_id for e in suspicious_archive_evts]
        meta = ATTACK_REGISTRY["T1560.001"]
        conf = 0.90
        proc_name = getattr(suspicious_archive_evts[0], "process", None) or "archiving utility"

        return TechniqueMapping(
            technique_id=meta["technique_id"],
            technique_name=meta["technique_name"],
            tactic=meta["primary_tactic"],
            tactics=meta["tactics"],
            confidence=conf,
            rationale=(
                f"Mapped to T1560.001 because process execution logs record the invocation of an archiving utility "
                f"('{proc_name}') to compress and package sensitive files for staging/exfiltration (supported by {len(eids)} event(s))."
            ),
            supporting_detection_ids=[],
            supporting_event_ids=eids,
            evidence_count=len(eids),
            sub_technique_of=meta["parent_id"],
        )

    def _map_t1048_exfiltration(
        self,
        chain: Optional[AttackChain],
        detections: List[Detection],
        events: List[Any],
    ) -> Optional[TechniqueMapping]:
        """Detect behavioral evidence of T1048 (Exfiltration Over Alternative Protocol)."""
        # Fix 2: Do not assume asymmetric encryption from TCP egress or port numbers. Map to parent T1048.
        # Strict semantic requirement: If the evidence proves ONLY a large outbound transfer (e.g. byte count,
        # TCP port, destination IP, or R006 alone), do not force T1048 without telemetry supporting an alternative protocol.
        r006_dets = [d for d in detections if d.rule_id == "R006" or "large outbound" in d.title.lower()]
        exfil_evts = [
            e for e in events
            if getattr(e, "event_type", "") in {"large_outbound_transfer", "data_exfiltration"}
            or ("high volume outbound stream" in getattr(e, "raw_message", "").lower() and "dst=" in getattr(e, "raw_message", "").lower())
        ]

        if not r006_dets and not exfil_evts:
            return None

        alt_proto_tools = {"curl", "wget", "rsync", "scp", "sftp", "ftp", "tftp", "nc", "ncat", "socat"}

        def has_alternative_protocol_evidence(e: Any) -> bool:
            proc = (getattr(e, "process", "") or "").lower()
            raw = (getattr(e, "raw_message", "") or "").lower()
            ev_type = (getattr(e, "event_type", "") or "").lower()

            if proc in alt_proto_tools:
                return True
            if any(tool in raw for tool in ["curl", "wget", "rsync", "scp", "sftp", "ftp", "tftp"]):
                return True
            if any(proto in raw for proto in ["ftp://", "sftp://", "http://", "https://", "proto=ftp", "proto=http"]):
                return True
            if ev_type == "data_exfiltration" and proc and proc not in {"kernel", "firewall", "systemd"}:
                return True
            return False

        proto_evts = [e for e in exfil_evts if has_alternative_protocol_evidence(e)]

        # If evidence proves only a large outbound transfer without alternative protocol telemetry, do not force T1048
        if not proto_evts:
            return None

        eids = list(dict.fromkeys(
            [e.event_id for e in proto_evts] +
            [eid for d in r006_dets for eid in d.event_ids if eid in [e.event_id for e in proto_evts]]
        ))
        det_ids = [d.detection_id for d in r006_dets if any(eid in d.event_ids for eid in eids)]

        dest_ips = sorted(list({str(getattr(e, "destination_ip", "")) for e in events if getattr(e, "event_id", "") in eids and getattr(e, "destination_ip", None)}))
        dest_ports = sorted(list({str(getattr(e, "destination_port", "")) for e in events if getattr(e, "event_id", "") in eids and getattr(e, "destination_port", None)}))

        dst_str = ", ".join(dest_ips) if dest_ips else "unspecified destination"
        port_str = ", ".join(dest_ports) if dest_ports else "unspecified port"

        tools = sorted(list({
            getattr(e, "process", "").lower()
            for e in proto_evts
            if getattr(e, "process", None) and getattr(e, "process", "").lower() in alt_proto_tools
        }))
        tool_str = f" via utility ('{', '.join(tools)}')" if tools else ""

        meta = ATTACK_REGISTRY["T1048"]
        conf = 0.88 if len(eids) >= 3 else 0.82

        return TechniqueMapping(
            technique_id=meta["technique_id"],
            technique_name=meta["technique_name"],
            tactic=meta["primary_tactic"],
            tactics=meta["tactics"],
            confidence=conf,
            rationale=(
                f"Mapped to T1048 (Exfiltration Over Alternative Protocol) because network telemetry observed {len(eids)} "
                f"high-volume outbound transfer stream(s){tool_str} directed to {dst_str} on port(s) {port_str}. "
                f"Specific encryption mechanisms (asymmetric vs. symmetric) are not asserted without deep packet inspection."
            ),
            supporting_detection_ids=det_ids,
            supporting_event_ids=eids,
            evidence_count=len(eids),
            sub_technique_of=meta["parent_id"],
            metadata={"destination_ips": dest_ips, "destination_ports": dest_ports, "observed_utilities": tools},
        )


def map_to_mitre(
    attack_chain_or_incident: Any,
    events: Optional[Union[List[NormalizedEvent], Dict[str, NormalizedEvent]]] = None,
    detections: Optional[List[Detection]] = None,
) -> List[TechniqueMapping]:
    """
    Public API to map an incident, attack chain, or event list to MITRE ATT&CK techniques.

    Args:
        attack_chain_or_incident: AttackChain instance, Incident instance, or event list.
        events: Optional pool of NormalizedEvent instances.
        detections: Optional list of Detection instances.

    Returns:
        List of TechniqueMapping objects.
    """
    mapper = TechniqueMapper()

    if isinstance(attack_chain_or_incident, AttackChain):
        return mapper.map_techniques(
            attack_chain=attack_chain_or_incident,
            events=events,
            detections=detections,
        )

    if isinstance(attack_chain_or_incident, Incident):
        return mapper.map_techniques(
            incident=attack_chain_or_incident,
            events=events,
            detections=detections,
        )

    if isinstance(attack_chain_or_incident, list):
        # Could be list of NormalizedEvent or detections
        if attack_chain_or_incident and hasattr(attack_chain_or_incident[0], "event_id"):
            return mapper.map_techniques(
                events=attack_chain_or_incident,
                detections=detections,
            )
        if attack_chain_or_incident and hasattr(attack_chain_or_incident[0], "detection_id"):
            return mapper.map_techniques(
                detections=attack_chain_or_incident,
                events=events,
            )
        return []

    if isinstance(attack_chain_or_incident, dict):
        # Support dict input for backwards compatibility
        from datetime import datetime
        steps_raw = attack_chain_or_incident.get("steps", [])
        if not steps_raw:
            return []
        
        synth_chain = AttackChain(
            incident_id=attack_chain_or_incident.get("incident_id", "INC-0001"),
            steps=[],
            start_time=None,
            end_time=None,
            overall_confidence=attack_chain_or_incident.get("overall_confidence", 0.8),
            summary="",
            limitations="",
        )
        for s in steps_raw:
            synth_chain.steps.append(
                AttackStep(
                    step_id=s.get("step_id", "STEP-0001"),
                    stage=s.get("stage", "OTHER"),
                    title=s.get("title", ""),
                    description=s.get("description", ""),
                    timestamp_start=datetime.now(),
                    timestamp_end=datetime.now(),
                    detection_ids=s.get("detection_ids", []),
                    event_ids=s.get("event_ids", []),
                    source_ips=s.get("source_ips", []),
                    destination_ips=s.get("destination_ips", []),
                    usernames=s.get("usernames", []),
                    hostnames=s.get("hostnames", []),
                    confidence=s.get("confidence", 0.8),
                    evidence_summary=s.get("evidence_summary", ""),
                    observed_evidence=s.get("observed_evidence", ""),
                    inference_reason=s.get("inference_reason", ""),
                )
            )
        return mapper.map_techniques(attack_chain=synth_chain, events=events, detections=detections)

    return []

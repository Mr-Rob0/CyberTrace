"""
Root Cause Analysis Module (Preliminary)
=========================================
Analyzes the reconstructed attack chain and associated forensic evidence to formulate
ranked Probable Root Cause Candidates.

Terminology:
    - "probable root cause"
    - "root-cause candidate"
    - NEVER "confirmed root cause" or "absolute ground truth"

Controlled Candidate Types:
    - CREDENTIAL_COMPROMISE: Weak, guessed, or brute-forced account credentials
    - PRIVILEGE_ABUSE: Misuse of elevated execution rights (sudo/root)
    - SUSPICIOUS_REMOTE_ACCESS: Perimeter breach via unusual ingress or external subnet
    - INSIDER_DATA_ACCESS: Abuse of authorized local access to extract sensitive stores
    - MALWARE_EXECUTION: Unauthorized script or binary execution
    - UNKNOWN: Inconclusive or insufficient log telemetry
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from enum import Enum

from reconstruction.attack_chain import AttackChain, AttackStep, AttackStage


class RootCauseType(str, Enum):
    """
    Controlled vocabulary of probable root-cause candidate types.
    """
    CREDENTIAL_COMPROMISE = "CREDENTIAL_COMPROMISE"
    PRIVILEGE_ABUSE = "PRIVILEGE_ABUSE"
    SUSPICIOUS_REMOTE_ACCESS = "SUSPICIOUS_REMOTE_ACCESS"
    INSIDER_DATA_ACCESS = "INSIDER_DATA_ACCESS"
    MALWARE_EXECUTION = "MALWARE_EXECUTION"
    UNKNOWN = "UNKNOWN"

    def __str__(self) -> str:
        return self.value


VALID_ROOT_CAUSE_TYPES = {rc.value for rc in RootCauseType}


@dataclass
class RootCauseCandidate:
    """
    A probable root-cause candidate backed by chronological telemetry evidence.
    """
    candidate_type: str
    title: str
    confidence: float
    evidence_event_ids: List[str]
    reasoning: str
    rank: int = 1
    is_primary: bool = False

    def __post_init__(self):
        if self.candidate_type not in VALID_ROOT_CAUSE_TYPES:
            raise ValueError(f"Invalid root cause type '{self.candidate_type}'. Allowed: {VALID_ROOT_CAUSE_TYPES}")
        if not (0.0 <= self.confidence < 1.0):
            raise ValueError(f"Confidence {self.confidence} must be in [0.0, 1.0) and never 1.0.")
        if self.candidate_type != RootCauseType.UNKNOWN.value and not self.evidence_event_ids:
            raise ValueError("Supported root cause candidate must reference supporting evidence_event_ids.")

    def to_dict(self) -> Dict[str, Any]:
        """Convert candidate to serializable dictionary."""
        return {
            "rank": self.rank,
            "is_primary": self.is_primary,
            "candidate_type": self.candidate_type,
            "title": self.title,
            "confidence": round(self.confidence, 4),
            "evidence_event_ids": self.evidence_event_ids,
            "reasoning": self.reasoning,
        }


class RootCauseAnalyzer:
    """
    Evaluates an AttackChain and underlying evidence to identify and rank
    preliminary probable root-cause candidates.
    """

    def analyze(
        self,
        attack_chain: AttackChain,
        evidence: Optional[List[Any]] = None,
    ) -> List[RootCauseCandidate]:
        """
        Derive ranked probable root-cause candidates for the incident.

        Args:
            attack_chain: The reconstructed AttackChain.
            evidence: Optional underlying normalized events or timeline items.

        Returns:
            List of RootCauseCandidate instances sorted by confidence descending.
        """
        if not attack_chain or not attack_chain.steps:
            return [
                RootCauseCandidate(
                    candidate_type=RootCauseType.UNKNOWN.value,
                    title="Unknown Root Cause (Insufficient Telemetry Evidence)",
                    confidence=0.15,
                    evidence_event_ids=[],
                    reasoning="Log evidence is insufficient or empty; no attack stages could be verified to establish an entry point.",
                    rank=1,
                    is_primary=True,
                )
            ]

        candidates: List[RootCauseCandidate] = []
        stages_present = {s.stage: s for s in attack_chain.steps}

        # 1. Evaluate CREDENTIAL_COMPROMISE candidate
        cred_step = stages_present.get(AttackStage.CREDENTIAL_ACCESS.value)
        init_step = stages_present.get(AttackStage.INITIAL_ACCESS.value)
        priv_step = stages_present.get(AttackStage.PRIVILEGE_ESCALATION.value)

        if cred_step and (init_step or priv_step):
            # Strong indication of brute force leading to unauthorized access
            ev_ids = list(dict.fromkeys(cred_step.event_ids + (init_step.event_ids if init_step else [])))
            user_target = ", ".join(cred_step.usernames) or "account"
            src_ip = ", ".join(cred_step.source_ips) or "attacker IP"

            conf = 0.93 if len(cred_step.event_ids) >= 10 else 0.88
            candidates.append(
                RootCauseCandidate(
                    candidate_type=RootCauseType.CREDENTIAL_COMPROMISE.value,
                    title="Compromised Administrative Credentials via Authentication Brute Force",
                    confidence=conf,
                    evidence_event_ids=ev_ids,
                    reasoning=(
                        f"Repeated authentication failures ({len(cred_step.event_ids)} failed attempts) "
                        f"targeting account '{user_target}' from {src_ip} immediately preceding successful access "
                        f"and administrative elevation strongly points to credential compromise as the root entry point."
                    ),
                )
            )

        # 2. Evaluate SUSPICIOUS_REMOTE_ACCESS candidate
        if init_step:
            src_ip = ", ".join(init_step.source_ips) or "remote network"
            conf = 0.86 if not cred_step else 0.82
            candidates.append(
                RootCauseCandidate(
                    candidate_type=RootCauseType.SUSPICIOUS_REMOTE_ACCESS.value,
                    title="Unauthorized Remote Access / Ingress via Untrusted Subnet",
                    confidence=conf,
                    evidence_event_ids=init_step.event_ids,
                    reasoning=(
                        f"Successful perimeter ingress was established from {src_ip}. In the absence of multi-factor "
                        f"validation or strict ingress filtering, this allowed initial interactive access to internal hosts."
                    ),
                )
            )

        # 3. Evaluate PRIVILEGE_ABUSE candidate
        if priv_step:
            hosts = ", ".join(priv_step.hostnames) or "system"
            users = ", ".join(priv_step.usernames) or "compromised account"
            candidates.append(
                RootCauseCandidate(
                    candidate_type=RootCauseType.PRIVILEGE_ABUSE.value,
                    title="Privilege Escalation and Sudo Delegation Abuse",
                    confidence=0.84,
                    evidence_event_ids=priv_step.event_ids,
                    reasoning=(
                        f"Permissive local sudo delegation or misconfigured elevation controls permitted "
                        f"account '{users}' on {hosts} to elevate execution privileges to UID 0 (root)."
                    ),
                )
            )

        # 4. Fallback if no specific candidate emerged
        if not candidates:
            # Check if any step has events
            all_eids = [eid for s in attack_chain.steps for eid in s.event_ids]
            if all_eids:
                candidates.append(
                    RootCauseCandidate(
                        candidate_type=RootCauseType.UNKNOWN.value,
                        title="Indeterminate Incident Vector",
                        confidence=0.45,
                        evidence_event_ids=all_eids[:5],
                        reasoning="Observed activity indicates suspicious progression, but specific initial penetration vector remains unverified.",
                    )
                )
            else:
                candidates.append(
                    RootCauseCandidate(
                        candidate_type=RootCauseType.UNKNOWN.value,
                        title="Unknown Root Cause (Insufficient Evidence)",
                        confidence=0.10,
                        evidence_event_ids=[],
                        reasoning="Insufficient telemetry to identify a probable root cause candidate.",
                    )
                )

        # Deterministic ranking by confidence descending
        candidates.sort(key=lambda c: c.confidence, reverse=True)

        # Assign rank and is_primary
        for idx, cand in enumerate(candidates, start=1):
            cand.rank = idx
            cand.is_primary = (idx == 1)

        return candidates


def identify_root_cause(
    attack_chain: Union[AttackChain, dict],
    evidence: Optional[list] = None,
) -> Union[List[RootCauseCandidate], dict]:
    """
    Public entry point for preliminary root cause analysis.

    Args:
        attack_chain: AttackChain instance or serialized dict.
        evidence: Optional list of supporting evidence items.

    Returns:
        List of RootCauseCandidate instances.
    """
    analyzer = RootCauseAnalyzer()

    # Handle dictionary representation
    if isinstance(attack_chain, dict):
        steps_raw = attack_chain.get("steps", [])
        if not steps_raw:
            return [
                RootCauseCandidate(
                    candidate_type=RootCauseType.UNKNOWN.value,
                    title="Unknown Root Cause (Insufficient Telemetry Evidence)",
                    confidence=0.15,
                    evidence_event_ids=[],
                    reasoning="Dictionary representation contained no attack steps.",
                    rank=1,
                    is_primary=True,
                )
            ]

        # Convert dict steps to lightweight AttackStep instances for analysis
        from datetime import datetime
        dummy_steps: List[AttackStep] = []
        for s in steps_raw:
            dummy_steps.append(
                AttackStep(
                    step_id=s.get("step_id", "STEP-0001"),
                    stage=s.get("stage", "OTHER"),
                    title=s.get("title", ""),
                    description=s.get("description", ""),
                    timestamp_start=datetime.fromisoformat(s["timestamp_start"]) if "timestamp_start" in s else datetime.now(),
                    timestamp_end=datetime.fromisoformat(s["timestamp_end"]) if "timestamp_end" in s else datetime.now(),
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

        synth_chain = AttackChain(
            incident_id=attack_chain.get("incident_id", "INC-0001"),
            steps=dummy_steps,
            start_time=dummy_steps[0].timestamp_start if dummy_steps else None,
            end_time=dummy_steps[-1].timestamp_end if dummy_steps else None,
            overall_confidence=attack_chain.get("overall_confidence", 0.8),
            summary=attack_chain.get("summary", ""),
            limitations="Dictionary wrapper",
        )
        return analyzer.analyze(synth_chain, evidence)

    if isinstance(attack_chain, AttackChain):
        return analyzer.analyze(attack_chain, evidence)

    raise TypeError(f"Unsupported attack_chain type: {type(attack_chain)}")

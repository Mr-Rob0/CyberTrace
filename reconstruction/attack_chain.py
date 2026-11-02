"""
Attack Chain Module
===================
Reconstructs an evidence-backed chronological sequence of probable attack stages
from correlated incident evidence.

Distinguishes strictly between:
    - OBSERVED: What was actually recorded in telemetry (event IDs, counts, IPs, users)
    - INFERRED: Probable attack stage and behavioral interpretation

Traceability:
    AttackStep -> Detection IDs -> Event IDs -> Normalized Events -> raw_message

Controlled Stages:
    CREDENTIAL_ACCESS, INITIAL_ACCESS, PRIVILEGE_ESCALATION, DISCOVERY,
    COLLECTION, EXFILTRATION, EXECUTION, PERSISTENCE, LATERAL_MOVEMENT, OTHER
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional, Union, Set

from preprocessing.event_schema import NormalizedEvent
from detection.rule_engine import Detection
from correlation.incident_detector import Incident
from correlation.timeline_builder import TimelineItem


class AttackStage(str, Enum):
    """
    Controlled vocabulary of attack stages supported by evidence inference.
    """
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DISCOVERY = "DISCOVERY"
    COLLECTION = "COLLECTION"
    EXFILTRATION = "EXFILTRATION"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    OTHER = "OTHER"

    def __str__(self) -> str:
        return self.value


VALID_ATTACK_STAGES = {stage.value for stage in AttackStage}


@dataclass
class AttackStep:
    """
    A single evidence-backed step within an reconstructed attack chain.

    Attributes:
        step_id: Unique sequential identifier (e.g., 'STEP-0001').
        stage: Controlled AttackStage string value.
        title: Human-readable stage summary title.
        description: High-level overview of the activity in this stage.
        timestamp_start: Earliest timestamp among supporting evidence events.
        timestamp_end: Latest timestamp among supporting evidence events.
        detection_ids: IDs of detection rules directly corroborating this stage.
        event_ids: IDs of raw evidence log events underpinning this stage.
        source_ips: Originating IP addresses observed in this stage.
        destination_ips: Target IP addresses observed in this stage.
        usernames: User accounts associated with this stage.
        hostnames: Systems or hosts targeted in this stage.
        confidence: Deterministic evidence-support score (0.0 < confidence < 1.0; never 1.0).
        evidence_summary: Narrative summarizing the evidence supporting this stage.
        observed_evidence: Objective facts observed in the log records.
        inference_reason: Logical justification for inferring this attack stage.
    """
    step_id: str
    stage: str
    title: str
    description: str
    timestamp_start: datetime
    timestamp_end: datetime
    detection_ids: List[str]
    event_ids: List[str]
    source_ips: List[str]
    destination_ips: List[str]
    usernames: List[str]
    hostnames: List[str]
    confidence: float
    evidence_summary: str
    observed_evidence: str
    inference_reason: str
    observed_behavior: str = ""
    inferred_technique: str = ""
    dataset_label: str = "Unlabelled (none)"

    def __post_init__(self):
        if not self.step_id:
            raise ValueError("step_id cannot be empty")
        if self.stage not in VALID_ATTACK_STAGES:
            raise ValueError(f"Invalid attack stage '{self.stage}'. Allowed: {VALID_ATTACK_STAGES}")
        if not (0.0 < self.confidence < 1.0):
            raise ValueError(f"Confidence {self.confidence} must be strictly between 0.0 and 1.0 (exclusive). Never 1.0.")
        if not self.event_ids:
            raise ValueError("AttackStep must be backed by at least one event_id")
        if self.timestamp_start > self.timestamp_end:
            raise ValueError("timestamp_start cannot be after timestamp_end")

        # Populate new triad fields with backward-compatible defaults if empty
        if not self.observed_behavior:
            self.observed_behavior = self.observed_evidence
        if not self.inferred_technique:
            self.inferred_technique = self.inference_reason

    def to_dict(self) -> Dict[str, Any]:
        """Convert attack step to serializable dictionary."""
        return {
            "step_id": self.step_id,
            "stage": self.stage,
            "title": self.title,
            "description": self.description,
            "timestamp_start": self.timestamp_start.isoformat(),
            "timestamp_end": self.timestamp_end.isoformat(),
            "detection_ids": self.detection_ids,
            "event_ids": self.event_ids,
            "source_ips": self.source_ips,
            "destination_ips": self.destination_ips,
            "usernames": self.usernames,
            "hostnames": self.hostnames,
            "confidence": round(self.confidence, 4),
            "evidence_summary": self.evidence_summary,
            "observed_evidence": self.observed_evidence,
            "inference_reason": self.inference_reason,
            "observed_behavior": self.observed_behavior,
            "inferred_technique": self.inferred_technique,
            "dataset_label": self.dataset_label,
        }


@dataclass
class AttackChain:
    """
    Structured attack chain representing the reconstructed progression of an incident.
    """
    incident_id: str
    steps: List[AttackStep]
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    overall_confidence: float
    summary: str
    limitations: str

    def __post_init__(self):
        if not self.incident_id:
            raise ValueError("incident_id cannot be empty")
        if not (0.0 <= self.overall_confidence < 1.0):
            raise ValueError(f"overall_confidence {self.overall_confidence} must be in [0.0, 1.0) and never 1.0.")

    def to_dict(self) -> Dict[str, Any]:
        """Convert attack chain to serializable dictionary."""
        return {
            "incident_id": self.incident_id,
            "steps": [s.to_dict() for s in self.steps],
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "overall_confidence": round(self.overall_confidence, 4),
            "summary": self.summary,
            "limitations": self.limitations,
        }


DEFAULT_RECONSTRUCTION_LIMITATIONS = (
    "Attack reconstruction is based solely on available synthetic log telemetry and represents "
    "probable evidence-backed inference rather than ground-truth certainty. Gaps in logging, "
    "unmonitored network segments, or unlogged attacker activity may omit intermediate stages."
)


class AttackChainReconstructor:
    """
    Infers probable attack stages from incident evidence and builds a chronologically
    ordered AttackChain.

    Evidence-based Deterministic Stage Inference:
        - CREDENTIAL_ACCESS: Repeated failed logins, brute force patterns.
        - INITIAL_ACCESS: Successful login directly following authentication bursts or untrusted ingress.
        - PRIVILEGE_ESCALATION: Sudo execution, privilege transitions to root.
        - DISCOVERY: Reconnaissance, enumeration, port scanning.
        - COLLECTION: Access to sensitive system secrets, keys, or data archive commands.
        - EXFILTRATION: High-volume outbound network flow streams to remote IPs.
    """

    def reconstruct(
        self,
        incident: Incident,
        events: Optional[Union[List[NormalizedEvent], Dict[str, NormalizedEvent], List[TimelineItem]]] = None,
        detections: Optional[List[Detection]] = None,
    ) -> AttackChain:
        """
        Reconstruct the probable attack chain for an incident.

        Args:
            incident: Correlated Incident instance.
            events: Pool of normalized events or timeline items (list or dict).
            detections: List of Detection instances.

        Returns:
            AttackChain with chronologically sorted, evidence-backed steps.
        """
        if not incident or not incident.incident_id or not incident.event_ids:
            return AttackChain(
                incident_id=incident.incident_id if incident else "INC-UNKNOWN",
                steps=[],
                start_time=None,
                end_time=None,
                overall_confidence=0.0,
                summary="Empty incident: no evidence available for reconstruction.",
                limitations=DEFAULT_RECONSTRUCTION_LIMITATIONS,
            )

        # Normalize events into lookup dictionary
        event_dict: Dict[str, Any] = {}
        all_event_list: List[Any] = []
        if events:
            if isinstance(events, dict):
                event_dict = events
                all_event_list = list(events.values())
            else:
                all_event_list = events
                for e in events:
                    if hasattr(e, "event_id"):
                        event_dict[e.event_id] = e

        # Normalize detections into lookup dictionary
        det_map: Dict[str, Detection] = {}
        if detections:
            for d in detections:
                det_map[d.detection_id] = d

        # Filter detections associated with this incident
        incident_detections = [det_map[did] for did in incident.detection_ids if did in det_map]

        # Gather all evidence events known for this incident
        incident_events: List[Any] = []
        for eid in incident.event_ids:
            if eid in event_dict:
                incident_events.append(event_dict[eid])

        # Infer stages from evidence
        candidate_steps: List[AttackStep] = []

        # 1. Infer CREDENTIAL_ACCESS
        cred_step = self._infer_credential_access(incident, incident_events, incident_detections)
        if cred_step:
            candidate_steps.append(cred_step)

        # 2. Infer INITIAL_ACCESS
        init_step = self._infer_initial_access(incident, incident_events, incident_detections, all_event_list)
        if init_step:
            candidate_steps.append(init_step)

        # 3. Infer PRIVILEGE_ESCALATION
        priv_step = self._infer_privilege_escalation(incident, incident_events, incident_detections)
        if priv_step:
            candidate_steps.append(priv_step)

        # 4. Infer DISCOVERY
        disc_step = self._infer_discovery(incident, incident_events, incident_detections)
        if disc_step:
            candidate_steps.append(disc_step)

        # 5. Infer COLLECTION
        coll_step = self._infer_collection(incident, incident_events, incident_detections)
        if coll_step:
            candidate_steps.append(coll_step)

        # 6. Infer EXFILTRATION
        exfil_step = self._infer_exfiltration(incident, incident_events, incident_detections)
        if exfil_step:
            candidate_steps.append(exfil_step)

        # Sort candidate steps strictly by chronological evidence start time
        candidate_steps.sort(key=lambda s: s.timestamp_start)

        # Re-assign sequential step IDs (STEP-0001, STEP-0002, ...)
        assigned_steps: List[AttackStep] = []
        for idx, step in enumerate(candidate_steps, start=1):
            assigned_steps.append(
                AttackStep(
                    step_id=f"STEP-{idx:04d}",
                    stage=step.stage,
                    title=step.title,
                    description=step.description,
                    timestamp_start=step.timestamp_start,
                    timestamp_end=step.timestamp_end,
                    detection_ids=step.detection_ids,
                    event_ids=step.event_ids,
                    source_ips=step.source_ips,
                    destination_ips=step.destination_ips,
                    usernames=step.usernames,
                    hostnames=step.hostnames,
                    confidence=step.confidence,
                    evidence_summary=step.evidence_summary,
                    observed_evidence=step.observed_evidence,
                    inference_reason=step.inference_reason,
                    observed_behavior=step.observed_behavior,
                    inferred_technique=step.inferred_technique,
                    dataset_label=step.dataset_label,
                )
            )

        if not assigned_steps:
            return AttackChain(
                incident_id=incident.incident_id,
                steps=[],
                start_time=incident.start_time,
                end_time=incident.end_time,
                overall_confidence=0.0,
                summary=f"Incident {incident.incident_id} contains no verifiable attack stages.",
                limitations=DEFAULT_RECONSTRUCTION_LIMITATIONS,
            )

        # Calculate overall confidence
        overall_conf = self._calculate_overall_confidence(assigned_steps, incident)
        chain_start = min(s.timestamp_start for s in assigned_steps)
        chain_end = max(s.timestamp_end for s in assigned_steps)
        stage_names = " -> ".join(s.stage for s in assigned_steps)
        if len(assigned_steps) == 1:
            summary = (
                f"Reconstructed single-stage activity ({stage_names}) "
                f"spanning {len(set(eid for s in assigned_steps for eid in s.event_ids))} distinct evidence events "
                f"with evidence support score of {overall_conf:.2f}. "
                f"No subsequent intrusion progression observed."
            )
        else:
            summary = (
                f"Reconstructed {len(assigned_steps)}-stage attack chain ({stage_names}) "
                f"spanning {len(set(eid for s in assigned_steps for eid in s.event_ids))} distinct evidence events "
                f"with overall confidence of {overall_conf:.2f}."
            )

        limitations = (
            "Attack reconstruction represents evidence-backed behavioral inference rather than "
            "ground-truth certainty. Unlabelled dataset records (e.g. mitre_attack_tactics = none) "
            "indicate observed network behavior that has not been confirmed as malicious by ground-truth labels. "
            "Single-stage reconnaissance does not establish host compromise or data impact without corroborating telemetry."
        )

        return AttackChain(
            incident_id=incident.incident_id,
            steps=assigned_steps,
            start_time=chain_start,
            end_time=chain_end,
            overall_confidence=overall_conf,
            summary=summary,
            limitations=limitations,
        )

    # -------------------------------------------------------------------------
    # Inference Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _extract_dataset_label(ev_objs: List[Any]) -> str:
        """
        Extract ground-truth tactic or label if recorded in underlying telemetry raw messages.
        Distinguishes explicitly between:
            - Unlabelled (none)
            - Ground truth labeled (e.g. Reconnaissance)
            - Missing ground truth column
        """
        if not ev_objs:
            return "Unlabelled in dataset (none)"

        tactics: Set[str] = set()
        has_tactic_field = False
        import re

        for e in ev_objs:
            raw = getattr(e, "raw_message", "")
            if not raw:
                continue
            m = re.search(r"(?:mitre_attack_tactics|tactics|attack_tactic|label)=([^\s]+)", raw, re.IGNORECASE)
            if m:
                has_tactic_field = True
                val = m.group(1).strip()
                if val and val.lower() not in {"none", "null", "nan"}:
                    tactics.add(val)

        if tactics:
            return f"Labelled in dataset ({', '.join(sorted(tactics))})"
        elif has_tactic_field:
            return "Unlabelled in dataset (mitre_attack_tactics: none)"
        else:
            return "Unlabelled (no ground-truth column in dataset)"

    def _infer_credential_access(
        self,
        incident: Incident,
        incident_events: List[Any],
        detections: List[Detection],
    ) -> Optional[AttackStep]:
        """Infer CREDENTIAL_ACCESS if repeated failed logins or authentication attacks are observed."""
        matching_dets = [d for d in detections if d.rule_id == "R001" or "brute force" in d.title.lower()]
        
        # Check matching events in incident
        failed_events = [
            e for e in incident_events
            if getattr(e, "event_type", "") in {"login_failed", "auth_failed", "authentication_failure"}
            or (getattr(e, "action", "") == "failure" and getattr(e, "process", "") in {"sshd", "login", "auth"})
        ]

        if not matching_dets and len(failed_events) < 3:
            return None

        # Collect event IDs and details
        eids: List[str] = []
        for d in matching_dets:
            eids.extend(d.event_ids)
        for e in failed_events:
            if e.event_id not in eids:
                eids.append(e.event_id)

        # Must preserve only event IDs that are part of the incident evidence
        eids = [eid for eid in eids if eid in incident.event_ids]
        if not eids:
            return None

        # Filter events for timestamps & entities
        ev_objs = [e for e in incident_events if e.event_id in eids]
        if ev_objs:
            t_start = min(e.timestamp for e in ev_objs)
            t_end = max(e.timestamp for e in ev_objs)
            src_ips = sorted(list({e.source_ip for e in ev_objs if getattr(e, "source_ip", None)}))
            dst_ips = sorted(list({e.destination_ip for e in ev_objs if getattr(e, "destination_ip", None)}))
            users = sorted(list({e.username for e in ev_objs if getattr(e, "username", None)}))
            hosts = sorted(list({e.hostname for e in ev_objs if getattr(e, "hostname", None)}))
        else:
            t_start = incident.start_time
            t_end = incident.end_time
            src_ips = incident.source_ips
            dst_ips = incident.destination_ips
            users = incident.usernames
            hosts = incident.hostnames

        # Confidence deterministic calculation
        # Strong direct detection + multiple failed attempts
        if len(eids) >= 10:
            confidence = 0.95
        elif len(eids) >= 5 or matching_dets:
            confidence = 0.90
        else:
            confidence = 0.75

        user_str = ", ".join(users) if users else "unknown user"
        src_str = ", ".join(src_ips) if src_ips else "external source"
        det_ids = [d.detection_id for d in matching_dets]
        label_desc = self._extract_dataset_label(ev_objs)

        observed_behavior = (
            f"Observed {len(eids)} failed authentication attempt(s) targeting account '{user_str}' "
            f"originating from {src_str}."
        )
        inferred_technique = (
            "T1110 - Brute Force (Credential Access). Repeated authentication failures "
            "indicative of automated password guessing or credential abuse."
        )

        return AttackStep(
            step_id="STEP-PENDING",
            stage=AttackStage.CREDENTIAL_ACCESS.value,
            title="Credential Access Activity (Authentication Failures / Brute Force)",
            description=f"Automated credential guessing attempts against account '{user_str}' from {src_str}.",
            timestamp_start=t_start,
            timestamp_end=t_end,
            detection_ids=det_ids,
            event_ids=eids,
            source_ips=src_ips,
            destination_ips=dst_ips,
            usernames=users,
            hostnames=hosts,
            confidence=confidence,
            evidence_summary=(
                f"Observed {len(eids)} failed login attempt(s) for user '{user_str}' "
                f"originating from {src_str}. Supported by detection(s): {', '.join(det_ids) or 'direct log evidence'}."
            ),
            observed_evidence=f"{len(eids)} failed authentication events recorded targeting '{user_str}' from {src_str}.",
            inference_reason=(
                "A dense burst of failed login attempts targeting an administrative or system account "
                "is consistent with credential brute-force or dictionary attack behavior."
            ),
            observed_behavior=observed_behavior,
            inferred_technique=inferred_technique,
            dataset_label=label_desc,
        )

    def _infer_initial_access(
        self,
        incident: Incident,
        incident_events: List[Any],
        detections: List[Detection],
        all_events: List[Any],
    ) -> Optional[AttackStep]:
        """
        Infer INITIAL_ACCESS if there is strong evidence of:
            - Detection R003 (Suspicious login from unusual/external network)
            - Successful login following credential brute-force for the same entity/host
        """
        matching_dets = [d for d in detections if d.rule_id == "R003" or "suspicious login" in d.title.lower()]
        
        # Check for R003 first
        if matching_dets:
            eids = [eid for d in matching_dets for eid in d.event_ids if eid in incident.event_ids]
            if eids:
                ev_objs = [e for e in incident_events if e.event_id in eids]
                t_start = min(e.timestamp for e in ev_objs) if ev_objs else incident.start_time
                t_end = max(e.timestamp for e in ev_objs) if ev_objs else incident.end_time
                src_ips = sorted(list({e.source_ip for e in ev_objs if getattr(e, "source_ip", None)})) or incident.source_ips
                dst_ips = sorted(list({e.destination_ip for e in ev_objs if getattr(e, "destination_ip", None)})) or incident.destination_ips
                users = sorted(list({e.username for e in ev_objs if getattr(e, "username", None)})) or incident.usernames
                hosts = sorted(list({e.hostname for e in ev_objs if getattr(e, "hostname", None)})) or incident.hostnames

                user_str = ", ".join(users) if users else "account"
                src_str = ", ".join(src_ips) if src_ips else "remote source"
                det_ids = [d.detection_id for d in matching_dets]
                label_desc = self._extract_dataset_label(ev_objs)

                observed_behavior = (
                    f"Observed interactive authentication session established for user '{user_str}' "
                    f"from external IP {src_str}."
                )
                inferred_technique = (
                    "T1078 - Valid Accounts (Initial Access). Remote login originating from untrusted "
                    "or anomalous network address."
                )

                return AttackStep(
                    step_id="STEP-PENDING",
                    stage=AttackStage.INITIAL_ACCESS.value,
                    title="Perimeter Access via Unusual / External Remote Connection",
                    description=f"Suspicious successful login to host for user '{user_str}' from {src_str}.",
                    timestamp_start=t_start,
                    timestamp_end=t_end,
                    detection_ids=det_ids,
                    event_ids=eids,
                    source_ips=src_ips,
                    destination_ips=dst_ips,
                    usernames=users,
                    hostnames=hosts,
                    confidence=0.90,
                    evidence_summary=(
                        f"Observed unauthorized remote ingress from external subnet {src_str} "
                        f"for user '{user_str}'. Corroborated by detection(s): {', '.join(det_ids)}."
                    ),
                    observed_evidence=f"Successful remote login event(s) from external/unusual network {src_str}.",
                    inference_reason=(
                        "Direct interactive authentication from an unapproved or anomalous network address "
                        "represents perimeter breach and initial entry into the environment."
                    ),
                    observed_behavior=observed_behavior,
                    inferred_technique=inferred_technique,
                    dataset_label=label_desc,
                )

        # Check for successful login following credential attack
        # Prioritize successful logins that are part of the correlated incident evidence
        candidate_success_events = [
            e for e in incident_events
            if getattr(e, "event_type", "") in {"login_success", "session_opened"}
            or (getattr(e, "action", "") == "success" and getattr(e, "process", "") in {"sshd", "login"})
        ]
        if not candidate_success_events and all_events:
            # Fallback: check all_events only within the strict incident time window and attacker entity
            candidate_success_events = [
                e for e in all_events
                if getattr(e, "event_type", "") in {"login_success", "session_opened"}
                or (getattr(e, "action", "") == "success" and getattr(e, "process", "") in {"sshd", "login"})
            ]

        # Check if any success event aligns with incident attacker IP / username
        target_success = None
        for s_evt in candidate_success_events:
            s_ip = getattr(s_evt, "source_ip", "")
            s_user = getattr(s_evt, "username", "")
            if (s_ip in incident.source_ips or s_user in incident.usernames) and incident.start_time <= s_evt.timestamp <= incident.end_time:
                target_success = s_evt
                break

        if target_success:
            # We identified a compromised login session succeeding the brute force
            eids = [target_success.event_id]
            # Ensure the event_id is registered in incident event_ids for forensic consistency
            if target_success.event_id not in incident.event_ids:
                incident.event_ids.append(target_success.event_id)

            src_ips = [target_success.source_ip] if getattr(target_success, "source_ip", None) else incident.source_ips
            dst_ips = [target_success.destination_ip] if getattr(target_success, "destination_ip", None) else incident.destination_ips
            users = [target_success.username] if getattr(target_success, "username", None) else incident.usernames
            hosts = [target_success.hostname] if getattr(target_success, "hostname", None) else incident.hostnames

            user_str = ", ".join(users)
            src_str = ", ".join(src_ips)
            label_desc = self._extract_dataset_label([target_success])

            observed_behavior = (
                f"Observed successful authentication event {target_success.event_id} for user '{user_str}' "
                f"from source {src_str} chronologically following repeated failed login attempts."
            )
            inferred_technique = (
                "T1078 - Valid Accounts (Initial Access). Successful authentication immediately succeeding "
                "credential guessing bursts."
            )

            return AttackStep(
                step_id="STEP-PENDING",
                stage=AttackStage.INITIAL_ACCESS.value,
                title="Initial Compromised Login (Post-Brute-Force Ingress)",
                description=f"Successful authentication for '{user_str}' from {src_str} immediately following brute-force attempts.",
                timestamp_start=target_success.timestamp,
                timestamp_end=target_success.timestamp,
                detection_ids=[],
                event_ids=eids,
                source_ips=src_ips,
                destination_ips=dst_ips,
                usernames=users,
                hostnames=hosts,
                confidence=0.92,
                evidence_summary=(
                    f"Observed successful authentication event {target_success.event_id} for user '{user_str}' "
                    f"from source {src_str} chronologically immediately following repetitive authentication failures."
                ),
                observed_evidence=(
                    f"Accepted password session opened for '{user_str}' from {src_str} "
                    f"at {target_success.timestamp}."
                ),
                inference_reason=(
                    "A successful authentication originating from the exact same source IP and targeting the same "
                    "account immediately following a brute force burst signifies a successful credential crack and initial entry."
                ),
                observed_behavior=observed_behavior,
                inferred_technique=inferred_technique,
                dataset_label=label_desc,
            )

        return None

    def _infer_privilege_escalation(
        self,
        incident: Incident,
        incident_events: List[Any],
        detections: List[Detection],
    ) -> Optional[AttackStep]:
        """Infer PRIVILEGE_ESCALATION from sudo executions, privilege transitions, or R004 detections."""
        matching_dets = [d for d in detections if d.rule_id == "R004" or "privilege" in d.title.lower()]

        priv_events = [
            e for e in incident_events
            if getattr(e, "event_type", "") in {"privilege_escalation_attempt", "privilege_change", "sudo_enum"}
            or "privilege" in getattr(e, "event_type", "").lower()
            or getattr(e, "action", "") in {"elevate", "elevated"}
            or (getattr(e, "process", "") in {"sudo", "su", "pkexec"} and getattr(e, "action", "") == "executed")
        ]

        if not matching_dets and not priv_events:
            return None

        eids: List[str] = []
        for d in matching_dets:
            eids.extend(d.event_ids)
        for e in priv_events:
            if e.event_id not in eids:
                eids.append(e.event_id)

        eids = [eid for eid in eids if eid in incident.event_ids]
        if not eids:
            return None

        ev_objs = [e for e in incident_events if e.event_id in eids]
        if ev_objs:
            t_start = min(e.timestamp for e in ev_objs)
            t_end = max(e.timestamp for e in ev_objs)
            src_ips = sorted(list({e.source_ip for e in ev_objs if getattr(e, "source_ip", None)})) or incident.source_ips
            dst_ips = sorted(list({e.destination_ip for e in ev_objs if getattr(e, "destination_ip", None)})) or incident.destination_ips
            users = sorted(list({e.username for e in ev_objs if getattr(e, "username", None)})) or incident.usernames
            hosts = sorted(list({e.hostname for e in ev_objs if getattr(e, "hostname", None)})) or incident.hostnames
        else:
            t_start = incident.start_time
            t_end = incident.end_time
            src_ips = incident.source_ips
            dst_ips = incident.destination_ips
            users = incident.usernames
            hosts = incident.hostnames

        # Deterministic confidence based on evidence richness
        if len(matching_dets) >= 2 or any("uid changed" in getattr(e, "raw_message", "").lower() for e in ev_objs):
            confidence = 0.95
        elif matching_dets:
            confidence = 0.88
        else:
            confidence = 0.75

        det_ids = [d.detection_id for d in matching_dets]
        label_desc = self._extract_dataset_label(ev_objs)
        host_str = ', '.join(hosts) or 'host'
        user_str = ', '.join(users) or 'user'
        observed_behavior = (
            f"Observed {len(eids)} privileged execution and transition event(s) "
            f"by '{user_str}' escalating to superuser (root) privileges on {host_str}."
        )
        inferred_technique = (
            "T1548.003 - Sudo and Sudo Caching (Privilege Escalation). Execution of privileged utility "
            "commands resulting in privilege elevation."
        )

        return AttackStep(
            step_id="STEP-PENDING",
            stage=AttackStage.PRIVILEGE_ESCALATION.value,
            title="Local Privilege Escalation to Superuser / Root",
            description=f"Execution of privileged escalation commands and transition to root uid on {host_str}.",
            timestamp_start=t_start,
            timestamp_end=t_end,
            detection_ids=det_ids,
            event_ids=eids,
            source_ips=src_ips,
            destination_ips=dst_ips,
            usernames=users,
            hostnames=hosts,
            confidence=confidence,
            evidence_summary=(
                f"Observed {len(eids)} privilege escalation indicator event(s) including privileged execution "
                f"and identity transition to root. Corroborated by detection(s): {', '.join(det_ids) or 'system audit events'}."
            ),
            observed_evidence=(
                f"{len(eids)} privilege transition and execution event(s) recorded in audit logs "
                f"(Event IDs: {', '.join(eids)})."
            ),
            inference_reason=(
                "Execution of privilege escalation commands via sudo followed by transition from standard "
                "user identifier to UID 0 (root) indicates compromise of host administrative authority."
            ),
            observed_behavior=observed_behavior,
            inferred_technique=inferred_technique,
            dataset_label=label_desc,
        )

    def _infer_discovery(
        self,
        incident: Incident,
        incident_events: List[Any],
        detections: List[Detection],
    ) -> Optional[AttackStep]:
        """Infer DISCOVERY from port scanning, network enumeration, or system reconnaissance."""
        matching_dets = [d for d in detections if d.rule_id == "R002" or "port scan" in d.title.lower() or "recon" in d.title.lower()]

        disc_events = [
            e for e in incident_events
            if getattr(e, "event_type", "") in {"port_scan", "network_recon", "session_enum", "privilege_recon", "recon"}
            or "recon" in getattr(e, "raw_message", "").lower()
            or getattr(e, "process", "") in {"nmap", "netstat"}
        ]

        if not matching_dets and not disc_events:
            return None

        eids: List[str] = []
        for d in matching_dets:
            eids.extend(d.event_ids)
        for e in disc_events:
            if e.event_id not in eids:
                eids.append(e.event_id)

        eids = [eid for eid in eids if eid in incident.event_ids]
        if not eids:
            return None

        ev_objs = [e for e in incident_events if e.event_id in eids]
        t_start = min(e.timestamp for e in ev_objs) if ev_objs else incident.start_time
        t_end = max(e.timestamp for e in ev_objs) if ev_objs else incident.end_time
        src_ips = sorted(list({e.source_ip for e in ev_objs if getattr(e, "source_ip", None)})) or incident.source_ips
        dst_ips = sorted(list({e.destination_ip for e in ev_objs if getattr(e, "destination_ip", None)})) or incident.destination_ips
        dst_ports = sorted(list({e.destination_port for e in ev_objs if getattr(e, "destination_port", None) is not None}))
        users = sorted(list({e.username for e in ev_objs if getattr(e, "username", None)})) or incident.usernames
        hosts = sorted(list({e.hostname for e in ev_objs if getattr(e, "hostname", None)})) or incident.hostnames

        label_desc = self._extract_dataset_label(ev_objs)
        is_unlabelled = "unlabelled" in label_desc.lower() or "none" in label_desc.lower()
        has_multi_stage_context = len(incident.detection_ids) > 3 and any(
            d for d in detections if d.rule_id in {"R001", "R003", "R004", "R005", "R006", "R007"}
        )

        # Recalibrate confidence based on evidence support rather than assuming compromise
        if not matching_dets:
            confidence = 0.60
        elif is_unlabelled and not has_multi_stage_context:
            # Pure network flow port scan with mitre_attack_tactics=none and no subsequent breach
            confidence = 0.70
        elif len(matching_dets) >= 2 or len(eids) >= 20:
            confidence = 0.85
        else:
            confidence = 0.78

        det_ids = [d.detection_id for d in matching_dets]
        src_str = ", ".join(src_ips) if src_ips else "external source"
        port_summary = f"{len(dst_ports)} distinct port(s)" if dst_ports else "multiple network ports"
        target_summary = f"destination IP(s) {', '.join(dst_ips)}" if dst_ips else "target network systems"

        observed_behavior = (
            f"Observed {len(eids)} network flow connection attempt(s) from source IP {src_str} "
            f"targeting {port_summary} across {target_summary}."
        )
        inferred_technique = (
            "T1046 - Network Service Discovery (Reconnaissance / Discovery). Behavioral pattern of rapid "
            "sequential probes across diverse ports is consistent with network enumeration."
        )
        observed_evidence = (
            f"{len(eids)} network flow probe event(s) recorded across targeted ports "
            f"(Event IDs: {', '.join(eids[:8])}{' ...' if len(eids) > 8 else ''})."
        )
        inference_reason = (
            f"Behavioral pattern indicates network service discovery probes. "
            f"However, telemetry records are {label_desc.lower()} and lack corroborating intrusion stages "
            f"(no authentication breach, privilege escalation, or data exfiltration observed)."
        )

        return AttackStep(
            step_id="STEP-PENDING",
            stage=AttackStage.DISCOVERY.value,
            title="System & Network Reconnaissance / Discovery",
            description=f"Host or network enumeration probes observed originating from {src_str}.",
            timestamp_start=t_start,
            timestamp_end=t_end,
            detection_ids=det_ids,
            event_ids=eids,
            source_ips=src_ips,
            destination_ips=dst_ips,
            usernames=users,
            hostnames=hosts,
            confidence=confidence,
            evidence_summary=(
                f"Observed {len(eids)} reconnaissance event(s) scanning network ports or probing system configurations. "
                f"Supported by detection(s): {', '.join(det_ids) or 'flow telemetry'}."
            ),
            observed_evidence=observed_evidence,
            inference_reason=inference_reason,
            observed_behavior=observed_behavior,
            inferred_technique=inferred_technique,
            dataset_label=label_desc,
        )

    def _infer_collection(
        self,
        incident: Incident,
        incident_events: List[Any],
        detections: List[Detection],
    ) -> Optional[AttackStep]:
        """Infer COLLECTION from access to sensitive files, shadow/keys, or archive bundling."""
        matching_dets = [d for d in detections if d.rule_id == "R005" or "sensitive" in d.title.lower()]

        coll_events = [
            e for e in incident_events
            if getattr(e, "event_type", "") in {"sensitive_file_read", "file_archive", "credential_access"}
            or any(k in getattr(e, "raw_message", "").lower() for k in ["/etc/shadow", "private_key", ".pem", "tar -c", "export.csv"])
        ]

        if not matching_dets and not coll_events:
            return None

        eids: List[str] = []
        for d in matching_dets:
            eids.extend(d.event_ids)
        for e in coll_events:
            if e.event_id not in eids:
                eids.append(e.event_id)

        eids = [eid for eid in eids if eid in incident.event_ids]
        if not eids:
            return None

        ev_objs = [e for e in incident_events if e.event_id in eids]
        t_start = min(e.timestamp for e in ev_objs) if ev_objs else incident.start_time
        t_end = max(e.timestamp for e in ev_objs) if ev_objs else incident.end_time
        src_ips = sorted(list({e.source_ip for e in ev_objs if getattr(e, "source_ip", None)})) or incident.source_ips
        dst_ips = sorted(list({e.destination_ip for e in ev_objs if getattr(e, "destination_ip", None)})) or incident.destination_ips
        users = sorted(list({e.username for e in ev_objs if getattr(e, "username", None)})) or incident.usernames
        hosts = sorted(list({e.hostname for e in ev_objs if getattr(e, "hostname", None)})) or incident.hostnames

        confidence = 0.92 if len(matching_dets) >= 2 or len(eids) >= 2 else 0.85
        det_ids = [d.detection_id for d in matching_dets]
        label_desc = self._extract_dataset_label(ev_objs)
        host_str = ', '.join(hosts) or 'host'

        observed_behavior = (
            f"Observed {len(eids)} filesystem access and archiving event(s) reading sensitive system secrets "
            f"or staging data files on {host_str}."
        )
        inferred_technique = (
            "T1005 - Data from Local System (Collection). Targeted staging of cryptographic keys, "
            "password files, and system configuration archives."
        )

        return AttackStep(
            step_id="STEP-PENDING",
            stage=AttackStage.COLLECTION.value,
            title="Sensitive Data & Credential Staging / Collection",
            description=f"Direct access to sensitive credentials, cryptographic keys, and data files on {host_str}.",
            timestamp_start=t_start,
            timestamp_end=t_end,
            detection_ids=det_ids,
            event_ids=eids,
            source_ips=src_ips,
            destination_ips=dst_ips,
            usernames=users,
            hostnames=hosts,
            confidence=confidence,
            evidence_summary=(
                f"Observed {len(eids)} sensitive resource access and archiving events targeting password hashes, "
                f"crypto keys, and confidential stores. Supported by detection(s): {', '.join(det_ids) or 'audit logs'}."
            ),
            observed_evidence=(
                f"Access recorded against sensitive files (/etc/shadow, private keys) and data bundling "
                f"(Event IDs: {', '.join(eids)})."
            ),
            inference_reason=(
                "Targeted retrieval of sensitive credential stores and private keys by an elevated user "
                "is indicative of data collection and staging for unauthorized extraction."
            ),
            observed_behavior=observed_behavior,
            inferred_technique=inferred_technique,
            dataset_label=label_desc,
        )

    def _infer_exfiltration(
        self,
        incident: Incident,
        incident_events: List[Any],
        detections: List[Detection],
    ) -> Optional[AttackStep]:
        """Infer EXFILTRATION from high-volume outbound network flow transfers."""
        matching_dets = [d for d in detections if d.rule_id == "R006" or "large outbound" in d.title.lower() or "exfiltration" in d.title.lower()]

        exfil_events = [
            e for e in incident_events
            if getattr(e, "event_type", "") in {"large_outbound_transfer", "data_exfiltration"}
            or ("high volume outbound stream" in getattr(e, "raw_message", "").lower() and "bytes=" in getattr(e, "raw_message", "").lower())
        ]

        if not matching_dets and not exfil_events:
            return None

        eids: List[str] = []
        for d in matching_dets:
            eids.extend(d.event_ids)
        for e in exfil_events:
            if e.event_id not in eids:
                eids.append(e.event_id)

        eids = [eid for eid in eids if eid in incident.event_ids]
        if not eids:
            return None

        ev_objs = [e for e in incident_events if e.event_id in eids]
        t_start = min(e.timestamp for e in ev_objs) if ev_objs else incident.start_time
        t_end = max(e.timestamp for e in ev_objs) if ev_objs else incident.end_time
        src_ips = sorted(list({e.source_ip for e in ev_objs if getattr(e, "source_ip", None)})) or incident.source_ips
        dst_ips = sorted(list({e.destination_ip for e in ev_objs if getattr(e, "destination_ip", None)})) or incident.destination_ips
        users = sorted(list({e.username for e in ev_objs if getattr(e, "username", None)})) or incident.usernames
        hosts = sorted(list({e.hostname for e in ev_objs if getattr(e, "hostname", None)})) or incident.hostnames

        confidence = 0.95 if len(matching_dets) >= 3 or len(eids) >= 3 else 0.88
        det_ids = [d.detection_id for d in matching_dets]
        label_desc = self._extract_dataset_label(ev_objs)
        dst_str = ', '.join(dst_ips) or 'external host'

        observed_behavior = (
            f"Observed {len(eids)} high-volume outbound network flow stream(s) transmitting "
            f"megabytes of payload data to remote destination {dst_str}."
        )
        inferred_technique = (
            "T1048 - Exfiltration Over Alternative Protocol (Exfiltration). High-volume egress stream "
            "directed to external IP address following data collection."
        )

        return AttackStep(
            step_id="STEP-PENDING",
            stage=AttackStage.EXFILTRATION.value,
            title="Unauthorized Outbound Data Exfiltration",
            description=f"High-volume encrypted outbound transfer streams directed to external destination {dst_str}.",
            timestamp_start=t_start,
            timestamp_end=t_end,
            detection_ids=det_ids,
            event_ids=eids,
            source_ips=src_ips,
            destination_ips=dst_ips,
            usernames=users,
            hostnames=hosts,
            confidence=confidence,
            evidence_summary=(
                f"Observed {len(eids)} large outbound transfer events moving hundreds of megabytes "
                f"to destination IP(s) {dst_str}. Supported by detection(s): {', '.join(det_ids)}."
            ),
            observed_evidence=(
                f"{len(eids)} high-volume outbound network flow streams recorded through firewall "
                f"to external IP {dst_str} (Event IDs: {', '.join(eids)})."
            ),
            inference_reason=(
                "Repetitive, high-volume egress streams over encrypted channels directed to an external IP "
                "following data staging strongly indicates completed data exfiltration."
            ),
            observed_behavior=observed_behavior,
            inferred_technique=inferred_technique,
            dataset_label=label_desc,
        )

    # -------------------------------------------------------------------------
    # Overall Confidence Calculation
    # -------------------------------------------------------------------------

    def _calculate_overall_confidence(self, steps: List[AttackStep], incident: Incident) -> float:
        """
        Calculate overall confidence deterministically from individual steps.

        Formula:
            - Weighted average of step confidences
            - Diversity bonus (+0.02 per distinct supported stage beyond 1, up to +0.06)
            - Single-stage penalty (-0.05) if an uncorroborated single stage is inferred
            - Unlabelled dataset penalty (-0.05) if single stage evidence is unlabelled in dataset
            - Chronological consistency check
            - Clamped strictly between 0.0 and 0.98 (never 1.0)
        """
        if not steps:
            return 0.0

        avg_step_conf = sum(s.confidence for s in steps) / len(steps)

        # Multi-stage coherence bonus
        unique_stages = len(set(s.stage for s in steps))
        if unique_stages > 1:
            coherence_bonus = min(0.06, max(0.0, (unique_stages - 1) * 0.02))
            single_stage_penalty = 0.0
        else:
            coherence_bonus = 0.0
            single_stage_penalty = 0.05

        # Check chronological consistency
        chrono_penalty = 0.0
        for i in range(len(steps) - 1):
            if steps[i].timestamp_start > steps[i + 1].timestamp_start:
                chrono_penalty += 0.05

        any_unlabelled = any(
            "unlabelled" in getattr(s, "dataset_label", "").lower() or "none" in getattr(s, "dataset_label", "").lower()
            for s in steps
        )
        unlabelled_penalty = 0.05 if (any_unlabelled and unique_stages == 1) else 0.0

        computed = (avg_step_conf * 0.85) + (incident.confidence * 0.15) + coherence_bonus - single_stage_penalty - chrono_penalty - unlabelled_penalty
        return max(0.10, min(0.97, round(computed, 4)))


def build_attack_chain(
    incident_or_timeline: Union[Incident, list],
    events: Optional[Union[List[NormalizedEvent], Dict[str, NormalizedEvent]]] = None,
    detections: Optional[List[Detection]] = None,
) -> AttackChain:
    """
    Public convenience API for constructing an AttackChain.

    Args:
        incident_or_timeline: Incident instance, or list of timeline items.
        events: Optional list or dict of NormalizedEvent instances.
        detections: Optional list of Detection instances.

    Returns:
        AttackChain instance.
    """
    reconstructor = AttackChainReconstructor()

    if isinstance(incident_or_timeline, Incident):
        return reconstructor.reconstruct(
            incident=incident_or_timeline,
            events=events,
            detections=detections,
        )

    # If passed a list of events/timeline items directly
    if isinstance(incident_or_timeline, list):
        if not incident_or_timeline:
            return AttackChain(
                incident_id="INC-EMPTY",
                steps=[],
                start_time=None,
                end_time=None,
                overall_confidence=0.0,
                summary="Empty event timeline: no attack stages could be inferred.",
                limitations=DEFAULT_RECONSTRUCTION_LIMITATIONS,
            )

        # Formulate a synthetic lightweight Incident wrapper for the timeline list
        t_items = incident_or_timeline
        first_t = getattr(t_items[0], "timestamp", datetime.now())
        last_t = getattr(t_items[-1], "timestamp", datetime.now())
        all_eids = [getattr(it, "event_id", f"EVT-{i}") for i, it in enumerate(t_items)]
        
        synthetic_inc = Incident(
            incident_id="INC-RECON-0001",
            created_at=datetime.now(),
            start_time=first_t,
            end_time=last_t,
            severity="HIGH",
            status="OPEN",
            confidence=0.85,
            detection_ids=[d.detection_id for d in (detections or [])],
            event_ids=all_eids,
            source_ips=list({getattr(it, "source_ip", "") for it in t_items if getattr(it, "source_ip", None)}),
            destination_ips=list({getattr(it, "destination_ip", "") for it in t_items if getattr(it, "destination_ip", None)}),
            usernames=list({getattr(it, "username", "") for it in t_items if getattr(it, "username", None)}),
            hostnames=list({getattr(it, "hostname", "") for it in t_items if getattr(it, "hostname", None)}),
            detection_count=len(detections or []),
            summary="Incident synthesized from timeline items for attack chain reconstruction.",
            correlation_score=0.85,
        )

        return reconstructor.reconstruct(
            incident=synthetic_inc,
            events=t_items,
            detections=detections,
        )

    raise TypeError(f"Unsupported input type for incident_or_timeline: {type(incident_or_timeline)}")

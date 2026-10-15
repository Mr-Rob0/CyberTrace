"""
Incident Report Data Models and Schema
======================================
Defines strongly typed data structures for AI-assisted and deterministic
incident investigation reports in CyberTrace.

Key Principles:
    - Structured & Verifiable: Every report section is typed and queryable.
    - Grounded Traceability: Evidence references are tracked across all sections.
    - Explicit Provenance: Distinguishes between LLM-generated and deterministic fallback reports.
    - Read-Only Pipeline: Incident reports summarize pipeline outputs without mutating them.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
import json


@dataclass
class IncidentReport:
    """
    Structured incident report model representing an evidence-grounded investigation report.
    """
    incident_id: str
    generation_method: str                     # "llm" or "deterministic_fallback"
    generated_at: str                          # ISO 8601 timestamp string
    executive_summary: str
    incident_overview: Dict[str, Any]          # severity, confidence, duration, impacted entities
    timeline_summary: List[Dict[str, Any]]     # chronological key events with event_id
    attack_stages: List[Dict[str, Any]]        # reconstructed attack stages with evidence links
    rule_detections: List[Dict[str, Any]]      # deterministic rule detections (R001-R006)
    mitre_mappings: List[Dict[str, Any]]       # verified MITRE ATT&CK techniques
    ml_anomaly_observations: List[Dict[str, Any]] # ML anomaly detector results (clearly separated)
    probable_root_cause: Dict[str, Any]        # ranked probable root cause candidate
    impact_assessment: Dict[str, Any]          # impact scope, affected systems, uncertainty
    defensive_recommendations: List[Dict[str, Any]] # recommended actions with priority
    limitations_and_gaps: List[str]            # missing telemetry, gaps, alternative explanations
    evidence_references: Dict[str, List[str]]  # event_ids, detection_ids, technique_ids
    provider_info: Optional[str] = None        # provider model/type (e.g., "openai:gpt-4o-mini", no credentials!)
    validation_warnings: List[str] = field(default_factory=list) # warnings from output validation
    is_valid: bool = True
    raw_response: Optional[str] = None         # raw text or LLM output

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to serializable dictionary representation."""
        return {
            "incident_id": self.incident_id,
            "generation_method": self.generation_method,
            "generated_at": self.generated_at,
            "provider_info": self.provider_info,
            "executive_summary": self.executive_summary,
            "incident_overview": self.incident_overview,
            "timeline_summary": self.timeline_summary,
            "attack_stages": self.attack_stages,
            "rule_detections": self.rule_detections,
            "mitre_mappings": self.mitre_mappings,
            "ml_anomaly_observations": self.ml_anomaly_observations,
            "probable_root_cause": self.probable_root_cause,
            "impact_assessment": self.impact_assessment,
            "defensive_recommendations": self.defensive_recommendations,
            "limitations_and_gaps": self.limitations_and_gaps,
            "evidence_references": self.evidence_references,
            "validation_warnings": self.validation_warnings,
            "is_valid": self.is_valid,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert report to pretty-printed JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Convert report into a human-readable GitHub-flavored markdown document."""
        md = []
        is_fallback = self.generation_method == "deterministic_fallback"

        # Header & Provenance Badge
        md.append(f"# Incident Investigation Report: {self.incident_id}\n")
        if is_fallback:
            md.append(
                "> **Report Mode: Deterministic Evidence Summary (Non-LLM Generated)**\n"
                "> Generated directly from verified CyberTrace pipeline outputs. "
                "No external LLM provider was utilized.\n"
            )
        else:
            provider_label = self.provider_info or "Configured LLM"
            md.append(
                f"> **Report Mode: AI-Assisted Incident Report ({provider_label})**\n"
                "> Synthesized by an AI model grounded strictly in pipeline telemetry.\n"
            )

        md.append(f"- **Generated At:** {self.generated_at}")
        md.append(f"- **Incident ID:** {self.incident_id}")
        md.append(f"- **Overall Severity:** {self.incident_overview.get('severity', 'UNKNOWN')}")
        md.append(f"- **Pipeline Confidence:** {self.incident_overview.get('confidence', 'N/A')}\n")

        if self.validation_warnings:
            md.append("### ⚠️ Validation & Grounding Warnings")
            for w in self.validation_warnings:
                md.append(f"- {w}")
            md.append("")

        # 1. Executive Summary
        md.append("## 1. Executive Summary")
        md.append(self.executive_summary.strip() + "\n")

        # 2. Incident Overview
        md.append("## 2. Incident Overview")
        ov = self.incident_overview
        md.append(f"- **Severity:** {ov.get('severity', 'Unknown')}")
        md.append(f"- **Lifecycle Status:** {ov.get('status', 'OPEN')}")
        md.append(f"- **Start Time:** {ov.get('start_time', 'Unknown')}")
        md.append(f"- **End Time:** {ov.get('end_time', 'Unknown')}")
        md.append(f"- **Duration:** {ov.get('duration_seconds', 'Unknown')} seconds")
        src_ips = ", ".join(ov.get("source_ips", [])) or "None identified"
        dst_ips = ", ".join(ov.get("destination_ips", [])) or "None identified"
        users = ", ".join(ov.get("usernames", [])) or "None identified"
        hosts = ", ".join(ov.get("hostnames", [])) or "None identified"
        md.append(f"- **Source IPs:** {src_ips}")
        md.append(f"- **Target / Destination IPs:** {dst_ips}")
        md.append(f"- **Impacted Usernames:** {users}")
        md.append(f"- **Impacted Hostnames:** {hosts}\n")

        # 3. Timeline of Important Events
        md.append("## 3. Timeline of Important Events")
        if self.timeline_summary:
            md.append("| Timestamp | Event ID | Source | Action | Severity | Raw Message Snippet |")
            md.append("|---|---|---|---|---|---|")
            for item in self.timeline_summary[:25]:
                raw = (item.get("raw_message", "")[:60] + "...") if len(item.get("raw_message", "")) > 60 else item.get("raw_message", "")
                raw_clean = raw.replace("|", "/")
                md.append(
                    f"| {item.get('timestamp', 'N/A')} | `{item.get('event_id', 'N/A')}` | "
                    f"{item.get('source', 'N/A')} | {item.get('action', 'N/A')} | "
                    f"{item.get('severity', 'N/A')} | {raw_clean} |"
                )
            if len(self.timeline_summary) > 25:
                md.append(f"\n*(Showing 25 of {len(self.timeline_summary)} timeline events)*\n")
        else:
            md.append("No timeline events recorded for this incident.\n")
        md.append("")

        # 4. Observed Attack Stages
        md.append("## 4. Reconstructed Attack Stages")
        if self.attack_stages:
            for s in self.attack_stages:
                step_id = s.get("step_id", "STEP")
                stage = s.get("stage", "STAGE")
                title = s.get("title", "Attack Step")
                conf = s.get("confidence", "N/A")
                ev_ids = ", ".join(f"`{e}`" for e in s.get("event_ids", [])[:8])
                if len(s.get("event_ids", [])) > 8:
                    ev_ids += f" (+{len(s.get('event_ids', [])) - 8} more)"
                md.append(f"### {step_id}: {stage} — {title}")
                md.append(f"- **Inference Confidence:** {conf}")
                md.append(f"- **Description:** {s.get('description', '')}")
                md.append(f"- **Observed Telemetry:** {s.get('observed_evidence', 'N/A')}")
                md.append(f"- **Inference Justification:** {s.get('inference_reason', 'N/A')}")
                md.append(f"- **Supporting Event IDs:** {ev_ids or 'None'}\n")
        else:
            md.append("No multi-stage attack chain reconstructed. Activity may represent isolated detections.\n")

        # 5. Deterministic Detections
        md.append("## 5. Relevant Deterministic Detections (Rule Engine)")
        if self.rule_detections:
            for d in self.rule_detections:
                det_id = d.get("detection_id", "DET")
                rule_id = d.get("rule_id", "RULE")
                title = d.get("title", d.get("rule_name", "Detection"))
                sev = d.get("severity", "MEDIUM")
                ev_ids = ", ".join(f"`{e}`" for e in d.get("event_ids", [])[:8])
                md.append(f"- **`{det_id}` [{rule_id}] — {title}** (Severity: `{sev}`)")
                md.append(f"  - Description: {d.get('description', '')}")
                md.append(f"  - Supporting Evidence: {ev_ids}")
            md.append("")
        else:
            md.append("No deterministic rule detections associated with this incident.\n")

        # 6. MITRE ATT&CK Mappings
        md.append("## 6. MITRE ATT&CK Mappings")
        if self.mitre_mappings:
            md.append("| Technique ID | Technique Name | Primary Tactic | Confidence | Evidence Count | Supporting Events |")
            md.append("|---|---|---|---|---|---|")
            for m in self.mitre_mappings:
                tid = m.get("technique_id", "N/A")
                tname = m.get("technique_name", "N/A")
                tactic = m.get("tactic", "N/A")
                conf = m.get("confidence", "N/A")
                cnt = m.get("evidence_count", 0)
                eids = ", ".join(f"`{e}`" for e in m.get("supporting_event_ids", [])[:4])
                if len(m.get("supporting_event_ids", [])) > 4:
                    eids += f" (+{len(m.get('supporting_event_ids', [])) - 4})"
                md.append(f"| [{tid}](https://attack.mitre.org/techniques/{tid.replace('.', '/')}) | {tname} | {tactic} | {conf} | {cnt} | {eids} |")
            md.append("")
        else:
            md.append("No MITRE ATT&CK techniques mapped to this incident.\n")

        # 7. ML Anomaly Observations
        md.append("## 7. Machine Learning Anomaly Observations")
        md.append(
            "> ⚠️ **Important Disclaimer:** ML anomaly detection flags statistical divergence "
            "from benign baseline telemetry. Anomaly scores are NOT attack probabilities or confirmed malicious acts.\n"
        )
        if self.ml_anomaly_observations:
            flagged = [a for a in self.ml_anomaly_observations if a.get("is_anomaly")]
            md.append(f"Observed **{len(flagged)}** statistically anomalous telemetry events out of {len(self.ml_anomaly_observations)} scored:")
            for a in flagged[:10]:
                eid = a.get("event_id", "N/A")
                score = a.get("anomaly_score", "N/A")
                expl = a.get("explanation", "Statistical divergence")
                md.append(f"- Event `{eid}` (Score: `{score}`): {expl}")
            if len(flagged) > 10:
                md.append(f"\n*(Showing 10 of {len(flagged)} flagged anomalies)*")
            md.append("")
        else:
            md.append("No ML anomaly observations recorded for this incident context.\n")

        # 8. Probable Root Cause
        md.append("## 8. Evidence-Backed Probable Root Cause")
        rc = self.probable_root_cause
        rc_type = rc.get("candidate_type", "UNKNOWN")
        rc_title = rc.get("title", "Unknown Root Cause")
        rc_conf = rc.get("confidence", "N/A")
        rc_ev = ", ".join(f"`{e}`" for e in rc.get("evidence_event_ids", [])[:8])
        md.append(f"**Primary Candidate:** {rc_title} (`{rc_type}`)")
        md.append(f"- **Confidence:** {rc_conf} (Probabilistic estimate, never absolute certainty)")
        md.append(f"- **Reasoning:** {rc.get('reasoning', 'No reasoning provided.')}")
        md.append(f"- **Supporting Evidence Event IDs:** {rc_ev or 'None'}\n")

        # 9. Impact Assessment
        md.append("## 9. Impact Assessment")
        ia = self.impact_assessment
        md.append(f"- **Scope:** {ia.get('scope', 'Unknown')}")
        md.append(f"- **Impacted Systems / Accounts:** {', '.join(ia.get('impacted_systems', [])) or 'None established'}")
        md.append(f"- **Assessment Narrative:** {ia.get('narrative', 'N/A')}")
        md.append(f"- **Explicit Uncertainty:** {ia.get('uncertainty_statement', 'Telemetry may have blind spots.')}\n")

        # 10. Recommended Defensive Actions
        md.append("## 10. Recommended Defensive Actions")
        md.append("*(Advisory Note: Defensive recommendations are generated strictly as suggestions; actions are never executed automatically.)*\n")
        if self.defensive_recommendations:
            for rec in self.defensive_recommendations:
                prio = rec.get("priority", "MEDIUM")
                act = rec.get("action", "")
                rat = rec.get("rationale", "")
                md.append(f"- **[{prio.upper()}]** {act}")
                if rat:
                    md.append(f"  - *Rationale:* {rat}")
            md.append("")
        else:
            md.append("No specific defensive recommendations established.\n")

        # 11. Limitations, Gaps & Alternative Explanations
        md.append("## 11. Limitations, Telemetry Gaps & Alternative Explanations")
        if self.limitations_and_gaps:
            for lim in self.limitations_and_gaps:
                md.append(f"- {lim}")
        else:
            md.append("- Analysis bounded strictly by provided synthetic log telemetry.")
            md.append("- Network perimeter visibility without full packet capture limits payload inspection.")
            md.append("- Alternative benign explanation: Authorized penetration testing, administrative scripting, or scheduled maintenance.")
        md.append("")

        return "\n".join(md)

"""
Temporary CyberTrace Audit Runner
Executes comprehensive diagnostics for Audits 9, 10, 11, 13, 14, 15, 16.
"""

import os
import sys
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine, Detection
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector
from correlation.timeline_builder import TimelineBuilder
from reconstruction.attack_chain import AttackChainReconstructor, AttackStage
from reconstruction.attack_graph import build_attack_graph
from reconstruction.root_cause import RootCauseAnalyzer, identify_root_cause

DATA_DIR = os.path.join(PROJECT_ROOT, "data", "sample_attacks")

def audit_9_forensic_trace():
    print("=" * 60)
    print("AUDIT 9: INCIDENT FORENSIC TRACE")
    print("=" * 60)
    parsed = parse_log_file(os.path.join(DATA_DIR, "combined_attack.csv"))
    events_map = {e.event_id: e for e in parsed.events}
    detections = RuleEngine().detect(parsed.events)
    groups = EventCorrelator().correlate(detections)
    incidents = IncidentDetector().detect_incidents(groups)
    inc = incidents[0]

    print(f"Incident: {inc.incident_id} | Detections: {len(inc.detection_ids)} | Evidence Events: {len(inc.event_ids)}")
    print(f"Start: {inc.start_time} | End: {inc.end_time} | Severity: {inc.severity} | Conf: {inc.confidence}")

    all_links_valid = True
    for did in inc.detection_ids:
        det = next((d for d in detections if d.detection_id == did), None)
        if not det:
            print(f"FAILED: Detection {did} not found")
            all_links_valid = False
            continue
        for eid in det.event_ids:
            if eid not in events_map:
                print(f"FAILED: Event {eid} not found in normalized events")
                all_links_valid = False
            else:
                ev = events_map[eid]
                if not ev.raw_message:
                    print(f"FAILED: Event {eid} missing raw_message")
                    all_links_valid = False

    print("All forensic links (Incident -> Detection -> Event ID -> Normalized Event -> raw_message):", "PASS" if all_links_valid else "FAIL")

def audit_10_timeline_integrity():
    print("\n" + "=" * 60)
    print("AUDIT 10: TIMELINE INTEGRITY")
    print("=" * 60)
    parsed = parse_log_file(os.path.join(DATA_DIR, "combined_attack.csv"))
    events_map = {e.event_id: e for e in parsed.events}
    detections = RuleEngine().detect(parsed.events)
    groups = EventCorrelator().correlate(detections)
    incidents = IncidentDetector().detect_incidents(groups)
    inc = incidents[0]
    timeline = TimelineBuilder.build_for_incident(inc, events_map, detections=detections)

    print(f"Timeline items count: {len(timeline)} (incident.event_ids count: {len(inc.event_ids)})")
    is_sorted = all(timeline[i].timestamp <= timeline[i+1].timestamp for i in range(len(timeline)-1))
    print(f"Strictly chronological: {is_sorted}")

    # Check duplicates
    eids = [it.event_id for it in timeline]
    has_duplicates = len(eids) != len(set(eids))
    print(f"Has duplicate event IDs: {has_duplicates}")

    # Check evidence preservation
    preserved = all(it.raw_message == events_map[it.event_id].raw_message for it in timeline)
    print(f"Raw messages perfectly preserved: {preserved}")

def audit_11_mutation_tests():
    print("\n" + "=" * 60)
    print("AUDIT 11: ATTACK RECONSTRUCTION MUTATION TESTS")
    print("=" * 60)
    parsed = parse_log_file(os.path.join(DATA_DIR, "combined_attack.csv"))
    reconstructor = AttackChainReconstructor()

    # Baseline
    dets_base = RuleEngine().detect(parsed.events)
    inc_base = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets_base))[0]
    chain_base = reconstructor.reconstruct(inc_base, events=parsed.events, detections=dets_base)
    stages_base = [s.stage for s in chain_base.steps]
    print(f"Baseline stages: {stages_base}")

    # Mutation A: Remove all failed logins
    events_no_failed = [e for e in parsed.events if e.event_type != "login_failed"]
    dets_no_failed = RuleEngine().detect(events_no_failed)
    inc_no_failed = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets_no_failed))[0]
    chain_no_failed = reconstructor.reconstruct(inc_no_failed, events=events_no_failed, detections=dets_no_failed)
    stages_no_failed = [s.stage for s in chain_no_failed.steps]
    mut_A = AttackStage.CREDENTIAL_ACCESS.value not in stages_no_failed
    print(f"Mutation A (Remove failed logins) -> CREDENTIAL_ACCESS removed: {mut_A} ({stages_no_failed})")

    # Mutation B: Remove the successful login (CA-6097)
    events_no_succ = [e for e in parsed.events if e.event_id != "CA-6097"]
    dets_no_succ = RuleEngine().detect(events_no_succ)
    inc_no_succ = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets_no_succ))[0]
    chain_no_succ = reconstructor.reconstruct(inc_no_succ, events=events_no_succ, detections=dets_no_succ)
    stages_no_succ = [s.stage for s in chain_no_succ.steps]
    mut_B = AttackStage.INITIAL_ACCESS.value not in stages_no_succ
    print(f"Mutation B (Remove CA-6097) -> INITIAL_ACCESS removed: {mut_B} ({stages_no_succ})")

    # Mutation C: Remove privilege escalation events (CA-6108, CA-6110, CA-6111)
    priv_ids = {"CA-6108", "CA-6110", "CA-6111"}
    events_no_priv = [e for e in parsed.events if e.event_id not in priv_ids]
    dets_no_priv = RuleEngine().detect(events_no_priv)
    inc_no_priv = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets_no_priv))[0]
    chain_no_priv = reconstructor.reconstruct(inc_no_priv, events=events_no_priv, detections=dets_no_priv)
    stages_no_priv = [s.stage for s in chain_no_priv.steps]
    mut_C = AttackStage.PRIVILEGE_ESCALATION.value not in stages_no_priv
    print(f"Mutation C (Remove priv esc events) -> PRIVILEGE_ESCALATION removed: {mut_C} ({stages_no_priv})")

    # Mutation D: Remove sensitive file access (CA-6127, CA-6129)
    coll_ids = {"CA-6127", "CA-6129"}
    events_no_coll = [e for e in parsed.events if e.event_id not in coll_ids]
    dets_no_coll = RuleEngine().detect(events_no_coll)
    inc_no_coll = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets_no_coll))[0]
    chain_no_coll = reconstructor.reconstruct(inc_no_coll, events=events_no_coll, detections=dets_no_coll)
    stages_no_coll = [s.stage for s in chain_no_coll.steps]
    mut_D = AttackStage.COLLECTION.value not in stages_no_coll
    print(f"Mutation D (Remove sensitive files) -> COLLECTION removed: {mut_D} ({stages_no_coll})")

    # Mutation E: Remove outbound transfer events (CA-6132 to CA-6137)
    exfil_ids = {f"CA-613{i}" for i in range(2, 8)}
    events_no_exfil = [e for e in parsed.events if e.event_id not in exfil_ids]
    dets_no_exfil = RuleEngine().detect(events_no_exfil)
    inc_no_exfil = IncidentDetector().detect_incidents(EventCorrelator().correlate(dets_no_exfil))[0]
    chain_no_exfil = reconstructor.reconstruct(inc_no_exfil, events=events_no_exfil, detections=dets_no_exfil)
    stages_no_exfil = [s.stage for s in chain_no_exfil.steps]
    mut_E = AttackStage.EXFILTRATION.value not in stages_no_exfil
    print(f"Mutation E (Remove outbound transfers) -> EXFILTRATION removed: {mut_E} ({stages_no_exfil})")

def audit_13_root_cause_scenarios():
    print("\n" + "=" * 60)
    print("AUDIT 13: ROOT-CAUSE SCENARIO TESTING")
    print("=" * 60)
    analyzer = RootCauseAnalyzer()
    reconstructor = AttackChainReconstructor()
    t0 = datetime(2026, 10, 16, 9, 0, 0)

    # 1. Failed logins only (Brute force without access)
    d_bf = Detection(
        detection_id="DET-01", rule_id="R001", rule_name="Brute Force",
        timestamp=t0, severity="HIGH", title="Brute Force", description="",
        event_ids=[f"BF-{i}" for i in range(10)], source_ip="192.168.1.188",
        username="admin", hostname="host-01", confidence=0.92
    )
    inc_bf = IncidentDetector().detect_incidents([[d_bf]])[0]
    chain_bf = reconstructor.reconstruct(inc_bf, detections=[d_bf])
    cands_bf = analyzer.analyze(chain_bf)
    print(f"1. Failed logins only: Primary={cands_bf[0].candidate_type} (conf={cands_bf[0].confidence}) - {cands_bf[0].title}")

    # 2. Data transfer only
    d_tr = Detection(
        detection_id="DET-02", rule_id="R006", rule_name="Transfer",
        timestamp=t0, severity="HIGH", title="Transfer", description="",
        event_ids=["TR-01"], source_ip="192.168.1.188", destination_ip="10.0.0.1",
        hostname="host-01", confidence=0.88
    )
    inc_tr = IncidentDetector().detect_incidents([[d_tr]])[0]
    chain_tr = reconstructor.reconstruct(inc_tr, detections=[d_tr])
    cands_tr = analyzer.analyze(chain_tr)
    print(f"2. Data transfer only: Primary={cands_tr[0].candidate_type} (conf={cands_tr[0].confidence}) - {cands_tr[0].title}")

    # 3. Privileged activity only
    d_pr = Detection(
        detection_id="DET-03", rule_id="R004", rule_name="Privilege Escalation",
        timestamp=t0, severity="HIGH", title="Priv esc", description="",
        event_ids=["PR-01"], source_ip="192.168.1.188", username="root",
        hostname="host-01", confidence=0.88
    )
    inc_pr = IncidentDetector().detect_incidents([[d_pr]])[0]
    chain_pr = reconstructor.reconstruct(inc_pr, detections=[d_pr])
    cands_pr = analyzer.analyze(chain_pr)
    print(f"3. Privileged activity only: Primary={cands_pr[0].candidate_type} (conf={cands_pr[0].confidence}) - {cands_pr[0].title}")

    # 4. Empty incident
    cands_empty = analyzer.analyze(AttackChainReconstructor().reconstruct(None))
    print(f"4. Empty incident: Primary={cands_empty[0].candidate_type} (conf={cands_empty[0].confidence}) - {cands_empty[0].title}")

def audit_15_remove_the_knowledge():
    print("\n" + "=" * 60)
    print("AUDIT 15: REMOVE THE KNOWLEDGE (UNSEEN ATTRIBUTES)")
    print("=" * 60)
    # Synthetic incident with COMPLETELY UNSEEN attributes:
    # IP: 172.16.50.99, User: alice_ops, Host: prod-k8s-worker, Process: sudo
    t0 = datetime(2027, 3, 1, 14, 0, 0)
    from preprocessing.event_schema import NormalizedEvent

    unseen_events = []
    # 8 failed logins
    for i in range(8):
        unseen_events.append(NormalizedEvent(
            event_id=f"UNSEEN-FAIL-{i}", timestamp=t0 + timedelta(seconds=i*5),
            source="auth.log", event_type="login_failed",
            source_ip="172.16.50.99", destination_ip="172.16.10.5",
            username="alice_ops", hostname="prod-k8s-worker", process="sshd",
            action="failure", severity="medium", raw_message=f"Failed login for alice_ops from 172.16.50.99"
        ))
    # 1 successful login
    unseen_events.append(NormalizedEvent(
        event_id="UNSEEN-SUCC-01", timestamp=t0 + timedelta(seconds=45),
        source="auth.log", event_type="login_success",
        source_ip="172.16.50.99", destination_ip="172.16.10.5",
        username="alice_ops", hostname="prod-k8s-worker", process="sshd",
        action="success", severity="high", raw_message="Accepted password for alice_ops from 172.16.50.99"
    ))
    # Sudo priv esc
    unseen_events.append(NormalizedEvent(
        event_id="UNSEEN-PRIV-01", timestamp=t0 + timedelta(minutes=5),
        source="audit.log", event_type="privilege_change",
        source_ip="172.16.50.99", destination_ip="172.16.10.5",
        username="root", hostname="prod-k8s-worker", process="sudo",
        action="elevated", severity="critical", raw_message="Privilege transition: uid changed to 0(root)"
    ))

    dets = RuleEngine().detect(unseen_events)
    groups = EventCorrelator().correlate(dets)
    incidents = IncidentDetector().detect_incidents(groups)
    print(f"Unseen telemetry -> Detections: {len(dets)} | Incidents: {len(incidents)}")
    if incidents:
        chain = AttackChainReconstructor().reconstruct(incidents[0], events=unseen_events, detections=dets)
        print(f"Unseen telemetry -> Stages: {[s.stage for s in chain.steps]} (Conf: {chain.overall_confidence})")
        cands = RootCauseAnalyzer().analyze(chain)
        print(f"Unseen telemetry -> Primary Root Cause: {cands[0].candidate_type} ({cands[0].title})")

def audit_16_reproducibility():
    print("\n" + "=" * 60)
    print("AUDIT 16: DETERMINISM & REPRODUCIBILITY")
    print("=" * 60)
    parsed = parse_log_file(os.path.join(DATA_DIR, "combined_attack.csv"))

    def run_full():
        d = RuleEngine().detect(parsed.events)
        g = EventCorrelator().correlate(d)
        inc = IncidentDetector().detect_incidents(g)[0]
        c = AttackChainReconstructor().reconstruct(inc, events=parsed.events, detections=d)
        gr = build_attack_graph(c)
        rc = RootCauseAnalyzer().analyze(c)
        return inc, c, gr, rc

    inc1, c1, gr1, rc1 = run_full()
    inc2, c2, gr2, rc2 = run_full()

    match_inc = (inc1.detection_count == inc2.detection_count and inc1.event_ids == inc2.event_ids)
    match_stages = ([s.stage for s in c1.steps] == [s.stage for s in c2.steps])
    match_confs = ([s.confidence for s in c1.steps] == [s.confidence for s in c2.steps])
    match_graph = (len(gr1.nodes) == len(gr2.nodes) and len(gr1.edges) == len(gr2.edges))
    match_rc = ([r.candidate_type for r in rc1] == [r.candidate_type for r in rc2])

    print(f"Incident match: {match_inc}")
    print(f"Stage order match: {match_stages}")
    print(f"Confidence values match: {match_confs}")
    print(f"Graph nodes/edges match: {match_graph}")
    print(f"Root cause ranking match: {match_rc}")

if __name__ == "__main__":
    audit_9_forensic_trace()
    audit_10_timeline_integrity()
    audit_11_mutation_tests()
    audit_13_root_cause_scenarios()
    audit_15_remove_the_knowledge()
    audit_16_reproducibility()

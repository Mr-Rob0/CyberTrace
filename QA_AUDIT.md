# CyberTrace QA Audit

**Audit date:** 1 November 2026  
**Scope:** Core investigation pipeline, bundled datasets, visualisation components, response logic, report exports, and Streamlit navigation/state handling.

## Executive result

The core CyberTrace workflow is functioning as an end-to-end offline incident-investigation prototype. All automated tests pass, every bundled data source parses without rejected rows, the combined attack path produces a fully grounded report, and the normal dataset remains free of deterministic incidents.

The analyst-facing application supports the expected sequence:

`Dataset → alerts → correlated incident → reconstruction → MITRE mapping → response plan → report export`

## Automated verification

| Check | Result |
|---|---:|
| Full automated test suite | **337 passed** |
| Parsing failures in bundled datasets | **0** |
| Dashboard/reconstruction visual components that rendered and serialized | **6 / 6** |
| Combined-attack report evidence references | **178 verified / 0 unverified** |
| Report export formats | Markdown and JSON both valid |

The test suite was run in three groups because the execution environment limits individual command duration. One invariance test needs a workspace-local temporary folder because the environment blocks writes to its default Windows sandbox temp folder; the test itself passed when given a writable temporary location.

## Scenario results

| Dataset | Events | Rule detections | Incidents | ML outliers | Expected behaviour |
|---|---:|---:|---:|---:|---|
| `brute_force.csv` | 71 | 1 | 1 | 61 | Brute-force investigation path |
| `combined_attack.csv` | 178 | 12 | 1 | 20 | Full multi-stage investigation demo |
| `compromised_login.csv` | 53 | 5 | 1 | 20 | Credential compromise investigation |
| `data_exfiltration.csv` | 55 | 10 | 1 | 18 | Data collection/exfiltration investigation |
| `normal_activity.csv` | 130 | 0 | 0 | 7 | Benign baseline and empty-state behaviour |
| `port_scan.csv` | 75 | 1 | 1 | 44 | Network reconnaissance investigation |
| `privilege_escalation.csv` | 53 | 5 | 1 | 18 | Privilege-abuse investigation |

All seven CSV files normalized every row successfully.

## Full workflow verification

### Combined attack

- **Incident:** `INC-0001`, High severity, 0.95 confidence, 46 linked evidence events.
- **Triggered rules:** one R001 brute-force detection, three R004 privilege-escalation detections, two R005 sensitive-file detections, and six R006 outbound-transfer detections.
- **Reconstructed stages:** Credential Access → Initial Access → Privilege Escalation → Collection → Exfiltration.
- **Probable root cause:** Compromised administrative credentials through authentication brute force, 0.93 confidence.
- **MITRE evidence:** six mappings: T1110.001, T1078, T1548.003, T1003.008, T1552.004, and T1048.
- **Response priority:** 91/100, Critical; eight evidence-led recommendations generated.
- **Report:** Deterministic fallback report generated successfully and passed grounding validation.

### Normal baseline

- **Deterministic detections:** zero.
- **Formal incidents:** zero.
- **Reconstructed attack stages:** zero.
- **MITRE mappings:** zero.
- **Root-cause result:** `UNKNOWN`, correctly signalling insufficient telemetry evidence rather than inventing an incident.
- **Expected UI outcome:** empty states for incident, reconstruction, MITRE, response, and report views.

## Checked features

| Feature | Verification |
|---|---|
| Dataset switching | All bundled files load through the same pipeline; report state is reset when the evidence source changes. |
| Dashboard | Alert-severity totals, active queue data, severity donut, rule chart, and reconstructed timeline all have valid source data. |
| Telemetry search/filter/export | Filtering is based on event ID, IP, account, host, and raw message; reset uses a Streamlit callback so the visible controls reset as well. CSV export is constructed from all matching rows. |
| Correlated incidents | Evidence lists and incident details use linked IDs from the correlation result. |
| Reconstruction | Attack stages, evidence graph, graph table, and ranked root-cause candidates render from the selected incident. |
| MITRE mapping | Evidence-backed mappings are available for incident scenarios and correctly empty for the benign dataset. |
| ML anomaly view | Score distribution and flagged-event table have valid serializable input for every dataset. |
| Response planning | Risk priority, recommendations, and all eight selectable controls were exercised against the combined attack chain. |
| Report exports | Markdown and JSON exports are valid and contain the expected report sections. |
| Report cache safety | A report regenerates if the active incident changes and clears if the dataset changes. |
| Navigation state | `active_nav_view` is initialized explicitly on fresh page loads, preventing the previous refresh-only `KeyError`. |

## Response-control results on the combined attack

| Control | Modeled coverage | Earliest affected stage |
|---|---:|---|
| MFA | 100% | STEP-0001 |
| Rate Limiting | 100% | STEP-0001 |
| Firewall Filtering | 80% | STEP-0002 |
| Privileged Access Management | 60% | STEP-0003 |
| Endpoint Detection | 60% | STEP-0003 |
| Data Loss Prevention | 40% | STEP-0004 |
| Network Segmentation | 20% | STEP-0005 |
| Egress Filtering | 20% | STEP-0005 |

These are counterfactual estimates based on stage/control coverage, not claims that a control certainly would have prevented the incident.

## Known limits and follow-up items

1. **Streamlit UI test harness cannot run in this execution environment.** It stalls before the app script executes because Windows’ sandbox blocks the local socket operation needed by Streamlit’s `AppTest` runner. This is an environment limitation, not an app exception. The app’s normal browser execution is separate from that runner.
2. **Visual QA still needs a final browser check after any styling change.** Functional data and component rendering were verified programmatically, but exact pixel layout needs a normal local browser session.
3. **ML outlier volume is deliberately high on some focused synthetic datasets.** For example, the brute-force and port-scan files contain homogeneous attack patterns rather than a representative production baseline. Present ML anomaly results as investigation leads, not confirmed attacks.
4. **The project is an offline prototype.** Data arrives from local CSV files; it does not yet ingest live SIEM, firewall, cloud, or endpoint feeds.
5. **The `detection.classifier` module is not part of the active pipeline.** It remains an unimplemented future extension and is not exposed by the current UI.
6. **Response actions are recommendations only.** The application does not automatically block IPs, disable accounts, or modify real infrastructure.

## Recommended presentation dataset

Use **`combined_attack.csv`** for the demo. It exercises every important feature in one sequence: alert queue, incident correlation, five attack stages, six MITRE mappings, response recommendations, defense simulation, and report downloads.

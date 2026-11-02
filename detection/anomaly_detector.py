"""
Anomaly Detector Module (Phase 8)
==================================
Unsupervised machine-learning threat anomaly detection for CyberTrace using Isolation Forest.

Key Principles:
    - Independent Stage: Supplements, rather than replaces, deterministic rules R001-R006.
    - Zero Data Leakage: Features never use raw IP addresses, usernames, hostnames,
      event IDs, scenario filenames, or synthetic attack labels.
    - Strictly Unsupervised: Trained exclusively on benign baseline activity (`normal_activity.csv`).
    - Explainable & Traceable: Flags specific feature divergences from baseline telemetry
      and preserves links to original event_ids and raw log messages.
    - No False Certainty: Anomaly scores reflect statistical divergence from baseline,
      NOT confirmed attack probabilities or malicious intent.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Union, Set, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest

from preprocessing.event_schema import NormalizedEvent


# =============================================================================
# 1. ANOMALY RESULT DATA MODEL
# =============================================================================

@dataclass
class AnomalyResult:
    """
    Structured anomaly detection result produced by the ML anomaly detector.
    """
    event_id: str
    anomaly_score: float             # Normalized anomaly intensity in [0.0, 1.0], higher = more anomalous
    is_anomaly: bool                 # Boolean flag (True = flagged as outlier by Isolation Forest)
    decision_score: float            # Raw decision_function output from Isolation Forest (negative = outlier)
    model_name: str = "IsolationForest"
    model_version: str = "0.1.0"
    explanation: str = ""            # Human-readable factual summary of diverging feature characteristics
    contributing_factors: List[str] = field(default_factory=list) # Contributing factor details
    feature_values: Dict[str, float] = field(default_factory=dict) # Extracted numerical feature dictionary
    supporting_event_id: str = ""    # Traceability link to original NormalizedEvent.event_id
    raw_message: str = ""            # Verbatim raw audit log line
    disclaimer: str = (
        "Statistical anomaly signal only. An anomaly indicates divergence from benign baseline "
        "telemetry and does NOT constitute proof of malicious activity or an attack."
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert the anomaly result to a serializable dictionary."""
        return {
            "event_id": self.event_id,
            "anomaly_score": round(self.anomaly_score, 4),
            "is_anomaly": self.is_anomaly,
            "decision_score": round(self.decision_score, 4),
            "model_name": self.model_name,
            "model_version": self.model_version,
            "explanation": self.explanation,
            "contributing_factors": self.contributing_factors,
            "feature_values": {k: round(v, 4) for k, v in self.feature_values.items()},
            "supporting_event_id": self.supporting_event_id,
            "raw_message": self.raw_message,
            "disclaimer": self.disclaimer,
        }


# =============================================================================
# 2. CONFIGURATION
# =============================================================================

@dataclass
class AnomalyDetectorConfig:
    """
    Configuration options for the Isolation Forest Anomaly Detector.
    """
    contamination: float = 0.05
    n_estimators: int = 100
    max_samples: Union[str, int, float] = "auto"
    random_state: int = 42
    rolling_window_seconds: int = 120
    score_threshold: float = 0.50


# =============================================================================
# 3. FEATURE EXTRACTION
# =============================================================================

class EventFeatureExtractor:
    """
    Deterministic, leakage-free numerical feature extractor for NormalizedEvents.

    Extracts:
        - Severity level numeric mapping
        - Intrinsic event category flags (auth, network, file, process, privilege)
        - Port characteristics (privileged, ephemeral, presence)
        - Vocabulary-based one-hot categorical features learned from training data
        - Chronological rolling window contextual aggregations
    """

    def __init__(self, rolling_window_seconds: int = 120):
        self.rolling_window_seconds = rolling_window_seconds
        self.training_sources: Set[str] = set()
        self.training_event_types: Set[str] = set()
        self.training_actions: Set[str] = set()
        self.training_processes: Set[str] = set()
        self.feature_names: List[str] = []
        self.baseline_stats: Dict[str, Dict[str, float]] = {}
        self.is_fitted: bool = False

    def fit(self, events: List[NormalizedEvent]) -> "EventFeatureExtractor":
        """Learn categorical vocabularies and baseline feature distributions from training events."""
        if not events:
            raise ValueError("Cannot fit EventFeatureExtractor on empty event list.")

        # Learn vocabularies strictly from training baseline
        self.training_sources = {e.source.lower() for e in events if e.source}
        self.training_event_types = {e.event_type.lower() for e in events if e.event_type}
        self.training_actions = {e.action.lower() for e in events if e.action}
        self.training_processes = {e.process.lower() for e in events if e.process}

        # Build feature names
        self.feature_names = self._build_feature_names()

        # Compute baseline feature distributions
        X = self._extract_raw_matrix(events)
        self.baseline_stats = {}
        for col_idx, feat_name in enumerate(self.feature_names):
            vals = X[:, col_idx]
            self.baseline_stats[feat_name] = {
                "mean": float(np.mean(vals)),
                "std": float(np.std(vals)),
                "min": float(np.min(vals)),
                "max": float(np.max(vals)),
            }

        self.is_fitted = True
        return self

    def _build_feature_names(self) -> List[str]:
        """Construct deterministic feature name list."""
        names = [
            "severity_num",
            "is_auth_event",
            "is_network_event",
            "is_file_event",
            "is_process_event",
            "is_privilege_event",
            "has_dst_port",
            "dst_port_privileged",
            "dst_port_ephemeral",
            "has_src_port",
            "src_port_ephemeral",
        ]
        # Vocabulary features sorted for reproducibility
        for s in sorted(self.training_sources):
            names.append(f"src_{s}")
        names.append("src_other")

        for et in sorted(self.training_event_types):
            names.append(f"ev_type_{et}")
        names.append("ev_type_other")

        for act in sorted(self.training_actions):
            names.append(f"act_{act}")
        names.append("act_other")

        for pr in sorted(self.training_processes):
            names.append(f"proc_{pr}")
        names.extend([
            "proc_is_shell",
            "proc_is_priv",
            "proc_is_transfer",
            "proc_is_archive",
            "proc_other",
        ])

        # Rolling window features
        names.extend([
            "rolling_events_window",
            "rolling_failed_auth_window",
            "rolling_unique_ports_window",
            "rolling_priv_events_window",
            "time_delta_to_prev_sec",
        ])
        return names

    def transform(self, events: List[NormalizedEvent]) -> np.ndarray:
        """Transform events into a 2D numpy array of shape (len(events), n_features)."""
        if not self.is_fitted:
            raise RuntimeError("EventFeatureExtractor must be fitted before calling transform().")
        if not events:
            return np.empty((0, len(self.feature_names)), dtype=float)

        return self._extract_raw_matrix(events)

    def extract_feature_dicts(self, events: List[NormalizedEvent]) -> List[Dict[str, float]]:
        """Extract feature dictionaries for each event."""
        X = self.transform(events)
        result = []
        for row in X:
            feat_dict = {name: float(val) for name, val in zip(self.feature_names, row)}
            result.append(feat_dict)
        return result

    def _extract_raw_matrix(self, events: List[NormalizedEvent]) -> np.ndarray:
        """Internal helper to convert event list into numerical feature matrix."""
        if not events:
            return np.empty((0, len(self.feature_names)), dtype=float)

        # Robust, deterministic chronological ordering
        # Handles missing/None timestamps and ties in timestamps explicitly
        def _get_sort_key(idx: int) -> Tuple[datetime, str, int]:
            e = events[idx]
            t = getattr(e, "timestamp", None)
            if not isinstance(t, datetime):
                t = datetime.min
            eid = getattr(e, "event_id", "") or ""
            return (t, eid, idx)

        sorted_indices = sorted(range(len(events)), key=_get_sort_key)
        sorted_events = [events[idx] for idx in sorted_indices]
        timestamps = [
            e.timestamp if isinstance(getattr(e, "timestamp", None), datetime) else datetime.min
            for e in sorted_events
        ]

        rows = []
        # Precompute chronological index mapping
        idx_to_sorted_pos = {orig_idx: pos for pos, orig_idx in enumerate(sorted_indices)}

        for orig_idx, event in enumerate(events):
            pos = idx_to_sorted_pos[orig_idx]
            curr_t = timestamps[pos]

            # Rolling window calculations: strictly causal (past-to-present, back_pos <= pos)
            w_seconds = self.rolling_window_seconds
            window_events = []
            for back_pos in range(pos, -1, -1):
                cand_t = timestamps[back_pos]
                dt = (curr_t - cand_t).total_seconds()
                if dt < 0:
                    dt = 0
                if dt <= w_seconds:
                    window_events.append(sorted_events[back_pos])
                else:
                    break

            rolling_events_count = float(len(window_events))
            failed_count = float(sum(
                1 for e in window_events
                if getattr(e, "is_auth_event", False) and (
                    "fail" in (getattr(e, "event_type", "") or "").lower()
                    or "fail" in (getattr(e, "action", "") or "").lower()
                    or "invalid" in (getattr(e, "raw_message", "") or "").lower()
                )
            ))
            unique_dst_ports = float(len({
                e.destination_port for e in window_events
                if getattr(e, "destination_port", None) is not None and e.destination_port > 0
            }))
            priv_count = float(sum(1 for e in window_events if getattr(e, "is_privilege_event", False)))

            if pos > 0:
                prev_t = timestamps[pos - 1]
                delta_prev = float(min(max((curr_t - prev_t).total_seconds(), 0.0), 600.0))
            else:
                delta_prev = 0.0

            # Severity numeric
            sev_map = {"info": 0.0, "low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}
            sev_val = sev_map.get(str(getattr(event, "severity", "low")).lower(), 1.0)

            # Ports
            dst_p = getattr(event, "destination_port", None)
            has_dst_p = 1.0 if (dst_p is not None and dst_p > 0) else 0.0
            dst_priv = 1.0 if (dst_p is not None and 1 <= dst_p < 1024) else 0.0
            dst_ephem = 1.0 if (dst_p is not None and dst_p >= 10000) else 0.0

            src_p = getattr(event, "source_port", None)
            has_src_p = 1.0 if (src_p is not None and src_p > 0) else 0.0
            src_ephem = 1.0 if (src_p is not None and src_p >= 10000) else 0.0

            # Categorical strings
            src_str = (getattr(event, "source", "") or "").lower()
            et_str = (getattr(event, "event_type", "") or "").lower()
            act_str = (getattr(event, "action", "") or "").lower()
            proc_str = (getattr(event, "process", "") or "").lower()

            row = [
                sev_val,
                1.0 if getattr(event, "is_auth_event", False) else 0.0,
                1.0 if getattr(event, "is_network_event", False) else 0.0,
                1.0 if getattr(event, "is_file_event", False) else 0.0,
                1.0 if getattr(event, "is_process_event", False) else 0.0,
                1.0 if getattr(event, "is_privilege_event", False) else 0.0,
                has_dst_p,
                dst_priv,
                dst_ephem,
                has_src_p,
                src_ephem,
            ]

            # Sources
            src_matched = False
            for s in sorted(self.training_sources):
                if src_str == s:
                    row.append(1.0)
                    src_matched = True
                else:
                    row.append(0.0)
            row.append(0.0 if src_matched else 1.0)

            # Event types
            et_matched = False
            for et in sorted(self.training_event_types):
                if et_str == et:
                    row.append(1.0)
                    et_matched = True
                else:
                    row.append(0.0)
            row.append(0.0 if et_matched else 1.0)

            # Actions
            act_matched = False
            for act in sorted(self.training_actions):
                if act_str == act:
                    row.append(1.0)
                    act_matched = True
                else:
                    row.append(0.0)
            row.append(0.0 if act_matched else 1.0)

            # Processes
            proc_matched = False
            for pr in sorted(self.training_processes):
                if proc_str == pr:
                    row.append(1.0)
                    proc_matched = True
                else:
                    row.append(0.0)

            is_shell = 1.0 if proc_str in {"sh", "bash", "zsh", "dash"} else 0.0
            is_priv = 1.0 if proc_str in {"sudo", "su", "pkexec"} else 0.0
            is_trans = 1.0 if proc_str in {"curl", "wget", "rsync", "scp"} else 0.0
            is_arch = 1.0 if proc_str in {"tar", "zip", "gzip", "7z"} else 0.0
            is_other_proc = 1.0 if (not proc_matched and not (is_shell or is_priv or is_trans or is_arch) and bool(proc_str)) else 0.0

            row.extend([is_shell, is_priv, is_trans, is_arch, is_other_proc])

            # Rolling metrics
            row.extend([
                rolling_events_count,
                failed_count,
                unique_dst_ports,
                priv_count,
                delta_prev,
            ])

            rows.append(row)

        return np.array(rows, dtype=float)


# =============================================================================
# 4. ANOMALY DETECTOR ENGINE
# =============================================================================

class AnomalyDetector:
    """
    Unsupervised ML-based anomaly detector using Isolation Forest for defensive security logs.
    """

    def __init__(self, config: Optional[AnomalyDetectorConfig] = None):
        self.config = config or AnomalyDetectorConfig()
        self.extractor = EventFeatureExtractor(rolling_window_seconds=self.config.rolling_window_seconds)
        self.model: Optional[IsolationForest] = None
        self.is_fitted: bool = False
        self.training_event_count: int = 0

    def fit(self, events: List[NormalizedEvent]) -> "AnomalyDetector":
        """
        Train the Isolation Forest model on benign baseline telemetry.

        Args:
            events: List of NormalizedEvent instances (e.g. from normal_activity.csv).

        Returns:
            Fitted AnomalyDetector instance.
        """
        if not events:
            raise ValueError("Cannot fit AnomalyDetector on an empty event list.")

        self.extractor.fit(events)
        X = self.extractor.transform(events)

        self.model = IsolationForest(
            contamination=self.config.contamination,
            n_estimators=self.config.n_estimators,
            max_samples=self.config.max_samples,
            random_state=self.config.random_state,
        )
        self.model.fit(X)
        self.is_fitted = True
        self.training_event_count = len(events)
        return self

    def predict(self, events: List[NormalizedEvent]) -> List[AnomalyResult]:
        """
        Score and classify security events for anomalies.

        Args:
            events: List of NormalizedEvent instances to evaluate.

        Returns:
            List of AnomalyResult instances.
        """
        if not self.is_fitted or self.model is None:
            raise RuntimeError(
                "AnomalyDetector has not been fitted yet. Call fit() with baseline training events first."
            )

        if not events:
            return []

        X = self.extractor.transform(events)
        raw_preds = self.model.predict(X)              # +1 inlier, -1 outlier
        raw_scores = self.model.decision_function(X)    # Negative = outlier

        results: List[AnomalyResult] = []

        for idx, event in enumerate(events):
            dec_score = float(raw_scores[idx])
            is_anom = bool(raw_preds[idx] == -1)

            # Normalized anomaly score: higher = more anomalous in [0.0, 1.0]
            # Decision function: 0.0 is boundary. Negative is outlier, positive is inlier.
            norm_score = float(np.clip(0.5 - dec_score, 0.0, 1.0))

            feat_dict = {
                name: float(val) for name, val in zip(self.extractor.feature_names, X[idx])
            }

            factors, explanation = self._generate_explanation(event, feat_dict, is_anom)

            res = AnomalyResult(
                event_id=event.event_id,
                anomaly_score=norm_score,
                is_anomaly=is_anom,
                decision_score=dec_score,
                model_name="IsolationForest",
                model_version="0.1.0",
                explanation=explanation,
                contributing_factors=factors,
                feature_values=feat_dict,
                supporting_event_id=event.event_id,
                raw_message=getattr(event, "raw_message", ""),
            )
            results.append(res)

        return results

    def fit_predict(self, events: List[NormalizedEvent]) -> List[AnomalyResult]:
        """Convenience method to fit on events and score them."""
        self.fit(events)
        return self.predict(events)

    def _generate_explanation(
        self,
        event: NormalizedEvent,
        feat_dict: Dict[str, float],
        is_anom: bool,
    ) -> Tuple[List[str], str]:
        """
        Derive factual, objective explanation by comparing event features to baseline statistics.

        Audited in Phase 8.1:
            - Distinguishes intrinsic event attributes from ambient/neighboring window context.
            - Uses neutral, statistical terminology rather than claiming malicious certainty.
            - Explicitly reports rolling window scopes when reporting concurrent activity.
            - Bases explanations strictly on actual extracted features (e.g. src_other) rather than
              inventing ad-hoc heuristic rules.
        """
        factors: List[str] = []

        # 1. Failed authentication context (differentiating event vs ambient context)
        failed_count = feat_dict.get("rolling_failed_auth_window", 0.0)
        if failed_count > 0:
            if getattr(event, "is_auth_event", False):
                factors.append(
                    f"Elevated failed authentication frequency: {int(failed_count)} failure(s) in preceding {self.config.rolling_window_seconds}s window (baseline: 0)"
                )
            else:
                factors.append(
                    f"Concurrent temporal context: {int(failed_count)} failed authentication attempt(s) observed across telemetry stream within preceding {self.config.rolling_window_seconds}s window"
                )

        # 2. Elevated severity
        sev_val = feat_dict.get("severity_num", 1.0)
        if sev_val > 1.0:
            factors.append(
                f"Elevated event severity: '{event.severity}' (baseline: low)"
            )

        # 3. Privilege escalation or administrative execution indicator
        is_priv_evt = feat_dict.get("is_privilege_event", 0.0)
        proc_priv = feat_dict.get("proc_is_priv", 0.0)
        if is_priv_evt > 0.0 or proc_priv > 0.0:
            proc_desc = f" (process: '{event.process}')" if getattr(event, "process", None) else ""
            factors.append(
                f"Privilege modification or administrative execution indicator{proc_desc}"
            )

        # 4. Unobserved event source (grounded in actual src_other feature)
        src_other = feat_dict.get("src_other", 0.0)
        if src_other > 0.0:
            factors.append(
                f"Unobserved log source '{event.source}' outside baseline training vocabulary"
            )

        # 5. Unobserved event type
        ev_other = feat_dict.get("ev_type_other", 0.0)
        if ev_other > 0.0:
            factors.append(
                f"Unobserved event type '{event.event_type}' outside baseline training vocabulary"
            )

        # 6. Unobserved action
        act_other = feat_dict.get("act_other", 0.0)
        if act_other > 0.0:
            factors.append(
                f"Unobserved action '{event.action}' outside baseline training vocabulary"
            )

        # 7. Novel or special process
        proc_trans = feat_dict.get("proc_is_transfer", 0.0)
        proc_arch = feat_dict.get("proc_is_archive", 0.0)
        proc_shell = feat_dict.get("proc_is_shell", 0.0)
        proc_other = feat_dict.get("proc_other", 0.0)
        if proc_trans > 0.0:
            factors.append(f"Network data transfer utility executed: '{event.process}'")
        elif proc_arch > 0.0:
            factors.append(f"File compression utility executed: '{event.process}'")
        elif proc_shell > 0.0:
            factors.append(f"Command interpreter execution: '{event.process}'")
        elif proc_other > 0.0 and getattr(event, "process", None):
            factors.append(f"Unobserved process '{event.process}' outside baseline training vocabulary")

        # 8. Port distribution (differentiating event vs ambient context)
        unique_ports = feat_dict.get("rolling_unique_ports_window", 0.0)
        if unique_ports > 3:
            if getattr(event, "is_network_event", False):
                factors.append(
                    f"Multi-port contact frequency: {int(unique_ports)} distinct destination ports contacted within {self.config.rolling_window_seconds}s window"
                )
            else:
                factors.append(
                    f"Concurrent temporal context: {int(unique_ports)} distinct destination ports contacted across telemetry stream within {self.config.rolling_window_seconds}s window"
                )

        # 9. High burst density
        density = feat_dict.get("rolling_events_window", 0.0)
        base_max_density = self.extractor.baseline_stats.get("rolling_events_window", {}).get("max", 5.0)
        if density > max(base_max_density, 5.0):
            factors.append(
                f"Elevated event burst density: {int(density)} events within {self.config.rolling_window_seconds}s window (baseline max: {int(base_max_density)})"
            )

        # 10. Inter-event timing anomaly
        delta_val = feat_dict.get("time_delta_to_prev_sec", 0.0)
        base_max_delta = self.extractor.baseline_stats.get("time_delta_to_prev_sec", {}).get("max", 60.0)
        if delta_val > max(base_max_delta * 1.5, 90.0):
            factors.append(
                f"Extended inter-event time gap: {int(delta_val)}s elapsed since preceding event (baseline max: {int(base_max_delta)}s)"
            )

        if not factors:
            if is_anom:
                explanation = "Statistical baseline divergence: Divergence across joint feature distribution without single dominant attribute."
            else:
                explanation = "Consistent with normal baseline behavioral distributions."
        else:
            if is_anom:
                explanation = "Statistical baseline divergence: " + "; ".join(factors) + "."
            else:
                explanation = "Sub-threshold baseline variance: " + "; ".join(factors) + "."

        return factors, explanation


# =============================================================================
# 5. CONVENIENCE FUNCTIONAL API
# =============================================================================

def detect_anomalies(
    events: List[NormalizedEvent],
    detector: Optional[AnomalyDetector] = None,
    training_events: Optional[List[NormalizedEvent]] = None,
) -> List[AnomalyResult]:
    """
    Run ML-based anomaly detection on normalized events.

    Args:
        events: List of NormalizedEvent instances to score.
        detector: Optional pre-fitted AnomalyDetector instance.
        training_events: Optional training baseline events to fit detector if detector is None.

    Returns:
        List of AnomalyResult objects for each event in `events`.
    """
    if not events:
        return []

    if detector is not None:
        return detector.predict(events)

    # Initialize new detector
    new_detector = AnomalyDetector()

    if training_events:
        new_detector.fit(training_events)
    else:
        # Attempt to load default baseline dataset if available
        import os
        from preprocessing.log_parser import parse_log_file

        base_path = os.path.join("data", "sample_attacks", "normal_activity.csv")
        if os.path.exists(base_path):
            res = parse_log_file(base_path)
            new_detector.fit(res.events)
        else:
            # Fall back to self-fitting if large enough, else return empty
            if len(events) >= 5:
                new_detector.fit(events)
            else:
                return []

    return new_detector.predict(events)

from response import calculate_risk_score, recommend_actions, run_what_if_analysis


def _incident():
    return {
        "severity": "CRITICAL", "confidence": 0.9, "detection_count": 5,
        "event_ids": ["EVT-1", "EVT-2", "EVT-3"], "source_ips": ["10.0.0.1"],
        "hostnames": ["server-a"], "attack_chain": {"steps": [
            {"step_id": "STEP-0001", "stage": "CREDENTIAL_ACCESS"},
            {"step_id": "STEP-0002", "stage": "PRIVILEGE_ESCALATION"},
            {"step_id": "STEP-0003", "stage": "EXFILTRATION"},
        ]}, "root_cause": {"candidate_type": "CREDENTIAL_COMPROMISE"},
    }


def test_risk_score_is_explainable_and_bounded():
    result = calculate_risk_score(_incident())
    assert result["risk_level"] == "CRITICAL"
    assert 0 <= result["overall_score"] <= 100
    assert 0 <= result["confidence"] <= 0.95
    assert result["factors"]["potential_impact"]["high_impact_stage_present"]


def test_recommendations_follow_evidence():
    actions = recommend_actions(_incident())
    text = " ".join(item["action"] for item in actions)
    assert "MFA" in text
    assert "sudo" in text
    assert "egress" in text
    assert len({item["action"] for item in actions}) == len(actions)


def test_counterfactual_uses_earliest_matching_stage():
    result = run_what_if_analysis(_incident()["attack_chain"], ["MFA", "EGRESS_FILTERING"])
    assert result["blocked_at"]["step_id"] == "STEP-0001"
    assert result["prevented_steps"] == ["STEP-0001", "STEP-0002", "STEP-0003"]
    assert result["effectiveness"] == 100


def test_counterfactual_reports_no_coverage_honestly():
    result = run_what_if_analysis(_incident()["attack_chain"], ["EMAIL_FILTERING"])
    assert result["blocked_at"] is None
    assert result["effectiveness"] == 0

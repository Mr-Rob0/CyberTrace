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


def test_recommendations_for_discovery_and_insider_data_access():
    inc_discovery = {
        "severity": "MEDIUM", "confidence": 0.8, "detection_count": 1,
        "attack_chain": {"steps": [{"step_id": "STEP-0001", "stage": "DISCOVERY"}]},
        "root_cause": {"candidate_type": "UNKNOWN"},
    }
    actions_disc = recommend_actions(inc_discovery)
    text_disc = " ".join(item["action"] for item in actions_disc)
    assert "port-scan" in text_disc or "network services" in text_disc

    inc_insider = {
        "severity": "HIGH", "confidence": 0.85, "detection_count": 2,
        "attack_chain": {"steps": [
            {"step_id": "STEP-0001", "stage": "COLLECTION"},
            {"step_id": "STEP-0002", "stage": "EXFILTRATION"},
        ]},
        "root_cause": {"candidate_type": "INSIDER_DATA_ACCESS"},
    }
    actions_insider = recommend_actions(inc_insider)
    text_insider = " ".join(item["action"] for item in actions_insider)
    assert "local file access" in text_insider or "staging" in text_insider


def test_what_if_analysis_with_dlp_and_firewall():
    chain = {
        "steps": [
            {"step_id": "STEP-0001", "stage": "DISCOVERY"},
            {"step_id": "STEP-0002", "stage": "COLLECTION"},
            {"step_id": "STEP-0003", "stage": "EXFILTRATION"},
        ]
    }
    res_fw = run_what_if_analysis(chain, ["FIREWALL_FILTERING"])
    assert res_fw["blocked_at"]["step_id"] == "STEP-0001"
    assert res_fw["prevented_steps"] == ["STEP-0001", "STEP-0002", "STEP-0003"]
    assert res_fw["unmitigated_steps"] == []
    assert res_fw["effectiveness"] == 100

    res_dlp = run_what_if_analysis(chain, ["DATA_LOSS_PREVENTION"])
    assert res_dlp["blocked_at"]["step_id"] == "STEP-0002"
    assert res_dlp["prevented_steps"] == ["STEP-0002", "STEP-0003"]
    assert res_dlp["unmitigated_steps"] == ["STEP-0001"]
    assert res_dlp["effectiveness"] == 67


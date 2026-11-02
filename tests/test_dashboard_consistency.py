"""Regression tests for dashboard alert/telemetry count consistency."""

from types import SimpleNamespace

from app import count_severities, create_severity_donut


def test_alert_severity_cards_and_donut_share_one_tally():
    """The chart must faithfully represent the same alert set as the KPI cards."""
    alerts = [
        SimpleNamespace(severity="HIGH"),
        SimpleNamespace(severity="high"),
        SimpleNamespace(severity="medium"),
    ]

    counts = count_severities(alerts)
    chart = create_severity_donut(
        alerts,
        title="Rule Alert Severity (3 total)",
        record_label="rule alerts",
    )

    assert counts == {
        "critical": 0,
        "high": 2,
        "medium": 1,
        "low": 0,
        "info": 0,
    }
    assert sum(chart.data[0].values) == sum(counts.values()) == len(alerts)
    assert list(chart.data[0].labels) == ["HIGH", "MEDIUM"]


def test_empty_alert_set_has_an_explicit_empty_chart():
    """An empty alert set must not be rendered as fabricated severity data."""
    chart = create_severity_donut([], title="Rule Alert Severity (0 total)", record_label="rule alerts")

    assert not chart.data
    assert chart.layout.annotations[0].text == "No rule alerts"

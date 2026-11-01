"""Release smoke check for the primary CyberTrace Streamlit workflows.

Run with ``venv\\Scripts\\python.exe scripts\\verify_ui.py``. The check uses
Streamlit's native test harness and does not start a browser or network service.
"""

import os

from streamlit.testing.v1 import AppTest


def _messages(elements):
    return [str(getattr(element, "value", "")) for element in elements]


def audit_app_ui_flow():
    app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
    app = AppTest.from_file(app_path, default_timeout=30)

    app.run()
    assert not app.exception, f"Initial app load produced exception: {app.exception}"
    assert app.selectbox(key="selected_dataset").value == "combined_attack.csv"
    navigation = app.radio(key="workspace_section")
    assert "Response" in navigation.options

    navigation.set_value("Response").run()
    assert not app.exception, f"Response Planning produced exception: {app.exception}"
    metric_labels = [metric.label for metric in app.metric]
    assert {"Response Priority", "Risk Level", "Evidence Confidence"}.issubset(metric_labels)
    assert app.multiselect(key="what_if_defenses").value == ["MFA"]
    assert any("Earliest potentially disrupted step" in message for message in _messages(app.success))

    app.multiselect(key="what_if_defenses").set_value(["Network Segmentation"]).run()
    assert not app.exception, f"What-if control change produced exception: {app.exception}"
    assert any("Earliest potentially disrupted step" in message for message in _messages(app.success))

    app.selectbox(key="selected_dataset").set_value("normal_activity.csv").run()
    assert not app.exception, f"Benign response state produced exception: {app.exception}"
    assert any("No incident available" in message for message in _messages(app.markdown))
    print("CyberTrace UI release smoke check passed.")


if __name__ == "__main__":
    audit_app_ui_flow()

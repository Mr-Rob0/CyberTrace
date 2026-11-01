"""
Timeline Visualization Module
==============================
Creates interactive timeline charts using Plotly to show the
chronological sequence of reconstructed attack events and stages.
"""

from datetime import datetime
from typing import List, Dict, Any, Union, Optional
import plotly.graph_objects as go

# Curated stage palette consistent with CyberTrace dark design tokens
STAGE_COLORS: Dict[str, str] = {
    "INITIAL_ACCESS": "#58A6FF",
    "EXECUTION": "#79C0FF",
    "PERSISTENCE": "#BC8CFF",
    "PRIVILEGE_ESCALATION": "#D29922",
    "DEFENSE_EVASION": "#BB8009",
    "CREDENTIAL_ACCESS": "#58A6FF",
    "DISCOVERY": "#8B949E",
    "LATERAL_MOVEMENT": "#F778BA",
    "COLLECTION": "#BC8CFF",
    "EXFILTRATION": "#F85149",
    "IMPACT": "#DA3633",
}

DEFAULT_STAGE_COLOR = "#58A6FF"


def _parse_timestamp(val: Any) -> Optional[datetime]:
    """Robust timestamp extractor supporting datetime, ISO strings, and standard log timestamps."""
    if isinstance(val, datetime):
        return val
    if isinstance(val, str) and val.strip():
        s = val.strip()
        # Try ISO format
        try:
            return datetime.fromisoformat(s)
        except Exception:
            pass
        # Try standard space-separated format
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%b %d %H:%M:%S"):
            try:
                return datetime.strptime(s, fmt)
            except Exception:
                pass
    return None


def render_timeline(timeline_data: Any) -> go.Figure:
    """
    Create an interactive Plotly figure showing the chronological sequence of events or attack stages.

    Ensures chronological ordering so progression lines never zigzag even if input events
    arrive unordered or from disparate sources.

    Args:
        timeline_data: An AttackChain instance, list of AttackStep objects,
                       list of NormalizedEvent objects, or list of event dicts.

    Returns:
        A Plotly go.Figure object ready for display via st.plotly_chart.
    """
    fig = go.Figure()

    if not timeline_data:
        fig.update_layout(
            title=dict(text="No timeline data available", font=dict(size=12, color="#8B949E")),
            paper_bgcolor="#0D1117",
            plot_bgcolor="#0D1117",
            height=200,
        )
        return fig

    # Handle AttackChain object
    steps = getattr(timeline_data, "steps", None)
    if steps is not None:
        items = steps
    elif isinstance(timeline_data, list):
        items = timeline_data
    else:
        items = [timeline_data]

    parsed_entries = []

    for item in items:
        # Determine timestamp with fallback hierarchy
        ts = None
        if hasattr(item, "timestamp_start") and item.timestamp_start:
            ts = _parse_timestamp(item.timestamp_start)
        elif hasattr(item, "timestamp_end") and item.timestamp_end:
            ts = _parse_timestamp(item.timestamp_end)
        elif hasattr(item, "timestamp") and item.timestamp:
            ts = _parse_timestamp(item.timestamp)
        elif isinstance(item, dict):
            for k in ("timestamp_start", "timestamp", "timestamp_end"):
                if item.get(k):
                    ts = _parse_timestamp(item[k])
                    if ts:
                        break

        if not ts:
            ts = datetime.now()

        # Determine stage or title
        stage = getattr(item, "stage", None) or (item.get("stage") if isinstance(item, dict) else None)
        title = getattr(item, "title", None) or getattr(item, "event_type", None) or (
            item.get("title") or item.get("event_type") if isinstance(item, dict) else str(item)
        )
        step_id = getattr(item, "step_id", None) or getattr(item, "event_id", None) or (
            item.get("step_id") or item.get("event_id") if isinstance(item, dict) else ""
        )
        raw_conf = getattr(item, "confidence", None) if hasattr(item, "confidence") else (
            item.get("confidence") if isinstance(item, dict) else None
        )
        conf = float(raw_conf) if raw_conf is not None else None

        raw_eids = getattr(item, "event_ids", None) if hasattr(item, "event_ids") else (
            item.get("event_ids") if isinstance(item, dict) else None
        )
        ev_count = len(raw_eids) if isinstance(raw_eids, list) else 1

        stage_name = str(stage).upper() if stage else "ACTIVITY"
        c = STAGE_COLORS.get(stage_name, DEFAULT_STAGE_COLOR)

        label_txt = f"{step_id}: {stage_name}" if step_id else stage_name
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")

        tip = (
            f"<b>{step_id}: {title}</b><br>"
            f"Stage: {stage_name}<br>"
            + (f"Confidence: {conf:.2f}<br>" if conf is not None else "")
            + f"Time: {ts_str}<br>"
            f"Evidence: {ev_count} event(s)"
        )

        parsed_entries.append((ts, label_txt, c, tip))

    if not parsed_entries:
        fig.update_layout(
            title=dict(text="No chronological events to display", font=dict(size=12, color="#8B949E")),
            paper_bgcolor="#0D1117",
            plot_bgcolor="#0D1117",
            height=200,
        )
        return fig

    # Sort strictly chronologically by timestamp
    parsed_entries.sort(key=lambda entry: entry[0])

    times = [e[0] for e in parsed_entries]
    labels = [e[1] for e in parsed_entries]
    colors = [e[2] for e in parsed_entries]
    tooltips = [e[3] for e in parsed_entries]

    # Add progression line and markers
    fig.add_trace(
        go.Scatter(
            x=times,
            y=[1] * len(times),
            mode="lines+markers",
            line=dict(color="#21262D", width=2),
            marker=dict(
                size=14,
                color=colors,
                symbol="circle",
                line=dict(color="#0D1117", width=2),
            ),
            hovertext=tooltips,
            hoverinfo="text",
            showlegend=False,
        )
    )

    # Add stage badge annotations above each point
    for t, lbl, c in zip(times, labels, colors):
        fig.add_annotation(
            x=t,
            y=1.05,
            text=f"<b>{lbl}</b>",
            showarrow=False,
            font=dict(color=c, size=9, family="JetBrains Mono"),
            bgcolor="#0D1117",
            bordercolor="#21262D",
            borderwidth=1,
            borderpad=3,
        )

    fig.update_layout(
        title=dict(text="Reconstructed Attack Timeline", font=dict(size=12, color="#C9D1D9")),
        xaxis=dict(title="Timestamp", gridcolor="#21262D", zeroline=False, color="#8B949E"),
        yaxis=dict(showticklabels=False, range=[0.92, 1.18], showgrid=False, zeroline=False),
        paper_bgcolor="#0D1117",
        plot_bgcolor="#0D1117",
        height=220,
        margin=dict(l=20, r=20, t=35, b=25),
    )
    return fig

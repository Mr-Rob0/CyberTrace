"""
Graph Visualization Module
===========================
Creates interactive attack graph visualizations using Plotly and NetworkX
to show causal, evidentiary, and chronological relationships between attack stages.
"""

from typing import Any, Dict, List, Optional
import networkx as nx
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

RELATIONSHIP_COLORS: Dict[str, str] = {
    "leads_to": "#58A6FF",
    "supports": "#D29922",
    "precedes": "#8B949E",
}


def render_attack_graph(graph_data: Any) -> go.Figure:
    """
    Create an interactive directed graph visualization of an attack chain.

    Args:
        graph_data: An AttackGraph instance, a NetworkX DiGraph, or a dictionary representation.

    Returns:
        A Plotly go.Figure object displaying the directed attack graph.
    """
    fig = go.Figure()

    if not graph_data:
        fig.update_layout(
            title=dict(text="No attack graph data available", font=dict(size=12, color="#8B949E")),
            paper_bgcolor="#0D1117",
            plot_bgcolor="#0D1117",
            height=260,
        )
        return fig

    # Extract nodes and edges
    nodes_dict: Dict[str, Dict[str, Any]] = {}
    edges_list: List[Dict[str, Any]] = []

    if isinstance(graph_data, nx.DiGraph):
        for n, data in graph_data.nodes(data=True):
            nodes_dict[n] = {
                "node_id": n,
                "stage": data.get("stage", "OTHER"),
                "title": data.get("title", n),
                "confidence": data.get("confidence", 0.8),
                "event_ids": data.get("event_ids", []),
            }
        for u, v, data in graph_data.edges(data=True):
            edges_list.append({
                "source": u,
                "target": v,
                "relationship": data.get("relationship", "precedes"),
                "description": data.get("description", ""),
            })
    elif hasattr(graph_data, "nodes") and hasattr(graph_data, "edges"):
        # AttackGraph instance
        for nid, n in graph_data.nodes.items():
            nodes_dict[nid] = {
                "node_id": getattr(n, "node_id", nid),
                "stage": getattr(n, "stage", "OTHER"),
                "title": getattr(n, "title", nid),
                "confidence": getattr(n, "confidence", 0.8),
                "event_ids": getattr(n, "event_ids", []),
            }
        for e in graph_data.edges:
            edges_list.append({
                "source": getattr(e, "source", None),
                "target": getattr(e, "target", None),
                "relationship": getattr(e, "relationship", "precedes"),
                "description": getattr(e, "description", ""),
            })
    elif isinstance(graph_data, dict):
        raw_nodes = graph_data.get("nodes", [])
        if isinstance(raw_nodes, list):
            for n in raw_nodes:
                nid = n.get("node_id") or n.get("id") or "NODE"
                nodes_dict[nid] = {
                    "node_id": nid,
                    "stage": n.get("stage", "OTHER"),
                    "title": n.get("title", nid),
                    "confidence": n.get("confidence", 0.8),
                    "event_ids": n.get("event_ids", []),
                }
        for e in graph_data.get("edges", []):
            edges_list.append({
                "source": e.get("source"),
                "target": e.get("target"),
                "relationship": e.get("relationship", "precedes"),
                "description": e.get("description", ""),
            })

    if not nodes_dict:
        fig.add_annotation(
            x=0.5,
            y=0.5,
            text=(
                "<b>No Attack Stages Reconstructed</b><br><br>"
                "<span style='font-size:11px; color:#8B949E;'>"
                "The current incident telemetry does not support multi-stage attack reconstruction.<br>"
                "Events may represent isolated baseline telemetry or uncorroborated alerts."
                "</span>"
            ),
            showarrow=False,
            font=dict(color="#C9D1D9", size=13, family="JetBrains Mono"),
            align="center",
            xref="paper",
            yref="paper",
        )
        fig.update_layout(
            title=dict(text="Attack Progression Graph · No Active Stages", font=dict(size=12, color="#8B949E")),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1.0, 1.0]),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1.0, 1.0]),
            paper_bgcolor="#0D1117",
            plot_bgcolor="#0D1117",
            height=260,
            margin=dict(l=20, r=20, t=35, b=25),
        )
        return fig

    # Compute horizontal progression layout
    node_order = list(nodes_dict.keys())
    total_nodes = len(node_order)

    # Dedicated handling for single-stage isolated attack graphs
    if total_nodes == 1:
        nid = node_order[0]
        data = nodes_dict[nid]
        stage = data.get("stage", "OTHER")
        c = STAGE_COLORS.get(stage, "#58A6FF")
        conf_val = data.get("confidence")
        conf_str = f"{float(conf_val):.2f}" if conf_val is not None else "N/A"
        ev_count = len(data.get("event_ids", []))

        # Main prominent stage marker (single trace)
        tip = (
            f"<b>{nid}: {data.get('title')}</b><br>"
            f"Stage: {stage}<br>"
            f"Confidence: {conf_str}<br>"
            f"Supporting Evidence: {ev_count} events<br>"
            f"Status: Isolated Stage (No downstream progression detected)"
        )
        fig.add_trace(
            go.Scatter(
                x=[0.0],
                y=[0.0],
                mode="markers",
                marker=dict(
                    size=42,
                    color=c,
                    symbol="circle",
                    line=dict(color="#F0F6FC", width=3),
                ),
                hovertext=[tip],
                hoverinfo="text",
                showlegend=False,
            )
        )

        # 1. Label above node
        fig.add_annotation(
            x=0.0,
            y=0.22,
            text=f"<b>{nid}</b> · <span style='color:{c}; font-weight:600;'>{stage}</span>",
            showarrow=False,
            font=dict(color="#E6EDF3", size=12, family="JetBrains Mono"),
            align="center",
        )

        # 2. Metrics directly below node
        fig.add_annotation(
            x=0.0,
            y=-0.16,
            text=f"Confidence: <b>{conf_str}</b> · Evidence: <b>{ev_count}</b> events",
            showarrow=False,
            font=dict(color="#8B949E", size=10, family="JetBrains Mono"),
            align="center",
        )

        # 3. Explanatory pill badge below metrics
        fig.add_annotation(
            x=0.0,
            y=-0.32,
            text="<b>Isolated Stage</b> · No Downstream Intrusion Progression Observed",
            showarrow=False,
            font=dict(color="#C9D1D9", size=9, family="JetBrains Mono"),
            bgcolor="#161B22",
            bordercolor="#30363D",
            borderwidth=1,
            borderpad=4,
            align="center",
        )

        fig.update_layout(
            title=dict(text=f"Reconstructed Attack Progression Graph · {stage} (Isolated Stage)", font=dict(size=12, color="#C9D1D9")),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1.0, 1.0]),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.45, 0.45]),
            paper_bgcolor="#0D1117",
            plot_bgcolor="#0D1117",
            height=260,
            margin=dict(l=20, r=20, t=35, b=25),
        )
        return fig

    # Multi-node progression layout (total_nodes > 1)
    pos: Dict[str, tuple] = {}
    for i, nid in enumerate(node_order):
        # Spaced horizontally from 0 to total_nodes - 1
        pos[nid] = (float(i), 0.0)

    # Draw edge lines and transition annotations
    for edge in edges_list:
        src = edge["source"]
        tgt = edge["target"]
        if src in pos and tgt in pos:
            x0, y0 = pos[src]
            x1, y1 = pos[tgt]
            rel = edge.get("relationship", "precedes")
            edge_color = RELATIONSHIP_COLORS.get(rel, "#58A6FF")

            # Draw connector line
            fig.add_trace(
                go.Scatter(
                    x=[x0, x1],
                    y=[y0, y1],
                    mode="lines",
                    line=dict(color=edge_color, width=2, dash="solid" if rel == "leads_to" else "dot"),
                    hoverinfo="none",
                    showlegend=False,
                )
            )

            # Draw directional arrow annotation midway
            mid_x = (x0 + x1) / 2.0
            mid_y = (y0 + y1) / 2.0
            fig.add_annotation(
                x=x1 - 0.15,
                y=y1,
                ax=x0 + 0.15,
                ay=y0,
                xref="x",
                yref="y",
                axref="x",
                ayref="y",
                showarrow=True,
                arrowhead=2,
                arrowsize=1.2,
                arrowwidth=2,
                arrowcolor=edge_color,
            )
            # Label relationship above connector
            fig.add_annotation(
                x=mid_x,
                y=mid_y + 0.18,
                text=f"<b>{rel.replace('_', ' ')}</b>",
                showarrow=False,
                font=dict(color=edge_color, size=9, family="JetBrains Mono"),
                bgcolor="#0D1117",
                bordercolor="#21262D",
                borderwidth=1,
                borderpad=2,
            )

    # Draw node markers
    node_x = []
    node_y = []
    node_colors = []
    node_hover = []

    for nid in node_order:
        x, y = pos[nid]
        node_x.append(x)
        node_y.append(y)
        data = nodes_dict[nid]
        stage = data.get("stage", "OTHER")
        c = STAGE_COLORS.get(stage, "#58A6FF")
        node_colors.append(c)

        conf_val = data.get("confidence")
        conf_str = f"{float(conf_val):.2f}" if conf_val is not None else "N/A"
        tip = (
            f"<b>{data.get('node_id')}: {data.get('title')}</b><br>"
            f"Stage: {stage}<br>"
            f"Confidence: {conf_str}<br>"
            f"Supporting Events: {len(data.get('event_ids', []))}"
        )
        node_hover.append(tip)

        # Stage label below node
        fig.add_annotation(
            x=x,
            y=y - 0.22,
            text=f"<b>{data.get('node_id')}</b><br><span style='font-size:8px; color:{c};'>{stage}</span>",
            showarrow=False,
            font=dict(color="#C9D1D9", size=10, family="JetBrains Mono"),
            align="center",
        )

    fig.add_trace(
        go.Scatter(
            x=node_x,
            y=node_y,
            mode="markers",
            marker=dict(
                size=32,
                color=node_colors,
                symbol="circle",
                line=dict(color="#F0F6FC", width=2),
            ),
            hovertext=node_hover,
            hoverinfo="text",
            showlegend=False,
        )
    )

    x_min = -0.6
    x_max = max(1.4, total_nodes - 0.4)

    fig.update_layout(
        title=dict(text="Reconstructed Attack Progression Graph", font=dict(size=12, color="#C9D1D9")),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[x_min, x_max]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.45, 0.45]),
        paper_bgcolor="#0D1117",
        plot_bgcolor="#0D1117",
        height=260,
        margin=dict(l=20, r=20, t=35, b=25),
    )
    return fig

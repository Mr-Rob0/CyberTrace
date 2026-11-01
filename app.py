"""
CyberTrace - Cyber Incident Investigation and Reconstruction Platform
=====================================================================
Enterprise incident investigation workstation.
Provides deterministic detection (R001-R006), cross-source correlation,
attack-chain reconstruction, MITRE ATT&CK mapping, unsupervised ML anomaly
detection, and evidence-grounded report generation.
"""

import os
import glob
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# CyberTrace Pipeline Modules
from preprocessing.log_parser import parse_log_file
from detection.rule_engine import RuleEngine
from correlation.event_correlator import EventCorrelator
from correlation.incident_detector import IncidentDetector
from reconstruction.attack_chain import AttackChainReconstructor
from reconstruction.root_cause import RootCauseAnalyzer
from reconstruction.attack_graph import build_attack_graph
from mitre.technique_mapper import map_to_mitre
from detection.anomaly_detector import detect_anomalies
from ai.report_generator import generate_report
from ai.provider import get_configured_provider
from response import calculate_risk_score, recommend_actions, run_what_if_analysis
from visualization.graph import render_attack_graph
from visualization.timeline import render_timeline

# =====================================================================
# Page Configuration
# =====================================================================
st.set_page_config(
    page_title="CyberTrace | Incident Investigation Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# =====================================================================
# Design System — Robust CSS (no pseudo-element nav hacks)
# =====================================================================
CUSTOM_CSS = """
<style>
/* ── Typography ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

/* ── Canvas ── */
.stApp {
    background-color: #0D1117;
    color: #C9D1D9;
}

header[data-testid="stHeader"] {
    display: none !important;
}

/* ── Main Content Area ── */
.block-container {
    padding-top: 1.5rem !important;
    padding-bottom: 2rem !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
    max-width: 100% !important;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    width: 244px !important;
    min-width: 244px !important;
    max-width: 248px !important;
    background-color: #0D1117 !important;
    border-right: 1px solid #21262D !important;
}

[data-testid="stSidebar"] > div:first-child {
    padding-top: 0.75rem;
    padding-left: 0.85rem;
    padding-right: 0.85rem;
}

/* ── Hide radio button label "Navigation" ── */
[data-testid="stSidebar"] [data-testid="stRadio"] > label,
[data-testid="stSidebar"] [data-testid="stRadio"] > div > label {
    display: none !important;
}

/* ── Override Streamlit default h1/h2/h3 sizing for custom headers ── */
.pg-header h2.pg-title,
h2.pg-title {
    font-size: 1.35rem !important;
    font-weight: 700 !important;
    color: #F0F6FC !important;
    margin: 0 !important;
    padding: 0 !important;
    letter-spacing: -0.015em !important;
    line-height: 1.25 !important;
}

/* ── Sidebar Radio Items: compact nav buttons ── */
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label {
    display: flex !important;
    align-items: center !important;
    padding: 7px 12px !important;
    border-radius: 6px !important;
    margin-bottom: 2px !important;
    font-size: 0.825rem !important;
    font-weight: 500 !important;
    color: #8B949E !important;
    cursor: pointer !important;
    border-left: 3px solid transparent !important;
    transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease !important;
    background: transparent !important;
    line-height: 1.4 !important;
    min-height: 32px !important;
    white-space: normal !important;
    overflow: visible !important;
    text-overflow: unset !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label p {
    color: #8B949E !important;
    margin: 0 !important;
    font-size: 0.825rem !important;
    font-weight: 500 !important;
    transition: color 0.15s ease !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:hover {
    background: rgba(255, 255, 255, 0.05) !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:hover p {
    color: #E6EDF3 !important;
}

/* Active navigation item: highlighted background, blue left accent bar, vivid text */
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked),
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has(input[aria-checked="true"]),
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has([aria-checked="true"]) {
    background: rgba(56, 139, 253, 0.15) !important;
    border-left: 3px solid #58A6FF !important;
    border-radius: 6px !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) p,
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has(input[aria-checked="true"]) p,
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has([aria-checked="true"]) p {
    color: #58A6FF !important;
    font-weight: 600 !important;
}

/* Hide radio circle/bullet indicators — Streamlit 1.65
   DOM: label > div(wrapper) > div(indicator [input+circle]) + div(text [p])
   Use width collapse + clip, NOT display:none (which breaks flex layout) */
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label > div > div:first-child {
    width: 0 !important;
    height: 0 !important;
    min-width: 0 !important;
    min-height: 0 !important;
    max-width: 0 !important;
    max-height: 0 !important;
    overflow: hidden !important;
    margin: 0 !important;
    padding: 0 !important;
    flex: 0 0 0px !important;
    opacity: 0 !important;
    position: absolute !important;
    clip: rect(0, 0, 0, 0) !important;
    pointer-events: none !important;
}
/* Ensure the text container takes full width */
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label > div > div:last-child {
    flex: 1 !important;
}
/* Ensure hidden radio inputs don't take space */
[data-testid="stSidebar"] [data-testid="stRadio"] input[type="radio"] {
    position: absolute !important;
    opacity: 0 !important;
    width: 0 !important;
    height: 0 !important;
    clip: rect(0, 0, 0, 0) !important;
}

/* ── Sidebar section headers (rendered via markdown, not CSS pseudo) ── */
.sb-section {
    font-size: 0.66rem;
    font-weight: 600;
    letter-spacing: 0.07em;
    color: #484F58;
    text-transform: uppercase;
    margin-top: 0.7rem;
    margin-bottom: 0.3rem;
    padding-left: 2px;
}
.sb-section-border {
    border-top: 1px solid #21262D;
    padding-top: 0.6rem;
    margin-top: 0.55rem;
}
.sb-brand {
    display: flex;
    align-items: baseline;
    gap: 0.4rem;
    margin-bottom: 0.1rem;
}
.sb-brand-name {
    font-size: 1.05rem;
    font-weight: 700;
    color: #E6EDF3;
    letter-spacing: -0.01em;
}
.sb-brand-ver {
    font-size: 0.68rem;
    color: #484F58;
    font-family: 'JetBrains Mono', monospace;
}
.sb-brand-desc {
    font-size: 0.72rem;
    color: #8B949E;
    margin-bottom: 0.7rem;
}
.sb-divider {
    height: 1px;
    background: #21262D;
    margin-bottom: 0.65rem;
}
.sb-status {
    background: #161B22;
    border: 1px solid #21262D;
    border-radius: 5px;
    padding: 0.5rem 0.65rem;
    font-size: 0.7rem;
    color: #8B949E;
    margin-top: 0.85rem;
    line-height: 1.4;
}
.sb-status-title {
    font-weight: 600;
    color: #484F58;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    font-size: 0.64rem;
    margin-bottom: 0.25rem;
}
.sb-footer {
    font-size: 0.68rem;
    color: #30363D;
    margin-top: 0.6rem;
    text-align: center;
}

/* ── Page Headers ── */
.pg-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 0.85rem;
    margin-bottom: 1.15rem;
    border-bottom: 1px solid #21262D;
}
.pg-title {
    font-size: 1.35rem;
    font-weight: 700;
    color: #F0F6FC;
    margin: 0;
    letter-spacing: -0.015em;
    line-height: 1.25;
}
.pg-subtitle {
    font-size: 0.82rem;
    color: #8B949E;
    margin: 0.25rem 0 0 0;
    line-height: 1.35;
}
.pg-meta {
    font-size: 0.73rem;
    color: #484F58;
    font-family: 'JetBrains Mono', monospace;
    white-space: nowrap;
    text-align: right;
}

/* ── Severity Badges ── */
.sev-badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 3px;
    font-size: 0.68rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: 0.03em;
    text-transform: uppercase;
}
.sev-critical { background: rgba(248,81,73,0.12); color: #F85149; border: 1px solid rgba(248,81,73,0.25); }
.sev-high     { background: rgba(210,153,34,0.12); color: #D29922; border: 1px solid rgba(210,153,34,0.25); }
.sev-medium   { background: rgba(187,128,9,0.10);  color: #BB8009; border: 1px solid rgba(187,128,9,0.20); }
.sev-low      { background: rgba(88,166,255,0.10);  color: #58A6FF; border: 1px solid rgba(88,166,255,0.20); }
.sev-info     { background: rgba(139,148,158,0.10); color: #8B949E; border: 1px solid rgba(139,148,158,0.20); }
.sev-healthy  { background: rgba(63,185,80,0.10);   color: #3FB950; border: 1px solid rgba(63,185,80,0.20); }
.sev-accent   { background: rgba(88,166,255,0.10);  color: #58A6FF; border: 1px solid rgba(88,166,255,0.20); }

/* ── KPI Strip (Overview Only) ── */
.kpi-row {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 0.65rem;
    margin-bottom: 1.15rem;
}
@media (max-width: 1200px) {
    .kpi-row { grid-template-columns: repeat(3, 1fr); }
}
.kpi-cell {
    background: #161B22;
    border: 1px solid #21262D;
    border-radius: 5px;
    padding: 0.65rem 0.8rem;
}
.kpi-label {
    font-size: 0.66rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #484F58;
    margin-bottom: 0.2rem;
}
.kpi-val {
    font-size: 1.4rem;
    font-weight: 700;
    color: #E6EDF3;
    line-height: 1.15;
}
.kpi-note {
    font-size: 0.66rem;
    color: #484F58;
    margin-top: 0.15rem;
}

/* ── Panel ── */
.ct-panel {
    background: #161B22;
    border: 1px solid #21262D;
    border-radius: 5px;
    padding: 0.85rem 1rem;
    margin-bottom: 0.9rem;
}
.ct-panel-title {
    font-size: 0.88rem;
    font-weight: 600;
    color: #E6EDF3;
    margin: 0 0 0.6rem 0;
    padding-bottom: 0.45rem;
    border-bottom: 1px solid #21262D;
}

/* ── Section Title (outside panels) ── */
.sec-title {
    font-size: 0.88rem;
    font-weight: 600;
    color: #C9D1D9;
    margin: 0.85rem 0 0.5rem 0;
}

/* ── Compact Empty State ── */
.empty-state {
    background: #161B22;
    border: 1px solid #21262D;
    border-radius: 5px;
    padding: 0.85rem 1rem;
    margin: 0.5rem 0;
}
.empty-state h4 {
    font-size: 0.86rem;
    font-weight: 600;
    color: #C9D1D9;
    margin: 0 0 0.25rem 0;
}
.empty-state p {
    font-size: 0.79rem;
    color: #8B949E;
    line-height: 1.4;
    margin: 0;
}

/* ── Info Banner ── */
.ct-banner {
    background: #161B22;
    border-left: 3px solid #58A6FF;
    border-top: 1px solid #21262D;
    border-right: 1px solid #21262D;
    border-bottom: 1px solid #21262D;
    border-radius: 4px;
    padding: 0.6rem 0.85rem;
    font-size: 0.79rem;
    color: #8B949E;
    line-height: 1.4;
    margin-bottom: 0.85rem;
}
.ct-banner b { color: #C9D1D9; }
.ct-banner-warn {
    border-left-color: #D29922;
}

/* ── Timeline Stage Card ── */
.tl-stage {
    background: #161B22;
    border: 1px solid #21262D;
    border-left: 3px solid #58A6FF;
    border-radius: 5px;
    padding: 0.75rem 0.9rem;
    margin-bottom: 0.6rem;
}

/* ── Technical Monospace Values ── */
.mv {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.73rem;
    background: #0D1117;
    color: #8B949E;
    padding: 1px 5px;
    border-radius: 3px;
    border: 1px solid #21262D;
    display: inline-block;
    margin-right: 2px;
    margin-bottom: 2px;
}

/* ── Streamlit Overrides ── */
.stButton>button {
    background: #21262D;
    color: #C9D1D9;
    border: 1px solid #30363D;
    border-radius: 5px;
    font-size: 0.8rem;
    font-weight: 500;
    padding: 0.35rem 0.8rem;
    transition: all 0.1s;
}
.stButton>button:hover {
    background: #30363D;
    color: #58A6FF;
    border-color: #58A6FF;
}

div[data-testid="stDataFrame"] {
    background: #0D1117;
    border: 1px solid #21262D;
    border-radius: 4px;
}

div[data-baseweb="select"] > div {
    background-color: #161B22 !important;
    border-color: #30363D !important;
    color: #C9D1D9 !important;
    font-size: 0.8rem !important;
    border-radius: 5px !important;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 2px;
    background-color: #0D1117;
    padding: 3px 4px;
    border-radius: 5px;
    border: 1px solid #21262D;
}
.stTabs [data-baseweb="tab"] {
    height: 32px;
    border-radius: 4px;
    color: #8B949E;
    font-size: 0.8rem;
    font-weight: 500;
    padding: 0 10px;
}
.stTabs [aria-selected="true"] {
    background-color: #161B22 !important;
    color: #58A6FF !important;
    border-bottom: 2px solid #58A6FF !important;
}

/* ── Pipeline Diagram ── */
.pipe-step {
    display: flex;
    align-items: center;
    background: #161B22;
    border: 1px solid #21262D;
    border-radius: 5px;
    padding: 0.6rem 0.85rem;
    margin-bottom: 0.35rem;
    transition: border-color 0.1s;
}
.pipe-step:hover {
    border-color: #30363D;
}
.pipe-num {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.78rem;
    font-weight: 700;
    color: #58A6FF;
    background: #0D1117;
    border: 1px solid #21262D;
    border-radius: 3px;
    padding: 3px 7px;
    min-width: 32px;
    text-align: center;
    margin-right: 0.75rem;
    flex-shrink: 0;
}
.pipe-body { flex: 1; }
.pipe-title {
    font-size: 0.82rem;
    font-weight: 600;
    color: #E6EDF3;
    margin-bottom: 0.1rem;
}
.pipe-desc {
    font-size: 0.73rem;
    color: #8B949E;
    line-height: 1.3;
}
.pipe-tag {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.66rem;
    color: #484F58;
    background: #0D1117;
    padding: 2px 6px;
    border-radius: 3px;
    border: 1px solid #21262D;
    margin-left: 0.6rem;
    white-space: nowrap;
    flex-shrink: 0;
}
.pipe-arrow {
    padding-left: 22px;
    color: #30363D;
    font-size: 0.7rem;
    line-height: 1;
    margin: -1px 0;
}

/* ── Expander styling ── */
details summary {
    font-size: 0.82rem !important;
}

/* ── Metric overrides (report page) ── */
[data-testid="stMetric"] {
    background: #161B22;
    border: 1px solid #21262D;
    border-radius: 5px;
    padding: 0.5rem 0.7rem;
}
[data-testid="stMetric"] label {
    font-size: 0.7rem !important;
    color: #484F58 !important;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}
[data-testid="stMetric"] [data-testid="stMetricValue"] {
    font-size: 1.15rem !important;
    color: #E6EDF3 !important;
}

/* ── Professional visual refinement ────────────────────────────────
   A restrained incident-response workspace: layered navy surfaces,
   clear operational hierarchy, and purposeful cyan rather than a
   collection of indistinguishable dark cards. */
:root {
    --ct-canvas: #080d18;
    --ct-sidebar: #0b1120;
    --ct-surface: #101a2c;
    --ct-surface-raised: #14213a;
    --ct-border: #243550;
    --ct-border-subtle: #1b2a43;
    --ct-text: #e8eef9;
    --ct-muted: #91a3bf;
    --ct-faint: #5f7190;
    --ct-accent: #4cc9f0;
    --ct-accent-strong: #26a9d1;
}

.stApp {
    background:
        radial-gradient(900px 460px at 82% -180px, rgba(32, 121, 165, 0.14), transparent 68%),
        var(--ct-canvas) !important;
    color: var(--ct-text);
}

.block-container {
    padding-top: 2.1rem !important;
    padding-bottom: 2.75rem !important;
    padding-left: clamp(1.35rem, 3.1vw, 3.25rem) !important;
    padding-right: clamp(1.35rem, 3.1vw, 3.25rem) !important;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0c1425 0%, #090f1c 100%) !important;
    border-right: 1px solid var(--ct-border-subtle) !important;
    box-shadow: 12px 0 38px rgba(0, 0, 0, 0.12);
}
[data-testid="stSidebar"] > div:first-child {
    padding: 1.2rem 0.8rem 1rem !important;
}

.sb-brand { align-items: center; gap: 0.5rem; margin: 0.1rem 0 0.25rem; }
.sb-brand::before {
    content: "";
    width: 23px;
    height: 23px;
    border-radius: 7px;
    display: inline-block;
    flex: 0 0 23px;
    background: linear-gradient(145deg, #5ee3ff 0%, #2789bd 100%);
    box-shadow: 0 0 0 4px rgba(76, 201, 240, 0.09), 0 7px 17px rgba(4, 100, 148, 0.28);
}
.sb-brand-name { color: #f5f8ff; font-size: 1.12rem; letter-spacing: -0.035em; }
.sb-brand-ver { color: var(--ct-faint); background: rgba(145, 163, 191, 0.08); padding: 0.12rem 0.32rem; border-radius: 4px; }
.sb-brand-desc { color: var(--ct-muted); padding-left: 1px; margin-bottom: 1.05rem; }
.sb-divider { background: var(--ct-border-subtle); margin-bottom: 0.9rem; }
.sb-section { color: var(--ct-faint); font-size: 0.64rem; letter-spacing: 0.1em; margin: 0.9rem 0 0.45rem; }
.sb-section-border { border-color: var(--ct-border-subtle); padding-top: 0.9rem; }

[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label {
    border-left: 0 !important;
    border-radius: 7px !important;
    padding: 0.52rem 0.7rem !important;
    margin: 0 0 0.16rem !important;
    min-height: 34px !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:hover {
    background: rgba(145, 163, 191, 0.08) !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked),
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has(input[aria-checked="true"]),
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has([aria-checked="true"]) {
    background: linear-gradient(90deg, rgba(76, 201, 240, 0.18), rgba(76, 201, 240, 0.055)) !important;
    box-shadow: inset 3px 0 0 var(--ct-accent), 0 1px 0 rgba(255, 255, 255, 0.025) !important;
}
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) p,
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has(input[aria-checked="true"]) p,
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has([aria-checked="true"]) p { color: #dff8ff !important; }
.sb-status { background: rgba(20, 33, 58, 0.72); border-color: var(--ct-border); border-radius: 8px; padding: 0.65rem 0.7rem; color: var(--ct-muted); }
.sb-status-title { color: var(--ct-faint); }

.pg-header { border-color: var(--ct-border-subtle); padding: 0 0 1.05rem; margin-bottom: 1.45rem; }
.pg-header h2.pg-title, h2.pg-title, .pg-title { color: #f3f7ff !important; font-size: clamp(1.4rem, 1.8vw, 1.75rem) !important; letter-spacing: -0.035em !important; }
.pg-subtitle { color: var(--ct-muted); font-size: 0.84rem; margin-top: 0.38rem; }
.pg-meta { color: var(--ct-faint); }

.sev-badge { border-radius: 999px; padding: 0.23rem 0.52rem; letter-spacing: 0.055em; font-size: 0.64rem; }
.sev-critical { background: rgba(248, 81, 73, 0.16); border-color: rgba(248, 81, 73, 0.4); }
.sev-high { background: rgba(255, 183, 77, 0.14); border-color: rgba(255, 183, 77, 0.34); color: #ffc66d; }
.sev-medium { background: rgba(252, 197, 72, 0.13); border-color: rgba(252, 197, 72, 0.28); color: #f6ca62; }
.sev-low, .sev-accent { background: rgba(76, 201, 240, 0.12); border-color: rgba(76, 201, 240, 0.3); color: #79ddf6; }

.kpi-row { grid-template-columns: repeat(4, 1fr); gap: 0.8rem; margin-bottom: 1.45rem; }
.kpi-cell, .ct-panel, .empty-state, [data-testid="stMetric"] {
    background: linear-gradient(145deg, rgba(20, 33, 58, 0.96), rgba(14, 25, 44, 0.96)) !important;
    border-color: var(--ct-border) !important;
    border-radius: 9px !important;
    box-shadow: 0 9px 22px rgba(0, 0, 0, 0.11);
}
.kpi-cell { padding: 0.82rem 0.88rem; position: relative; overflow: hidden; }
.kpi-cell::after { content: ""; position: absolute; left: 0.88rem; right: 0.88rem; top: 0; height: 2px; background: linear-gradient(90deg, var(--kpi-accent, var(--ct-accent)), transparent); opacity: 0.82; }
.kpi-label, [data-testid="stMetric"] label { color: var(--ct-faint) !important; }
.kpi-val { color: var(--ct-text); font-size: 1.52rem; letter-spacing: -0.035em; }
.kpi-note { color: var(--ct-muted); }

.sec-title { color: #dce8f8; font-size: 0.76rem; letter-spacing: 0.085em; text-transform: uppercase; margin: 1rem 0 0.62rem; }
.ct-panel { padding: 1rem 1.05rem; }
.ct-panel-title { color: var(--ct-text); border-color: var(--ct-border-subtle); }
.empty-state { padding: 1rem 1.1rem; }
.empty-state h4 { color: var(--ct-text); }
.empty-state p { color: var(--ct-muted); }
.ct-banner { background: rgba(20, 33, 58, 0.8); border-color: var(--ct-border); border-left-color: var(--ct-accent); border-radius: 7px; color: var(--ct-muted); }
.mv { background: rgba(8, 13, 24, 0.8); border-color: var(--ct-border); color: #abc2df; }

.stButton > button {
    background: rgba(23, 39, 67, 0.96);
    color: #cfe8f3;
    border-color: #345171;
    border-radius: 7px;
    padding: 0.42rem 0.82rem;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.13);
}
.stButton > button:hover { background: #1b3556; color: #f1fbff; border-color: var(--ct-accent); transform: translateY(-1px); box-shadow: 0 5px 14px rgba(10, 96, 137, 0.2); }
.stButton > button:focus-visible, [data-baseweb="tab"] :focus-visible, [data-baseweb="select"] :focus-visible { outline: 2px solid var(--ct-accent) !important; outline-offset: 2px !important; }

div[data-baseweb="select"] > div { background-color: rgba(20, 33, 58, 0.92) !important; border-color: var(--ct-border) !important; color: var(--ct-text) !important; border-radius: 7px !important; }
.stTabs [data-baseweb="tab-list"] { background: rgba(10, 17, 30, 0.74); border-color: var(--ct-border-subtle); border-radius: 8px; padding: 4px; }
.stTabs [data-baseweb="tab"] { border-radius: 6px; color: var(--ct-muted); }
.stTabs [aria-selected="true"] { background: rgba(76, 201, 240, 0.12) !important; color: #b8f0ff !important; border-bottom-color: var(--ct-accent) !important; }
div[data-testid="stDataFrame"] { background: var(--ct-surface) !important; border-color: var(--ct-border) !important; border-radius: 8px; overflow: hidden; }

/* ── SIEM-style operational navigation ──────────────────────────── */
div[data-testid="stHorizontalBlock"]:has(.ct-topbar-brand) {
    align-items: center !important;
    margin: 0 0 0.75rem !important;
    padding: 0.2rem 0.85rem !important;
    background: linear-gradient(90deg, #0c1425 0%, #101b31 55%, #0c1425 100%);
    border: 1px solid var(--ct-border-subtle);
    border-radius: 9px;
    box-shadow: 0 6px 16px rgba(0, 0, 0, 0.15);
}
.ct-topbar-brand {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    color: #f2f7ff;
    font-size: 0.9rem;
    font-weight: 750;
    letter-spacing: 0.08em;
    white-space: nowrap;
}
.ct-brand-mark {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border: 1px solid rgba(101, 222, 248, 0.7);
    border-radius: 6px;
    color: #64dcf7;
    background: rgba(76, 201, 240, 0.1);
    font-size: 0.9rem;
}
div[data-testid="stHorizontalBlock"]:has(.ct-topbar-brand) [data-testid="stRadio"] div[role="radiogroup"] {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.2rem !important;
}
div[data-testid="stHorizontalBlock"]:has(.ct-topbar-brand) [data-testid="stRadio"] label > div > div:first-child {
    position: absolute !important;
    width: 0 !important;
    height: 0 !important;
    min-width: 0 !important;
    min-height: 0 !important;
    overflow: hidden !important;
    opacity: 0 !important;
}
div[data-testid="stHorizontalBlock"]:has(.ct-topbar-brand) [data-testid="stRadio"] label {
    display: flex !important;
    align-items: center !important;
    margin: 0.1rem 0 !important;
    padding: 0.45rem 0.62rem !important;
    border-radius: 6px !important;
    border: 1px solid transparent !important;
    color: var(--ct-muted) !important;
    font-size: 0.74rem !important;
    font-weight: 600 !important;
    white-space: nowrap;
}
div[data-testid="stHorizontalBlock"]:has(.ct-topbar-brand) [data-testid="stRadio"] label:hover {
    color: #e8f8fc !important;
    background: rgba(145, 163, 191, 0.07) !important;
}
div[data-testid="stHorizontalBlock"]:has(.ct-topbar-brand) [data-testid="stRadio"] label:has(input:checked) {
    color: #eafaff !important;
    background: rgba(76, 201, 240, 0.13) !important;
    border-color: rgba(76, 201, 240, 0.3) !important;
}
div[data-testid="stHorizontalBlock"]:has(.ct-topbar-brand) [data-testid="stRadio"] label p,
div[data-testid="stHorizontalBlock"]:has(.ct-topbar-brand) [data-testid="stRadio"] label:has(input:checked) p { color: inherit !important; }

/* Dataset and active-case controls sit underneath the main navigation. */
[data-testid="stCaptionContainer"] p { color: var(--ct-faint) !important; font-size: 0.61rem !important; font-weight: 700 !important; letter-spacing: 0.09em !important; }
.ct-control-empty {
    display: flex;
    align-items: center;
    min-height: 38px;
    box-sizing: border-box;
    padding: 0 0.7rem;
    color: var(--ct-faint);
    font-size: 0.75rem;
    background: rgba(20, 33, 58, 0.6);
    border: 1px solid var(--ct-border);
    border-radius: 7px;
}
.ct-status-chip {
    display: flex;
    align-items: center;
    gap: 0.38rem;
    min-height: 38px;
    box-sizing: border-box;
    padding: 0 0.65rem;
    border: 1px solid var(--ct-border);
    border-radius: 7px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.67rem;
    font-weight: 700;
    letter-spacing: 0.045em;
}
.ct-status-chip span { width: 6px; height: 6px; border-radius: 50%; box-shadow: 0 0 9px currentColor; }
.ct-status-alert { color: #ffc66d; background: rgba(255, 183, 77, 0.08); }
.ct-status-alert span { background: #ffc66d; }
.ct-status-clear { color: #72df9a; background: rgba(63, 185, 80, 0.08); }
.ct-status-clear span { background: #72df9a; }

@media (max-width: 760px) {
    .block-container { padding-top: 1.25rem !important; }
    div[data-testid="stHorizontalBlock"]:has(.ct-topbar-brand) { padding: 0.35rem 0.55rem !important; }
    div[data-testid="stHorizontalBlock"]:has(.ct-topbar-brand) [data-testid="stRadio"] label { padding: 0.38rem 0.5rem !important; }
    .pg-header { align-items: flex-start; gap: 0.65rem; flex-direction: column; }
    .pg-meta { text-align: left; }
    .kpi-row { grid-template-columns: repeat(2, 1fr); gap: 0.55rem; }
}
</style>
"""

# =====================================================================
# Pipeline Processing & Data Caching
# =====================================================================
@st.cache_data(show_spinner=False)
def load_and_process_telemetry(dataset_path: str):
    """
    Execute deterministic CyberTrace pipeline.
    Preserves all backend logic verbatim.
    """
    parsed = parse_log_file(dataset_path)
    rule_engine = RuleEngine()
    detections = rule_engine.detect(parsed.events)
    correlator = EventCorrelator()
    groups = correlator.correlate(detections)
    detector = IncidentDetector()
    incidents = detector.detect_incidents(groups)
    return parsed.events, detections, incidents


def save_uploaded_telemetry(uploaded_file) -> str:
    """Store an uploaded CSV under a content-derived name for this app run.

    The SHA-256 filename makes a repeated Streamlit rerun reuse the same file
    and prevents an uploaded filename from being used as a filesystem path.
    """
    file_bytes = uploaded_file.getvalue()
    if not file_bytes:
        raise ValueError("The uploaded CSV is empty.")
    if len(file_bytes) > 25 * 1024 * 1024:
        raise ValueError("The uploaded CSV is larger than the 25 MB limit.")

    upload_dir = os.path.join("data", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    file_hash = hashlib.sha256(file_bytes).hexdigest()[:20]
    saved_path = os.path.join(upload_dir, f"upload_{file_hash}.csv")
    if not os.path.exists(saved_path):
        with open(saved_path, "wb") as upload_destination:
            upload_destination.write(file_bytes)
    return saved_path


@st.cache_data(show_spinner=False)
def process_incident_reconstruction(dataset_path: str, incident_id: str):
    """
    Reconstruct attack chain, root causes, MITRE mappings, and graph for an incident.
    """
    events, detections, incidents = load_and_process_telemetry(dataset_path)
    target_inc = next((i for i in incidents if i.incident_id == incident_id), None)
    if not target_inc:
        return None, None, None, None

    reconstructor = AttackChainReconstructor()
    chain = reconstructor.reconstruct(target_inc, events=events, detections=detections)
    rc_analyzer = RootCauseAnalyzer()
    root_causes = rc_analyzer.analyze(chain)
    mitre_mappings = map_to_mitre(chain, events=events, detections=detections)
    graph = build_attack_graph(chain)
    return chain, root_causes, mitre_mappings, graph


@st.cache_data(show_spinner=False)
def run_ml_baseline_scoring(dataset_path: str):
    """
    Run Isolation Forest anomaly scoring on events.
    """
    events, _, _ = load_and_process_telemetry(dataset_path)
    return detect_anomalies(events)


# =====================================================================
# Plotly Theme
# =====================================================================
PLOTLY_LAYOUT = dict(
    paper_bgcolor="#161B22",
    plot_bgcolor="#161B22",
    font=dict(family="Inter, sans-serif", color="#8B949E", size=11),
    margin=dict(l=25, r=25, t=32, b=25),
    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
)


def create_severity_donut(events: List[Any]):
    """Severity breakdown donut chart."""
    sev_counts = {}
    for e in events:
        s = getattr(e, "severity", "low").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    color_map = {
        "critical": "#F85149",
        "high": "#D29922",
        "medium": "#BB8009",
        "low": "#58A6FF",
        "info": "#484F58",
    }
    labels = list(sev_counts.keys())
    values = list(sev_counts.values())
    colors = [color_map.get(k, "#484F58") for k in labels]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=[l.upper() for l in labels],
                values=values,
                hole=0.68,
                marker=dict(colors=colors, line=dict(color="#0D1117", width=2)),
                textinfo="label+value",
                textfont=dict(family="Inter", size=10, color="#C9D1D9"),
                hoverinfo="label+percent+value",
            )
        ]
    )
    fig.update_layout(
        title=dict(text="Severity Breakdown", font=dict(size=12, color="#C9D1D9")),
        showlegend=False,
        height=220,
        **PLOTLY_LAYOUT,
    )
    return fig


def create_rule_detection_bar(detections: List[Any]):
    """Horizontal bar chart of triggered detection rules."""
    rule_counts = {}
    rule_names = {}
    for d in detections:
        rid = d.rule_id
        rule_counts[rid] = rule_counts.get(rid, 0) + 1
        rule_names[rid] = d.rule_name

    if not rule_counts:
        return None

    sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1])
    rids = [r[0] for r in sorted_rules]
    counts = [r[1] for r in sorted_rules]
    labels = [f"{rid} ({rule_names.get(rid, '')[:22]})" for rid in rids]

    fig = go.Figure(
        data=[
            go.Bar(
                x=counts,
                y=labels,
                orientation="h",
                marker=dict(
                    color="#58A6FF",
                    line=dict(color="#21262D", width=1),
                ),
                text=counts,
                textposition="auto",
                textfont=dict(color="#0D1117", size=10, family="JetBrains Mono"),
            )
        ]
    )
    fig.update_layout(
        title=dict(text="Detections by Rule (R001–R006)", font=dict(size=12, color="#C9D1D9")),
        xaxis=dict(title="Detections", gridcolor="#21262D", zeroline=False),
        yaxis=dict(gridcolor="#21262D", tickfont=dict(size=10, color="#8B949E")),
        height=220,
        **PLOTLY_LAYOUT,
    )
    return fig


def create_attack_timeline_chart(chain: Any):
    """Chronological attack stage timeline chart."""
    if not chain or not chain.steps:
        return None

    stage_colors = {
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

    steps = chain.steps
    times = []
    labels = []
    colors = []
    tooltips = []

    for s in steps:
        t = s.timestamp_start or s.timestamp_end or datetime.now()
        times.append(t)
        labels.append(f"{s.step_id}: {s.stage}")
        colors.append(stage_colors.get(s.stage, "#58A6FF"))
        tooltips.append(
            f"<b>{s.step_id}: {s.title}</b><br>"
            f"Stage: {s.stage}<br>"
            f"Confidence: {s.confidence:.2f}<br>"
            f"Time: {t.strftime('%Y-%m-%d %H:%M:%S')}<br>"
            f"Evidence: {len(s.event_ids)} events"
        )

    fig = go.Figure()
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
        xaxis=dict(title="Timestamp", gridcolor="#21262D", zeroline=False),
        yaxis=dict(showticklabels=False, range=[0.92, 1.18], showgrid=False, zeroline=False),
        height=220,
        **PLOTLY_LAYOUT,
    )
    return fig


def create_anomaly_distribution_chart(anomaly_results: List[Any]):
    """Histogram of Isolation Forest anomaly scores."""
    if not anomaly_results:
        return None

    normal_scores = [r.anomaly_score for r in anomaly_results if not r.is_anomaly]
    anomaly_scores = [r.anomaly_score for r in anomaly_results if r.is_anomaly]

    fig = go.Figure()
    if normal_scores:
        fig.add_trace(
            go.Histogram(
                x=normal_scores,
                name="Baseline Normal",
                marker_color="#3FB950",
                opacity=0.75,
                nbinsx=20,
            )
        )
    if anomaly_scores:
        fig.add_trace(
            go.Histogram(
                x=anomaly_scores,
                name="Statistical Outliers",
                marker_color="#D29922",
                opacity=0.85,
                nbinsx=20,
            )
        )

    fig.add_vline(
        x=0.50,
        line_width=1.5,
        line_dash="dash",
        line_color="#58A6FF",
        annotation_text="Threshold (0.50)",
        annotation_font=dict(color="#58A6FF", size=9),
    )

    fig.update_layout(
        barmode="overlay",
        title=dict(text="Isolation Forest Anomaly Score Distribution", font=dict(size=12, color="#C9D1D9")),
        xaxis=dict(title="Normalized Anomaly Score (0.0 to 1.0)", gridcolor="#21262D"),
        yaxis=dict(title="Event Frequency", gridcolor="#21262D"),
        height=220,
        **PLOTLY_LAYOUT,
    )
    return fig


# =====================================================================
# Reusable UI Components
# =====================================================================
def render_page_header(title: str, subtitle: str, meta_right: str = "", badge_html: str = ""):
    """Consistent page header with title, subtitle, optional right meta and badge."""
    right = ""
    if badge_html:
        right = badge_html
    elif meta_right:
        right = f'<div class="pg-meta">{meta_right}</div>'
    st.markdown(f"""
    <div class="pg-header">
        <div>
            <h2 class="pg-title">{title}</h2>
            <div class="pg-subtitle">{subtitle}</div>
        </div>
        <div>{right}</div>
    </div>
    """, unsafe_allow_html=True)


def render_empty_state(headline: str, body: str):
    """Compact empty state panel."""
    st.markdown(f"""
    <div class="empty-state">
        <h4>{headline}</h4>
        <p>{body}</p>
    </div>
    """, unsafe_allow_html=True)


def render_info_banner(html_content: str, warn: bool = False):
    """Info banner with left accent bar."""
    cls = "ct-banner ct-banner-warn" if warn else "ct-banner"
    st.markdown(f'<div class="{cls}">{html_content}</div>', unsafe_allow_html=True)


def sev_badge(severity: str) -> str:
    """Return badge HTML for a severity string."""
    s = severity.lower()
    cls_map = {"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium",
               "low": "sev-low", "info": "sev-info"}
    cls = cls_map.get(s, "sev-info")
    return f'<span class="sev-badge {cls}">{severity.upper()}</span>'


# =====================================================================
# Main Application
# =====================================================================
def main():
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    workspace_sections = {
        "Dashboard": ["Overview"],
        "Events": ["Telemetry & Logs", "ML Anomaly Detection"],
        "Investigations": ["Correlated Incidents", "Attack Reconstruction", "MITRE ATT&CK Matrix"],
        "Response": ["Response Planning"],
        "Reports": ["AI Investigation Report"],
    }
    view_to_section = {
        view: section
        for section, views in workspace_sections.items()
        for view in views
    }

    def navigate_to(view: str):
        """Keep the top navigation and the selected operational view in sync."""
        st.session_state["active_nav_view"] = view
        st.session_state["workspace_section"] = view_to_section[view]

    def select_workspace_section():
        navigate_to(workspace_sections[st.session_state["workspace_section"]][0])

    def select_subview(widget_key: str):
        navigate_to(st.session_state[widget_key])

    # Provider status
    active_provider = get_configured_provider()
    is_live_provider = active_provider is not None

    # -----------------------------------------------------------------
    # Operational top bar — analyst controls only (no backend settings)
    # -----------------------------------------------------------------
    # A browser refresh starts a fresh Streamlit session. Initialise the
    # dashboard explicitly before any view reads this key.
    if "active_nav_view" not in st.session_state:
        st.session_state["active_nav_view"] = "Overview"
    current_view = st.session_state["active_nav_view"]
    if current_view not in view_to_section:
        current_view = "Overview"
        st.session_state["active_nav_view"] = current_view
    current_section = view_to_section[current_view]
    st.session_state["workspace_section"] = current_section

    brand_col, nav_col = st.columns([1.25, 5.75], gap="small")
    with brand_col:
        st.markdown('<div class="ct-topbar-brand"><span class="ct-brand-mark">◈</span><span>CYBERTRACE</span></div>', unsafe_allow_html=True)
    with nav_col:
        st.radio(
            "Workspace",
            list(workspace_sections),
            horizontal=True,
            label_visibility="collapsed",
            key="workspace_section",
            on_change=select_workspace_section,
        )

    dataset_files = sorted(glob.glob("data/sample_attacks/*.csv"))
    if not dataset_files:
        st.error("No telemetry datasets in data/sample_attacks/")
        return

    dataset_options = {os.path.basename(path): path for path in dataset_files}
    default_idx = list(dataset_options).index("combined_attack.csv") if "combined_attack.csv" in dataset_options else 0
    control_spacer, source_col, dataset_col, incident_col, status_col = st.columns([0.5, 1.65, 2.8, 2.4, 1.5], gap="small")
    with source_col:
        st.caption("DATA SOURCE")
        source_mode = st.selectbox(
            "Choose data source",
            ["Sample data", "Upload CSV"],
            label_visibility="collapsed",
            key="telemetry_source_mode",
        )
    with dataset_col:
        if source_mode == "Sample data":
            st.caption("TELEMETRY DATASET")
            selected_dataset_name = st.selectbox(
                "Select telemetry source",
                list(dataset_options),
                index=default_idx,
                label_visibility="collapsed",
                key="selected_dataset",
            )
            selected_path = dataset_options[selected_dataset_name]
        else:
            st.caption("UPLOAD SECURITY LOG")
            uploaded_csv = st.file_uploader(
                "Upload a CSV security log",
                type=["csv"],
                accept_multiple_files=False,
                label_visibility="collapsed",
                key="uploaded_telemetry_csv",
                help="Required columns: timestamp, source, event_type, event_id. Maximum file size: 25 MB.",
            )
            if uploaded_csv is None:
                st.info("Choose a CSV log file to begin analysis.")
                return
            try:
                selected_path = save_uploaded_telemetry(uploaded_csv)
            except ValueError as upload_error:
                st.error(str(upload_error))
                return
            selected_dataset_name = f"Uploaded · {uploaded_csv.name}"

    # Reset report state when the evidence source changes.
    if "active_dataset_name" not in st.session_state:
        st.session_state["active_dataset_name"] = selected_dataset_name
    elif st.session_state["active_dataset_name"] != selected_dataset_name:
        st.session_state["active_dataset_name"] = selected_dataset_name
        st.session_state.pop("active_incident_report", None)
        st.session_state.pop("active_report_incident_id", None)

    try:
        events, detections, incidents = load_and_process_telemetry(selected_path)
    except (UnicodeDecodeError, ValueError) as ingestion_error:
        st.error(f"Could not read this CSV: {ingestion_error}")
        st.caption("Required columns: timestamp, source, event_type, event_id.")
        return
    events_count, detections_count, incidents_count = len(events), len(detections), len(incidents)

    selected_incident_id = None
    with incident_col:
        st.caption("ACTIVE CASE")
        if incidents:
            incident_lookup = {incident.incident_id: incident for incident in incidents}
            selected_incident_id = st.selectbox(
                "Select active incident",
                options=list(incident_lookup),
                format_func=lambda incident_id: f"{incident_id} · {incident_lookup[incident_id].severity.upper()}",
                key="active_incident_id",
                label_visibility="collapsed",
            )
        else:
            st.markdown('<div class="ct-control-empty">No open cases</div>', unsafe_allow_html=True)

    with status_col:
        status_label = "INVESTIGATING" if incidents_count else "BASELINE"
        status_class = "ct-status-alert" if incidents_count else "ct-status-clear"
        st.caption("ANALYSIS STATUS")
        st.markdown(f'<div class="ct-status-chip {status_class}"><span></span>{status_label}</div>', unsafe_allow_html=True)

    selected_view = st.session_state["active_nav_view"]
    section_views = workspace_sections[current_section]
    if len(section_views) > 1:
        subview_key = f"{current_section.lower()}_view"
        st.session_state[subview_key] = selected_view if selected_view in section_views else section_views[0]
        selected_view = st.radio(
            f"{current_section} views",
            section_views,
            horizontal=True,
            label_visibility="collapsed",
            key=subview_key,
            on_change=select_subview,
            args=(subview_key,),
        )
        st.session_state["active_nav_view"] = selected_view

    # -----------------------------------------------------------------
    # Primary Data Pre-computation
    # -----------------------------------------------------------------
    primary_incident = next(
        (incident for incident in incidents if incident.incident_id == selected_incident_id),
        None,
    ) if selected_incident_id else None

    if primary_incident:
        chain, root_causes, mitre_mappings, attack_graph = process_incident_reconstruction(
            selected_path, primary_incident.incident_id
        )
        stages_count = len(chain.steps) if chain else 0
        mitre_count = len(mitre_mappings) if mitre_mappings else 0
    else:
        chain, root_causes, mitre_mappings, attack_graph = None, None, None, None
        stages_count = 0
        mitre_count = 0

    ml_results = run_ml_baseline_scoring(selected_path)
    anom_count = sum(1 for r in ml_results if r.is_anomaly) if ml_results else 0

    # =================================================================
    # VIEW 1: OVERVIEW
    # =================================================================
    if selected_view == "Overview":
        status_badge = '<span class="sev-badge sev-high">ACTIVE INVESTIGATION</span>' if primary_incident else '<span class="sev-badge sev-healthy">BASELINE HEALTHY</span>'
        render_page_header(
            "Security Operations Dashboard",
            f"Live analysis workspace for {selected_dataset_name} · {events_count} telemetry events ingested.",
            badge_html=status_badge,
        )

        # Alert-first overview: mirrors how an analyst triages the queue.
        severity_counts = {severity: 0 for severity in ("critical", "high", "medium", "low")}
        for detection in detections:
            severity = getattr(detection, "severity", "low").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        st.markdown(f"""
        <div class="kpi-row">
            <div class="kpi-cell" style="--kpi-accent:#f85149;">
                <div class="kpi-label">Critical Alerts</div>
                <div class="kpi-val" style="color:#ff8b85;">{severity_counts['critical']}</div>
                <div class="kpi-note">Immediate review</div>
            </div>
            <div class="kpi-cell" style="--kpi-accent:#ffb74d;">
                <div class="kpi-label">High Alerts</div>
                <div class="kpi-val" style="color:#ffc66d;">{severity_counts['high']}</div>
                <div class="kpi-note">Priority triage</div>
            </div>
            <div class="kpi-cell" style="--kpi-accent:#f6ca62;">
                <div class="kpi-label">Medium Alerts</div>
                <div class="kpi-val" style="color:#f6ca62;">{severity_counts['medium']}</div>
                <div class="kpi-note">Monitor and validate</div>
            </div>
            <div class="kpi-cell" style="--kpi-accent:#72df9a;">
                <div class="kpi-label">Low Alerts</div>
                <div class="kpi-val" style="color:#72df9a;">{severity_counts['low']}</div>
                <div class="kpi-note">Baseline deviations</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        queue_col, distribution_col = st.columns([7, 3], gap="medium")
        with queue_col:
            st.markdown('<div class="sec-title">Active Alert Queue</div>', unsafe_allow_html=True)
            if detections:
                alert_rows = [
                    {
                        "Time": detection.timestamp.strftime("%H:%M:%S"),
                        "Alert": detection.title,
                        "Severity": detection.severity,
                        "Source": detection.source_ip or detection.hostname or "—",
                        "Status": "Under review",
                    }
                    for detection in sorted(detections, key=lambda item: item.timestamp, reverse=True)[:6]
                ]
                st.dataframe(
                    pd.DataFrame(alert_rows),
                    use_container_width=True,
                    hide_index=True,
                    height=230,
                )
            else:
                render_empty_state("No active alerts", "The active dataset has no rule-based detections requiring analyst review.")
        with distribution_col:
            st.markdown('<div class="sec-title">Alert Distribution</div>', unsafe_allow_html=True)
            st.plotly_chart(create_severity_donut(events), use_container_width=True)

        # Main content: 60/40 split
        col_left, col_right = st.columns([6, 4])

        with col_left:
            st.markdown('<div class="sec-title">Incidents Requiring Review</div>', unsafe_allow_html=True)
            if not incidents:
                render_empty_state(
                    "No rule-based incidents detected",
                    f"{events_count} events analyzed across all sources. No deterministic rule clusters met the configured escalation criteria. "
                    f"{anom_count} statistical outlier(s) were flagged by ML anomaly detection and can be reviewed on the ML Anomaly Detection page."
                )
            else:
                inc = primary_incident
                sev_cls = f"sev-{inc.severity.lower()}" if inc.severity.lower() in ["critical", "high", "medium", "low"] else "sev-high"
                rc_title = root_causes[0].title if root_causes else "Multi-source attack pattern"
                st.markdown(f"""
                <div class="ct-panel" style="border-left: 3px solid #D29922;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.35rem;">
                        <span style="font-weight:600; font-size:0.9rem; color:#E6EDF3; font-family:'JetBrains Mono',monospace;">{inc.incident_id}</span>
                        <div>
                            {sev_badge(inc.severity)}
                            <span class="sev-badge sev-accent" style="margin-left:3px;">CONF: {inc.confidence:.2f}</span>
                        </div>
                    </div>
                    <div style="font-size:0.8rem; color:#8B949E; margin-bottom:0.45rem; line-height:1.4;">{inc.summary}</div>
                    <div style="font-size:0.78rem; color:#C9D1D9; margin-bottom:0.35rem;">
                        <span style="color:#484F58;">Probable Cause:</span> <b>{rc_title}</b>
                    </div>
                    <div style="display:flex; gap:0.85rem; font-size:0.72rem; color:#484F58;">
                        <span>Detections: <b style="color:#8B949E;">{inc.detection_count}</b></span>
                        <span>Events: <b style="color:#8B949E;">{len(inc.event_ids)}</b></span>
                        <span>Window: <b style="color:#8B949E;">{inc.start_time.strftime('%H:%M:%S')} → {inc.end_time.strftime('%H:%M:%S')}</b></span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                c1, c2, c3 = st.columns(3)
                with c1:
                    st.button(
                        "Review Incidents →", key="ov_to_inc", use_container_width=True,
                        on_click=navigate_to, args=("Correlated Incidents",),
                    )
                with c2:
                    st.button(
                        "Attack Reconstruction →", key="ov_to_recon", use_container_width=True,
                        on_click=navigate_to, args=("Attack Reconstruction",),
                    )
                with c3:
                    st.button(
                        "Generate Report →", key="ov_to_rep", use_container_width=True,
                        on_click=navigate_to, args=("AI Investigation Report",),
                    )

        with col_right:
            st.markdown('<div class="sec-title">Detection Summary</div>', unsafe_allow_html=True)
            bar_fig = create_rule_detection_bar(detections)
            if bar_fig:
                st.plotly_chart(bar_fig, use_container_width=True)
            else:
                render_empty_state(
                    "No rule detections",
                    f"Rules R001–R006 did not trigger in {selected_dataset_name}."
                )

        # Timeline / Distribution
        st.markdown('<div class="sec-title" style="margin-top:0.5rem;">Investigation Signals</div>', unsafe_allow_html=True)
        if chain and chain.steps:
            st.plotly_chart(create_attack_timeline_chart(chain), use_container_width=True)
        else:
            tcol1, tcol2 = st.columns(2)
            with tcol1:
                st.plotly_chart(create_severity_donut(events), use_container_width=True)
            with tcol2:
                st.plotly_chart(create_anomaly_distribution_chart(ml_results), use_container_width=True)

    # =================================================================
    # VIEW 2: TELEMETRY & LOGS
    # =================================================================
    elif selected_view == "Telemetry & Logs":
        render_page_header(
            "Telemetry & Log Analysis",
            "Search and inspect normalized security events from the active dataset.",
            meta_right=f"{events_count} total events",
        )

        # Filter toolbar
        source_options = sorted(list(set(e.source for e in events if getattr(e, "source", None))))
        sev_options = ["low", "medium", "high", "critical", "info"]

        def reset_telemetry_filters():
            """Restore the visible telemetry controls as well as their results."""
            st.session_state["telemetry_search"] = ""
            st.session_state["source_filter"] = source_options
            st.session_state["sev_filter"] = sev_options

        search_query = st.text_input(
            "Search events (ID, IP, user, message, host):",
            placeholder="e.g. 192.168.1.188, root, failed, sudo...",
            key="telemetry_search",
        )

        fcol1, fcol2, fcol3 = st.columns([2, 2, 1])
        with fcol1:
            selected_sources = st.multiselect("Source:", source_options, default=source_options, key="source_filter")
        with fcol2:
            selected_sevs = st.multiselect("Severity:", sev_options, default=sev_options, key="sev_filter")
        with fcol3:
            st.write("")
            st.write("")
            st.button("Clear Filters", key="clear_filt_btn", on_click=reset_telemetry_filters)

        # Filter logic
        filtered = []
        for e in events:
            if getattr(e, "source", None) not in selected_sources:
                continue
            if getattr(e, "severity", "low").lower() not in [s.lower() for s in selected_sevs]:
                continue
            if search_query:
                q = search_query.lower()
                msg = getattr(e, "raw_message", "").lower()
                eid = getattr(e, "event_id", "").lower()
                sip = str(getattr(e, "source_ip", "")).lower()
                dip = str(getattr(e, "destination_ip", "")).lower()
                usr = str(getattr(e, "username", "")).lower()
                hst = str(getattr(e, "hostname", "")).lower()
                if not (q in msg or q in eid or q in sip or q in dip or q in usr or q in hst):
                    continue
            filtered.append(e)

        st.caption(f"Showing **{len(filtered)}** of {events_count} events")

        if filtered:
            table_rows = [
                {
                    "Timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if hasattr(e.timestamp, "strftime") else str(e.timestamp),
                    "Event ID": e.event_id,
                    "Source": e.source,
                    "Type": e.event_type,
                    "Severity": getattr(e, "severity", "low").upper(),
                    "Src IP": e.source_ip or "—",
                    "Dst IP": e.destination_ip or "—",
                    "User": e.username or "—",
                    "Action": e.action or "—",
                }
                for e in filtered
            ]
            table_df = pd.DataFrame(table_rows)
            st.download_button(
                "Download filtered telemetry (CSV)",
                data=table_df.to_csv(index=False).encode("utf-8"),
                file_name=f"{os.path.splitext(selected_dataset_name)[0]}_filtered.csv",
                mime="text/csv",
                key="download_filtered_telemetry",
            )
            if len(table_rows) > 200:
                st.caption("The table shows the first 200 matching events; the CSV contains all matching events.")
            st.dataframe(table_df.head(200), use_container_width=True, height=380)

            with st.expander("Inspect Raw Event", expanded=False):
                event_ids = [e.event_id for e in filtered]
                chosen_eid = st.selectbox("Select Event ID:", event_ids, key="inspect_eid")
                chosen_ev = next((e for e in filtered if e.event_id == chosen_eid), None)
                if chosen_ev:
                    st.json({
                        "event_id": chosen_ev.event_id,
                        "timestamp": str(chosen_ev.timestamp),
                        "source": chosen_ev.source,
                        "event_type": chosen_ev.event_type,
                        "severity": chosen_ev.severity,
                        "source_ip": chosen_ev.source_ip,
                        "destination_ip": chosen_ev.destination_ip,
                        "username": chosen_ev.username,
                        "hostname": chosen_ev.hostname,
                        "process": chosen_ev.process,
                        "action": chosen_ev.action,
                        "raw_message": chosen_ev.raw_message,
                    })
        else:
            st.info("No events match the active search or filter criteria.")

    # =================================================================
    # VIEW 3: CORRELATED INCIDENTS
    # =================================================================
    elif selected_view == "Correlated Incidents":
        render_page_header(
            "Correlated Incidents",
            "Security findings correlated from multiple detection rules and event sources.",
            meta_right=f"{incidents_count} incident{'s' if incidents_count != 1 else ''}",
        )

        if not incidents:
            render_empty_state(
                "No correlated incidents",
                f"No event clusters in {selected_dataset_name} met the incident escalation criteria. "
                f"Review individual events on the Telemetry page or ML outliers on the ML Anomaly Detection page."
            )
        else:
            inc_table = [
                {
                    "Incident ID": inc.incident_id,
                    "Severity": inc.severity,
                    "Start": inc.start_time.strftime("%H:%M:%S"),
                    "End": inc.end_time.strftime("%H:%M:%S"),
                    "Detections": inc.detection_count,
                    "Events": len(inc.event_ids),
                    "Confidence": f"{inc.confidence:.2f}",
                    "Summary": inc.summary[:80],
                }
                for inc in incidents
            ]
            st.dataframe(pd.DataFrame(inc_table), use_container_width=True)

            # Detail view
            inc = primary_incident
            st.markdown(f'<div class="sec-title" style="margin-top:0.85rem;">Incident Detail: {inc.incident_id}</div>', unsafe_allow_html=True)
            st.markdown(f"""
            <div class="ct-panel">
                <div style="font-size:0.82rem; color:#C9D1D9; margin-bottom:0.6rem;"><b>Summary:</b> {inc.summary}</div>
                <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:0.75rem; font-size:0.76rem;">
                    <div>
                        <span style="color:#484F58; font-weight:600;">ACCOUNTS</span><br>
                        {' '.join([f'<span class="mv">{u}</span>' for u in inc.usernames]) or '<span style="color:#30363D;">None</span>'}
                    </div>
                    <div>
                        <span style="color:#484F58; font-weight:600;">HOSTS</span><br>
                        {' '.join([f'<span class="mv">{h}</span>' for h in inc.hostnames]) or '<span style="color:#30363D;">None</span>'}
                    </div>
                    <div>
                        <span style="color:#484F58; font-weight:600;">SOURCE IPs</span><br>
                        {' '.join([f'<span class="mv">{ip}</span>' for ip in inc.source_ips]) or '<span style="color:#30363D;">None</span>'}
                    </div>
                    <div>
                        <span style="color:#484F58; font-weight:600;">TIME WINDOW</span><br>
                        <span class="mv">{inc.start_time.strftime('%H:%M:%S')} → {inc.end_time.strftime('%H:%M:%S')}</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            with st.expander(f"Supporting Evidence ({len(inc.event_ids)} Events)", expanded=False):
                ev_data = [
                    {
                        "Event ID": e.event_id,
                        "Timestamp": str(e.timestamp),
                        "Source": e.source,
                        "Type": e.event_type,
                        "Action": e.action,
                        "Message": e.raw_message[:80],
                    }
                    for e in events if e.event_id in inc.event_ids
                ]
                st.dataframe(pd.DataFrame(ev_data), use_container_width=True, height=240)

            c1, c2 = st.columns(2)
            with c1:
                st.button(
                    "Reconstruct Attack Chain →", key="inc_to_recon", use_container_width=True,
                    on_click=navigate_to, args=("Attack Reconstruction",),
                )
            with c2:
                st.button(
                    "Generate Investigation Report →", key="inc_to_rep", use_container_width=True,
                    on_click=navigate_to, args=("AI Investigation Report",),
                )

    # =================================================================
    # VIEW 4: ATTACK RECONSTRUCTION
    # =================================================================
    elif selected_view == "Attack Reconstruction":
        meta_str = f"{primary_incident.incident_id} • {primary_incident.severity}" if primary_incident else "No Active Incident"
        render_page_header(
            "Attack Reconstruction",
            "Inferred attack progression with supporting evidence and probable causal relationships.",
            meta_right=meta_str,
        )

        if not chain or not chain.steps:
            render_empty_state(
                "No attack progression reconstructed",
                "The current dataset did not produce the correlated evidence required for multi-stage reconstruction."
            )
        else:
            render_info_banner(
                "<b>Inference Disclaimer:</b> Attack stages are reconstructed from correlated telemetry evidence. "
                "Stages represent <em>probable</em> interpretations, not confirmed attacker intent. "
                "Confidence scores reflect evidence support strength, not certainty.",
                warn=True,
            )

            st.markdown('<div class="sec-title">Inferred Attack Stages</div>', unsafe_allow_html=True)

            stage_left_colors = {
                "CREDENTIAL_ACCESS": "#58A6FF",
                "INITIAL_ACCESS": "#58A6FF",
                "PRIVILEGE_ESCALATION": "#D29922",
                "DISCOVERY": "#8B949E",
                "COLLECTION": "#BC8CFF",
                "EXFILTRATION": "#F85149",
                "EXECUTION": "#79C0FF",
                "PERSISTENCE": "#BC8CFF",
                "LATERAL_MOVEMENT": "#F778BA",
                "IMPACT": "#DA3633",
            }

            for idx, step in enumerate(chain.steps, 1):
                t_str = str(step.timestamp_start or step.timestamp_end or "Unknown")
                left_c = stage_left_colors.get(step.stage, "#58A6FF")
                st.markdown(f"""
                <div class="tl-stage" style="border-left-color:{left_c};">
                    <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:0.3rem;">
                        <div>
                            <span style="font-family:'JetBrains Mono',monospace; font-size:0.76rem; color:{left_c}; font-weight:600;">STAGE {idx}: {step.stage}</span>
                            <span style="margin:0 5px; color:#30363D;">·</span>
                            <span style="font-weight:600; font-size:0.84rem; color:#E6EDF3;">{step.title}</span>
                        </div>
                        <span class="sev-badge sev-accent">CONF: {step.confidence:.2f}</span>
                    </div>
                    <div style="font-size:0.79rem; color:#8B949E; line-height:1.4; margin-bottom:0.4rem;">{step.description}</div>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.6rem; background:#0D1117; padding:0.45rem 0.65rem; border-radius:4px; font-size:0.74rem; margin-bottom:0.35rem;">
                        <div>
                            <span style="color:#484F58; font-weight:600;">OBSERVED EVIDENCE</span><br>
                            <span style="color:#8B949E;">{step.observed_evidence}</span>
                        </div>
                        <div>
                            <span style="color:#484F58; font-weight:600;">ANALYTICAL INTERPRETATION</span><br>
                            <span style="color:#8B949E;">{step.inference_reason}</span>
                        </div>
                    </div>
                    <div style="font-size:0.7rem; color:#484F58;">
                        Evidence: {' '.join([f'<span class="mv">{eid}</span>' for eid in step.event_ids])}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            # Attack Graph Visualization
            if attack_graph and attack_graph.nodes:
                st.markdown('<div class="sec-title" style="margin-top:0.85rem;">Attack Progression Graph</div>', unsafe_allow_html=True)
                graph_fig = render_attack_graph(attack_graph)
                st.plotly_chart(graph_fig, use_container_width=True)

                if attack_graph.edges:
                    with st.expander("Stage Transitions & Evidentiary Linkages Table", expanded=False):
                        edge_data = [
                            {
                                "Source Stage": e.source,
                                "Relationship": e.relationship.upper(),
                                "Target Stage": e.target,
                                "Interpretation": e.description or "Chronological progression",
                            }
                            for e in attack_graph.edges
                        ]
                        st.dataframe(pd.DataFrame(edge_data), use_container_width=True)

            # Probable Root-Cause Analysis
            if root_causes:
                st.markdown('<div class="sec-title" style="margin-top:0.85rem;">Probable Root-Cause Candidates</div>', unsafe_allow_html=True)
                for rc in root_causes:
                    is_prim = getattr(rc, "is_primary", False)
                    border_color = "#3FB950" if is_prim else "#30363D"
                    prim_badge = '<span class="sev-badge sev-healthy" style="margin-left:6px;">PRIMARY CANDIDATE</span>' if is_prim else ""
                    conf_pct = f"{rc.confidence:.0%}"
                    st.markdown(f"""
                    <div class="ct-panel" style="border-left: 3px solid {border_color}; margin-bottom: 0.6rem;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.35rem;">
                            <div>
                                <span style="font-family:'JetBrains Mono',monospace; font-size:0.75rem; color:#8B949E; font-weight:600;">RANK #{rc.rank}</span>
                                <span style="margin:0 5px; color:#30363D;">·</span>
                                <span style="font-weight:600; font-size:0.86rem; color:#E6EDF3;">{rc.title}</span>
                                {prim_badge}
                            </div>
                            <span class="sev-badge sev-accent">CONFIDENCE: {conf_pct}</span>
                        </div>
                        <div style="font-size:0.78rem; color:#8B949E; line-height:1.45; margin-bottom:0.4rem;">
                            <b>Analytical Reasoning:</b> {rc.reasoning}
                        </div>
                        <div style="font-size:0.72rem; color:#484F58;">
                            Type: <span class="mv">{rc.candidate_type}</span> •
                            Evidence: {' '.join([f'<span class="mv">{eid}</span>' for eid in rc.evidence_event_ids[:8]])}
                            {' ...' if len(rc.evidence_event_ids) > 8 else ''}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

            st.button(
                "Proceed to Investigation Report →", key="recon_to_rep", type="primary",
                on_click=navigate_to, args=("AI Investigation Report",),
            )

    # =================================================================
    # VIEW 5: MITRE ATT&CK MATRIX
    # =================================================================
    elif selected_view == "MITRE ATT&CK Matrix":
        render_page_header(
            "MITRE ATT&CK Mapping",
            "Techniques mapped from observed behavioral evidence in the reconstructed incident.",
            meta_right=f"{mitre_count} techniques mapped",
        )

        if not mitre_mappings:
            render_empty_state(
                "No techniques mapped",
                "No supported technique mappings were produced from the available incident evidence."
            )
        else:
            table_data = [
                {
                    "Technique ID": m.technique_id,
                    "Technique Name": m.technique_name,
                    "Primary Tactic": m.tactic,
                    "Confidence": f"{m.confidence:.2f}",
                    "Evidence": m.evidence_count,
                    "Supporting Detections": ", ".join(m.supporting_detection_ids),
                    "Event IDs": ", ".join(m.supporting_event_ids[:4]),
                }
                for m in mitre_mappings
            ]
            st.dataframe(pd.DataFrame(table_data), use_container_width=True)

            st.markdown('<div class="sec-title" style="margin-top:0.75rem;">Evidence Rationale</div>', unsafe_allow_html=True)
            for m in mitre_mappings:
                with st.expander(f"{m.technique_id}: {m.technique_name} ({m.tactic})", expanded=False):
                    st.write(f"**Rationale:** {m.rationale}")
                    st.caption(f"Supporting Detections: {', '.join(m.supporting_detection_ids)} | Evidence Count: {m.evidence_count}")
                    st.caption(f"Event Traceability: {', '.join(m.supporting_event_ids)}")

    # =================================================================
    # VIEW 6: ML ANOMALY DETECTION
    # =================================================================
    elif selected_view == "ML Anomaly Detection":
        render_page_header(
            "ML Anomaly Detection",
            "Isolation Forest statistical analysis — events deviating from the learned baseline.",
            meta_right=f"{anom_count} outliers flagged",
        )

        # Prominent disclaimer
        render_info_banner(
            "<b>Statistical Disclaimer:</b> Anomaly scores measure statistical deviation from the learned baseline. "
            "An outlier is <b>not</b> conclusive evidence of malicious activity. Scores are not attack probabilities. "
            "Treat all flagged events as candidates for further investigation, not as confirmed threats.",
            warn=True,
        )

        # Distribution chart
        dist_fig = create_anomaly_distribution_chart(ml_results)
        if dist_fig:
            st.plotly_chart(dist_fig, use_container_width=True)

        # Flagged events table
        flagged = [r for r in ml_results if r.is_anomaly]
        st.markdown(f'<div class="sec-title">Flagged Statistical Outliers ({len(flagged)})</div>', unsafe_allow_html=True)
        if flagged:
            anom_table = [
                {
                    "Event ID": r.event_id,
                    "Anomaly Score": round(r.anomaly_score, 4),
                    "Decision Score": round(r.decision_score, 4),
                    "Explanation": r.explanation,
                    "Raw Message": r.raw_message[:90],
                }
                for r in flagged
            ]
            st.dataframe(pd.DataFrame(anom_table), use_container_width=True, height=320)
        else:
            st.info("No events exceeded the Isolation Forest anomaly threshold in this dataset.")

    # =================================================================
    # VIEW 7: RESPONSE PLANNING
    # =================================================================
    elif selected_view == "Response Planning":
        render_page_header(
            "Response Planning",
            "Explainable risk prioritisation, evidence-led containment actions, and defensive counterfactuals.",
            badge_html='<span class="sev-badge sev-high">ANALYST DECISION SUPPORT</span>',
        )
        if not primary_incident or not chain:
            render_empty_state("No incident available for response planning", "Select a dataset with correlated incidents to build a response plan.")
            return
        primary_root_cause = root_causes[0].to_dict() if root_causes else {}
        response_context = primary_incident.to_dict()
        response_context.update({"attack_chain": chain, "root_cause": primary_root_cause})
        risk = calculate_risk_score(response_context)
        k1, k2, k3 = st.columns(3)
        k1.metric("Response Priority", f"{risk['overall_score']} / 100")
        k2.metric("Risk Level", risk["risk_level"])
        k3.metric("Evidence Confidence", f"{risk['confidence']:.0%}")
        with st.expander("Why this priority score?", expanded=False):
            st.caption(risk["disclaimer"])
            st.dataframe(pd.DataFrame([
                {"Factor": name.replace("_", " ").title(), "Points": detail["points"], "Evidence": str({k: v for k, v in detail.items() if k != "points"})}
                for name, detail in risk["factors"].items()
            ]), use_container_width=True, hide_index=True)

        st.markdown('<div class="sec-title">Recommended Response Actions</div>', unsafe_allow_html=True)
        for action in recommend_actions(response_context):
            st.markdown(f"- **[{action['priority']}]** {action['action']}  ")
            st.caption(f"{action['category'].title()}: {action['rationale']}")

        st.markdown('<div class="sec-title" style="margin-top:1rem;">What-if Defense Simulation</div>', unsafe_allow_html=True)
        defense_options = [
            "MFA", "Rate Limiting", "Privileged Access Management",
            "Endpoint Detection", "Network Segmentation", "Egress Filtering",
            "Data Loss Prevention", "Firewall Filtering"
        ]
        selected_defenses = st.multiselect("Controls assumed active", defense_options, default=["MFA"], key="what_if_defenses")
        simulation = run_what_if_analysis(chain, selected_defenses)
        if simulation["blocked_at"]:
            blocked = simulation["blocked_at"]
            st.success(f"Earliest potentially disrupted step: {blocked['step_id']} — {blocked['title']}. Modelled downstream coverage: {simulation['effectiveness']}%.")
            st.caption(f"Potentially avoided steps: {', '.join(simulation['prevented_steps'])}")
        else:
            st.info(simulation["explanation"])
        st.caption("This is a transparent counterfactual based on control-to-stage coverage, not proof that a control would certainly have prevented the incident.")

    # =================================================================
    # VIEW 8: AI INVESTIGATION REPORT
    # =================================================================
    elif selected_view == "AI Investigation Report":
        mode_label = "LIVE PROVIDER" if is_live_provider else "DETERMINISTIC FALLBACK"
        mode_cls = "sev-accent" if is_live_provider else "sev-healthy"
        render_page_header(
            "Investigation Report",
            "Evidence-grounded incident findings and defensive recommendations.",
            badge_html=f'<span class="sev-badge {mode_cls}">{mode_label}</span>',
        )

        if not incidents:
            render_empty_state(
                "No incident report available",
                f"No incidents detected in {selected_dataset_name}. "
                "Switch to combined_attack.csv to inspect an end-to-end investigation report."
            )
            return

        # Fallback disclosure
        if not is_live_provider:
            render_info_banner(
                "<b>Deterministic Fallback Active:</b> This report is synthesized locally from verified pipeline findings. "
                "No live external LLM was used. All content is derived deterministically from rule detections, "
                "correlation results, attack reconstruction, and ML anomaly scores.",
                warn=True,
            )

        # Generator action
        col_act1, col_act2 = st.columns([4, 1])
        with col_act1:
            st.caption(f"Target: **{primary_incident.incident_id}** ({primary_incident.severity}, Confidence: {primary_incident.confidence:.2f})")
        with col_act2:
            generate_clicked = st.button("Generate Report", type="primary", key="btn_gen_rep", use_container_width=True)

        # A report is only valid for the incident from which it was generated.
        # Regenerate automatically if the analyst switches active incident.
        report_is_stale = (
            st.session_state.get("active_report_incident_id") != primary_incident.incident_id
        )
        if generate_clicked or "active_incident_report" not in st.session_state or report_is_stale:
            spinner_message = "Updating report for the active incident..." if report_is_stale else "Synthesizing evidence-grounded report..."
            with st.spinner(spinner_message):
                try:
                    rep = generate_report(
                        incident_or_findings=primary_incident,
                        events=events,
                        detections=detections,
                        attack_chain=chain,
                        root_causes=root_causes,
                        mitre_mappings=mitre_mappings,
                        anomaly_results=ml_results,
                        provider=active_provider if is_live_provider else None,
                        force_fallback=(not is_live_provider),
                    )
                    st.session_state["active_incident_report"] = rep
                    st.session_state["active_report_incident_id"] = primary_incident.incident_id
                except Exception as exc:
                    st.error(f"Report generation failed: {exc}")
                    return

        rep = st.session_state.get("active_incident_report")
        if rep:
            # Export controls
            ecol1, ecol2, ecol3 = st.columns([5, 2, 2])
            with ecol2:
                st.download_button(
                    label="Download Markdown",
                    data=rep.to_markdown(),
                    file_name=f"{rep.incident_id}_report.md",
                    mime="text/markdown",
                    use_container_width=True,
                )
            with ecol3:
                st.download_button(
                    label="Download JSON",
                    data=rep.to_json(),
                    file_name=f"{rep.incident_id}_report.json",
                    mime="application/json",
                    use_container_width=True,
                )

            st.markdown("---")

            # Report provenance
            gen_method = rep.generation_method
            if gen_method == "deterministic_fallback":
                render_info_banner(
                    "<b>Report Provenance:</b> Deterministic evidence summary — generated directly from CyberTrace pipeline outputs. "
                    "No external LLM provider was utilized."
                )
            else:
                provider_label = rep.provider_info or "Configured LLM"
                render_info_banner(
                    f"<b>Report Provenance:</b> AI-assisted report generated via {provider_label}, "
                    "grounded in pipeline telemetry."
                )

            # Report sections
            st.markdown("### 1. Executive Summary")
            st.markdown(rep.executive_summary)

            st.markdown("### 2. Incident Overview")
            ov = rep.incident_overview
            ocol1, ocol2, ocol3, ocol4 = st.columns(4)
            ocol1.metric("Severity", ov.get("severity", "UNKNOWN"))
            ocol2.metric("Confidence", f"{ov.get('confidence', 0.0):.2f}")
            ocol3.metric("Rule Detections", len(rep.rule_detections))
            ocol4.metric("Evidence Events", len(ov.get("event_ids", [])))

            st.markdown(f"- **Impacted Accounts:** {', '.join(ov.get('usernames', [])) or 'None'}")
            st.markdown(f"- **Impacted Hostnames:** {', '.join(ov.get('hostnames', [])) or 'None'}")
            st.markdown(f"- **Source IPs:** {', '.join(ov.get('source_ips', [])) or 'None'}")
            st.markdown(f"- **Destination IPs:** {', '.join(ov.get('destination_ips', [])) or 'None'}")

            st.markdown("### 3. Key Findings (Rule Detections)")
            for d in rep.rule_detections:
                st.markdown(f"- **{d.get('rule_id')} ({d.get('severity')}):** {d.get('title')} — *{d.get('description')}*")

            st.markdown("### 4. Attack Timeline")
            if rep.timeline_summary:
                st.dataframe(pd.DataFrame([
                    {
                        "Event ID": item.get("event_id"),
                        "Timestamp": item.get("timestamp"),
                        "Source": item.get("source"),
                        "Action": item.get("action"),
                        "Severity": item.get("severity"),
                        "Message": item.get("raw_message", "")[:75],
                    }
                    for item in rep.timeline_summary[:20]
                ]), use_container_width=True)

            st.markdown("### 5. Probable Root Cause")
            rc = rep.probable_root_cause
            st.markdown(f"**Candidate:** `{rc.get('candidate_type')}` — **{rc.get('title')}** (Confidence: `{rc.get('confidence')}`)")
            st.markdown(f"*{rc.get('reasoning')}*")
            st.caption(f"Supporting Evidence: {', '.join(rc.get('evidence_event_ids', [])) or 'None'}")

            st.markdown("### 6. MITRE ATT&CK Evidence")
            if rep.mitre_mappings:
                st.dataframe(pd.DataFrame([
                    {
                        "Technique ID": m.get("technique_id"),
                        "Name": m.get("technique_name"),
                        "Tactic": m.get("tactic"),
                        "Confidence": m.get("confidence"),
                        "Evidence": m.get("evidence_count", 0),
                    }
                    for m in rep.mitre_mappings
                ]), use_container_width=True)

            st.markdown("### 7. ML Anomaly Signals")
            anoms = [a for a in rep.ml_anomaly_observations if a.get("is_anomaly")]
            st.caption(f"Isolation Forest flagged {len(anoms)} statistical outlier events.")
            if anoms:
                st.dataframe(pd.DataFrame([
                    {
                        "Event ID": a.get("event_id"),
                        "Anomaly Score": round(float(a.get("anomaly_score", 0.0)), 4),
                        "Explanation": a.get("explanation"),
                    }
                    for a in anoms[:15]
                ]), use_container_width=True)

            st.markdown("### 8. Defensive Recommendations")
            for rec in rep.defensive_recommendations:
                prio = rec.get("priority", "MEDIUM")
                st.markdown(f"- **[{prio.upper()}]** {rec.get('action')}")
                if rec.get("rationale"):
                    st.caption(f"Rationale: {rec.get('rationale')}")

            st.markdown("### 9. Evidence References and Limitations")
            for lim in rep.limitations_and_gaps:
                st.markdown(f"- {lim}")

    # =================================================================
    # VIEW 8: ARCHITECTURE & SETTINGS
    # =================================================================
    elif selected_view == "Architecture & Settings":
        render_page_header(
            "Architecture & Settings",
            "Detection rules, analytical pipeline specifications, and system configuration.",
            meta_right="CyberTrace v1.0",
        )

        rules_specs = [
            {"Rule ID": "R001", "Name": "Brute Force Login Attempt", "Severity": "HIGH", "Trigger": "≥ 5 failed auths within 300s window", "MITRE": "T1110.001"},
            {"Rule ID": "R002", "Name": "Port Scan (Reconnaissance)", "Severity": "MEDIUM", "Trigger": "≥ 10 distinct dest ports in 120s window", "MITRE": "T1046"},
            {"Rule ID": "R003", "Name": "Suspicious Subnet Login", "Severity": "MEDIUM", "Trigger": "Successful auth from 10.0.0.x subnet", "MITRE": "T1078"},
            {"Rule ID": "R004", "Name": "Privilege Escalation", "Severity": "HIGH", "Trigger": "Sudo elevation or root UID transition", "MITRE": "T1548.003"},
            {"Rule ID": "R005", "Name": "Sensitive File Access", "Severity": "HIGH", "Trigger": "Read/access of sensitive keywords (/etc/shadow, .pem, keys)", "MITRE": "T1552.004 / T1003.008"},
            {"Rule ID": "R006", "Name": "Large Outbound Transfer", "Severity": "HIGH", "Trigger": "Outbound stream ≥ 100 MB or explicit exfil telemetry", "MITRE": "T1048"},
        ]
        st.dataframe(pd.DataFrame(rules_specs), use_container_width=True)

        st.markdown('<div class="sec-title" style="margin-top:1rem;">Pipeline Architecture</div>', unsafe_allow_html=True)
        pipeline_steps = [
            ("01", "Raw Telemetry Ingestion", "Multi-source security logs (Auth, Syslog, Audit, Firewall) ingested with full forensic fidelity.", "INPUT"),
            ("02", "Parsing & Normalization", "Structured attribute extraction (timestamps, IPs, users, hosts, actions) into canonical event models.", "SCHEMA"),
            ("03", "Detection Engine (R001–R006)", "Stateful detection rules evaluated against normalized events with evidence-event traceability.", "RULES"),
            ("04", "Cross-Source Correlation", "Temporal sliding windows and entity linking across IPs, accounts, hosts to group detections.", "CORRELATION"),
            ("05", "Attack Reconstruction & Root Cause", "Chronological attack stage inference, directed graph edges, and ranked root-cause candidates.", "CAUSAL"),
            ("06", "MITRE ATT&CK Mapping", "Behavioral evidence aligned to Enterprise ATT&CK tactics and techniques with confidence scoring.", "MITRE"),
            ("07", "ML Anomaly Scoring (Isolation Forest)", "Baseline divergence scoring. Independent from rule detections to prevent false-positive inflation.", "ML", "#D29922"),
            ("08", "Report Synthesis", "Structured executive summary, timeline, and recommendations. Fully operational offline via deterministic fallback.", "OUTPUT", "#3FB950"),
        ]

        for step in pipeline_steps:
            num, title, desc, tag = step[0], step[1], step[2], step[3]
            accent = step[4] if len(step) > 4 else None
            num_style = f' style="color:{accent};"' if accent else ""
            border_style = f' style="border-left:3px solid {accent};"' if accent else ""
            st.markdown(f"""
            <div class="pipe-step"{border_style}>
                <div class="pipe-num"{num_style}>{num}</div>
                <div class="pipe-body">
                    <div class="pipe-title">{title}</div>
                    <div class="pipe-desc">{desc}</div>
                </div>
                <div class="pipe-tag">{tag}</div>
            </div>
            """, unsafe_allow_html=True)

        # Provider status
        st.markdown('<div class="sec-title" style="margin-top:1rem;">AI Provider Status</div>', unsafe_allow_html=True)
        if is_live_provider:
            render_info_banner(f"<b>Live provider configured.</b> Reports will use the connected LLM for synthesis.")
        else:
            render_info_banner(
                "<b>No live AI provider configured.</b> Reports use the deterministic fallback generator. "
                "All output is derived from verified pipeline data without external API calls.",
                warn=True,
            )


if __name__ == "__main__":
    main()

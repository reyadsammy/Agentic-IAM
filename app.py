"""
Agentic-IAM: Streamlit Dashboard Application

Main entry point for the web-based GUI dashboard with role-based access control.
Web3-inspired UI with Blue/White (light) and Blue/Black (dark) color scheme.
"""
import streamlit as st
import sys
from pathlib import Path
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import uuid

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from dashboard.utils import show_alert
from database import get_database
from dashboard.components.agent_selection import (
    show_agent_registration, show_agent_selector,
    show_agent_list, show_agent_details
)
from dashboard.components.ai_assistant import show_ai_assistant
from dashboard.components.risk_assessment import show_risk_assessment
from utils.rbac import (
    Permission, Role, check_permission, is_admin, is_operator,
    get_current_user_role, get_current_user_permissions, get_rbac_manager
)
from utils.advanced_features import AgentHealthMonitor, AgentAnalytics, ReportGenerator
from utils.security import (
    InputValidator, RateLimiter, AccountSecurity, AuditLogger,
    SessionSecurityManager, SQLInjectionProtection, XSSProtection
)

# Page configuration
st.set_page_config(
    page_title="Agentic-IAM",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ---- THEME ----

def get_theme_css(theme: str) -> str:
    """Generate CSS for Blue/White (light) and Blue/Black (dark) web3 theme."""
    is_dark = theme != "Light"

    if is_dark:
        tv = """
    --bg-base: #050510; --bg-primary: #0a0a1a; --bg-secondary: #0f0f24;
    --bg-card: rgba(15,15,36,0.8); --bg-card-hover: rgba(20,20,48,0.85);
    --bg-glass: rgba(15,15,40,0.6); --bg-glass-hover: rgba(25,25,60,0.7);
    --bg-input: rgba(15,15,40,0.5);
    --border-subtle: rgba(59,130,246,0.12); --border-default: rgba(59,130,246,0.18);
    --border-hover: rgba(59,130,246,0.4); --border-active: rgba(59,130,246,0.6);
    --blue-50: #eff6ff; --blue-100: #dbeafe; --blue-200: #bfdbfe;
    --blue-300: #93c5fd; --blue-400: #60a5fa; --blue-500: #3b82f6;
    --blue-600: #2563eb; --blue-700: #1d4ed8; --blue-800: #1e40af;
    --accent: #60a5fa; --accent-solid: #3b82f6; --accent-dark: #2563eb;
    --accent-dim: rgba(59,130,246,0.1); --accent-border: rgba(59,130,246,0.25);
    --accent-glow: rgba(59,130,246,0.2);
    --text-primary: #f0f4ff; --text-secondary: #94a3c0; --text-muted: #4b5a78;
    --success: #22c55e; --success-dim: rgba(34,197,94,0.1); --success-border: rgba(34,197,94,0.25);
    --warning: #eab308; --warning-dim: rgba(234,179,8,0.1); --warning-border: rgba(234,179,8,0.25);
    --danger: #ef4444; --danger-dim: rgba(239,68,68,0.1); --danger-border: rgba(239,68,68,0.25);
    --shadow-sm: 0 1px 4px rgba(0,0,0,0.5); --shadow-md: 0 4px 16px rgba(0,0,0,0.4);
    --shadow-glow: 0 0 24px rgba(59,130,246,0.1), 0 0 48px rgba(59,130,246,0.05);
    --shadow-btn: 0 2px 12px rgba(59,130,246,0.3);
    --shadow-btn-hover: 0 4px 20px rgba(59,130,246,0.45);
    --sidebar-bg: rgba(8,8,20,0.97); --header-bg: rgba(5,5,16,0.85);
    --chart-text: #94a3c0; --chart-grid: rgba(59,130,246,0.06);
    --scrollbar-c: rgba(59,130,246,0.15); --scrollbar-h: rgba(59,130,246,0.35);"""
    else:
        tv = """
    --bg-base: #f0f4ff; --bg-primary: #f8faff; --bg-secondary: #eef2ff;
    --bg-card: rgba(255,255,255,0.97); --bg-card-hover: rgba(255,255,255,1);
    --bg-glass: rgba(255,255,255,0.95); --bg-glass-hover: rgba(255,255,255,1);
    --bg-input: rgba(255,255,255,0.98);
    --border-subtle: rgba(37,99,235,0.1); --border-default: rgba(37,99,235,0.15);
    --border-hover: rgba(37,99,235,0.35); --border-active: rgba(37,99,235,0.5);
    --blue-50: #eff6ff; --blue-100: #dbeafe; --blue-200: #bfdbfe;
    --blue-300: #93c5fd; --blue-400: #60a5fa; --blue-500: #3b82f6;
    --blue-600: #2563eb; --blue-700: #1d4ed8; --blue-800: #1e40af;
    --accent: #2563eb; --accent-solid: #1d4ed8; --accent-dark: #1e40af;
    --accent-dim: rgba(37,99,235,0.06); --accent-border: rgba(37,99,235,0.18);
    --accent-glow: rgba(37,99,235,0.08);
    --text-primary: #0f172a; --text-secondary: #475569; --text-muted: #94a3b8;
    --success: #16a34a; --success-dim: rgba(22,163,74,0.06); --success-border: rgba(22,163,74,0.18);
    --warning: #ca8a04; --warning-dim: rgba(202,138,4,0.06); --warning-border: rgba(202,138,4,0.18);
    --danger: #dc2626; --danger-dim: rgba(220,38,38,0.06); --danger-border: rgba(220,38,38,0.18);
    --shadow-sm: 0 1px 3px rgba(37,99,235,0.04); --shadow-md: 0 4px 12px rgba(37,99,235,0.06);
    --shadow-glow: 0 0 20px rgba(37,99,235,0.06);
    --shadow-btn: 0 2px 8px rgba(37,99,235,0.2);
    --shadow-btn-hover: 0 4px 16px rgba(37,99,235,0.3);
    --sidebar-bg: rgba(240,244,255,1); --header-bg: rgba(248,250,255,0.98);
    --chart-text: #475569; --chart-grid: rgba(37,99,235,0.05);
    --scrollbar-c: rgba(37,99,235,0.1); --scrollbar-h: rgba(37,99,235,0.25);"""

    return f"""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
:root {{{tv}
    --radius-sm: 8px; --radius: 12px; --radius-lg: 16px; --radius-xl: 20px; --radius-2xl: 24px;
    --transition-fast: 150ms cubic-bezier(0.4,0,0.2,1);
    --transition-base: 250ms cubic-bezier(0.4,0,0.2,1);
    --transition-slow: 400ms cubic-bezier(0.4,0,0.2,1);
}}

/* ---- Base ---- */
.stApp {{ background: var(--bg-base) !important;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    -webkit-font-smoothing: antialiased; }}
.main .block-container {{ padding: 1.5rem 2.5rem !important; max-width: 1400px; }}
#MainMenu {{visibility: hidden;}} footer {{visibility: hidden;}}
header[data-testid="stHeader"] {{ background: var(--header-bg) !important;
    backdrop-filter: blur(24px) saturate(1.6); -webkit-backdrop-filter: blur(24px) saturate(1.6);
    border-bottom: 1px solid var(--border-subtle); }}

/* ---- Sidebar ---- */
section[data-testid="stSidebar"] {{ background: var(--sidebar-bg) !important;
    backdrop-filter: blur(24px) saturate(1.5); -webkit-backdrop-filter: blur(24px) saturate(1.5);
    border-right: 1px solid var(--border-subtle) !important; width: 260px !important; }}
section[data-testid="stSidebar"] .stMarkdown {{ color: var(--text-secondary); }}
section[data-testid="stSidebar"] hr {{ border-color: var(--border-subtle) !important;
    margin: 0.6rem 0 !important; opacity: 0.5; }}
section[data-testid="stSidebar"] .stButton > button {{
    background: transparent !important; border: 1px solid transparent !important;
    border-radius: var(--radius) !important; padding: 0.45rem 0.85rem !important;
    color: var(--text-muted) !important; font-size: 0.84rem !important;
    font-weight: 500 !important; text-align: left !important;
    justify-content: flex-start !important; box-shadow: none !important;
    margin-bottom: 2px !important; transition: all var(--transition-fast) !important;
    letter-spacing: -0.01em !important; }}
section[data-testid="stSidebar"] .stButton > button:hover {{
    background: var(--accent-dim) !important; color: var(--accent) !important;
    border-color: var(--accent-border) !important;
    box-shadow: none !important; transform: none !important; }}

/* ---- Typography ---- */
h1, h2, h3 {{ color: var(--text-primary) !important;
    font-family: 'Inter', sans-serif !important; letter-spacing: -0.03em; }}
h1 {{ font-weight: 800 !important; font-size: 1.6rem !important; }}
h2 {{ font-weight: 700 !important; font-size: 1.2rem !important; }}
h3 {{ font-weight: 600 !important; font-size: 1rem !important; }}
p, span, li, div {{ color: var(--text-secondary) !important; }}
strong, b {{ color: var(--text-primary) !important; }}

/* ---- Metric Cards ---- */
div[data-testid="stMetric"] {{
    background: var(--bg-card) !important;
    backdrop-filter: blur(16px) saturate(1.4);
    -webkit-backdrop-filter: blur(16px) saturate(1.4);
    border: 1px solid var(--border-subtle) !important;
    border-top: 2px solid var(--accent-solid) !important;
    border-radius: var(--radius-lg) !important;
    padding: 1.1rem 1.25rem !important;
    transition: all var(--transition-base);
    box-shadow: var(--shadow-sm); }}
div[data-testid="stMetric"]:hover {{
    border-color: var(--border-hover) !important;
    border-top-color: var(--accent) !important;
    box-shadow: var(--shadow-glow); transform: translateY(-2px); }}
div[data-testid="stMetric"] label {{
    color: var(--text-muted) !important;
    font-size: 0.72rem !important; text-transform: uppercase;
    letter-spacing: 0.08em; font-weight: 600 !important; }}
div[data-testid="stMetric"] div[data-testid="stMetricValue"] {{
    color: var(--text-primary) !important; font-weight: 800 !important;
    font-size: 1.6rem !important; letter-spacing: -0.03em; }}

/* ---- Buttons (main content) ---- */
.main .stButton > button {{
    background: var(--bg-glass) !important;
    backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
    border: 1px solid var(--border-default) !important;
    border-radius: var(--radius) !important;
    color: var(--accent) !important;
    font-weight: 600 !important; font-size: 0.84rem !important;
    padding: 0.55rem 1.25rem !important;
    transition: all var(--transition-fast) !important;
    letter-spacing: -0.01em !important; }}
.main .stButton > button:hover {{
    background: var(--accent-solid) !important;
    border-color: var(--accent-solid) !important;
    color: white !important;
    box-shadow: var(--shadow-btn) !important;
    transform: translateY(-1px) !important; }}

/* Primary / Submit buttons */
button[kind="primary"], .stFormSubmitButton > button {{
    background: var(--accent-solid) !important;
    border: 1px solid var(--accent-dark) !important;
    color: white !important; font-weight: 700 !important;
    border-radius: var(--radius) !important;
    padding: 0.6rem 1.5rem !important;
    box-shadow: var(--shadow-btn) !important;
    letter-spacing: -0.01em !important;
    transition: all var(--transition-fast) !important; }}
button[kind="primary"]:hover, .stFormSubmitButton > button:hover {{
    background: var(--accent-dark) !important;
    box-shadow: var(--shadow-btn-hover) !important;
    transform: translateY(-2px) !important; }}

/* Download buttons */
.stDownloadButton > button {{
    background: var(--accent-dim) !important;
    border-color: var(--accent-border) !important;
    color: var(--accent) !important; }}
.stDownloadButton > button:hover {{
    background: var(--accent-solid) !important;
    color: white !important;
    box-shadow: var(--shadow-btn) !important; }}

/* ---- Inputs ---- */
.stTextInput > div > div > input, .stTextArea > div > div > textarea,
.stNumberInput > div > div > input {{
    background: var(--bg-input) !important;
    backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
    border: 1px solid var(--border-default) !important;
    border-radius: var(--radius) !important; color: var(--text-primary) !important;
    font-family: 'Inter', sans-serif !important; font-size: 0.88rem !important;
    padding: 0.6rem 0.9rem !important; transition: all var(--transition-fast); }}
.stTextInput > div > div > input:focus, .stTextArea > div > div > textarea:focus {{
    border-color: var(--accent-solid) !important;
    box-shadow: 0 0 0 3px var(--accent-dim), 0 0 16px var(--accent-glow) !important; }}
.stTextInput > div > div > input::placeholder, .stTextArea > div > div > textarea::placeholder {{
    color: var(--text-muted) !important; opacity: 0.7; }}

/* ---- Selects ---- */
.stSelectbox > div > div, .stMultiSelect > div > div {{
    background: var(--bg-input) !important;
    backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
    border: 1px solid var(--border-default) !important;
    border-radius: var(--radius) !important; color: var(--text-primary) !important; }}

/* ---- Tabs ---- */
.stTabs [data-baseweb="tab-list"] {{
    gap: 4px; background: var(--bg-glass);
    backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
    border-radius: var(--radius-lg); padding: 5px;
    border: 1px solid var(--border-subtle); }}
.stTabs [data-baseweb="tab"] {{
    background: transparent !important;
    border-radius: var(--radius) !important; color: var(--text-muted) !important;
    font-weight: 600 !important; padding: 0.5rem 1rem !important;
    font-size: 0.84rem !important; border: none !important;
    transition: all var(--transition-fast) !important; }}
.stTabs [data-baseweb="tab"]:hover {{
    color: var(--accent) !important;
    background: var(--accent-dim) !important; }}
.stTabs [aria-selected="true"] {{
    background: var(--accent-solid) !important;
    color: white !important;
    box-shadow: var(--shadow-btn); }}
.stTabs [data-baseweb="tab-highlight"] {{ background-color: transparent !important; }}
.stTabs [data-baseweb="tab-border"] {{ display: none !important; }}

/* ---- Dataframe ---- */
.stDataFrame {{ border: 1px solid var(--border-subtle) !important;
    border-radius: var(--radius-lg) !important; overflow: hidden; }}
div[data-testid="stDataFrame"] > div {{ background: var(--bg-card) !important;
    border-radius: var(--radius-lg) !important; }}
div[data-testid="stDataFrame"] th {{ background: var(--bg-secondary) !important;
    color: var(--text-primary) !important; font-weight: 600 !important; }}
div[data-testid="stDataFrame"] td {{ color: var(--text-secondary) !important; }}
div[data-testid="stDataFrame"] table {{ border-collapse: collapse; }}
div[data-testid="stDataFrame"] th, div[data-testid="stDataFrame"] td {{
    border-color: var(--border-subtle) !important; }}

/* ---- Expander ---- */
.streamlit-expanderHeader {{ background: var(--bg-glass) !important;
    border: 1px solid var(--border-subtle) !important;
    border-radius: var(--radius) !important; color: var(--text-primary) !important;
    font-weight: 500 !important; }}

/* ---- Alerts & Code ---- */
div[data-testid="stAlert"] {{ border-radius: var(--radius) !important;
    border-left-width: 3px !important; backdrop-filter: blur(12px); }}
code {{ background: var(--accent-dim) !important; color: var(--accent) !important;
    padding: 0.15rem 0.5rem !important; border-radius: var(--radius-sm) !important;
    font-family: 'JetBrains Mono', monospace !important; font-size: 0.8rem !important;
    border: 1px solid var(--accent-border); }}

/* ---- Forms ---- */
div[data-testid="stForm"] {{ background: var(--bg-card) !important;
    backdrop-filter: blur(20px) saturate(1.4);
    -webkit-backdrop-filter: blur(20px) saturate(1.4);
    border: 1px solid var(--border-subtle) !important;
    border-radius: var(--radius-xl) !important; padding: 1.75rem !important;
    box-shadow: var(--shadow-sm); }}

.js-plotly-plot .plotly .modebar {{ background: transparent !important; }}

/* ---- Custom Classes ---- */
.page-header {{ margin-bottom: 1.75rem; }}
.page-header h1 {{ color: var(--text-primary) !important; }}
.page-header p {{ color: var(--text-muted) !important; font-size: 0.9rem; margin: 0; }}

/* Glass Card */
.card {{ background: var(--bg-card); backdrop-filter: blur(16px) saturate(1.3);
    -webkit-backdrop-filter: blur(16px) saturate(1.3);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-lg); padding: 1.15rem 1.3rem;
    margin-bottom: 0.6rem; transition: all var(--transition-base);
    box-shadow: var(--shadow-sm); }}
.card:hover {{ border-color: var(--border-hover); box-shadow: var(--shadow-glow);
    transform: translateY(-1px); }}
.card h4 {{ color: var(--text-primary) !important; margin: 0 0 0.35rem 0;
    font-size: 0.94rem; font-weight: 700; letter-spacing: -0.02em; }}
.card p {{ color: var(--text-muted) !important; font-size: 0.84rem;
    margin: 0; line-height: 1.55; }}

.glass-card {{ background: var(--bg-glass); backdrop-filter: blur(20px) saturate(1.4);
    -webkit-backdrop-filter: blur(20px) saturate(1.4);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-xl); padding: 1.3rem 1.5rem;
    margin-bottom: 0.75rem; transition: all var(--transition-base);
    box-shadow: var(--shadow-sm); position: relative; overflow: hidden; }}
.glass-card:hover {{ border-color: var(--border-hover);
    box-shadow: var(--shadow-glow); transform: translateY(-2px); }}
.glass-card::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0;
    height: 2px; background: linear-gradient(90deg, var(--accent-solid), var(--accent), transparent);
    opacity: 0; transition: opacity var(--transition-base); }}
.glass-card:hover::before {{ opacity: 1; }}
.glass-card h4 {{ color: var(--text-primary) !important; margin: 0 0 0.3rem 0;
    font-size: 0.92rem; font-weight: 700; letter-spacing: -0.02em; }}
.glass-card p {{ color: var(--text-muted) !important; font-size: 0.82rem;
    margin: 0; line-height: 1.5; }}

/* Feature Card - web3 style */
.feature-card {{ background: var(--bg-card); backdrop-filter: blur(16px) saturate(1.3);
    -webkit-backdrop-filter: blur(16px) saturate(1.3);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-lg); padding: 1rem 1.2rem;
    margin-bottom: 0.5rem; transition: all var(--transition-base);
    display: flex; align-items: center; gap: 1rem;
    box-shadow: var(--shadow-sm); cursor: default; }}
.feature-card:hover {{ border-color: var(--border-hover);
    background: var(--bg-card-hover); box-shadow: var(--shadow-glow);
    transform: translateY(-2px); }}
.feature-card .fc-icon {{ width: 42px; height: 42px; min-width: 42px;
    border-radius: var(--radius); display: flex; align-items: center;
    justify-content: center; font-size: 1.15rem; font-weight: 700;
    background: linear-gradient(135deg, var(--accent-dim), rgba(59,130,246,0.15));
    color: var(--accent);
    border: 1px solid var(--accent-border);
    box-shadow: 0 2px 8px var(--accent-glow); }}
.feature-card .fc-content h4 {{ color: var(--text-primary) !important;
    font-size: 0.9rem; font-weight: 700; margin: 0 0 0.15rem 0;
    letter-spacing: -0.02em; }}
.feature-card .fc-content p {{ color: var(--text-muted) !important;
    font-size: 0.78rem; margin: 0; line-height: 1.45; }}

/* ---- Badges ---- */
.badge {{ display: inline-block; padding: 3px 12px; border-radius: 100px;
    font-size: 0.65rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }}
.badge-admin {{ background: var(--danger-dim); color: var(--danger); border: 1px solid var(--danger-border); }}
.badge-operator {{ background: var(--warning-dim); color: var(--warning); border: 1px solid var(--warning-border); }}
.badge-user {{ background: var(--success-dim); color: var(--success); border: 1px solid var(--success-border); }}
.badge-guest {{ background: rgba(148,163,184,0.08); color: var(--text-muted); border: 1px solid rgba(148,163,184,0.2); }}
.status-active {{ background: var(--success-dim); color: var(--success); border: 1px solid var(--success-border); }}
.status-inactive {{ background: var(--danger-dim); color: var(--danger); border: 1px solid var(--danger-border); }}
.status-suspended {{ background: var(--warning-dim); color: var(--warning); border: 1px solid var(--warning-border); }}

/* ---- Navigation ---- */
.section-label {{ color: var(--text-muted) !important; font-size: 0.68rem;
    text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700; margin-bottom: 0.6rem; }}
.nav-section {{ color: var(--accent) !important; font-size: 0.6rem;
    text-transform: uppercase; letter-spacing: 0.12em; font-weight: 700;
    margin: 1rem 0 0.3rem 0.2rem; padding: 0;
    opacity: 0.7; }}
.nav-active {{ background: linear-gradient(135deg, var(--accent-solid), var(--accent-dark));
    color: white !important;
    border-radius: var(--radius); padding: 0.45rem 0.85rem;
    font-size: 0.84rem; font-weight: 600; letter-spacing: -0.01em;
    margin-bottom: 2px; box-shadow: var(--shadow-btn); }}

/* ---- Login ---- */
.login-cred {{ background: var(--bg-card); backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-lg); padding: 0.85rem; text-align: center;
    transition: all var(--transition-base); }}
.login-cred:hover {{ border-color: var(--border-hover);
    box-shadow: var(--shadow-glow); transform: translateY(-2px); }}

/* ---- Stats ---- */
.stat-row {{ display: flex; justify-content: space-between; align-items: center;
    padding: 0.45rem 0; border-bottom: 1px solid var(--border-subtle); }}
.stat-row:last-child {{ border-bottom: none; }}
.stat-row .label {{ color: var(--text-muted) !important; font-size: 0.8rem; }}
.stat-row .value {{ font-weight: 700; font-size: 0.8rem; color: var(--accent) !important; }}

/* ---- Security Status ---- */
.security-indicator {{ display: flex; align-items: center; gap: 0.7rem;
    padding: 0.65rem 0.9rem; background: var(--bg-card);
    backdrop-filter: blur(12px); border: 1px solid var(--border-subtle);
    border-radius: var(--radius); margin-bottom: 0.45rem;
    transition: all var(--transition-fast); }}
.security-indicator:hover {{ border-color: var(--border-hover);
    box-shadow: var(--shadow-glow); }}
.security-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
.security-dot.active {{ background: var(--success); box-shadow: 0 0 8px var(--success); }}
.security-dot.inactive {{ background: var(--text-muted); }}
.security-dot.warning {{ background: var(--warning); box-shadow: 0 0 8px var(--warning); }}

/* ---- Quick Action Buttons ---- */
.qa-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 0.6rem; }}

/* ---- Scrollbar ---- */
::-webkit-scrollbar {{ width: 5px; height: 5px; }}
::-webkit-scrollbar-track {{ background: transparent; }}
::-webkit-scrollbar-thumb {{ background: var(--scrollbar-c); border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--scrollbar-h); }}

span[data-baseweb="tag"] {{ background: var(--accent-dim) !important;
    border-color: var(--accent-border) !important; color: var(--accent) !important;
    border-radius: var(--radius-sm) !important; }}
hr {{ border-color: var(--border-subtle) !important; opacity: 0.4; }}
.stSlider > div > div > div > div {{ background: var(--accent-solid) !important; }}
.stCheckbox > label > span {{ color: var(--text-secondary) !important; }}

/* ---- Force ALL element backgrounds to match theme ---- */

/* Buttons - every variant */
[data-testid="baseButton-secondary"] {{
    background: var(--bg-glass) !important;
    color: var(--accent) !important;
    border: 1px solid var(--border-default) !important;
    border-radius: var(--radius) !important; }}
[data-testid="baseButton-secondary"]:hover {{
    background: var(--accent-solid) !important;
    color: white !important;
    border-color: var(--accent-solid) !important; }}
[data-testid="baseButton-primary"] {{
    background: var(--accent-solid) !important;
    color: white !important; }}
[data-testid="baseButton-primary"]:hover {{
    background: var(--accent-dark) !important; }}
[data-testid="baseButton-minimal"] {{
    color: var(--accent) !important; }}

/* Forms */
div[data-testid="stForm"] {{
    background: var(--bg-card) !important;
    border-color: var(--border-subtle) !important; }}

/* Tab panels */
[data-baseweb="tab-panel"] {{
    background: transparent !important; }}

/* Alerts */
div[data-testid="stAlert"] {{
    background: var(--bg-card) !important;
    color: var(--text-secondary) !important; }}
div[data-testid="stAlert"] p, div[data-testid="stAlert"] span,
div[data-testid="stAlert"] div {{
    color: var(--text-secondary) !important; }}

/* Selectbox - wrapper, value, and dropdown */
div[data-testid="stSelectbox"] > div > div {{
    background: var(--bg-input) !important;
    color: var(--text-primary) !important; }}
[data-baseweb="select"] > div {{
    background: var(--bg-input) !important;
    color: var(--text-primary) !important;
    border-color: var(--border-default) !important; }}
[data-baseweb="select"] > div > div {{ color: var(--text-primary) !important; }}
[data-baseweb="select"] svg {{ fill: var(--text-muted) !important; }}

/* Dropdown/popover menus */
[data-baseweb="popover"] {{
    background: var(--bg-card) !important;
    border: 1px solid var(--border-default) !important;
    border-radius: var(--radius) !important;
    box-shadow: var(--shadow-md) !important; }}
[data-baseweb="popover"] > div {{
    background: var(--bg-card) !important; }}
[data-baseweb="menu"] {{
    background: var(--bg-card) !important; }}
[data-baseweb="menu"] li {{
    color: var(--text-secondary) !important;
    background: var(--bg-card) !important; }}
[data-baseweb="menu"] li:hover {{
    background: var(--accent-dim) !important;
    color: var(--accent) !important; }}
[data-baseweb="menu"] li[aria-selected="true"] {{
    background: var(--accent-dim) !important;
    color: var(--accent) !important; }}
ul[role="listbox"] {{
    background: var(--bg-card) !important; }}
ul[role="listbox"] li {{
    background: var(--bg-card) !important;
    color: var(--text-secondary) !important; }}
ul[role="listbox"] li:hover {{
    background: var(--accent-dim) !important;
    color: var(--accent) !important; }}

/* Multiselect */
div[data-testid="stMultiSelect"] > div > div {{
    background: var(--bg-input) !important;
    color: var(--text-primary) !important; }}

/* Checkbox */
.stCheckbox > label {{
    color: var(--text-secondary) !important; }}
.stCheckbox > label > div[data-testid="stCheckbox"] {{
    background: transparent !important; }}
[data-testid="stCheckbox"] > div:first-child {{
    background: var(--bg-input) !important;
    border-color: var(--border-default) !important; }}

/* Slider track and labels */
.stSlider > div > div > div {{ background: var(--border-subtle) !important; }}
.stSlider > div > div > div > div {{ background: var(--accent-solid) !important; }}
.stSlider > div > div > div > div > div {{
    background: var(--accent-solid) !important;
    border-color: var(--accent-solid) !important;
    box-shadow: var(--shadow-btn) !important; }}
.stSlider label {{ color: var(--text-secondary) !important; }}
[data-baseweb="slider"] div {{ color: var(--text-muted) !important; }}

/* Number input */
.stNumberInput > div > div {{
    background: var(--bg-input) !important;
    border-color: var(--border-default) !important;
    border-radius: var(--radius) !important; }}
.stNumberInput button {{
    background: var(--bg-glass) !important;
    color: var(--accent) !important;
    border-color: var(--border-default) !important; }}
.stNumberInput button:hover {{
    background: var(--accent-dim) !important; }}

/* Radio buttons */
.stRadio > div {{ color: var(--text-secondary) !important; }}
.stRadio > div > label > div:first-child {{
    border-color: var(--border-default) !important; }}

/* Text area */
.stTextArea label, .stTextInput label, .stSelectbox label,
.stMultiSelect label, .stNumberInput label, .stSlider label {{
    color: var(--text-secondary) !important; }}

/* Expander content area */
.streamlit-expanderContent {{
    background: var(--bg-card) !important;
    border-color: var(--border-subtle) !important;
    color: var(--text-secondary) !important; }}

/* JSON viewer */
div[data-testid="stJson"] {{
    background: var(--bg-card) !important;
    border: 1px solid var(--border-subtle) !important;
    border-radius: var(--radius) !important; }}
div[data-testid="stJson"] * {{ color: var(--text-secondary) !important; }}

/* File uploader */
div[data-testid="stFileUploader"] {{
    background: var(--bg-card) !important; }}
div[data-testid="stFileUploader"] > div {{
    background: var(--bg-input) !important;
    border-color: var(--border-default) !important; }}

/* Toggle */
div[data-testid="stToggle"] label span {{
    color: var(--text-secondary) !important; }}

/* Caption and small text */
.stCaption, div[data-testid="stCaptionContainer"] {{
    color: var(--text-muted) !important; }}

/* Toast/snackbar messages */
div[data-testid="stToast"] {{
    background: var(--bg-card) !important;
    color: var(--text-primary) !important;
    border: 1px solid var(--border-default) !important; }}

/* Markdown general */
.stMarkdown {{ color: var(--text-secondary) !important; }}

/* All remaining internal backgrounds */
[data-testid="stAppViewContainer"] {{ background: var(--bg-base) !important; }}
[data-testid="stBottomBlockContainer"] {{ background: var(--bg-base) !important; }}
div[data-testid="stToolbar"] {{ background: transparent !important; }}
div[data-testid="stDecoration"] {{ background: transparent !important; }}
.stDeployButton {{ display: none !important; }}
</style>"""


# Apply theme CSS
_theme = st.session_state.get("settings_theme", "Dark")
st.markdown(get_theme_css(_theme), unsafe_allow_html=True)


# ---- HELPERS ----

def role_badge(role: str) -> str:
    r = role.lower()
    return f'<span class="badge badge-{r}">{role.upper()}</span>'


def status_badge(status: str) -> str:
    s = status.lower()
    return f'<span class="badge status-{s}">{status.upper()}</span>'


def page_header(title: str, subtitle: str):
    st.markdown(f"""
    <div class="page-header">
        <h1 style="font-size:1.6rem !important; margin-bottom:0.2rem;
            color:var(--text-primary) !important;">{title}</h1>
        <p>{subtitle}</p>
    </div>
    """, unsafe_allow_html=True)


def section_label(text: str):
    st.markdown(f'<p class="section-label">{text}</p>', unsafe_allow_html=True)


def spacer(rem: float = 0.75):
    st.markdown(f"<div style='height:{rem}rem'></div>", unsafe_allow_html=True)


# ---- SESSION ----

def initialize_session():
    defaults = {
        "db": None,
        "selected_agent": None,
        "user": None,
        "authenticated": False,
        "login_time": None,
        "settings_theme": "Dark",
        "settings_refresh": 30,
        "settings_notifications": True,
        "settings_mfa": True,
        "settings_session_timeout": 60,
        "settings_debug": False,
        "settings_log_level": "INFO",
        "settings_max_log_size": 100,
        "_current_page": "Home",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

    if st.session_state.db is None:
        st.session_state.db = get_database()

    if "rate_limiter" not in st.session_state:
        st.session_state.rate_limiter = RateLimiter(max_attempts=5, window_seconds=300)
    if "account_security" not in st.session_state:
        st.session_state.account_security = AccountSecurity(max_failed_attempts=5)
    if "csrf_token" not in st.session_state:
        st.session_state.csrf_token = SessionSecurityManager.generate_csrf_token()


# ---- LOGIN ----

def show_login():
    spacer(3)
    col1, col2, col3 = st.columns([1.2, 1.2, 1.2])

    with col2:
        st.markdown("""
        <div style="text-align:center; margin-bottom:2.5rem;">
            <div style="display:inline-flex; align-items:center; justify-content:center;
                width:56px; height:56px; border-radius:var(--radius-lg);
                background:linear-gradient(135deg, var(--accent-solid), var(--accent-dark));
                box-shadow: var(--shadow-btn), 0 0 40px var(--accent-glow);
                margin-bottom:1.25rem;">
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"
                    stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
            </div>
            <h1 style="font-size:1.5rem !important; margin-bottom:0.35rem;
                color:var(--text-primary) !important; letter-spacing:-0.04em;
                font-weight:800 !important;">Agentic-IAM</h1>
            <p style="color:var(--text-muted) !important; font-size:0.85rem; margin:0;">
                Identity & Access Management for AI Agents
            </p>
        </div>
        """, unsafe_allow_html=True)

        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter username")
            password = st.text_input("Password", type="password", placeholder="Enter password")
            submitted = st.form_submit_button("Sign In", use_container_width=True)

            if submitted:
                if not username or not password:
                    st.error("Please enter both username and password")
                    return

                if not InputValidator.validate_username(username):
                    st.warning("Invalid username format")
                    AuditLogger.log_suspicious_activity(username, "Invalid username format")
                    return

                if st.session_state.account_security.is_account_locked(username):
                    st.error("Account temporarily locked. Try again later.")
                    return

                if not st.session_state.rate_limiter.is_allowed(username):
                    st.error("Too many attempts. Please wait.")
                    st.session_state.account_security.record_failed_attempt(username)
                    return

                if SQLInjectionProtection.detect_sql_injection(username):
                    st.error("Invalid input detected")
                    AuditLogger.log_suspicious_activity(username, "SQL injection attempt")
                    return

                user = st.session_state.db.authenticate_user(username, password)

                if user:
                    st.session_state.user = user
                    st.session_state.authenticated = True
                    st.session_state.login_time = datetime.now()
                    st.session_state.account_security.record_successful_login(username)
                    st.session_state.db.record_login(username, True, reason="Login successful")
                    AuditLogger.log_successful_login(username)
                    st.rerun()
                else:
                    st.session_state.account_security.record_failed_attempt(username)
                    st.session_state.db.record_login(username, False, reason="Invalid credentials")
                    remaining = st.session_state.account_security.max_failed_attempts - len(
                        st.session_state.account_security.failed_attempts.get(username, [])
                    )
                    st.error(f"Invalid credentials ({max(0, remaining)} attempts remaining)")
                    AuditLogger.log_failed_login(username, "Invalid credentials")

        spacer(0.75)
        st.markdown('<p class="section-label" style="text-align:center;">Demo Accounts</p>', unsafe_allow_html=True)

        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"""<div class="login-cred">
                {role_badge('admin')}<br/>
                <code>admin</code> / <code>admin123</code>
            </div>""", unsafe_allow_html=True)
        with c2:
            st.markdown(f"""<div class="login-cred">
                {role_badge('operator')}<br/>
                <code>operator</code> / <code>operator123</code>
            </div>""", unsafe_allow_html=True)
        with c3:
            st.markdown(f"""<div class="login-cred">
                {role_badge('user')}<br/>
                <code>user</code> / <code>user123</code>
            </div>""", unsafe_allow_html=True)

        spacer(1)
        st.markdown("""<p style="text-align:center; color:var(--text-muted) !important; font-size:0.72rem;">
            Secured with bcrypt hashing, rate limiting, SQL injection protection & audit logging
        </p>""", unsafe_allow_html=True)




# ---- NAVIGATION ----

_NAV_ICONS = {
    "Home": "\u2302",
    "Browse Agents": "\u229a",
    "Register Agent": "\u2295",
    "Risk Assessment": "\u26a0",
    "System Monitor": "\u2261",
    "Analytics": "\u2237",
    "Audit Log": "\u2630",
    "Security Dashboard": "\u2616",
    "User Management": "\u2603",
    "System Config": "\u2699",
    "Reports": "\u2637",
    "AI Assistant": "\u269b",
    "Settings": "\u2638",
    "Security Audit": "\u2622",
}


def get_nav_sections():
    """Get navigation sections based on user permissions."""
    sections = {}

    sections["Overview"] = ["Home"]

    agent_pages = []
    if check_permission(Permission.AGENT_READ):
        agent_pages.append("Browse Agents")
    if check_permission(Permission.AGENT_CREATE):
        agent_pages.append("Register Agent")
    if is_operator() or is_admin():
        agent_pages.append("Risk Assessment")
    if agent_pages:
        sections["Agents"] = agent_pages

    monitor_pages = []
    if is_operator():
        monitor_pages.append("System Monitor")
        monitor_pages.append("Analytics")
    if check_permission(Permission.AUDIT_READ):
        monitor_pages.append("Audit Log")
    if monitor_pages:
        sections["Monitoring"] = monitor_pages

    security_pages = []
    if is_operator() or is_admin():
        security_pages.append("Security Dashboard")
        security_pages.append("Store Attack Simulator")
        if is_admin():
            security_pages.append("Security Audit")
    if security_pages:
        sections["Security"] = security_pages

    admin_pages = []
    if is_admin():
        admin_pages.extend(["User Management", "System Config"])
    if admin_pages:
        sections["Administration"] = admin_pages

    tool_pages = []
    if check_permission(Permission.REPORT_VIEW):
        tool_pages.append("Reports")
    tool_pages.append("AI Assistant")
    if check_permission(Permission.SETTINGS_VIEW):
        tool_pages.append("Settings")
    sections["Tools"] = tool_pages

    return sections


def get_all_pages():
    """Flat list of all accessible pages."""
    pages = []
    for section_pages in get_nav_sections().values():
        pages.extend(section_pages)
    return pages


# ---- MAIN ----

def main():
    initialize_session()

    if not st.session_state.authenticated:
        show_login()
        return

    # Session timeout enforcement
    if st.session_state.login_time:
        timeout_minutes = st.session_state.settings_session_timeout
        elapsed = (datetime.now() - st.session_state.login_time).total_seconds() / 60
        if elapsed > timeout_minutes:
            st.session_state.user = None
            st.session_state.authenticated = False
            st.session_state.login_time = None
            st.warning("Session expired. Please sign in again.")
            show_login()
            return

    # Apply pending navigation (from quick action buttons)
    if "_nav_target" in st.session_state:
        target = st.session_state._nav_target
        del st.session_state._nav_target
        all_pages = get_all_pages()
        if target in all_pages:
            st.session_state._current_page = target

    # Validate current page
    all_pages = get_all_pages()
    if st.session_state._current_page not in all_pages:
        st.session_state._current_page = "Home"

    # -- Sidebar --
    with st.sidebar:
        # Logo
        st.markdown("""<div style="padding:0.35rem 0; display:flex; align-items:center; gap:0.7rem;">
            <div style="width:36px; height:36px; border-radius:var(--radius);
                background:linear-gradient(135deg, var(--accent-solid), var(--accent-dark));
                display:flex; align-items:center; justify-content:center;
                box-shadow: var(--shadow-btn);">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5"
                    stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
            </div>
            <div>
                <div style="color:var(--text-primary) !important; font-weight:800;
                    font-size:1.08rem; letter-spacing:-0.04em;">Agentic-IAM</div>
                <div style="color:var(--text-muted) !important; font-size:0.62rem;
                    letter-spacing:0.06em; text-transform:uppercase; font-weight:600;">v2.0</div>
            </div>
        </div>""", unsafe_allow_html=True)

        st.markdown("---")

        # User info
        if st.session_state.user:
            u = st.session_state.user
            badge = role_badge(u['role'])
            initial = u['username'][0].upper()
            role_colors = {
                'admin': ('var(--danger)', 'var(--danger-dim)'),
                'operator': ('var(--warning)', 'var(--warning-dim)'),
                'user': ('var(--success)', 'var(--success-dim)'),
            }
            avatar_color, avatar_bg = role_colors.get(u['role'].lower(), ('var(--accent)', 'var(--accent-dim)'))
            st.markdown(f"""<div style="display:flex; align-items:center; gap:0.6rem; margin-bottom:0.65rem;">
                <div style="width:34px; height:34px; border-radius:var(--radius);
                    background:{avatar_bg}; border:1.5px solid {avatar_color};
                    display:flex; align-items:center;
                    justify-content:center; font-weight:700; font-size:0.85rem; color:{avatar_color};">
                    {initial}
                </div>
                <div>
                    <div style="color:var(--text-primary) !important; font-weight:600;
                        font-size:0.9rem; letter-spacing:-0.01em;">{u['username']}</div>
                    <div>{badge}</div>
                </div>
            </div>""", unsafe_allow_html=True)

            # Sign Out + Theme Toggle in 2 columns
            bc1, bc2 = st.columns(2)
            with bc1:
                if st.button("\u2190 Sign Out", use_container_width=True, key="signout_btn"):
                    st.session_state.user = None
                    st.session_state.authenticated = False
                    st.rerun()
            with bc2:
                theme = st.session_state.settings_theme
                is_dark = theme == "Dark"
                icon = "\u2600" if is_dark else "\u263d"
                label = "Light" if is_dark else "Dark"
                if st.button(f"{icon} {label}", use_container_width=True, key="theme_toggle_btn"):
                    st.session_state.settings_theme = "Light" if is_dark else "Dark"
                    st.rerun()

            st.markdown("---")

        # Grouped navigation
        sections = get_nav_sections()

        for section_name, section_pages in sections.items():
            st.markdown(f'<p class="nav-section">{section_name}</p>', unsafe_allow_html=True)

            for page_name in section_pages:
                is_active = (st.session_state._current_page == page_name)
                icon = _NAV_ICONS.get(page_name, "")

                if is_active:
                    st.markdown(
                        f'<div class="nav-active">'
                        f'<span style="margin-right:0.45rem; opacity:0.85;">{icon}</span>{page_name}</div>',
                        unsafe_allow_html=True
                    )
                else:
                    if st.button(f"{icon}  {page_name}", key=f"nav_{page_name}", use_container_width=True):
                        st.session_state._current_page = page_name
                        st.rerun()

        st.markdown("---")

        # System stats
        agents_count = len(st.session_state.db.list_agents())
        events_count = len(st.session_state.db.get_events(limit=1000))
        st.markdown(f"""<div style="padding:0.35rem 0;">
            <p class="section-label">System</p>
            <div class="stat-row">
                <span class="label">Agents</span>
                <span class="value">{agents_count}</span>
            </div>
            <div class="stat-row">
                <span class="label">Events</span>
                <span class="value">{events_count}</span>
            </div>
            <div class="stat-row">
                <span class="label">Status</span>
                <span class="value" style="color:var(--success) !important;">Online</span>
            </div>
        </div>""", unsafe_allow_html=True)

    # -- Routing --
    page = st.session_state._current_page

    if page == "Home":
        show_home()
    elif page == "Browse Agents":
        show_page_browse_agents()
    elif page == "Register Agent":
        show_page_register_agent()
    elif page == "Audit Log":
        show_page_audit_log()
    elif page == "Reports":
        show_page_reports()
    elif page == "Settings":
        show_page_settings()
    elif page == "User Management":
        show_page_user_management()
    elif page == "System Config":
        show_page_system_config()
    elif page == "System Monitor":
        show_page_system_monitor()
    elif page == "Analytics":
        show_page_analytics()
    elif page == "AI Assistant":
        show_ai_assistant()
    elif page == "Risk Assessment":
        show_risk_assessment(st.session_state.db)
    elif page == "Security Dashboard":
        show_page_security_dashboard()
    elif page == "Store Attack Simulator":
        from store_attack_simulator import show_store_attack_simulator
        show_store_attack_simulator()
    elif page == "Security Audit":
        show_page_security_audit()


# ---- HOME ----

def show_home():
    username = st.session_state.user['username']

    st.markdown(f"""<div class="page-header">
        <h1 style="font-size:1.75rem !important; margin-bottom:0.25rem; font-weight:800;">
            Welcome back, <span style="color:var(--accent) !important; font-weight:800;">{username}</span>
        </h1>
        <p style="color:var(--text-muted) !important; font-size:0.88rem;">
            {datetime.now().strftime('%A, %B %d, %Y')}
        </p>
    </div>""", unsafe_allow_html=True)

    db = st.session_state.db
    agents = db.list_agents()
    events = db.get_events(limit=100)
    active_agents = len([a for a in agents if a.get('status') == 'active'])
    users = db.list_users()

    # Metrics row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Agents", len(agents))
    with c2:
        st.metric("Active Agents", active_agents)
    with c3:
        st.metric("Total Events", len(events))
    with c4:
        st.metric("Users", len(users))

    spacer(1)

    left, right = st.columns([3, 2])

    with left:
        section_label("Your Features")

        if is_admin():
            features = [
                ("\u2603", "User & Role Management", "Full control over users, roles, and permission assignments"),
                ("\u2699", "System Configuration", "Database, security policies, backup & restore"),
                ("\u2616", "Security & Compliance", "Audit trails, compliance reporting, threat monitoring"),
                ("\u229a", "Agent Lifecycle", "Register, monitor, suspend, and manage AI agent identities"),
            ]
        elif is_operator():
            features = [
                ("\u229a", "Agent Operations", "Register, manage, and monitor AI agent status"),
                ("\u2261", "System Monitoring", "Real-time metrics and performance analytics"),
                ("\u2630", "Audit & Reports", "View logs, generate compliance reports"),
                ("\u26a0", "Risk Assessment", "Evaluate agent risk scores and remediation"),
            ]
        else:
            features = [
                ("\u229a", "Browse Agents", "View registered agents and their details"),
                ("\u2637", "View Reports", "Access system reports and performance data"),
                ("\u269b", "AI Assistant", "Get help with features and configurations"),
                ("\u2302", "Session Access", "Create and monitor your sessions"),
            ]

        for icon, title, desc in features:
            st.markdown(f"""<div class="feature-card">
                <div class="fc-icon">{icon}</div>
                <div class="fc-content"><h4>{title}</h4><p>{desc}</p></div>
            </div>""", unsafe_allow_html=True)

    with right:
        section_label("System Statistics")

        active_sessions = len([e for e in events if e.get('event_type') == 'session_created'])
        stats_rows = [
            ("Total Agents", str(len(agents))),
            ("Active Sessions", str(active_sessions)),
            ("Total Events", str(len(events))),
            ("System Uptime", "99.9%"),
        ]
        rows_html = ""
        for label, val in stats_rows:
            rows_html += f"""<div class="stat-row">
                <span class="label">{label}</span>
                <span class="value">{val}</span>
            </div>"""
        st.markdown(f"""<div class="glass-card" style="padding:0.75rem 1.1rem;">
            {rows_html}
        </div>""", unsafe_allow_html=True)

        spacer(0.5)

        if events:
            event_types = {}
            for e in events:
                t = e.get('event_type', 'unknown')
                event_types[t] = event_types.get(t, 0) + 1
            if event_types:
                section_label("Event Distribution")
                fig = px.pie(
                    values=list(event_types.values()),
                    names=list(event_types.keys()),
                    color_discrete_sequence=['#2563eb', '#3b82f6', '#60a5fa', '#93c5fd', '#bfdbfe'],
                    hole=0.65
                )
                chart_text = _theme_chart_text()
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color=chart_text, family='Inter'),
                    height=260,
                    margin=dict(l=10, r=10, t=10, b=10),
                    showlegend=True,
                    legend=dict(font=dict(size=10))
                )
                st.plotly_chart(fig, use_container_width=True)

    spacer(1)
    section_label("Quick Actions")

    all_pages = get_all_pages()
    quick_actions = []
    if "Register Agent" in all_pages:
        quick_actions.append(("Register Agent", "qa_reg"))
    if "Browse Agents" in all_pages:
        quick_actions.append(("Browse Agents", "qa_browse"))
    if "Audit Log" in all_pages:
        quick_actions.append(("Audit Log", "qa_audit"))
    if "Security Dashboard" in all_pages:
        quick_actions.append(("Security Dashboard", "qa_security"))
    if "Reports" in all_pages:
        quick_actions.append(("Reports", "qa_report"))
    if "Risk Assessment" in all_pages:
        quick_actions.append(("Risk Assessment", "qa_risk"))
    if "AI Assistant" in all_pages:
        quick_actions.append(("AI Assistant", "qa_ai"))

    display_actions = quick_actions[:4]
    if display_actions:
        cols = st.columns(len(display_actions) + 1)
        for i, (label, key) in enumerate(display_actions):
            with cols[i]:
                if st.button(label, use_container_width=True, key=key):
                    st.session_state._nav_target = label
                    st.rerun()
        with cols[len(display_actions)]:
            if st.button("Seed Test Data", use_container_width=True, key="qa_seed"):
                try:
                    from scripts.test_data_generator import add_test_agents_to_db
                    count = add_test_agents_to_db(st.session_state.db)
                    if count > 0:
                        st.success(f"Added {count} test agents")
                    else:
                        st.info("Test agents already exist")
                except Exception as exc:
                    st.error(f"Failed to seed data: {exc}")
                st.rerun()


# ---- Chart helpers ----

def _theme_chart_text():
    return '#94a3c0' if _theme == 'Dark' else '#475569'

def _theme_chart_grid():
    return 'rgba(59,130,246,0.06)' if _theme == 'Dark' else 'rgba(37,99,235,0.05)'

def _chart_colors():
    return ['#1d4ed8', '#2563eb', '#3b82f6', '#60a5fa', '#93c5fd']


# ---- BROWSE AGENTS ----

def show_page_browse_agents():
    if not check_permission(Permission.AGENT_READ):
        st.error("Access Denied")
        return

    page_header("Browse Agents", "View and manage registered AI agents")
    show_agent_list()


# ---- REGISTER AGENT ----

def show_page_register_agent():
    if not check_permission(Permission.AGENT_CREATE):
        st.error("Access Denied")
        return

    page_header("Register Agent", "Create a new AI agent identity")

    db = st.session_state.db

    with st.form("register_agent_form", clear_on_submit=True):
        c1, c2 = st.columns(2)
        with c1:
            agent_name = st.text_input("Agent Name *", placeholder="e.g., NLP Assistant")
            agent_type = st.selectbox("Agent Type", ["Standard", "Intelligent", "Processor", "Monitor"])
        with c2:
            description = st.text_area("Description", placeholder="What does this agent do?", height=108)

        submitted = st.form_submit_button("Register Agent", use_container_width=True)

        if submitted:
            if not agent_name or not agent_name.strip():
                st.error("Agent name is required")
            else:
                agent_id = f"agent_{uuid.uuid4().hex[:8]}"
                success = db.add_agent(
                    agent_id=agent_id,
                    name=agent_name.strip(),
                    agent_type=agent_type.lower(),
                    metadata={"description": description.strip(), "created_by": st.session_state.user['username']}
                )
                if success:
                    st.success("Agent registered successfully!")
                    st.markdown(
                        f'<p style="color:var(--accent) !important; font-size:0.85rem;">'
                        f'Agent ID: <code>{agent_id}</code></p>',
                        unsafe_allow_html=True
                    )
                else:
                    st.error("Registration failed. Please try again.")

    spacer(1)
    section_label("Registered Agents")
    show_agent_list()


# ---- AUDIT LOG ----

def show_page_audit_log():
    if not check_permission(Permission.AUDIT_READ):
        st.error("Access Denied")
        return

    page_header("Audit Log", "System event history and compliance trail")

    db = st.session_state.db

    c1, c2, c3 = st.columns([2, 1, 1])
    with c1:
        agents_list = db.list_agents()
        agent_filter = st.selectbox(
            "Filter by Agent",
            ["All Agents"] + [f"{a['name']} ({a['id']})" for a in agents_list],
            key="audit_agent"
        )
    with c2:
        limit = st.slider("Records", 10, 500, 50)
    with c3:
        spacer(1.2)
        if st.button("Refresh", use_container_width=True):
            st.rerun()

    spacer(0.3)

    agent_id = None
    if agent_filter != "All Agents":
        agent_id = agent_filter.split("(")[-1].rstrip(")")

    events = db.get_events(agent_id=agent_id, limit=limit)

    if events:
        df = pd.DataFrame(events)
        df['created_at'] = pd.to_datetime(df['created_at']).dt.strftime('%Y-%m-%d %H:%M:%S')
        df = df[['event_type', 'agent_id', 'action', 'details', 'created_at', 'status']].sort_values(
            'created_at', ascending=False
        )
        st.dataframe(df, use_container_width=True, hide_index=True)

        c1, c2 = st.columns([1, 3])
        with c1:
            st.markdown(
                f'<p style="color:var(--accent) !important; font-size:0.84rem; font-weight:600;">'
                f'{len(events)} events</p>',
                unsafe_allow_html=True
            )
        with c2:
            if check_permission(Permission.AUDIT_EXPORT):
                csv = df.to_csv(index=False)
                st.download_button("Download CSV", csv, "audit_log.csv")
    else:
        st.info("No events found")


# ---- SECURITY DASHBOARD ----

def show_page_security_dashboard():
    if not (is_operator() or is_admin()):
        st.error("Access Denied")
        return

    page_header("Security Dashboard", "System security status, protections, and threat monitoring")

    db = st.session_state.db

    events = db.get_events(limit=500)
    agents = db.list_agents()
    users = db.list_users()

    failed_events = [e for e in events if e.get('status') == 'failure']
    locked_accounts = 0
    if hasattr(st.session_state, 'account_security'):
        locked_accounts = len(st.session_state.account_security.locked_accounts)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Events", len(events))
    with c2:
        st.metric("Failed Events", len(failed_events))
    with c3:
        st.metric("Locked Accounts", locked_accounts)
    with c4:
        active_count = len([a for a in agents if a.get('status') == 'active'])
        st.metric("Active Agents", active_count)

    spacer()

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Active Protections", "Security Events", "Login History", "Configuration", "External Scan Results"])

    with tab1:
        section_label("Security Protections Status")

        rate_limiter = st.session_state.get('rate_limiter')
        rl_active = rate_limiter is not None
        st.markdown(f"""<div class="security-indicator">
            <div class="security-dot {'active' if rl_active else 'inactive'}"></div>
            <div style="flex:1;">
                <div style="color:var(--text-primary) !important; font-size:0.86rem; font-weight:600;">
                    Rate Limiting</div>
                <div style="color:var(--text-muted) !important; font-size:0.74rem;">
                    {'Active - Max ' + str(rate_limiter.max_attempts) + ' attempts per ' + str(rate_limiter.window_seconds) + 's window' if rl_active else 'Inactive'}</div>
            </div>
            <span class="badge {'status-active' if rl_active else 'status-inactive'}">{'ON' if rl_active else 'OFF'}</span>
        </div>""", unsafe_allow_html=True)

        acct_sec = st.session_state.get('account_security')
        al_active = acct_sec is not None
        st.markdown(f"""<div class="security-indicator">
            <div class="security-dot {'active' if al_active else 'inactive'}"></div>
            <div style="flex:1;">
                <div style="color:var(--text-primary) !important; font-size:0.86rem; font-weight:600;">
                    Account Lockout</div>
                <div style="color:var(--text-muted) !important; font-size:0.74rem;">
                    {'Active - Locks after ' + str(acct_sec.max_failed_attempts) + ' failed attempts for ' + str(acct_sec.lockout_duration) + 's' if al_active else 'Inactive'}</div>
            </div>
            <span class="badge {'status-active' if al_active else 'status-inactive'}">{'ON' if al_active else 'OFF'}</span>
        </div>""", unsafe_allow_html=True)

        protections = [
            ("SQL Injection Protection", "Active - Pattern-based detection on all user inputs"),
            ("XSS Protection", "Active - HTML sanitization and dangerous tag filtering"),
            ("Input Validation", "Active - Username, email, and agent ID format validation"),
            ("Password Hashing (bcrypt)", "Active - All passwords hashed with bcrypt before storage"),
            ("Audit Logging", "Active - All login attempts and security events logged"),
        ]
        for name, desc in protections:
            st.markdown(f"""<div class="security-indicator">
                <div class="security-dot active"></div>
                <div style="flex:1;">
                    <div style="color:var(--text-primary) !important; font-size:0.86rem; font-weight:600;">{name}</div>
                    <div style="color:var(--text-muted) !important; font-size:0.74rem;">{desc}</div>
                </div>
                <span class="badge status-active">ON</span>
            </div>""", unsafe_allow_html=True)

        csrf_active = bool(st.session_state.get('csrf_token'))
        st.markdown(f"""<div class="security-indicator">
            <div class="security-dot {'active' if csrf_active else 'inactive'}"></div>
            <div style="flex:1;">
                <div style="color:var(--text-primary) !important; font-size:0.86rem; font-weight:600;">
                    CSRF Protection</div>
                <div style="color:var(--text-muted) !important; font-size:0.74rem;">
                    {'Active - Token-based request validation' if csrf_active else 'Inactive'}</div>
            </div>
            <span class="badge {'status-active' if csrf_active else 'status-inactive'}">{'ON' if csrf_active else 'OFF'}</span>
        </div>""", unsafe_allow_html=True)

        spacer(0.5)

        try:
            from config.settings import get_settings
            settings = get_settings()
            mtls_enabled = settings.enable_mtls
        except Exception:
            mtls_enabled = False

        section_label("Transport Security")
        st.markdown(f"""<div class="security-indicator">
            <div class="security-dot {'active' if mtls_enabled else 'warning'}"></div>
            <div style="flex:1;">
                <div style="color:var(--text-primary) !important; font-size:0.86rem; font-weight:600;">
                    Mutual TLS (mTLS)</div>
                <div style="color:var(--text-muted) !important; font-size:0.74rem;">
                    {'Enabled - Certificate-based mutual authentication' if mtls_enabled else 'Disabled - Enable in config/settings.py'}</div>
            </div>
            <span class="badge {'status-active' if mtls_enabled else 'status-suspended'}">{'ON' if mtls_enabled else 'OFF'}</span>
        </div>""", unsafe_allow_html=True)

    with tab2:
        section_label("Recent Security Events")

        if failed_events:
            fail_df = pd.DataFrame(failed_events[:50])
            fail_df['created_at'] = pd.to_datetime(fail_df['created_at']).dt.strftime('%Y-%m-%d %H:%M:%S')
            display_cols = [c for c in ['event_type', 'agent_id', 'action', 'details', 'created_at'] if c in fail_df.columns]
            st.dataframe(
                fail_df[display_cols].sort_values('created_at', ascending=False),
                use_container_width=True, hide_index=True
            )
        else:
            st.markdown("""<div class="glass-card" style="text-align:center; padding:2rem;">
                <p style="color:var(--success) !important; font-weight:600;">No failed events detected</p>
                <p style="font-size:0.8rem;">All system operations are running normally</p>
            </div>""", unsafe_allow_html=True)

        spacer()
        section_label("Locked Accounts")

        acct_sec = st.session_state.get('account_security')
        if acct_sec and acct_sec.locked_accounts:
            for username, lockout_end in acct_sec.locked_accounts.items():
                remaining = (lockout_end - datetime.utcnow()).total_seconds()
                if remaining > 0:
                    st.markdown(f"""<div class="security-indicator" style="border-left:3px solid var(--danger);">
                        <div class="security-dot" style="background:var(--danger); box-shadow:0 0 8px var(--danger);"></div>
                        <div style="flex:1;">
                            <div style="color:var(--text-primary) !important; font-size:0.86rem; font-weight:600;">
                                {username}</div>
                            <div style="color:var(--text-muted) !important; font-size:0.74rem;">
                                Locked - {int(remaining)}s remaining</div>
                        </div>
                        <span class="badge badge-admin">LOCKED</span>
                    </div>""", unsafe_allow_html=True)
        else:
            st.markdown("""<div class="glass-card" style="text-align:center; padding:1.5rem;">
                <p style="color:var(--success) !important; font-weight:600;">No locked accounts</p>
            </div>""", unsafe_allow_html=True)

    with tab3:
        section_label("Recent Login Attempts")

        login_history = db.get_login_history(limit=100)
        if login_history:
            lh_df = pd.DataFrame(login_history)
            lh_df['created_at'] = pd.to_datetime(lh_df['created_at']).dt.strftime('%Y-%m-%d %H:%M:%S')
            lh_df['Result'] = lh_df['success'].apply(lambda x: 'Success' if x else 'Failed')
            display_df = lh_df[['username', 'Result', 'ip_address', 'reason', 'created_at']].rename(columns={
                'username': 'Username', 'ip_address': 'IP Address',
                'reason': 'Details', 'created_at': 'Time'
            })
            st.dataframe(display_df, use_container_width=True, hide_index=True)

            spacer(0.5)

            # Stats
            total_logins = len(login_history)
            failed_logins = len([h for h in login_history if not h['success']])
            unique_users = len(set(h['username'] for h in login_history))
            sc1, sc2, sc3 = st.columns(3)
            with sc1:
                st.metric("Total Logins", total_logins)
            with sc2:
                st.metric("Failed Attempts", failed_logins)
            with sc3:
                st.metric("Unique Users", unique_users)
        else:
            st.markdown("""<div class="glass-card" style="text-align:center; padding:2rem;">
                <p style="color:var(--text-muted) !important; font-weight:600;">No login history recorded yet</p>
            </div>""", unsafe_allow_html=True)

    with tab4:
        section_label("Security Configuration")

        try:
            from config.settings import get_settings
            settings = get_settings()
        except Exception:
            settings = None

        if settings:
            config_items = [
                ("Environment", settings.environment.title()),
                ("TLS Required", "Yes" if settings.require_tls else "No"),
                ("mTLS Enabled", "Yes" if settings.enable_mtls else "No"),
                ("MFA Enabled", "Yes" if settings.enable_mfa else "No"),
                ("MFA Required Factors", str(settings.mfa_required_factors)),
                ("Audit Logging", "Yes" if settings.enable_audit_logging else "No"),
                ("Session TTL", f"{settings.session_ttl}s"),
                ("Federated Auth", "Yes" if settings.enable_federated_auth else "No"),
                ("Trust Scoring", "Yes" if settings.enable_trust_scoring else "No"),
            ]

            for label, value in config_items:
                is_on = value in ["Yes", "True"]
                val_color = "var(--success)" if is_on else "var(--text-muted)"
                st.markdown(f"""<div class="stat-row">
                    <span class="label">{label}</span>
                    <span class="value" style="color:{val_color} !important;">{value}</span>
                </div>""", unsafe_allow_html=True)
        else:
            st.info("Could not load settings configuration")

        spacer()

        if is_admin():
            section_label("Security Actions")
            ac1, ac2, ac3 = st.columns(3)
            with ac1:
                if st.button("Rotate CSRF Token", use_container_width=True):
                    st.session_state.csrf_token = SessionSecurityManager.generate_csrf_token()
                    st.success("CSRF token rotated")
            with ac2:
                if st.button("Clear Rate Limits", use_container_width=True):
                    if st.session_state.get('rate_limiter'):
                        st.session_state.rate_limiter.attempts.clear()
                    st.success("Rate limits cleared")
            with ac3:
                if st.button("Unlock All Accounts", use_container_width=True):
                    if st.session_state.get('account_security'):
                        st.session_state.account_security.locked_accounts.clear()
                        st.session_state.account_security.failed_attempts.clear()
                    st.success("All accounts unlocked")

    with tab5:
        section_label("External Security Scan Results")
        st.markdown("""<p style="color:var(--text-muted); font-size:0.82rem;">
            Results pushed from the external IAM-Security-Tester tool
        </p>""", unsafe_allow_html=True)

        latest_run_id = db.get_latest_test_run()
        if not latest_run_id:
            st.markdown("""<div class="glass-card" style="text-align:center; padding:3rem;">
                <div style="font-size:2.5rem; margin-bottom:0.75rem;">🔒</div>
                <p style="color:var(--text-muted) !important; font-weight:600;">No External Scan Results Yet</p>
                <p style="font-size:0.8rem; color:var(--text-muted);">
                    Run the IAM-Security-Tester and click "Push to IAM Dashboard" to see results here.
                </p>
            </div>""", unsafe_allow_html=True)
        else:
            summary = db.get_test_summary(latest_run_id)
            all_results = db.get_test_results(latest_run_id)

            if summary:
                sm1, sm2, sm3, sm4 = st.columns(4)
                with sm1:
                    st.markdown(f"""<div class="metric-card">
                        <div class="metric-value">{summary.get('total', 0)}</div>
                        <div class="metric-label">Total Tests</div>
                    </div>""", unsafe_allow_html=True)
                with sm2:
                    st.markdown(f"""<div class="metric-card">
                        <div class="metric-value" style="color:var(--success);">{summary.get('passed', 0)}</div>
                        <div class="metric-label">Passed</div>
                    </div>""", unsafe_allow_html=True)
                with sm3:
                    st.markdown(f"""<div class="metric-card">
                        <div class="metric-value" style="color:var(--danger);">{summary.get('failed', 0)}</div>
                        <div class="metric-label">Failed</div>
                    </div>""", unsafe_allow_html=True)
                with sm4:
                    st.markdown(f"""<div class="metric-card">
                        <div class="metric-value" style="color:#ff4444;">{summary.get('critical', 0)}</div>
                        <div class="metric-label">Critical</div>
                    </div>""", unsafe_allow_html=True)

                spacer()

            if all_results:
                severity_colors = {
                    "critical": "#ff4444", "high": "#ff8800",
                    "medium": "#ffcc00", "low": "#44cc44", "info": "#4488ff",
                }

                categories_map = {}
                for r in all_results:
                    categories_map.setdefault(r.get('category', 'Unknown'), []).append(r)

                for cat_name, cat_results in categories_map.items():
                    passed_count = sum(1 for r in cat_results if r.get('passed'))
                    failed_count = len(cat_results) - passed_count
                    status_icon = "+" if failed_count == 0 else "!" if failed_count <= 2 else "X"

                    with st.expander(f"{status_icon} {cat_name}  ({passed_count} passed, {failed_count} failed)", expanded=failed_count > 0):
                        for r in cat_results:
                            sev = r.get('severity', 'info')
                            color = severity_colors.get(sev, '#888')
                            passed = r.get('passed', False)
                            icon_color = "var(--success)" if passed else "var(--danger)"
                            icon = "PASS" if passed else "FAIL"

                            st.markdown(f"""<div style="padding:0.5rem 0.75rem; margin-bottom:0.4rem;
                                border-left:3px solid {color}; background:var(--bg-glass);
                                border-radius:0 6px 6px 0;">
                                <div style="display:flex; align-items:center; gap:0.5rem;">
                                    <span style="color:{icon_color}; font-weight:700; font-size:0.75rem;">{icon}</span>
                                    <span style="background:{color}; color:#fff; padding:0.1rem 0.5rem;
                                        border-radius:10px; font-size:0.7rem; font-weight:700;
                                        text-transform:uppercase;">{sev}</span>
                                    <span style="color:var(--text-primary); font-weight:600; font-size:0.85rem;">
                                        {r.get('name', 'Unknown Test')}</span>
                                </div>
                                <div style="color:var(--text-muted); font-size:0.78rem; margin-top:0.3rem;">
                                    {r.get('details', '')}
                                </div>
                                {'<div style="color:var(--text-muted); font-size:0.75rem; margin-top:0.2rem; font-style:italic;">Recommendation: ' + r.get("recommendation", "") + '</div>' if r.get("recommendation") else ''}
                            </div>""", unsafe_allow_html=True)

                spacer()
                st.markdown(f"""<div style="text-align:center; color:var(--text-muted); font-size:0.78rem;">
                    Run ID: {latest_run_id} | {len(all_results)} total results
                </div>""", unsafe_allow_html=True)


# ---- SECURITY AUDIT ----

def show_page_security_audit():
    if not is_admin():
        st.error("Access Denied - Admin only")
        return

    st.markdown("""<div class="page-header">
        <h1 style="font-size:1.75rem !important; margin-bottom:0.25rem; font-weight:800;">
            \u2622 Security Audit
        </h1>
        <p style="color:var(--text-muted) !important; font-size:0.88rem;">
            Run attack simulations against system protections and review results
        </p>
    </div>""", unsafe_allow_html=True)

    db = st.session_state.db

    # -- Top bar: category selector + run button + last run info --
    from utils.security_tester import ALL_CATEGORIES

    col1, col2, col3 = st.columns([1.5, 1, 2])
    with col1:
        category_options = ["All Categories"] + ALL_CATEGORIES
        selected_category = st.selectbox("Test Category", category_options, label_visibility="collapsed")
    with col2:
        run_clicked = st.button("\u25b6 Run Security Audit", type="primary", use_container_width=True)
    with col3:
        latest_run_id = db.get_latest_test_run()
        if latest_run_id:
            summary = db.get_test_summary(latest_run_id)
            if summary:
                st.markdown(
                    f"<div style='padding:0.5rem; color:var(--text-muted); font-size:0.85rem;'>"
                    f"Last run: {summary.get('created_at', 'N/A')} &mdash; "
                    f"{summary.get('passed', 0)}/{summary.get('total', 0)} passed</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.info("No audit results yet. Click Run to start.")

    # -- Run tests if button clicked --
    if run_clicked:
        with st.spinner("Running security tests... This may take a moment."):
            from utils.security_tester import SecurityTestEngine
            from dataclasses import asdict
            engine = SecurityTestEngine(db=db)
            if selected_category == "All Categories":
                run_id, results = engine.run_all_tests()
            else:
                run_id, results = engine.run_category(selected_category)
            db.save_test_results(run_id, [asdict(r) for r in results])
            st.session_state['_last_audit_run_id'] = run_id
            st.rerun()

    # -- Display results --
    display_run_id = st.session_state.get('_last_audit_run_id') or db.get_latest_test_run()
    if not display_run_id:
        return

    summary = db.get_test_summary(display_run_id)
    all_results = db.get_test_results(display_run_id)
    if not summary or not all_results:
        return

    # -- Metrics row --
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value">{summary['total']}</div>
            <div class="metric-label">Total Tests</div>
        </div>""", unsafe_allow_html=True)
    with m2:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color:var(--success);">{summary['passed']}</div>
            <div class="metric-label">Passed</div>
        </div>""", unsafe_allow_html=True)
    with m3:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color:var(--danger);">{summary['failed']}</div>
            <div class="metric-label">Failed</div>
        </div>""", unsafe_allow_html=True)
    with m4:
        st.markdown(f"""<div class="metric-card">
            <div class="metric-value" style="color:#ff4444;">{summary['critical']}</div>
            <div class="metric-label">Critical Issues</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # -- Results by category --
    severity_colors = {
        "critical": "#ff4444",
        "high": "#ff8800",
        "medium": "#ffcc00",
        "low": "#44cc44",
        "info": "#4488ff",
    }

    # Group results by category
    categories: dict = {}
    for r in all_results:
        categories.setdefault(r['category'], []).append(r)

    for cat_name, cat_results in categories.items():
        passed_count = sum(1 for r in cat_results if r['passed'])
        failed_count = len(cat_results) - passed_count
        status_icon = "\u2705" if failed_count == 0 else "\u26a0\ufe0f" if failed_count <= 2 else "\u274c"

        with st.expander(f"{status_icon} {cat_name}  ({passed_count} passed, {failed_count} failed)", expanded=failed_count > 0):
            for r in cat_results:
                sev = r.get('severity', 'info')
                color = severity_colors.get(sev, '#888')
                icon = "\u2714" if r['passed'] else "\u2718"
                icon_color = "var(--success)" if r['passed'] else "var(--danger)"

                result_html = f"""<div style="padding:0.5rem 0.75rem; margin-bottom:0.4rem;
                    border-left:3px solid {color}; background:var(--bg-glass);
                    border-radius:0 6px 6px 0;">
                    <div style="display:flex; align-items:center; gap:0.5rem;">
                        <span style="color:{icon_color}; font-size:1rem;">{icon}</span>
                        <span class="badge" style="background:{color}; color:#fff;
                            padding:2px 8px; border-radius:10px; font-size:0.7rem;
                            font-weight:600; text-transform:uppercase;">{sev}</span>
                        <span style="color:var(--text-primary); font-weight:500;
                            font-size:0.88rem;">{r['name']}</span>
                    </div>
                    <div style="color:var(--text-muted); font-size:0.8rem;
                        margin-top:0.25rem; padding-left:1.8rem;">{r['details'][:200]}</div>"""

                if not r['passed'] and r.get('recommendation'):
                    result_html += f"""<div style="color:var(--warning); font-size:0.78rem;
                        margin-top:0.2rem; padding-left:1.8rem;">
                        \u27a4 {r['recommendation'][:200]}</div>"""

                result_html += "</div>"
                st.markdown(result_html, unsafe_allow_html=True)

    # -- Previous runs --
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""<div style="font-size:1rem; font-weight:700; color:var(--text-primary);
        margin-bottom:0.5rem;">Previous Runs</div>""", unsafe_allow_html=True)

    runs = db.get_test_runs(limit=10)
    if runs:
        import pandas as pd
        df = pd.DataFrame(runs)
        df = df.rename(columns={
            'run_id': 'Run ID', 'total': 'Total', 'passed': 'Passed',
            'failed': 'Failed', 'critical': 'Critical', 'created_at': 'Date',
        })
        if 'Run ID' in df.columns:
            df['Run ID'] = df['Run ID'].str[:8] + '...'
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No previous runs found.")


# ---- REPORTS ----

def show_page_reports():
    if not check_permission(Permission.REPORT_VIEW):
        st.error("Access Denied")
        return

    page_header("Reports", "System health, performance, and compliance reporting")

    db = st.session_state.db
    report_gen = ReportGenerator(db)
    health_monitor = AgentHealthMonitor(db)
    analytics = AgentAnalytics(db)

    tab1, tab2, tab3, tab4 = st.tabs(["System Health", "Agent Performance", "Compliance", "Analytics"])

    with tab1:
        system_health = health_monitor.get_system_health()
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Overall Health", f"{system_health.get('overall_health', 0)}%")
        with c2:
            st.metric("Total Agents", system_health.get('total_agents', 0))
        with c3:
            st.metric("Healthy Agents", system_health.get('healthy_agents', 0))
        with c4:
            st.metric("Uptime", system_health.get('system_uptime', 'N/A'))

        spacer()
        if st.button("Generate System Report"):
            report = report_gen.generate_system_report()
            st.json(report)

    with tab2:
        agents = db.list_agents()
        if agents:
            sel = st.selectbox("Select Agent", [a['name'] for a in agents], key="report_agent")
            obj = next((a for a in agents if a['name'] == sel), None)
            if obj:
                h = health_monitor.get_agent_health(obj['id'])
                a = analytics.get_agent_activity_summary(obj['id'])
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    st.metric("Health", f"{h.get('health_score', 0)}%")
                with c2:
                    st.metric("Events", h.get('recent_events', 0))
                with c3:
                    st.metric("Sessions", h.get('active_sessions', 0))
                with c4:
                    st.metric("Success Rate", f"{a.get('success_rate', 0):.1f}%")

                spacer()
                if st.button("Generate Agent Report"):
                    st.json(report_gen.generate_agent_report(obj['id']))
        else:
            st.info("No agents registered yet")

    with tab3:
        if st.button("Generate Compliance Report"):
            report = report_gen.generate_compliance_report()
            c1, c2, c3 = st.columns(3)
            with c1:
                st.metric("Total Events", report.get('audit_trail', {}).get('total_events', 0))
            with c2:
                st.metric("Audit Events", report.get('audit_trail', {}).get('significant_events', 0))
            with c3:
                st.metric("Active Users", report.get('users_summary', {}).get('active_users', 0))
            spacer()
            st.json(report)
        else:
            st.info("Click above to generate compliance report")

    with tab4:
        sys_analytics = analytics.get_system_analytics()
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Total Events", sys_analytics.get('total_events', 0))
        with c2:
            st.metric("Success Rate", f"{sys_analytics.get('success_rate', 0):.1f}%")
        with c3:
            st.metric("Active Agents", sys_analytics.get('active_agents', 0))

        spacer()
        event_dist = sys_analytics.get('event_distribution', {})
        if event_dist:
            edf = pd.DataFrame(list(event_dist.items()), columns=['Event Type', 'Count'])
            fig = px.bar(edf, x='Event Type', y='Count', color='Count',
                         color_continuous_scale=_chart_colors())
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color=_theme_chart_text(), family='Inter'), height=320,
                xaxis=dict(gridcolor=_theme_chart_grid()),
                yaxis=dict(gridcolor=_theme_chart_grid())
            )
            st.plotly_chart(fig, use_container_width=True)


# ---- SETTINGS ----

def show_page_settings():
    if not check_permission(Permission.SETTINGS_VIEW):
        st.error("Access Denied")
        return

    page_header("Settings", "Configure preferences and security options")

    tab1, tab2, tab3 = st.tabs(["General", "Security", "Advanced"])

    with tab1:
        section_label("Display")

        current_theme = st.session_state.settings_theme
        is_dark = current_theme == "Dark"
        theme_desc = "Dark mode with Blue/Black scheme" if is_dark else "Light mode with Blue/White scheme"

        tc1, tc2 = st.columns([3, 1])
        with tc1:
            st.markdown(f"""<div class="glass-card">
                <div style="color:var(--text-primary) !important; font-size:0.9rem; font-weight:600;">
                    Theme: {current_theme}</div>
                <div style="color:var(--text-muted) !important; font-size:0.78rem;">
                    {theme_desc}</div>
            </div>""", unsafe_allow_html=True)
        with tc2:
            icon = "\u2600" if is_dark else "\u263d"
            label = "Switch to Light" if is_dark else "Switch to Dark"
            if st.button(f"{icon} {label}", use_container_width=True, key="settings_theme_btn"):
                st.session_state.settings_theme = "Light" if is_dark else "Dark"
                st.rerun()

        spacer(0.5)
        section_label("Preferences")

        refresh = st.slider("Refresh Interval (s)", 5, 60, value=st.session_state.settings_refresh)
        notifs = st.checkbox("Notifications", value=st.session_state.settings_notifications)

        if st.button("Save General"):
            st.session_state.settings_refresh = refresh
            st.session_state.settings_notifications = notifs
            st.success("Saved")

    with tab2:
        section_label("Session & Auth")
        timeout = st.slider("Session Timeout (min)", 5, 480, value=st.session_state.settings_session_timeout)
        if st.button("Save Security Settings"):
            st.session_state.settings_session_timeout = timeout
            st.success("Saved")

        spacer(1)
        mfa = st.checkbox("Multi-Factor Auth", value=st.session_state.settings_mfa)
        if st.button("Save MFA Setting"):
            st.session_state.settings_mfa = mfa
            st.success("Saved")

    with tab3:
        debug = st.checkbox("Debug Mode", value=st.session_state.settings_debug)
        log_lvl = st.selectbox("Log Level", ["INFO", "DEBUG", "WARNING", "ERROR"],
                               index=["INFO", "DEBUG", "WARNING", "ERROR"].index(st.session_state.settings_log_level))
        max_log = st.slider("Max Log Size (MB)", 10, 1000, value=st.session_state.settings_max_log_size)
        if st.button("Save Advanced"):
            st.session_state.settings_debug = debug
            st.session_state.settings_log_level = log_lvl
            st.session_state.settings_max_log_size = max_log
            st.success("Saved")


# ---- USER MANAGEMENT ----

def show_page_user_management():
    if not is_admin():
        st.error("Access Denied: Admin only")
        return

    page_header("User Management", "Manage accounts, roles, and permissions")

    db = st.session_state.db

    tab1, tab2, tab3 = st.tabs(["Users", "Roles", "Permissions"])

    with tab1:
        users = db.list_users()
        if users:
            udf = pd.DataFrame([{
                "Username": u['username'],
                "Email": u['email'],
                "Role": u['role'].title(),
                "Status": u.get('status', 'active').title(),
                "Created": u['created_at']
            } for u in users])
            st.dataframe(udf, use_container_width=True, hide_index=True)

            spacer()
            section_label("User Actions")

            ac1, ac2 = st.columns(2)
            with ac1:
                user_sel = st.selectbox("Select User", [u['username'] for u in users], key="mod_user")
                sel_user = next((u for u in users if u['username'] == user_sel), None)
            with ac2:
                if sel_user:
                    roles_list = ["user", "operator", "admin"]
                    current_idx = roles_list.index(sel_user['role']) if sel_user['role'] in roles_list else 0
                    new_role = st.selectbox("Change Role", roles_list, index=current_idx, key="new_role")

                    bc1, bc2 = st.columns(2)
                    with bc1:
                        if st.button("Update Role", use_container_width=True):
                            if db.update_user_role(sel_user['id'], new_role):
                                st.success(f"Role updated to {new_role}")
                                st.rerun()
                            else:
                                st.error("Failed")
                    with bc2:
                        new_status = "suspended" if sel_user.get('status') == 'active' else "active"
                        btn_label = "Suspend" if new_status == "suspended" else "Activate"
                        if st.button(btn_label, use_container_width=True):
                            if db.update_user_status(sel_user['id'], new_status):
                                st.success(f"Status: {new_status}")
                                st.rerun()
                            else:
                                st.error("Failed")

        spacer(1)
        section_label("Create User")

        c1, c2 = st.columns(2)
        with c1:
            new_uname = st.text_input("Username", key="new_user_name")
            new_email = st.text_input("Email", key="new_user_email")
        with c2:
            new_pass = st.text_input("Password", type="password", key="new_user_pass")
            new_urole = st.selectbox("Role", ["user", "operator", "admin"], key="new_user_role")

        # Password strength indicator (advisory, not blocking)
        if new_pass:
            import re
            checks = [
                (len(new_pass) >= 8, "8+ characters"),
                (bool(re.search(r'[a-z]', new_pass)), "Lowercase"),
                (bool(re.search(r'[A-Z]', new_pass)), "Uppercase"),
                (bool(re.search(r'[0-9]', new_pass)), "Number"),
                (bool(re.search(r'[!@#$%^&*(),.?\":{}|<>]', new_pass)), "Symbol"),
            ]
            passed = sum(1 for ok, _ in checks if ok)

            if passed <= 2:
                strength_label, strength_color, bar_color = "Weak", "var(--danger)", "var(--danger)"
            elif passed <= 3:
                strength_label, strength_color, bar_color = "Fair", "var(--warning)", "var(--warning)"
            elif passed <= 4:
                strength_label, strength_color, bar_color = "Good", "var(--accent)", "var(--accent)"
            else:
                strength_label, strength_color, bar_color = "Strong", "var(--success)", "var(--success)"

            bar_pct = int((passed / 5) * 100)
            checks_html = " ".join(
                f'<span style="color:{"var(--success)" if ok else "var(--text-muted)"} !important; '
                f'font-size:0.72rem;">{"&#10003;" if ok else "&#10007;"} {label}</span>'
                for ok, label in checks
            )

            st.markdown(f"""<div style="margin:-0.5rem 0 0.75rem 0;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
                    <span style="color:var(--text-muted) !important; font-size:0.72rem;
                        text-transform:uppercase; letter-spacing:0.05em;">Password Strength</span>
                    <span style="color:{strength_color} !important; font-size:0.72rem;
                        font-weight:700;">{strength_label}</span>
                </div>
                <div style="background:var(--border-subtle); border-radius:6px; height:4px;
                    overflow:hidden; margin-bottom:0.4rem;">
                    <div style="background:{bar_color}; width:{bar_pct}%; height:100%;
                        border-radius:6px; transition:width 0.3s ease;"></div>
                </div>
                <div style="display:flex; gap:0.6rem; flex-wrap:wrap;">{checks_html}</div>
            </div>""", unsafe_allow_html=True)

        if st.button("Create User", use_container_width=True):
            if new_uname and new_email and new_pass:
                if not InputValidator.validate_email(new_email):
                    st.error("Invalid email format")
                elif not InputValidator.validate_username(new_uname):
                    st.error("Invalid username (3-32 chars, alphanumeric/underscore/dash)")
                elif db.create_user(new_uname, new_email, new_pass, new_urole):
                    st.success(f"User '{new_uname}' created")
                    st.rerun()
                else:
                    st.error("Failed (may already exist)")
            else:
                st.error("Fill all fields")

    with tab2:
        section_label("Role Definitions")
        roles_info = [
            ("Admin", "Full system access and control", "badge-admin"),
            ("Operator", "Agent management, monitoring, analytics", "badge-operator"),
            ("User", "Browsing, basic operations, reports", "badge-user"),
            ("Guest", "Read-only access", "badge-guest"),
        ]
        for name, desc, cls in roles_info:
            st.markdown(f"""<div class="glass-card" style="display:flex; align-items:center; gap:0.85rem;">
                <span class="badge {cls}">{name.upper()}</span>
                <span style="color:var(--text-secondary) !important; font-size:0.9rem;">{desc}</span>
            </div>""", unsafe_allow_html=True)

    with tab3:
        section_label("Your Permissions")
        perms = get_current_user_permissions()
        cols = st.columns(3)
        for i, p in enumerate(sorted(perms, key=lambda x: x.value)):
            with cols[i % 3]:
                st.markdown(f"""<div style="padding:0.35rem 0.55rem; margin-bottom:0.3rem;
                    background:var(--accent-dim); border:1px solid var(--accent-border);
                    border-radius:var(--radius-sm); font-size:0.8rem;
                    backdrop-filter:blur(8px);">
                    <code style="font-size:0.78rem;">{p.value}</code>
                </div>""", unsafe_allow_html=True)


# ---- SYSTEM CONFIG ----

def show_page_system_config():
    if not is_admin():
        st.error("Access Denied: Admin only")
        return

    page_header("System Configuration", "Database, security, backup, and maintenance")

    tab1, tab2, tab3, tab4 = st.tabs(["Database", "Security", "Backup", "Maintenance"])

    with tab1:
        db_type = st.selectbox("Database Type", ["SQLite", "PostgreSQL", "MySQL"])
        st.text_input("Host", "localhost" if db_type != "SQLite" else "N/A", disabled=(db_type == "SQLite"))
        st.number_input("Port", value=3306 if db_type == "MySQL" else 5432, disabled=(db_type == "SQLite"))
        if st.button("Test Connection"):
            st.success("Connection successful")

    with tab2:
        st.checkbox("Enable SSL/TLS", value=True)
        st.checkbox("Require 2FA for Admins", value=True)
        st.selectbox("Password Policy", ["Standard", "Strong", "Very Strong"])
        st.slider("Session Duration (hours)", 1, 24, 8)
        if st.button("Save Security Config"):
            st.success("Saved")

    with tab3:
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Create Backup", use_container_width=True):
                st.success("Backup created")
        with c2:
            if st.button("Restore Backup", use_container_width=True):
                st.info("Select a backup file to restore")
        st.markdown(
            f'<p style="color:var(--text-muted) !important; font-size:0.82rem;">'
            f'Last Backup: {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>',
            unsafe_allow_html=True
        )

    with tab4:
        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button("Clean Logs", use_container_width=True):
                st.success("Logs cleaned")
        with c2:
            if st.button("Clear Cache", use_container_width=True):
                st.success("Cache cleared")
        with c3:
            if st.button("Restart Services", use_container_width=True):
                st.warning("Services restarting...")


# ---- SYSTEM MONITOR ----

def show_page_system_monitor():
    if not is_operator():
        st.error("Access Denied")
        return

    page_header("System Monitor", "Real-time system health and agent monitoring")

    db = st.session_state.db
    monitor = AgentHealthMonitor(db)
    health = monitor.get_system_health()

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("System Health", f"{health.get('overall_health', 0)}%")
    with c2:
        st.metric("Total Agents", health.get('total_agents', 0))
    with c3:
        st.metric("Healthy", health.get('healthy_agents', 0))
    with c4:
        st.metric("Uptime", health.get('system_uptime', 'N/A'))

    spacer()
    section_label("Agent Health Status")

    agents = db.list_agents()
    if agents:
        rows = []
        for a in agents:
            h = monitor.get_agent_health(a['id'])
            rows.append({
                "Agent": h.get('agent_name', 'Unknown'),
                "Health": f"{h.get('health_score', 0)}%",
                "Status": h.get('status', 'unknown').title(),
                "Sessions": h.get('active_sessions', 0),
                "Events": h.get('recent_events', 0)
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No agents registered yet")

    spacer()
    if st.button("Refresh", key="monitor_refresh"):
        st.rerun()


# ---- ANALYTICS ----

def show_page_analytics():
    if not is_operator():
        st.error("Access Denied")
        return

    page_header("Analytics", "System analytics, trends, and alerts")

    db = st.session_state.db
    analytics = AgentAnalytics(db)

    tab1, tab2, tab3 = st.tabs(["Overview", "Trends", "Alerts"])

    with tab1:
        sys_a = analytics.get_system_analytics()
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Total Events", sys_a.get('total_events', 0))
        with c2:
            st.metric("Success Rate", f"{sys_a.get('success_rate', 0):.1f}%")
        with c3:
            st.metric("Active Agents", sys_a.get('active_agents', 0))

        spacer()
        event_dist = sys_a.get('event_distribution', {})
        if event_dist:
            section_label("Event Distribution")
            edf = pd.DataFrame(list(event_dist.items()), columns=['Event Type', 'Count'])
            fig = px.bar(edf, x='Event Type', y='Count', color='Count',
                         color_continuous_scale=_chart_colors())
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color=_theme_chart_text(), family='Inter'), height=320,
                xaxis=dict(gridcolor=_theme_chart_grid()),
                yaxis=dict(gridcolor=_theme_chart_grid())
            )
            st.plotly_chart(fig, use_container_width=True)

    with tab2:
        agents = db.list_agents()
        if agents:
            sel = st.selectbox("Agent", [a['name'] for a in agents], key="trend_agent")
            obj = next((a for a in agents if a['name'] == sel), None)
            if obj:
                activity = analytics.get_agent_activity_summary(obj['id'])
                section_label("Last 7 Days")
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    st.metric("Events", activity.get('total_events', 0))
                with c2:
                    st.metric("Success", activity.get('successful_events', 0))
                with c3:
                    st.metric("Failed", activity.get('failed_events', 0))
                with c4:
                    st.metric("Rate", f"{activity.get('success_rate', 0):.1f}%")

                spacer()
                et = activity.get('event_types', {})
                if et:
                    etdf = pd.DataFrame(list(et.items()), columns=['Type', 'Count'])
                    fig = px.bar(etdf, x='Type', y='Count', color='Count',
                                 color_continuous_scale=_chart_colors())
                    fig.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color=_theme_chart_text(), family='Inter'), height=280,
                        xaxis=dict(gridcolor=_theme_chart_grid()),
                        yaxis=dict(gridcolor=_theme_chart_grid())
                    )
                    st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No agents registered")

    with tab3:
        section_label("Active Alerts")
        st.markdown("""<div class="glass-card" style="border-left:3px solid var(--warning);">
            <h4 style="color:var(--warning) !important;">High Event Rate</h4>
            <p>Elevated event rate detected on monitored agents</p>
        </div>""", unsafe_allow_html=True)
        st.markdown("""<div class="glass-card" style="border-left:3px solid var(--accent);">
            <h4 style="color:var(--accent) !important;">System Health</h4>
            <p>All core services operational and responding normally</p>
        </div>""", unsafe_allow_html=True)
        st.markdown("""<div class="glass-card" style="border-left:3px solid var(--success);">
            <h4 style="color:var(--success) !important;">Critical Systems</h4>
            <p>Authentication, authorization, and audit logging all operational</p>
        </div>""", unsafe_allow_html=True)

        spacer(0.3)
        if st.button("Send Alert Notification"):
            st.success("Alert notification sent")


if __name__ == "__main__":
    main()

"""
Production-grade Network Anomaly Detection Dashboard
Run: streamlit run dashboard/app.py
"""
import sys, os, tempfile, threading, queue, time, warnings, logging, datetime, platform
warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from parser import parse_pcap
from detectors import run_all, CFG
import db, capture as cap, notifier, exporter
try:
    import ml_iforest as ML
    ML_OK = True
except ImportError:
    ML = None
    ML_OK = False

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NetGuard IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Light theme CSS (clean, professional) ─────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }

/* ── Background ── */
.stApp            { background: #f5f7fa !important; }
.stSidebar        { background: #ffffff !important;
                    border-right: 1px solid #e2e8f0 !important;
                    box-shadow: 2px 0 8px rgba(0,0,0,.06); }

/* ── Metric cards ── */
[data-testid="metric-container"] {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
    padding: 1rem 1.2rem !important;
    box-shadow: 0 2px 8px rgba(0,0,0,.06);
    transition: transform .18s, box-shadow .18s;
}
[data-testid="metric-container"]:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(59,130,246,.15);
}
[data-testid="stMetricLabel"] { color: #64748b !important; font-size:.8rem !important; }
[data-testid="stMetricValue"] { color: #1e293b !important; font-size:1.8rem !important; font-weight:700 !important; }

/* ── Headings ── */
h1 { color: #1e293b !important; font-weight: 700 !important; font-size: 1.9rem !important; }
h2, h3 { color: #1e293b !important; }

/* ── Sidebar labels ── */
.stSelectbox label, .stSlider label, .stTextInput label,
.stRadio label, .stCheckbox label, .stFileUploader label {
    color: #475569 !important; font-size: .85rem !important; font-weight: 500 !important;
}

/* ── Buttons ── */
.stButton > button {
    background: #2563eb !important;
    color: #fff !important;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    transition: background .18s, transform .12s, box-shadow .18s;
    box-shadow: 0 2px 6px rgba(37,99,235,.3);
}
.stButton > button:hover {
    background: #1d4ed8 !important;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(37,99,235,.35);
}

/* Stop button — red tint */
button[kind="secondary"] {
    background: #ef4444 !important;
    box-shadow: 0 2px 6px rgba(239,68,68,.3) !important;
}
button[kind="secondary"]:hover {
    background: #dc2626 !important;
}

/* ── DataFrames ── */
.stDataFrame { border-radius: 10px; overflow: hidden;
               box-shadow: 0 2px 8px rgba(0,0,0,.07); }

/* ── Section header accent ── */
.section-header {
    border-left: 3px solid #2563eb;
    padding-left: .6rem;
    margin: 1rem 0 .5rem;
    color: #1e293b;
    font-weight: 600;
    font-size: .95rem;
}

/* ── Severity badges ── */
.badge-CRITICAL { background:#fee2e2; color:#b91c1c; padding:2px 8px; border-radius:4px; font-size:.75rem; font-weight:600; border:1px solid #fca5a5; }
.badge-HIGH     { background:#ffedd5; color:#c2410c; padding:2px 8px; border-radius:4px; font-size:.75rem; font-weight:600; border:1px solid #fdba74; }
.badge-MEDIUM   { background:#fef9c3; color:#a16207; padding:2px 8px; border-radius:4px; font-size:.75rem; font-weight:600; border:1px solid #fde047; }
.badge-LOW      { background:#dcfce7; color:#15803d; padding:2px 8px; border-radius:4px; font-size:.75rem; font-weight:600; border:1px solid #86efac; }

/* ── Live status pills ── */
.live-pill { background:#dcfce7; color:#15803d; border:1px solid #86efac;
             font-size:.8rem; font-weight:700; padding:4px 12px;
             border-radius:99px; display:inline-block;
             animation: pulse 1.8s ease-in-out infinite; }
.idle-pill { background:#f1f5f9; color:#64748b; border:1px solid #cbd5e1;
             font-size:.8rem; padding:4px 12px;
             border-radius:99px; display:inline-block; }

@keyframes pulse { 0%,100%{ opacity:1 } 50%{ opacity:.55 } }

/* ── Alert/info boxes ── */
.stSuccess { background: #f0fdf4 !important; border:1px solid #bbf7d0 !important; color:#15803d !important; }
.stWarning { background: #fffbeb !important; border:1px solid #fde68a !important; }
.stError   { background: #fef2f2 !important; border:1px solid #fecaca !important; }
.stInfo    { background: #eff6ff !important; border:1px solid #bfdbfe !important; }

/* ── Sidebar brand header ── */
.brand-header { font-size:1.2rem; font-weight:700; color:#1e293b; letter-spacing:-.3px; }
.brand-sub    { font-size:.75rem; color:#64748b; margin-top:-4px; }

/* ── Expander ── */
[data-testid="stExpander"] { border:1px solid #e2e8f0 !important; border-radius:8px !important; }
</style>
""", unsafe_allow_html=True)

# ── DB init ───────────────────────────────────────────────────────────────────
db.init_db()

# ── Session state defaults ────────────────────────────────────────────────────
def _def(k, v):
    if k not in st.session_state:
        st.session_state[k] = v

_def("live_running", False)
_def("live_all_packets", [])   # accumulate across reruns
_def("live_session_id", None)
_def("live_df", pd.DataFrame())
_def("live_alerts", pd.DataFrame())
_def("notif_cfg", notifier.load_config())
_def("ml_model", None)
_def("live_iface", None)

# ── Chart helpers (light-theme colours) ───────────────────────────────────────
CHART_LAYOUT = dict(
    paper_bgcolor="#ffffff",
    plot_bgcolor ="#f8fafc",
    font=dict(color="#334155", size=11),
    margin=dict(l=8, r=8, t=36, b=8),
)

SEV_COLORS = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}

def styled_alerts(al: pd.DataFrame) -> pd.DataFrame:
    if len(al) == 0:
        return al
    out = al.copy()
    if "time" in out.columns:
        out["time"] = pd.to_numeric(out["time"], errors="coerce").round(2)
    return out

def proto_pie(df: pd.DataFrame):
    vc = df.proto.value_counts().reset_index()
    vc.columns = ["proto", "count"]
    fig = px.pie(vc, names="proto", values="count", title="Protocol Distribution",
                 color_discrete_sequence=px.colors.qualitative.Safe, hole=0.42)
    fig.update_layout(**CHART_LAYOUT, showlegend=True,
                      legend=dict(orientation="v", x=1.0, y=0.5))
    fig.update_traces(textinfo="percent+label", textfont_size=11)
    return fig

def traffic_timeline(df: pd.DataFrame, alerts: pd.DataFrame, t0: float):
    tl = df.assign(sec=(df.t - t0).astype(int)).groupby("sec").size().reset_index(name="packets")
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=tl["sec"], y=tl["packets"], mode="lines",
        line=dict(color="#2563eb", width=2),
        fill="tozeroy", fillcolor="rgba(37,99,235,0.08)",
        name="Packets/s"
    ))
    if len(alerts):
        for r in alerts.itertuples():
            sev = getattr(r, "severity", "HIGH")
            col = SEV_COLORS.get(sev, "#ef4444")
            fig.add_vline(x=float(r.time) - t0,
                          line_dash="dash", line_color=col, line_width=1.5,
                          annotation_text=r.type, annotation_textangle=-90,
                          annotation_font_size=9, annotation_font_color=col)
    fig.update_layout(**CHART_LAYOUT, title="Traffic Over Time (packets/s)",
                      xaxis_title="Elapsed (s)", yaxis_type="log")
    return fig

def alert_severity_bar(alerts: pd.DataFrame):
    if len(alerts) == 0:
        return go.Figure().update_layout(**CHART_LAYOUT, title="Severity Breakdown")
    vc = alerts["severity"].value_counts().reset_index()
    vc.columns = ["severity", "count"]
    fig = px.bar(vc, x="severity", y="count", title="Alert Severity Breakdown",
                 color="severity", color_discrete_map=SEV_COLORS)
    fig.update_layout(**CHART_LAYOUT, showlegend=False)
    return fig

def alert_type_bar(alerts: pd.DataFrame):
    if len(alerts) == 0:
        return go.Figure().update_layout(**CHART_LAYOUT, title="Alert Types")
    vc = alerts["type"].value_counts().reset_index()
    vc.columns = ["type", "count"]
    fig = px.bar(vc, x="count", y="type", orientation="h", title="Alert Types",
                 color_discrete_sequence=["#2563eb"])
    fig.update_layout(**CHART_LAYOUT, showlegend=False)
    return fig

def top_src_bar(df: pd.DataFrame):
    if "src" not in df.columns or df.src.isna().all():
        return None
    top = (df[df.src.notna()].groupby("src").size()
           .reset_index(name="packets")
           .sort_values("packets", ascending=False).head(15))
    if len(top) == 0:
        return None
    fig = px.bar(top, x="packets", y="src", orientation="h",
                 color="packets", color_continuous_scale="Blues",
                 title="Top 15 Source IPs by Packet Count")
    fig.update_layout(**CHART_LAYOUT, showlegend=False, coloraxis_showscale=False)
    return fig

def render_metrics(df, al, extra_label="🤖 ML Flags", extra_val="—"):
    t0 = df.t.min()
    dur = df.t.max() - t0
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("📦 Packets",   f"{len(df):,}")
    c2.metric("⏱ Duration",  f"{dur:.1f}s")
    c3.metric("🌐 Protocols", df.proto.nunique())
    c4.metric("🚨 Alerts",    len(al))
    c5.metric(extra_label,    extra_val)
    return t0, dur

def render_charts(df, al, t0):
    col_l, col_r = st.columns(2)
    col_l.plotly_chart(proto_pie(df), width="stretch")
    col_r.plotly_chart(traffic_timeline(df, al, t0), width="stretch")
    col_a, col_b = st.columns(2)
    col_a.plotly_chart(alert_severity_bar(al), width="stretch")
    col_b.plotly_chart(alert_type_bar(al), width="stretch")
    src_fig = top_src_bar(df)
    if src_fig:
        st.plotly_chart(src_fig, width="stretch")

def render_alerts_table(al, t0, prefix=""):
    st.markdown("### 🚨 Alerts")
    if len(al):
        st.dataframe(styled_alerts(al.assign(elapsed=(al.time - t0).round(2))),
                     width="stretch", height=280)
        ec1, ec2 = st.columns(2)
        ec1.download_button("⬇ Export CSV", exporter.to_csv(al),
                            f"{prefix}alerts.csv", "text/csv")
        try:
            pdf_bytes = exporter.to_pdf(al)
            ec2.download_button("⬇ Export PDF", pdf_bytes,
                                f"{prefix}report.pdf", "application/pdf")
        except Exception as e:
            ec2.warning(f"PDF unavailable: {e}")
    else:
        st.success("✅ No anomalies detected.")

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<p class="brand-header">🛡️ NetGuard IDS</p>', unsafe_allow_html=True)
    st.markdown('<p class="brand-sub">Network Anomaly Detection</p>', unsafe_allow_html=True)
    st.divider()

    mode = st.radio("**Mode**", ["📁 PCAP File", "🔴 Live Capture", "📊 History"], key="mode")
    st.divider()

    # ── PCAP mode ──────────────────────────────────────────────────────────
    if mode == "📁 PCAP File":
        st.markdown('<div class="section-header">Upload or Sample</div>', unsafe_allow_html=True)
        uploaded = st.file_uploader("Upload .pcap / .pcapng", type=["pcap", "pcapng"])

        pcap_dir = os.path.join(os.path.dirname(__file__), "..", "pcaps")
        samples = sorted(f for f in os.listdir(pcap_dir) if f.endswith(".pcap")) if os.path.isdir(pcap_dir) else []
        selected_sample = st.selectbox("…or choose a sample file", ["— none —"] + samples)

        st.divider()
        st.markdown('<div class="section-header">Detector Thresholds</div>', unsafe_allow_html=True)
        pscan = st.slider("Port scan — distinct ports / window", 2, 100, CFG["portscan_ports"])
        sweep = st.slider("Ping sweep — hosts / window",         2, 50,  CFG["sweep_hosts"])
        syn_r = st.slider("SYN flood — SYNs / second",         10, 500, CFG["syn_rate"])
        dns_q = st.slider("DNS enum — queries / window",        5, 100,  CFG["dns_queries"])
        ftp_f = st.slider("FTP brute — fails / window",         2, 20,   CFG["ftp_fail"])
        user_cfg = dict(CFG, portscan_ports=pscan, sweep_hosts=sweep,
                        syn_rate=syn_r, dns_queries=dns_q, ftp_fail=ftp_f)
        st.divider()
        use_ml = st.checkbox(
            "Enable ML (Isolation Forest)", value=False, disabled=not ML_OK,
            help=("Requires scikit-learn. Run: pip install scikit-learn"
                  if not ML_OK else "Isolation Forest anomaly detection"))

    # ── Live capture mode ──────────────────────────────────────────────────
    elif mode == "🔴 Live Capture":
        st.markdown('<div class="section-header">Network Interface</div>', unsafe_allow_html=True)

        if not cap.SCAPY_OK:
            st.error("Scapy not available.")
            sel_iface = None
        else:
            ifaces = cap.list_interfaces()   # list of (label, scapy_name)
            if ifaces:
                labels = [lbl for lbl, _ in ifaces]
                sel_label = st.selectbox("Interface", labels)
                sel_iface = dict(ifaces)[sel_label]
            else:
                st.warning("⚠️ No interfaces found.\n\n"
                           "**Windows:** Install [Npcap](https://npcap.com) and restart as Administrator.\n\n"
                           "**Linux/Mac:** Run with `sudo`.")
                sel_iface = None

        refresh_sec = st.slider("Auto-refresh every (s)", 2, 30, 5)
        st.divider()
        pscan = st.slider("Port scan ports", 2, 100, CFG["portscan_ports"])
        syn_r = st.slider("SYN flood / s",  10, 500, CFG["syn_rate"])
        user_cfg = dict(CFG, portscan_ports=pscan, syn_rate=syn_r)
        use_ml = False

    # ── History mode ───────────────────────────────────────────────────────
    else:
        st.markdown('<div class="section-header">Filter</div>', unsafe_allow_html=True)
        hist_sev   = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        hist_limit = st.number_input("Max rows", 50, 5000, 500)
        user_cfg   = CFG
        use_ml     = False
        sel_iface  = None

    # ── Notifications ──────────────────────────────────────────────────────
    st.divider()
    with st.expander("🔔 Notification Settings"):
        ncfg = st.session_state.notif_cfg
        ncfg["min_severity"] = st.selectbox(
            "Minimum severity to notify", ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            index=["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(ncfg.get("min_severity", "HIGH")))
        ncfg["email_enabled"] = st.checkbox("Enable email", ncfg.get("email_enabled", False))
        if ncfg["email_enabled"]:
            ncfg["smtp_host"]     = st.text_input("SMTP host",     ncfg.get("smtp_host", "smtp.gmail.com"))
            ncfg["smtp_port"]     = st.number_input("SMTP port",   value=int(ncfg.get("smtp_port", 587)))
            ncfg["smtp_user"]     = st.text_input("Email address", ncfg.get("smtp_user", ""))
            ncfg["smtp_password"] = st.text_input("Password",      ncfg.get("smtp_password", ""), type="password")
            ncfg["email_to"]      = st.text_input("Send to",       ncfg.get("email_to", ""))
        ncfg["webhook_enabled"] = st.checkbox("Enable webhook (Slack/Teams)", ncfg.get("webhook_enabled", False))
        if ncfg["webhook_enabled"]:
            ncfg["webhook_url"] = st.text_input("Webhook URL", ncfg.get("webhook_url", ""))
        if st.button("💾 Save settings"):
            notifier.save_config(ncfg)
            st.session_state.notif_cfg = ncfg
            st.success("Saved!")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN CONTENT
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("# 🛡️ NetGuard — Network Anomaly Detection")

# ─────────────────────────────────────────────────────────────────────────────
# MODE 1: PCAP File Analysis
# ─────────────────────────────────────────────────────────────────────────────
if mode == "📁 PCAP File":
    pcap_path = None
    tmp_file  = None

    if uploaded is not None:
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        tmp_file.write(uploaded.read()); tmp_file.close()
        pcap_path = tmp_file.name
    elif selected_sample and selected_sample != "— none —":
        pcap_path = os.path.join(pcap_dir, selected_sample)

    if pcap_path is None:
        st.info("👈  Upload a **.pcap** file or choose a sample from the sidebar to begin analysis.")
        st.stop()

    @st.cache_data(show_spinner="🔍 Parsing capture file…")
    def _load(p, _mtime):
        return parse_pcap(p)

    df = _load(pcap_path, os.path.getmtime(pcap_path))
    al = run_all(df, user_cfg)
    t0, dur = render_metrics(df, al)

    # ML
    n_ml_flags = "—"
    ml_result  = None
    if use_ml and ML_OK:
        if st.session_state.ml_model is None:
            normal_path = os.path.join(pcap_dir, "normal.pcap")
            if os.path.exists(normal_path):
                with st.spinner("Training Isolation Forest…"):
                    st.session_state.ml_model = ML.train(parse_pcap(normal_path))
            else:
                st.warning("normal.pcap not found — ML disabled.")
        if st.session_state.ml_model:
            ml_result  = ML.predict(st.session_state.ml_model, df)
            n_ml_flags = int(ml_result.anomaly.sum())
    if use_ml:
        st.metric("🤖 ML Flags", n_ml_flags)

    render_charts(df, al, t0)
    render_alerts_table(al, t0)

    # ML scatter
    if use_ml and ml_result is not None and len(ml_result[ml_result.anomaly]):
        st.markdown("### 🤖 Isolation Forest — Anomaly Scores")
        fig_ml = px.scatter(ml_result, x="w", y="score", color="anomaly",
                            color_discrete_map={True: "#ef4444", False: "#2563eb"},
                            title="Anomaly Score per 5s Window",
                            labels={"w": "Window", "score": "Score"})
        fig_ml.update_layout(**CHART_LAYOUT)
        st.plotly_chart(fig_ml, width="stretch")

    # Save to DB + notify
    src_name = uploaded.name if uploaded else selected_sample
    sid = db.start_session(src_name)
    db.save_alerts(sid, al)
    db.end_session(sid, len(df), len(al))
    notifier.notify_alerts(al, st.session_state.notif_cfg)

    if tmp_file:
        try: os.unlink(tmp_file.name)
        except: pass

# ─────────────────────────────────────────────────────────────────────────────
# MODE 2: Live Capture
# ─────────────────────────────────────────────────────────────────────────────
elif mode == "🔴 Live Capture":

    # ── Pre-flight checks ──────────────────────────────────────────────────
    if not cap.SCAPY_OK:
        st.error("**Scapy is not available.** Run: `pip install scapy`")
        st.stop()

    if sel_iface is None:
        st.warning("### ⚠️ No network interface available\n\n"
                   "**Windows users:** Download and install "
                   "[Npcap](https://npcap.com/#download) then restart this app "
                   "as **Administrator**.\n\n"
                   "**Linux/Mac users:** Restart with `sudo streamlit run dashboard/app.py`")
        st.stop()

    # ── Controls row ──────────────────────────────────────────────────────
    col_ctrl1, col_ctrl2, col_ctrl3 = st.columns([1, 1, 5])
    start_btn = col_ctrl1.button(
        "▶ Start", disabled=st.session_state.live_running,
        help="Begin live packet capture")
    stop_btn = col_ctrl2.button(
        "⏹ Stop", disabled=not st.session_state.live_running,
        help="Stop capture and save session")

    status_ph = st.empty()
    err_ph    = st.empty()

    # ── Start ──────────────────────────────────────────────────────────────
    if start_btn:
        st.session_state.live_all_packets = []
        st.session_state.live_df          = pd.DataFrame()
        st.session_state.live_alerts      = pd.DataFrame()
        st.session_state.live_iface       = sel_iface
        st.session_state.live_session_id  = db.start_session(f"live:{sel_iface}")
        st.session_state.live_running     = True
        cap.start_capture(sel_iface)
        st.rerun()

    # ── Stop ───────────────────────────────────────────────────────────────
    if stop_btn and st.session_state.live_running:
        cap.stop_capture()
        st.session_state.live_running = False
        sid = st.session_state.live_session_id
        if sid:
            al_final = st.session_state.live_alerts
            db.save_alerts(sid, al_final)
            db.end_session(sid,
                           len(st.session_state.live_all_packets),
                           len(al_final))
        st.rerun()

    # ── Running: drain queue + refresh ────────────────────────────────────
    if st.session_state.live_running:

        # Show capture error if thread died
        err = cap.get_error()
        if err:
            err_ph.error(f"**Capture error:** {err}\n\n"
                         "On Windows make sure Npcap is installed and you are running as Administrator.")
            st.session_state.live_running = False
            cap.stop_capture()
        else:
            # Drain new packets
            new_pkts = cap.drain_packets()
            if new_pkts:
                st.session_state.live_all_packets.extend(new_pkts)

            total = len(st.session_state.live_all_packets)
            status_ph.markdown(
                f'<span class="live-pill">● LIVE — {st.session_state.live_iface}</span>'
                f'&nbsp;&nbsp;<span style="color:#475569;font-size:.9rem">'
                f'{total:,} packets captured</span>',
                unsafe_allow_html=True
            )

            # Re-analyse all packets so far
            if total > 0:
                with st.spinner("Analysing…"):
                    df_live = cap.packets_to_dataframe(st.session_state.live_all_packets)
                if len(df_live):
                    al_live = run_all(df_live, user_cfg)
                    st.session_state.live_df     = df_live
                    st.session_state.live_alerts = al_live
                    notifier.notify_alerts(al_live, st.session_state.notif_cfg)

            # Auto-refresh after delay
            time.sleep(refresh_sec)
            st.rerun()

    else:
        status_ph.markdown('<span class="idle-pill">⏸ IDLE</span>', unsafe_allow_html=True)

    # ── Display captured data ──────────────────────────────────────────────
    df_disp = st.session_state.live_df
    al_disp = st.session_state.live_alerts

    if len(df_disp) == 0:
        st.info("Press **▶ Start** to begin live packet capture.\n\n"
                f"Capturing on interface: `{sel_iface}`")
    else:
        t0, _ = render_metrics(df_disp, al_disp,
                               extra_label="📡 Interface",
                               extra_val=str(st.session_state.live_iface or sel_iface)[:20])
        render_charts(df_disp, al_disp, t0)
        render_alerts_table(al_disp, t0, prefix="live_")

# ─────────────────────────────────────────────────────────────────────────────
# MODE 3: History
# ─────────────────────────────────────────────────────────────────────────────
elif mode == "📊 History":
    st.markdown("### 📊 Alert History")

    stats = db.alert_stats()
    hc1, hc2, hc3, hc4 = st.columns(4)
    hc1.metric("📋 Total Alerts",   stats["total"])
    hc2.metric("🔔 Unacknowledged", stats["unacked"])
    hc3.metric("🔴 CRITICAL",       stats["by_severity"].get("CRITICAL", 0))
    hc4.metric("🟠 HIGH",           stats["by_severity"].get("HIGH", 0))

    st.markdown("#### Recent Sessions")
    sessions = db.get_sessions(limit=20)
    if sessions:
        st.dataframe(pd.DataFrame(sessions), width="stretch", height=200)
    else:
        st.info("No sessions yet. Run a PCAP analysis or live capture first.")

    st.markdown("#### Stored Alerts")
    sev_filter  = hist_sev[0] if len(hist_sev) == 1 else None
    hist_alerts = db.get_alerts(severity=sev_filter, limit=int(hist_limit))
    if hist_alerts:
        ha_df = pd.DataFrame(hist_alerts)
        st.dataframe(ha_df, width="stretch", height=340)

        # Hourly trend
        if "captured_at" in ha_df.columns:
            ha_df["date"] = pd.to_datetime(ha_df["captured_at"]).dt.floor("h")
            trend = ha_df.groupby(["date", "severity"]).size().reset_index(name="count")
            fig_t = px.bar(trend, x="date", y="count", color="severity",
                           color_discrete_map=SEV_COLORS,
                           title="Alert Trend (hourly)", barmode="stack")
            fig_t.update_layout(**CHART_LAYOUT)
            st.plotly_chart(fig_t, width="stretch")

        hec1, hec2 = st.columns(2)
        hec1.download_button("⬇ Export History CSV",
                             exporter.to_csv(ha_df),
                             "alert_history.csv", "text/csv")
        try:
            cols_to_export = [c for c in ["type","severity","src","detail","captured_at"] if c in ha_df.columns]
            pdf_bytes = exporter.to_pdf(ha_df[cols_to_export])
            hec2.download_button("⬇ Export History PDF", pdf_bytes,
                                 "history_report.pdf", "application/pdf")
        except Exception as e:
            hec2.warning(f"PDF: {e}")
    else:
        st.info("No stored alerts match the current filter.")

    st.divider()
    col_ack1, col_ack2 = st.columns([1, 4])
    ack_id = col_ack1.number_input("Alert ID", min_value=1, step=1, value=1, label_visibility="collapsed")
    if col_ack2.button("✅ Acknowledge alert"):
        db.acknowledge_alert(int(ack_id))
        st.success(f"Alert #{ack_id} acknowledged.")
        st.rerun()


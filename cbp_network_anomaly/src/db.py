"""Persistent SQLite store for alerts and capture sessions."""
import sqlite3, json, os, datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "ids.db"

def _conn():
    DB_PATH.parent.mkdir(exist_ok=True)
    c = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with _conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at  TEXT NOT NULL,
            ended_at    TEXT,
            source      TEXT NOT NULL,
            packets     INTEGER DEFAULT 0,
            alerts      INTEGER DEFAULT 0,
            notes       TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  INTEGER REFERENCES sessions(id),
            captured_at TEXT NOT NULL,
            type        TEXT NOT NULL,
            severity    TEXT NOT NULL,
            src         TEXT,
            detail      TEXT,
            raw_time    REAL,
            acknowledged INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_type    ON alerts(type);
        CREATE INDEX IF NOT EXISTS idx_alerts_sev     ON alerts(severity);
        """)

def start_session(source: str) -> int:
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO sessions (started_at, source) VALUES (?,?)",
            (datetime.datetime.utcnow().isoformat(), source)
        )
        return cur.lastrowid

def end_session(session_id: int, packets: int, alerts: int):
    with _conn() as c:
        c.execute(
            "UPDATE sessions SET ended_at=?, packets=?, alerts=? WHERE id=?",
            (datetime.datetime.utcnow().isoformat(), packets, alerts, session_id)
        )

def save_alerts(session_id: int, alerts_df):
    if alerts_df is None or len(alerts_df) == 0:
        return
    now = datetime.datetime.utcnow().isoformat()
    rows = [
        (session_id, now, r.type, r.severity, str(r.src), r.detail, float(r.time))
        for r in alerts_df.itertuples()
    ]
    with _conn() as c:
        c.executemany(
            "INSERT INTO alerts (session_id,captured_at,type,severity,src,detail,raw_time) VALUES (?,?,?,?,?,?,?)",
            rows
        )

def get_sessions(limit=50):
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,)
        )]

def get_alerts(session_id=None, severity=None, limit=500):
    q = "SELECT a.*, s.source FROM alerts a JOIN sessions s ON a.session_id=s.id WHERE 1=1"
    params = []
    if session_id:
        q += " AND a.session_id=?"; params.append(session_id)
    if severity:
        q += " AND a.severity=?"; params.append(severity)
    q += " ORDER BY a.id DESC LIMIT ?"
    params.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, params)]

def acknowledge_alert(alert_id: int):
    with _conn() as c:
        c.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))

def alert_stats():
    with _conn() as c:
        rows = c.execute("""
            SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity
        """).fetchall()
        total = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        unacked = c.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
    return {"total": total, "unacked": unacked, "by_severity": {r["severity"]: r["cnt"] for r in rows}}

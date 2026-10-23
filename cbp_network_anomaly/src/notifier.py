"""Alert notifications: email (SMTP) and webhook (Slack/Teams/generic HTTP POST)."""
import smtplib, json, logging, os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
import requests

log = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent / "data" / "notifier_config.json"

DEFAULTS = {
    "email_enabled": False,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_user": "",
    "smtp_password": "",
    "email_to": "",
    "webhook_enabled": False,
    "webhook_url": "",
    "min_severity": "HIGH",   # LOW / MEDIUM / HIGH / CRITICAL
}

SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            saved = json.loads(CONFIG_PATH.read_text())
            return {**DEFAULTS, **saved}
        except Exception:
            pass
    return dict(DEFAULTS)

def save_config(cfg: dict):
    CONFIG_PATH.parent.mkdir(exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))

def _should_notify(severity: str, min_severity: str) -> bool:
    return SEV_RANK.get(severity, 0) >= SEV_RANK.get(min_severity, 2)

def send_email(cfg: dict, subject: str, body: str):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = cfg["smtp_user"]
        msg["To"] = cfg["email_to"]
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=10) as s:
            s.starttls()
            s.login(cfg["smtp_user"], cfg["smtp_password"])
            s.sendmail(cfg["smtp_user"], cfg["email_to"], msg.as_string())
        log.info("Email alert sent to %s", cfg["email_to"])
        return True
    except Exception as e:
        log.error("Email send failed: %s", e)
        return False

def send_webhook(cfg: dict, payload: dict):
    try:
        r = requests.post(cfg["webhook_url"], json=payload, timeout=8)
        r.raise_for_status()
        log.info("Webhook delivered (status %s)", r.status_code)
        return True
    except Exception as e:
        log.error("Webhook failed: %s", e)
        return False

def notify_alerts(new_alerts_df, cfg: dict = None):
    """Send notifications for any new alert rows that meet severity threshold."""
    if cfg is None:
        cfg = load_config()
    if len(new_alerts_df) == 0:
        return

    critical = new_alerts_df[new_alerts_df.severity.map(
        lambda s: _should_notify(s, cfg["min_severity"])
    )]
    if len(critical) == 0:
        return

    lines = [f"[{r.severity}] {r.type} — {r.src}\n  {r.detail}" for r in critical.itertuples()]
    body = f"Network Anomaly Detector — {len(critical)} alert(s)\n\n" + "\n\n".join(lines)
    subject = f"🚨 IDS Alert: {len(critical)} anomal{'y' if len(critical)==1 else 'ies'} detected"

    if cfg.get("email_enabled") and cfg.get("smtp_user") and cfg.get("email_to"):
        send_email(cfg, subject, body)

    if cfg.get("webhook_enabled") and cfg.get("webhook_url"):
        payload = {
            "text": subject,
            "attachments": [{"text": body}],
            "alerts": critical.to_dict(orient="records"),
        }
        send_webhook(cfg, payload)

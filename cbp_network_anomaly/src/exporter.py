"""Export alerts to PDF and CSV."""
import io, datetime
import pandas as pd

def to_csv(alerts_df: pd.DataFrame) -> bytes:
    buf = io.StringIO()
    alerts_df.to_csv(buf, index=False)
    return buf.getvalue().encode()

def to_pdf(alerts_df: pd.DataFrame, session_meta: dict = None) -> bytes:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
    except ImportError:
        raise RuntimeError("reportlab is not installed. Run: pip install reportlab")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Heading1"], alignment=TA_CENTER,
                                  textColor=colors.HexColor("#1a1a2e"), fontSize=16)
    sub_style = ParagraphStyle("Sub", parent=styles["Normal"], alignment=TA_CENTER,
                                textColor=colors.HexColor("#555"), fontSize=10)

    story = []
    story.append(Paragraph("Network Anomaly Detection Report", title_style))
    story.append(Spacer(1, 6))
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    story.append(Paragraph(f"Generated: {now}", sub_style))
    if session_meta:
        story.append(Paragraph(f"Source: {session_meta.get('source','—')}  |  "
                                f"Packets: {session_meta.get('packets','—')}  |  "
                                f"Duration: {session_meta.get('duration','—')}s", sub_style))
    story.append(Spacer(1, 16))

    SEV_COLORS = {
        "CRITICAL": colors.HexColor("#FF4B4B"),
        "HIGH":     colors.HexColor("#FF8C42"),
        "MEDIUM":   colors.HexColor("#FFD166"),
        "LOW":      colors.HexColor("#06D6A0"),
    }

    if len(alerts_df) == 0:
        story.append(Paragraph("✅ No anomalies detected.", styles["Normal"]))
    else:
        cols = ["type", "severity", "src", "detail", "time"]
        display_cols = [c for c in cols if c in alerts_df.columns]
        headers = [c.upper() for c in display_cols]

        data = [headers]
        for r in alerts_df[display_cols].itertuples(index=False):
            row = []
            for val in r:
                s = str(val)
                if len(s) > 60:
                    s = s[:57] + "…"
                row.append(s)
            data.append(row)

        col_widths = [3.5*cm, 2*cm, 3*cm, 7*cm, 2.5*cm][:len(display_cols)]
        t = Table(data, colWidths=col_widths, repeatRows=1)

        style_cmds = [
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8f8f8"), colors.white]),
            ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#cccccc")),
            ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING", (0,0), (-1,-1), 4),
            ("RIGHTPADDING",(0,0), (-1,-1), 4),
        ]

        # Colour severity cells
        sev_col = display_cols.index("severity") if "severity" in display_cols else None
        if sev_col is not None:
            for ri, r in enumerate(alerts_df[display_cols].itertuples(index=False), start=1):
                sev = getattr(r, "severity", "")
                c = SEV_COLORS.get(sev, colors.white)
                style_cmds.append(("BACKGROUND", (sev_col, ri), (sev_col, ri), c))

        t.setStyle(TableStyle(style_cmds))
        story.append(t)

    doc.build(story)
    buf.seek(0)
    return buf.read()

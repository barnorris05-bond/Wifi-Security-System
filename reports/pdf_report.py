from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(scan_session) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()

    story = []
    story.append(Paragraph("<b>Wi-Fi Security Analytics - Scan Executive Report</b>", styles['Title']))
    story.append(Spacer(1, 12))

    meta_text = f"<b>Scan ID:</b> {scan_session.scan_id} | <b>Backend:</b> {scan_session.backend_used} | <b>Networks Found:</b> {len(scan_session.networks)}"
    story.append(Paragraph(meta_text, styles['Normal']))
    story.append(Spacer(1, 18))

    table_data = [["SSID", "BSSID", "Band", "Signal (dBm)", "Encryption", "Risk Level", "Score"]]
    for net in scan_session.networks:
        asm = scan_session.assessments.get(net.bssid)
        table_data.append([
            net.ssid, net.bssid, net.band,
            str(net.signal_dbm if net.signal_dbm is not None else "N/A"),
            net.encryption,
            asm.risk_level if asm else "UNKNOWN",
            str(asm.risk_score) if asm else "0"
        ])

    t = Table(table_data, colWidths=[110, 110, 50, 70, 70, 70, 40])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
    ]))
    story.append(t)

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

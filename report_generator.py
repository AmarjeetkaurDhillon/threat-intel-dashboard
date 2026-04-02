from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import io

def generate_report(cves, indicators):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=20*mm, leftMargin=20*mm,
                            topMargin=20*mm, bottomMargin=20*mm)

    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle('title', fontSize=22, textColor=colors.HexColor('#1a1a2e'),
                                  spaceAfter=4, alignment=TA_CENTER, fontName='Helvetica-Bold')
    subtitle_style = ParagraphStyle('subtitle', fontSize=11, textColor=colors.HexColor('#457b9d'),
                                     spaceAfter=2, alignment=TA_CENTER, fontName='Helvetica')
    date_style = ParagraphStyle('date', fontSize=9, textColor=colors.HexColor('#888888'),
                                 spaceAfter=16, alignment=TA_CENTER, fontName='Helvetica')
    section_style = ParagraphStyle('section', fontSize=13, textColor=colors.HexColor('#1a1a2e'),
                                    spaceAfter=8, spaceBefore=16, fontName='Helvetica-Bold')
    body_style = ParagraphStyle('body', fontSize=9, textColor=colors.HexColor('#333333'),
                                 spaceAfter=4, fontName='Helvetica', leading=14)
    ai_style = ParagraphStyle('ai', fontSize=8, textColor=colors.HexColor('#457b9d'),
                               spaceAfter=6, fontName='Helvetica-Oblique', leading=12)

    elements.append(Spacer(1, 10*mm))
    elements.append(Paragraph("THREAT INTELLIGENCE BRIEFING", title_style))
    elements.append(Paragraph("Daily Security Report — Automated Analysis", subtitle_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%d %B %Y, %H:%M UTC')}", date_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1a1a2e')))
    elements.append(Spacer(1, 6*mm))

    elements.append(Paragraph("EXECUTIVE SUMMARY", section_style))
    summary_text = (f"This report presents <b>{len(cves)} critical vulnerabilities</b> identified from the NIST National "
                    f"Vulnerability Database and <b>{len(indicators)} active threat indicators</b> from AlienVault OTX. "
                    f"All vulnerabilities listed carry a CRITICAL severity rating and require immediate attention. "
                    f"Remediation actions are provided for each finding.")
    elements.append(Paragraph(summary_text, body_style))
    elements.append(Spacer(1, 4*mm))

    stats_data = [
        ['Critical CVEs', 'Threat Indicators', 'Severity Level', 'Report Status'],
        [str(len(cves)), str(len(indicators)), 'CRITICAL', 'LIVE']
    ]
    stats_table = Table(stats_data, colWidths=[42*mm, 42*mm, 42*mm, 42*mm])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#f0f4f8')),
        ('FONTNAME', (0,1), (-1,1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,1), (-1,1), 14),
        ('TEXTCOLOR', (0,1), (-1,1), colors.HexColor('#1a1a2e')),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,1), (-1,1), [colors.HexColor('#e8f4fd')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 6*mm))

    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Paragraph("CRITICAL VULNERABILITIES", section_style))

    cve_header = [['CVE ID', 'Published', 'Description']]
    cve_data = cve_header + [[
        Paragraph(f"<b>{cve['id']}</b>", ParagraphStyle('cveid', fontSize=8, textColor=colors.HexColor('#1a1a2e'), fontName='Helvetica-Bold')),
        Paragraph(cve['published'], ParagraphStyle('date2', fontSize=8, textColor=colors.HexColor('#888888'), fontName='Helvetica')),
        Paragraph(cve['description'][:200] + "...", ParagraphStyle('desc', fontSize=8, textColor=colors.HexColor('#333333'), fontName='Helvetica', leading=12))
    ] for cve in cves]

    cve_table = Table(cve_data, colWidths=[35*mm, 25*mm, 108*mm])
    cve_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#da3633')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fafafa')]),
        ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#dddddd')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    elements.append(cve_table)
    elements.append(Spacer(1, 6*mm))

    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Paragraph("ACTIVE THREAT INDICATORS", section_style))

    ind_header = [['Type', 'Indicator', 'Threat Pulse', 'Date']]
    ind_data = ind_header + [[
        Paragraph(item['type'], ParagraphStyle('type', fontSize=8, fontName='Helvetica-Bold', textColor=colors.HexColor('#1f6feb'))),
        Paragraph(item['indicator'], ParagraphStyle('ind', fontSize=8, fontName='Helvetica', textColor=colors.HexColor('#da3633'))),
        Paragraph(item['pulse'], ParagraphStyle('pulse', fontSize=8, fontName='Helvetica', textColor=colors.HexColor('#333333'))),
        Paragraph(item['created'], ParagraphStyle('created', fontSize=8, fontName='Helvetica', textColor=colors.HexColor('#888888')))
    ] for item in indicators]

    ind_table = Table(ind_data, colWidths=[22*mm, 45*mm, 85*mm, 22*mm])
    ind_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1f6feb')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('ALIGN', (0,0), (-1,0), 'CENTER'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fafafa')]),
        ('GRID', (0,0), (-1,-1), 0.3, colors.HexColor('#dddddd')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    elements.append(ind_table)
    elements.append(Spacer(1, 8*mm))

    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    elements.append(Spacer(1, 4*mm))
    footer_style = ParagraphStyle('footer', fontSize=8, textColor=colors.HexColor('#888888'),
                                   alignment=TA_CENTER, fontName='Helvetica')
    elements.append(Paragraph("Threat Intelligence Dashboard — MSc Cyber Security Project", footer_style))
    elements.append(Paragraph("University of Southampton — Amarjeet Kaur Dhillon", footer_style))
    elements.append(Paragraph("CONFIDENTIAL — FOR INTERNAL USE ONLY", footer_style))

    doc.build(elements)
    buffer.seek(0)
    return buffer
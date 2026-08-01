"""Stage 7 PDF Reporting — ReportLab PDF generation engine.

All dynamic string values are XML-escaped before being passed into ReportLab
Paragraph flowables to prevent ExpatError crashes on URLs containing & or <.
"""

import xml.sax.saxutils as saxutils

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from models import Finding
from logger import get_logger

logger = get_logger(__name__)


def _x(text) -> str:
    """XML-escape a value for safe use inside ReportLab Paragraph flowables."""
    if text is None:
        return ""
    return saxutils.escape(str(text))


def write_pdf_report(finding: Finding, out_path: str) -> None:
    if not REPORTLAB_AVAILABLE:
        logger.warning("reportlab is not installed — PDF report generation skipped.")
        return

    logger.debug(f"Writing ReportLab 13-section PDF report to {out_path}")
    doc = SimpleDocTemplate(
        out_path,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0B0F0D'),
        spaceAfter=6
    )

    h2_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#059669'),
        spaceBefore=10,
        spaceAfter=5
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#334155')
    )

    code_style = ParagraphStyle(
        'CodeStyleCustom',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        fontName='Helvetica-Oblique',
        textColor=colors.HexColor('#0284c7')
    )

    story = []

    # 1. EXECUTIVE BANNER & OVERALL VERDICT & RISK SCORE
    story.append(Paragraph("<b>SOC EMAIL FORENSIC INVESTIGATION REPORT</b>", title_style))
    story.append(Paragraph(
        f"Target Payload: <b>{_x(finding.file)}</b> | Score: <b>{finding.score}/100</b> | Risk Level: <b>{_x(finding.risk_level).upper()}</b>",
        body_style
    ))
    _confidence = getattr(finding, "confidence", None)
    _confidence_text = "N/A" if _confidence is None else f"{_confidence}%"
    story.append(Paragraph(
        f"Detection Confidence: <b>{_confidence_text}</b> ({_x(getattr(finding, 'confidence_label', 'Unknown'))}) "
        f"| Raw Weighted Evidence Total: <b>{getattr(finding, 'raw_score', finding.score)}</b>",
        body_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#10B981'), spaceAfter=10))

    # 4. EMAIL SUMMARY GRID
    story.append(Paragraph("1. Email Metadata &amp; Payload Summary", h2_style))
    meta_data = [
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(_x(finding.subject) or '(No Subject)', body_style)],
        [Paragraph("<b>From:</b>", body_style), Paragraph(_x(finding.from_addr) or '-', body_style)],
        [Paragraph("<b>Sender:</b>", body_style), Paragraph(_x(finding.sender_addr) or '-', body_style)],
        [Paragraph("<b>Reply-To:</b>", body_style), Paragraph(_x(finding.reply_to) or '-', body_style)],
        [Paragraph("<b>Return-Path:</b>", body_style), Paragraph(_x(finding.return_path) or '-', body_style)],
        [Paragraph("<b>Date:</b>", body_style), Paragraph(_x(finding.date) or '-', body_style)],
        [Paragraph("<b>Message-ID:</b>", body_style), Paragraph(_x(finding.message_id) or '-', body_style)]
    ]
    t_meta = Table(meta_data, colWidths=[100, 440])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 8))

    # 5. AUTHENTICATION ANALYSIS
    story.append(Paragraph("2. Authentication Analysis (SPF / DKIM / DMARC)", h2_style))
    auth = finding.authentication
    auth_data = [
        [Paragraph("<b>Mechanism</b>", body_style), Paragraph("<b>Verdict</b>", body_style), Paragraph("<b>Extracted Details</b>", body_style)],
        [Paragraph("SPF", body_style), Paragraph(_x(auth.spf).upper(), body_style), Paragraph(_x(auth.spf_details) or '-', body_style)],
        [Paragraph("DKIM", body_style), Paragraph(_x(auth.dkim).upper(), body_style), Paragraph(_x(auth.dkim_details) or '-', body_style)],
        [Paragraph("DMARC", body_style), Paragraph(_x(auth.dmarc).upper(), body_style), Paragraph(_x(auth.dmarc_details) or '-', body_style)]
    ]
    t_auth = Table(auth_data, colWidths=[80, 80, 380])
    t_auth.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_auth)
    story.append(Spacer(1, 8))

    # 6. HEADER ANALYSIS
    story.append(Paragraph(f"3. Header Forensics ({len(finding.header_findings)} Anomalies)", h2_style))
    if finding.header_findings:
        hf_data = [[Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Title</b>", body_style), Paragraph("<b>Evidence &amp; Description</b>", body_style)]]
        for hf in finding.header_findings:
            hf_data.append([
                Paragraph(_x(hf.risk_level), body_style),
                Paragraph(_x(hf.title), body_style),
                Paragraph(f"{_x(hf.description)}<br/><i>Evidence: {_x(hf.evidence)}</i>", body_style)
            ])
        t_hf = Table(hf_data, colWidths=[60, 150, 330])
        t_hf.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_hf)
    else:
        story.append(Paragraph("<i>Clean: No header spoofing anomalies detected.</i>", body_style))
    story.append(Spacer(1, 8))

    # 7. ROUTING ANALYSIS
    story.append(Paragraph(f"4. Delivery Routing Timeline ({finding.routing.hop_count} Hops)", h2_style))
    if finding.routing.timeline:
        rt_data = [[Paragraph("<b>Hop #</b>", body_style), Paragraph("<b>Timestamp</b>", body_style), Paragraph("<b>Delay</b>", body_style), Paragraph("<b>From Host</b>", body_style), Paragraph("<b>By Host</b>", body_style)]]
        for t in finding.routing.timeline:
            rt_data.append([
                Paragraph(f"#{t.hop_number}", body_style),
                Paragraph(_x(t.timestamp), body_style),
                Paragraph(_x(t.delay_display), body_style),
                Paragraph(_x(t.from_host), body_style),
                Paragraph(_x(t.by_host), body_style)
            ])
        t_rt = Table(rt_data, colWidths=[40, 130, 60, 155, 155])
        t_rt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_rt)
    story.append(Spacer(1, 8))

    # 8. URL ANALYSIS
    story.append(Paragraph(f"5. URL Analysis ({finding.url_analysis.total_urls} URLs, {finding.url_analysis.suspicious_count} Suspicious)", h2_style))
    if finding.url_analysis.urls:
        url_data = [[Paragraph("<b>Target URL</b>", body_style), Paragraph("<b>Domain</b>", body_style), Paragraph("<b>Flags</b>", body_style)]]
        for u in finding.url_analysis.urls:
            url_data.append([
                Paragraph(_x(u.normalized_url[:60]), code_style),
                Paragraph(_x(u.domain), body_style),
                Paragraph(_x("; ".join(u.findings)) if u.findings else "CLEAN", body_style)
            ])
        t_url = Table(url_data, colWidths=[240, 120, 180])
        t_url.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_url)
    story.append(Spacer(1, 8))

    # 9. ATTACHMENT ANALYSIS
    story.append(Paragraph(f"6. Attachment Forensics ({len(finding.attachments)} Attachments)", h2_style))
    if finding.attachments:
        att_data = [[Paragraph("<b>Filename</b>", body_style), Paragraph("<b>Signature</b>", body_style), Paragraph("<b>Size</b>", body_style), Paragraph("<b>Findings</b>", body_style)]]
        for a in finding.attachments:
            att_data.append([
                Paragraph(_x(a.filename), body_style),
                Paragraph(_x(a.true_type), body_style),
                Paragraph(f"{a.size_bytes} B", body_style),
                Paragraph(_x("; ".join(a.findings)) if a.findings else "CLEAN", body_style)
            ])
        t_att = Table(att_data, colWidths=[160, 80, 80, 220])
        t_att.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_att)
    story.append(Spacer(1, 8))

    # 10. PHISHING INDICATORS & 11. EVIDENCE TABLE
    story.append(Paragraph("7. Master Incident Evidence Log", h2_style))
    ev_data = [[Paragraph("<b>Category</b>", body_style), Paragraph("<b>Detection Signal</b>", body_style), Paragraph("<b>Matched Evidence</b>", body_style)]]
    for s in finding.signals:
        ev_data.append([Paragraph("Phishing Signal", body_style), Paragraph(_x(s.indicator), body_style), Paragraph(_x(s.evidence) or '-', code_style)])
    for hf in finding.header_findings:
        ev_data.append([Paragraph("Header Forensics", body_style), Paragraph(_x(hf.title), body_style), Paragraph(_x(hf.evidence), code_style)])
    for entry in getattr(finding, "html_findings", None) or []:
        ev_data.append([
            Paragraph("HTML Body Forensics", body_style),
            Paragraph(f"[{_x(getattr(entry, 'severity', ''))}] {_x(entry.indicator)}", body_style),
            Paragraph(_x(getattr(entry, 'evidence', '')) or '-', code_style),
        ])

    t_ev = Table(ev_data, colWidths=[110, 170, 260])
    t_ev.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_ev)
    story.append(Spacer(1, 8))

    # 12. RECOMMENDATIONS
    story.append(Paragraph("8. SOC Actionable Playbook", h2_style))
    if finding.risk_level in {"High", "Critical"}:
        rec_text = "&#8226; <b>Immediate Containment:</b> Purge message across tenant inboxes.<br/>&#8226; <b>Perimeter Blocking:</b> Block sender domain on Email Gateway.<br/>&#8226; <b>Network Defense:</b> Block malicious URLs/IPs on Proxy/Firewall.<br/>&#8226; <b>Credential Reset:</b> Force password reset for interacted users."
    else:
        rec_text = "&#8226; <b>No Action Required:</b> Email satisfied authentication standards and exhibits low threat indicators."
    story.append(Paragraph(rec_text, body_style))

    # 13. TECHNICAL DETAILS
    story.append(Paragraph("9. Technical Details &amp; MIME Architecture", h2_style))
    story.append(Paragraph(f"MIME Structure: {_x(finding.mime_structure)}", code_style))

    doc.build(story)

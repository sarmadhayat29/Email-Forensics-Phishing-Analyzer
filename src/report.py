"""Stage 7 — Reporting Engine.

Generates multi-format commercial investigation reports matching web application design language:
1. Professional HTML report (.report.html) styled in Charcoal (#0B0F0D) & Emerald (#10B981) with @media print CSS
2. Machine-readable JSON report (.report.json)
3. Native PDF report (.report.pdf) via ReportLab formatted for digital forensics documentation.

Includes 13 comprehensive investigation sections across all formats.
"""

import json
import os
import dataclasses
from typing import Optional, List

from models import (
    Finding, ParsedMessage, AuthVerdict, RoutingVerdict,
    ScoringVerdict, HeaderAnalysisVerdict, HeaderFinding, URLAnalysisVerdict
)
from logger import get_logger

logger = get_logger(__name__)

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

BADGE_STYLES = {
    "Critical": "background: #7f1d1d; color: #fca5a5; border: 1px solid #991b1b;",
    "High": "background: #991b1b; color: #fecaca; border: 1px solid #dc2626;",
    "Medium": "background: #78350f; color: #fef08a; border: 1px solid #d97706;",
    "Low": "background: #064e3b; color: #a7f3d0; border: 1px solid #059669;",
    "Safe": "background: #064e3b; color: #a7f3d0; border: 1px solid #059669;",
    "PASS": "background: #064e3b; color: #a7f3d0; border: 1px solid #059669;",
    "FAIL": "background: #991b1b; color: #fecaca; border: 1px solid #dc2626;",
    "NONE": "background: #16221c; color: #94a3b8; border: 1px solid #334155;",
}


def build_finding(
    path: str,
    parsed: ParsedMessage,
    auth: AuthVerdict,
    routing: RoutingVerdict,
    scoring: ScoringVerdict,
    header_verdict: Optional[HeaderAnalysisVerdict] = None,
    url_verdict: Optional[URLAnalysisVerdict] = None
) -> Finding:
    return Finding(
        file=os.path.basename(path),
        subject=parsed.subject,
        from_addr=parsed.from_raw,
        sender_addr=parsed.sender_raw,
        to_addr=parsed.to_raw,
        cc_addr=parsed.cc_raw,
        bcc_addr=parsed.bcc_raw,
        reply_to=parsed.reply_to_raw,
        return_path=parsed.return_path_raw,
        date=parsed.date,
        message_id=parsed.message_id,
        authentication=auth,
        routing=routing,
        attachments=parsed.attachments,
        embedded_images=parsed.embedded_images,
        mime_structure=parsed.mime_structure,
        header_findings=header_verdict.findings if header_verdict else [],
        url_analysis=url_verdict if url_verdict else URLAnalysisVerdict(),
        score=scoring.total_score,
        risk_level=scoring.risk_level,
        signals=scoring.signals,
    )


def write_json_report(finding: Finding, out_path: str) -> None:
    logger.debug(f"Writing JSON report to {out_path}")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(dataclasses.asdict(finding), f, indent=2, default=str)


def write_html_report(finding: Finding, out_path: str) -> None:
    logger.debug(f"Writing Charcoal/Emerald SOC HTML report to {out_path}")
    
    badge_style = BADGE_STYLES.get(finding.risk_level, BADGE_STYLES["NONE"])
    verdict_title = "MALICIOUS / HIGH RISK PHISHING THREAT" if finding.risk_level in {"High", "Critical"} else ("SUSPICIOUS EMAIL PAYLOAD" if finding.risk_level == "Medium" else "SAFE / CLEAN EMAIL PAYLOAD")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Email Forensics Report — {_escape(finding.subject)}</title>
<style>
  :root {{
    --bg-main: #0B0F0D;
    --card-bg: #121814;
    --card-border: #1b2e23;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
    --accent: #10B981;
    --accent-cyan: #22D3EE;
  }}
  body {{
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace, sans-serif;
    background-color: var(--bg-main);
    color: var(--text-main);
    margin: 0;
    padding: 2rem;
    line-height: 1.5;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  
  .verdict-header {{
    background: var(--card-bg);
    border: 2px solid var(--card-border);
    border-radius: 16px;
    padding: 2rem;
    margin-bottom: 2rem;
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
  }}
  .verdict-banner {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
    border-bottom: 1px solid var(--card-border);
    padding-bottom: 1rem;
    margin-bottom: 1.5rem;
  }}
  h1 {{ font-size: 1.6rem; margin: 0; font-weight: 800; color: var(--accent); letter-spacing: -0.02em; }}
  
  .badge {{
    display: inline-block;
    padding: 0.35rem 0.9rem;
    border-radius: 8px;
    font-weight: 800;
    font-size: 0.85rem;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    font-family: monospace;
  }}
  .score-box {{
    background: #060907;
    border: 1px solid var(--card-border);
    padding: 0.5rem 1.2rem;
    border-radius: 8px;
    font-size: 1.1rem;
    font-weight: bold;
    font-family: monospace;
    color: #f59e0b;
  }}

  .grid-4 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
  .info-card {{ background: #060907; border: 1px solid var(--card-border); border-radius: 10px; padding: 1rem; font-family: monospace; font-size: 0.85rem; }}
  .info-card strong {{ color: var(--accent-cyan); font-size: 0.75rem; text-transform: uppercase; display: block; margin-bottom: 0.3rem; letter-spacing: 0.05em; }}

  details {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 14px;
    margin-bottom: 1.2rem;
    overflow: hidden;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
  }}
  summary {{
    padding: 1.2rem 1.5rem;
    font-weight: 700;
    font-size: 1rem;
    cursor: pointer;
    background: #121814;
    user-select: none;
    display: flex;
    justify-content: space-between;
    align-items: center;
    color: var(--text-main);
  }}
  summary:hover {{ background: #16221c; }}
  summary::after {{ content: "▼"; font-size: 0.8rem; color: var(--accent); }}
  details[open] summary::after {{ content: "▲"; }}
  .section-content {{ padding: 1.5rem; border-top: 1px solid var(--card-border); background: #0b0f0d; }}

  table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; background: #060907; border-radius: 8px; overflow: hidden; }}
  th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--card-border); font-size: 0.85rem; font-family: monospace; }}
  th {{ background: #121814; color: var(--accent-cyan); font-weight: 700; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{ font-family: monospace; background: #16221c; padding: 0.2rem 0.5rem; border-radius: 4px; color: #22d3ee; font-size: 0.85em; border: 1px solid #1b2e23; }}

  .rec-box {{ background: #060907; border-left: 4px solid var(--accent); padding: 1.2rem; border-radius: 8px; margin-top: 0.5rem; font-family: monospace; font-size: 0.85rem; }}
  .rec-box li {{ margin-bottom: 0.5rem; }}

  @media print {{
    body {{ background-color: #ffffff; color: #000000; padding: 0; }}
    .container {{ max-width: 100%; }}
    .verdict-header, details, .info-card, table {{ background: #ffffff !important; color: #000000 !important; border: 1px solid #cccccc !important; box-shadow: none !important; }}
    h1, summary, th, .info-card strong {{ color: #000000 !important; background: #f0f0f0 !important; }}
    summary::after {{ display: none; }}
    details {{ open: true; page-break-inside: avoid; }}
    code {{ background: #f5f5f5 !important; color: #000000 !important; border: 1px solid #dddddd; }}
  }}
</style>
</head>
<body>
<div class="container">

  <!-- 1. Executive Summary & 2. Overall Verdict & 3. Risk Score -->
  <div class="verdict-header">
    <div class="verdict-banner">
      <div>
        <h1>SOC Email Forensics Investigation Report</h1>
        <small style="color: var(--text-muted); font-family: monospace;">Target Payload: <code>{_escape(finding.file)}</code></small>
      </div>
      <div>
        <span class="badge" style="{badge_style}">{finding.risk_level} THREAT</span>
        <span class="score-box">Risk Score: {finding.score} / 1000</span>
      </div>
    </div>
    
    <div>
      <h2 style="font-size: 1.1rem; margin-top:0; color: #f8fafc;">Executive Summary &amp; Overall Verdict</h2>
      <p style="margin: 0.5rem 0 1.5rem 0; color: var(--text-muted); font-size: 0.9rem;">
        Automated 100% offline forensic evaluation determined an overall verdict of <strong>{verdict_title}</strong> (Score: {finding.score}/1000).
        Review the 13 core investigation sections below for technical evidence and SOC playbooks.
      </p>
      
      <!-- 4. Email Summary Grid -->
      <div class="grid-4">
        <div class="info-card"><strong>Subject</strong>{_escape(finding.subject or '(No Subject)')}</div>
        <div class="info-card"><strong>From (Author)</strong>{_escape(finding.from_addr or '(Missing)')}</div>
        <div class="info-card"><strong>Sender (Transmitter)</strong>{_escape(finding.sender_addr or '-')}</div>
        <div class="info-card"><strong>Reply-To Target</strong>{_escape(finding.reply_to or '-')}</div>
        <div class="info-card"><strong>Return-Path (Bounce)</strong>{_escape(finding.return_path or '-')}</div>
        <div class="info-card"><strong>Date &amp; Timestamp</strong>{_escape(finding.date or '-')}</div>
        <div class="info-card"><strong>Attachments Extracted</strong>{len(finding.attachments) + len(finding.embedded_images)} File(s)</div>
        <div class="info-card"><strong>URLs Extracted</strong>{finding.url_analysis.total_urls} URL(s)</div>
      </div>
    </div>
  </div>

  <!-- 13 Core Investigation Sections -->
  <details open>
    <summary>5. Authentication Analysis (SPF / DKIM / DMARC)</summary>
    <div class="section-content">{_render_auth(finding)}</div>
  </details>

  <details open>
    <summary>6. Header Forensics &amp; Spoofing Anomalies ({len(finding.header_findings)} Flagged)</summary>
    <div class="section-content">{_render_header_forensics(finding.header_findings)}</div>
  </details>

  <details open>
    <summary>7. Routing Analysis &amp; Delivery Timeline ({finding.routing.hop_count} Hops)</summary>
    <div class="section-content">{_render_routing(finding)}</div>
  </details>

  <details open>
    <summary>8. Extracted &amp; Analyzed Link Targets ({finding.url_analysis.total_urls} URLs, {finding.url_analysis.suspicious_count} Suspicious)</summary>
    <div class="section-content">{_render_url_analysis(finding.url_analysis)}</div>
  </details>

  <details open>
    <summary>9. Attachment Binary Signature Forensics ({len(finding.attachments) + len(finding.embedded_images)} Files)</summary>
    <div class="section-content">
      {_render_attachments(finding.attachments, "Attachments")}
      {_render_attachments(finding.embedded_images, "Embedded Media")}
    </div>
  </details>

  <details open>
    <summary>10. Triggered Phishing Threat Indicators ({len(finding.signals)} Signals)</summary>
    <div class="section-content">{_render_signals(finding)}</div>
  </details>

  <details open>
    <summary>11. Master Incident Evidence Log Table</summary>
    <div class="section-content">{_render_master_evidence(finding)}</div>
  </details>

  <details open>
    <summary>12. SOC Incident Response Recommendations &amp; Playbooks</summary>
    <div class="section-content">{_render_soc_recommendations(finding)}</div>
  </details>

  <details>
    <summary>13. Technical Details &amp; MIME Structure Artifacts</summary>
    <div class="section-content">{_render_technical_details(finding)}</div>
  </details>

</div>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)


def write_pdf_report(finding: Finding, out_path: str) -> None:
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
    story.append(Paragraph(f"Target Payload: <b>{finding.file}</b> | Score: <b>{finding.score}/1000</b> | Risk Level: <b>{finding.risk_level.upper()}</b>", body_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#10B981'), spaceAfter=10))

    # 4. EMAIL SUMMARY GRID
    story.append(Paragraph("1. Email Metadata & Payload Summary", h2_style))
    meta_data = [
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(finding.subject or '(No Subject)', body_style)],
        [Paragraph("<b>From:</b>", body_style), Paragraph(finding.from_addr or '-', body_style)],
        [Paragraph("<b>Sender:</b>", body_style), Paragraph(finding.sender_addr or '-', body_style)],
        [Paragraph("<b>Reply-To:</b>", body_style), Paragraph(finding.reply_to or '-', body_style)],
        [Paragraph("<b>Return-Path:</b>", body_style), Paragraph(finding.return_path or '-', body_style)],
        [Paragraph("<b>Date:</b>", body_style), Paragraph(finding.date or '-', body_style)],
        [Paragraph("<b>Message-ID:</b>", body_style), Paragraph(finding.message_id or '-', body_style)]
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
        [Paragraph("SPF", body_style), Paragraph(auth.spf.upper(), body_style), Paragraph(auth.spf_details or '-', body_style)],
        [Paragraph("DKIM", body_style), Paragraph(auth.dkim.upper(), body_style), Paragraph(auth.dkim_details or '-', body_style)],
        [Paragraph("DMARC", body_style), Paragraph(auth.dmarc.upper(), body_style), Paragraph(auth.dmarc_details or '-', body_style)]
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
        hf_data = [[Paragraph("<b>Severity</b>", body_style), Paragraph("<b>Title</b>", body_style), Paragraph("<b>Evidence & Description</b>", body_style)]]
        for hf in finding.header_findings:
            hf_data.append([
                Paragraph(hf.risk_level, body_style),
                Paragraph(hf.title, body_style),
                Paragraph(f"{hf.description}<br/><code>Evidence: {hf.evidence}</code>", body_style)
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
                Paragraph(t.timestamp, body_style),
                Paragraph(t.delay_display, body_style),
                Paragraph(t.from_host, body_style),
                Paragraph(t.by_host, body_style)
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
                Paragraph(u.normalized_url[:60], code_style),
                Paragraph(u.domain, body_style),
                Paragraph("; ".join(u.findings) if u.findings else "CLEAN", body_style)
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
                Paragraph(a.filename, body_style),
                Paragraph(a.true_type, body_style),
                Paragraph(f"{a.size_bytes} B", body_style),
                Paragraph("; ".join(a.findings) if a.findings else "CLEAN", body_style)
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
        ev_data.append([Paragraph("Phishing Signal", body_style), Paragraph(s.indicator, body_style), Paragraph(s.evidence or '-', code_style)])
    for hf in finding.header_findings:
        ev_data.append([Paragraph("Header Forensics", body_style), Paragraph(hf.title, body_style), Paragraph(hf.evidence, code_style)])
    
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
        rec_text = "• <b>Immediate Containment:</b> Purge message across tenant inboxes.<br/>• <b>Perimeter Blocking:</b> Block sender domain on Email Gateway.<br/>• <b>Network Defense:</b> Block malicious URLs/IPs on Proxy/Firewall.<br/>• <b>Credential Reset:</b> Force password reset for interacted users."
    else:
        rec_text = "• <b>No Action Required:</b> Email satisfied authentication standards and exhibits low threat indicators."
    story.append(Paragraph(rec_text, body_style))

    # 13. TECHNICAL DETAILS
    story.append(Paragraph("9. Technical Details & MIME Architecture", h2_style))
    tech_info = f"MIME Structure: {finding.mime_structure}"
    story.append(Paragraph(tech_info, code_style))

    doc.build(story)


def _render_header_forensics(header_findings: List[HeaderFinding]) -> str:
    if not header_findings:
        return "<p style='color: var(--text-muted);'><em>No header anomalies or spoofing indicators detected.</em></p>"

    rows = ""
    for hf in header_findings:
        b_style = BADGE_STYLES.get(hf.risk_level, BADGE_STYLES["NONE"])
        rows += f"""<tr>
          <td><span class="badge" style="{b_style}">{hf.risk_level}</span></td>
          <td><strong>{_escape(hf.title)}</strong></td>
          <td>{_escape(hf.description)}<br><small><strong>Evidence:</strong> <code>{_escape(hf.evidence)}</code></small></td>
          <td>{_escape(hf.recommendation)}</td>
        </tr>"""

    return f"""<table>
      <tr><th>Risk</th><th>Detection</th><th>Description &amp; Evidence</th><th>SOC Recommendation</th></tr>
      {rows}
    </table>"""


def _render_auth(finding: Finding) -> str:
    auth = finding.authentication
    
    spf_b = BADGE_STYLES["PASS"] if auth.spf == "pass" else (BADGE_STYLES["FAIL"] if auth.spf in {"fail", "softfail"} else BADGE_STYLES["NONE"])
    dkim_b = BADGE_STYLES["PASS"] if auth.dkim == "pass" else (BADGE_STYLES["FAIL"] if auth.dkim in {"fail", "softfail"} else BADGE_STYLES["NONE"])
    dmarc_b = BADGE_STYLES["PASS"] if auth.dmarc == "pass" else (BADGE_STYLES["FAIL"] if auth.dmarc == "fail" else BADGE_STYLES["NONE"])

    inconsistencies_html = ""
    if auth.inconsistencies:
        inconsistencies_html = "<div style='margin-top: 1rem;'><strong style='color:#fca5a5;'>Authentication Anomalies Detected:</strong><ul>" + "".join(f"<li>⚠️ {_escape(inc)}</li>" for inc in auth.inconsistencies) + "</ul></div>"

    return f"""<table>
      <tr><th>Mechanism</th><th>Verdict</th><th>Extracted Details</th></tr>
      <tr><td><strong>SPF</strong></td><td><span class="badge" style="{spf_b}">{auth.spf.upper()}</span></td><td>{_escape(auth.spf_details or '-')}</td></tr>
      <tr><td><strong>DKIM</strong></td><td><span class="badge" style="{dkim_b}">{auth.dkim.upper()}</span></td><td>{_escape(auth.dkim_details or '-')}</td></tr>
      <tr><td><strong>DMARC</strong></td><td><span class="badge" style="{dmarc_b}">{auth.dmarc.upper()}</span></td><td>{_escape(auth.dmarc_details or '-')}</td></tr>
    </table>
    <div style="margin-top: 1rem;">
      <strong>SOC Analysis Summary:</strong> {_escape(auth.explanation)}
    </div>
    {inconsistencies_html}"""


def _render_routing(finding: Finding) -> str:
    r = finding.routing
    timeline_rows = ""
    if r.timeline:
        for t in r.timeline:
            timeline_rows += f"""<tr>
              <td><strong>Hop #{t.hop_number}</strong></td>
              <td>{_escape(t.timestamp)}</td>
              <td><code>{_escape(t.delay_display)}</code></td>
              <td>{_escape(t.from_host)}</td>
              <td>{_escape(t.by_host)}</td>
              <td>{_escape(t.ip_info)}</td>
              <td>{_escape(t.summary)}</td>
            </tr>"""
    else:
        timeline_rows = "<tr><td colspan='7'><em>No Received hops found in email chain.</em></td></tr>"

    flags_html = "".join(f"<li>⚠️ {_escape(f)}</li>" for f in r.flags) or "<li><em>None</em></li>"

    return f"""<table>
      <tr><th>Hop #</th><th>Timestamp</th><th>Elapsed Delay</th><th>Sending Host (From)</th><th>Receiving Host (By)</th><th>IP &amp; Classification</th><th>Summary / Flags</th></tr>
      {timeline_rows}
    </table>
    <div style="margin-top: 1rem;">
      <strong>Routing Anomaly Flags:</strong>
      <ul>{flags_html}</ul>
    </div>"""


def _render_signals(finding: Finding) -> str:
    if not finding.signals:
        return "<p style='color: var(--text-muted);'><em>No phishing indicators triggered.</em></p>"

    signal_rows = "".join(
        f"""<tr>
          <td><strong>{_escape(getattr(s, 'indicator', s.signal))}</strong></td>
          <td><span class="badge" style="background:#991b1b; color:#fecaca;">+{s.weight}</span></td>
          <td>{_escape(getattr(s, 'explanation', s.detail))}</td>
          <td><code>{_escape(getattr(s, 'evidence', '-'))}</code></td>
        </tr>"""
        for s in finding.signals
    )

    return f"""<table>
      <tr><th>Indicator</th><th>Points</th><th>Explanation</th><th>Supporting Evidence</th></tr>
      {signal_rows}
    </table>"""


def _render_url_analysis(url_analysis) -> str:
    if not url_analysis or not url_analysis.urls:
        return "<p style='color: var(--text-muted);'><em>No URLs extracted from email bodies.</em></p>"

    rows = ""
    for u in url_analysis.urls:
        findings_html = "<br>".join(f"⚠️ {_escape(f)}" for f in u.findings) if u.findings else "<span class='badge' style='" + BADGE_STYLES["PASS"] + "'>CLEAN</span>"
        anchor_disp = f"'{_escape(u.anchor_text)}'" if u.anchor_text else "<em>None</em>"
        rows += f"""<tr>
          <td><code>{_escape(u.normalized_url[:70])}</code></td>
          <td>{_escape(u.domain)}</td>
          <td>{anchor_disp}</td>
          <td>{findings_html}</td>
        </tr>"""

    return f"""<table>
      <tr><th>Normalized Target URL</th><th>Domain</th><th>Anchor Text</th><th>Forensic Analysis &amp; Findings</th></tr>
      {rows}
    </table>"""


def _render_attachments(attachments, title: str) -> str:
    if not attachments:
        return ""
    
    attach_rows = ""
    for a in attachments:
        mime = getattr(a, 'mime_type', 'application/octet-stream')
        findings_html = "<br>".join(f"⚠️ {_escape(f)}" for f in getattr(a, 'findings', [])) if getattr(a, 'findings', []) else "<span class='badge' style='" + BADGE_STYLES["PASS"] + "'>CLEAN</span>"
        attach_rows += f"""<tr>
          <td><strong>{_escape(a.filename)}</strong></td>
          <td>.{a.declared_extension}</td>
          <td>{a.true_type}</td>
          <td>{_escape(mime)}</td>
          <td>{a.size_bytes} B</td>
          <td><code>{a.hashes.get('sha256', '-')[:16]}...</code></td>
          <td>{findings_html}</td>
        </tr>"""

    return f"""<h3 style="font-size: 1rem; color: var(--accent);">{title}</h3>
    <table>
      <tr><th>Filename</th><th>Ext.</th><th>True Type</th><th>MIME Type</th><th>Size</th><th>SHA-256</th><th>Forensic Analysis &amp; Findings</th></tr>
      {attach_rows}
    </table>"""


def _render_master_evidence(finding: Finding) -> str:
    evidence_items = []

    for s in finding.signals:
        evidence_items.append((s.indicator, getattr(s, 'evidence', s.detail), "Phishing Signal"))
    for hf in finding.header_findings:
        evidence_items.append((hf.title, hf.evidence, "Header Forensics"))
    for u in finding.url_analysis.urls:
        if u.findings:
            evidence_items.append((f"URL: {u.domain}", f"{'; '.join(u.findings)} (URL: {u.raw_url})", "URL Forensics"))
    for a in finding.attachments:
        if getattr(a, 'findings', []):
            evidence_items.append((f"Attachment: {a.filename}", "; ".join(a.findings), "Attachment Forensics"))

    if not evidence_items:
        return "<p style='color: var(--text-muted);'><em>No suspicious evidence logged. Email appears legitimate.</em></p>"

    rows = "".join(
        f"<tr><td><strong>{_escape(cat)}</strong></td><td>{_escape(title)}</td><td><code>{_escape(ev)}</code></td></tr>"
        for title, ev, cat in evidence_items
    )

    return f"""<table>
      <tr><th>Category</th><th>Detection Signal</th><th>Matched Forensic Evidence</th></tr>
      {rows}
    </table>"""


def _render_soc_recommendations(finding: Finding) -> str:
    recs = []
    if finding.risk_level in {"High", "Critical"}:
        recs.append("🚨 <strong>Immediate Containment:</strong> Purge message from recipient inboxes across mail server / tenant.")
        recs.append("⛔ <strong>Perimeter Blocking:</strong> Block sender address and domain on Email Security Gateways.")
        if finding.url_analysis.suspicious_count > 0:
            recs.append("🌐 <strong>Network Defense:</strong> Add extracted malicious link domains/IPs to Web Proxy and Firewall blocklists.")
        if any(getattr(a, 'is_executable', False) or getattr(a, 'has_double_extension', False) for a in finding.attachments):
            recs.append("🛡️ <strong>Endpoint Security:</strong> Block attachment SHA-256 hashes on EDR and scan endpoints for execution artifacts.")
        recs.append("🔒 <strong>Credential Safeguard:</strong> Force password reset and revoke active SSO sessions for any user who interacted with links/attachments.")
    else:
        recs.append("✅ <strong>No Action Required:</strong> Message satisfied authentication standards and exhibited low risk.")

    items = "".join(f"<li>{r}</li>" for r in recs)
    return f"""<div class="rec-box">
      <ul style="margin: 0; padding-left: 1.2rem;">
        {items}
      </ul>
    </div>"""


def _render_technical_details(finding: Finding) -> str:
    return f"""<div style="font-family: monospace; font-size: 0.85rem; color: var(--accent-cyan);">
      <p><strong>MIME Structure Summary:</strong></p>
      <pre style="margin-top: 0; background: #16221c; padding: 0.5rem; border-radius: 4px; border: 1px solid #1b2e23;">{_escape(finding.mime_structure)}</pre>
      <p><strong>Raw Message-ID:</strong> <code>{_escape(finding.message_id or '-')}</code></p>
    </div>"""


def _escape(text) -> str:
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

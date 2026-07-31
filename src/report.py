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


from report_html import write_html_report
from report_pdf import write_pdf_report

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
        score=scoring.display_score,
        risk_level=scoring.risk_level,
        signals=scoring.signals,
        raw_score=scoring.total_score,
        confidence=scoring.confidence,
        confidence_label=scoring.confidence_label,
    )


def write_json_report(finding: Finding, out_path: str) -> None:
    logger.debug(f"Writing JSON report to {out_path}")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(dataclasses.asdict(finding), f, indent=2, default=str)




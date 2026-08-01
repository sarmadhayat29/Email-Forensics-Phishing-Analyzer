#!/usr/bin/env python3
"""Email Forensics & Phishing Analyzer — CLI entry point.

Usage:
    python src/main.py --input samples/ --output reports/
"""

import argparse
import json
import os
import sys
import dataclasses

from ingest import discover_messages, load_message
from parsing import parse_message
from header_analysis import analyze_headers
from url_analysis import analyze_urls
from attachment_analysis import analyze_attachments
from auth_checks import analyse_authentication, live_reverify
from domain_age import analyse_domain_age
from html_analysis import analyse_html
from routing import analyse_routing
from scoring import score_message
from report import build_finding, write_html_report, write_json_report, write_pdf_report
from exceptions import AnalyzerError, IngestionError
from models import Finding
from logger import get_logger

import logging

logger = get_logger(__name__)


class AnalyzerPipeline:
    """Runs every analysis stage over one message and assembles the Finding.

    ``sender_history_provider`` is an optional callable taking the parsed message
    and returning a :class:`~models.SenderHistory` (or ``None``). It exists so
    the API can contribute per-user correspondence history without the pipeline
    ever importing the database layer; the CLI passes nothing and stays fully
    offline. A provider that fails is treated as no history at all.
    """

    def __init__(self, output_dir: str, sender_history_provider=None):
        self.output_dir = output_dir
        self.sender_history_provider = sender_history_provider
        os.makedirs(self.output_dir, exist_ok=True)

    def analyse_one(self, path: str) -> Finding:
        logger.info(f"Analyzing {path}...")
        
        # Phase 1: Ingestion
        msg = load_message(path)
        
        # Phase 2: Parsing
        parsed = parse_message(msg)
        
        # Phase 2.2: Attachment Forensics Engine
        parsed.attachments = analyze_attachments(parsed)
        
        # Phase 2.4: URL Analysis Engine
        url_verdict = analyze_urls(parsed)

        # Phase 2.5: Header Forensics Analysis
        header_verdict = analyze_headers(parsed)
        
        # Phase 3-4: Authentication
        auth = live_reverify(parsed) or analyse_authentication(parsed)
        
        # Phase 5: Routing
        routing = analyse_routing(parsed)

        # Phase 5.5: Domain reputation (WHOIS registration age).
        # Degrades to an empty list whenever WHOIS is disabled or unreachable.
        domain_age_findings = analyse_domain_age(parsed, url_verdict)

        # Phase 5.6: HTML body forensics (hidden text, in-body forms, active
        # content). Returns an empty list when there is no HTML part or when
        # the markup could not be analysed; it never raises.
        html_findings = analyse_html(parsed.body_html, parsed.body_plain)

        # Phase 5.7: Sender-history baselining, when a caller supplied a source
        # of prior correspondence for this recipient (API only).
        sender_history = self._sender_history(parsed)

        # Phase 6: Scoring
        scoring = score_message(parsed, auth, routing, header_verdict, url_verdict,
                                domain_age_findings, html_findings, sender_history)
        
        # Phase 7: Finding assembly
        finding = build_finding(path, parsed, auth, routing, scoring, header_verdict,
                                url_verdict, domain_age_findings, html_findings)
        return finding

    def _sender_history(self, parsed):
        if not self.sender_history_provider:
            return None
        try:
            return self.sender_history_provider(parsed)
        except Exception as e:  # a history source must never break an analysis
            logger.warning(f"Sender-history provider failed and was skipped: {e}")
            return None



    def run(self, input_path: str):
        try:
            paths = discover_messages(input_path)
        except IngestionError as e:
            logger.critical(f"Input error: {e}")
            sys.exit(1)

        if not paths:
            logger.error(f"No .eml/.msg files found under: {input_path}")
            sys.exit(1)

        summary = []
        for path in paths:
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                finding = self.analyse_one(path)
            except AnalyzerError as e:
                logger.error(f"Skipping {path} due to analysis error: {e}")
                continue
            except Exception as e:
                logger.exception(f"Unexpected failure analysing {path}: {e}")
                continue

            html_path = os.path.join(self.output_dir, f"{name}.report.html")
            json_path = os.path.join(self.output_dir, f"{name}.report.json")
            pdf_path = os.path.join(self.output_dir, f"{name}.report.pdf")
            
            write_html_report(finding, html_path)
            write_json_report(finding, json_path)
            write_pdf_report(finding, pdf_path)

            summary.append({
                "file": os.path.basename(path),
                "subject": finding.subject,
                "from": finding.from_addr,
                "score": finding.score,
                "risk_level": finding.risk_level,
                "report_html": html_path,
                "report_pdf": pdf_path,
            })


            print(f"[{finding.risk_level:<6}] score={finding.score:<4} {os.path.basename(path)}  ->  {html_path}")

        summary.sort(key=lambda x: x["score"], reverse=True)
        summary_path = os.path.join(self.output_dir, "summary.json")
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"\nAnalysed {len(summary)} message(s). Summary: {summary_path}")


def main():
    ap = argparse.ArgumentParser(description="SOC-Ready Email Forensics & Phishing Analyzer")
    ap.add_argument("--input", "-i", required=True, help="Path to a .eml/.msg file or a folder of them")
    ap.add_argument("--output", "-o", default="reports", help="Output folder for reports (default: reports/)")
    ap.add_argument("--verbose", "-v", action="store_true", help="Enable verbose DEBUG logging")
    args = ap.parse_args()

    if args.verbose:
        get_logger("").setLevel(logging.DEBUG)

    pipeline = AnalyzerPipeline(output_dir=args.output)
    pipeline.run(args.input)


if __name__ == "__main__":
    main()


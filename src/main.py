#!/usr/bin/env python3
"""Email Forensics & Phishing Analyzer — CLI entry point.

Usage:
    python main.py --input samples/ --output reports/
    python main.py --input samples/phishing_sample_1.eml --output reports/
"""

import argparse
import json
import os
import sys

from ingest import discover_messages, load_message, IngestError
from parsing import parse_message
from auth_checks import analyse_authentication, live_reverify
from routing import analyse_routing
from scoring import score_message
from report import build_finding, write_html_report, write_json_report


def analyse_one(path: str) -> dict:
    msg = load_message(path)
    parsed = parse_message(msg)

    auth = live_reverify(parsed) or analyse_authentication(parsed)
    routing = analyse_routing(parsed)
    scoring = score_message(parsed, auth, routing)

    return build_finding(path, parsed, auth, routing, scoring)


def main():
    ap = argparse.ArgumentParser(description="Email Forensics & Phishing Analyzer")
    ap.add_argument("--input", "-i", required=True, help="Path to a .eml/.msg file or a folder of them")
    ap.add_argument("--output", "-o", default="reports", help="Output folder for reports (default: reports/)")
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)

    try:
        paths = discover_messages(args.input)
    except IngestError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not paths:
        print(f"No .eml/.msg files found under: {args.input}", file=sys.stderr)
        sys.exit(1)

    summary = []
    for path in paths:
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            finding = analyse_one(path)
        except IngestError as e:
            print(f"Skipping {path}: {e}", file=sys.stderr)
            continue
        except Exception as e:
            print(f"Failed to analyse {path}: {e}", file=sys.stderr)
            continue

        html_path = os.path.join(args.output, f"{name}.report.html")
        json_path = os.path.join(args.output, f"{name}.report.json")
        write_html_report(finding, html_path)
        write_json_report(finding, json_path)

        summary.append({
            "file": os.path.basename(path),
            "subject": finding["subject"],
            "from": finding["from"],
            "score": finding["score"],
            "risk_level": finding["risk_level"],
            "report_html": html_path,
        })

        print(f"[{finding['risk_level']:<6}] score={finding['score']:<4} {os.path.basename(path)}  ->  {html_path}")

    summary.sort(key=lambda x: x["score"], reverse=True)
    with open(os.path.join(args.output, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nAnalysed {len(summary)} message(s). Summary: {os.path.join(args.output, 'summary.json')}")


if __name__ == "__main__":
    main()

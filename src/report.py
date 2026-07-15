"""Stage 7 — Reporting.

Renders the combined findings into a human-readable HTML report and a
machine-readable JSON file. No templating dependency required (plain
f-strings) so the tool stays zero-dependency by default; swapping in
Jinja2 later is a drop-in change if the report grows more complex.
"""

import json
import os

RISK_COLORS = {"Low": "#2e7d32", "Medium": "#e6a700", "High": "#c62828"}


def build_finding(path: str, parsed: dict, auth: dict, routing: dict, scoring: dict) -> dict:
    return {
        "file": os.path.basename(path),
        "subject": parsed.get("subject", ""),
        "from": parsed.get("from_raw", ""),
        "date": parsed.get("date", ""),
        "message_id": parsed.get("message_id", ""),
        "authentication": {k: v for k, v in auth.items() if not k.startswith("_")},
        "routing": routing,
        "attachments": parsed.get("attachments", []),
        "score": scoring["total_score"],
        "risk_level": scoring["risk_level"],
        "signals": scoring["signals"],
    }


def write_json_report(finding: dict, out_path: str) -> None:
    with open(out_path, "w") as f:
        json.dump(finding, f, indent=2, default=str)


def write_html_report(finding: dict, out_path: str) -> None:
    color = RISK_COLORS.get(finding["risk_level"], "#333")

    signal_rows = "".join(
        f"<tr><td>{s['signal']}</td><td>{s['weight']}</td><td>{_escape(s['detail'])}</td></tr>"
        for s in finding["signals"]
    ) or "<tr><td colspan='3'><em>No phishing indicators triggered.</em></td></tr>"

    hop_rows = "".join(
        f"<tr><td>{h.get('from_host') or '-'}</td><td>{h.get('by_host') or '-'}</td>"
        f"<td>{h.get('ip') or '-'}</td><td>{h.get('timestamp') or '-'}</td></tr>"
        for h in finding["routing"].get("hops", [])
    ) or "<tr><td colspan='4'><em>No Received hops found.</em></td></tr>"

    routing_flags = "".join(f"<li>{_escape(f)}</li>" for f in finding["routing"].get("flags", [])) \
        or "<li><em>None</em></li>"

    attach_rows = "".join(
        f"<tr><td>{_escape(a['filename'])}</td><td>.{a['declared_extension']}</td>"
        f"<td>{a['true_type']}</td><td>{a['size_bytes']} B</td>"
        f"<td><code>{a['hashes'].get('sha256', '-')[:16]}...</code></td></tr>"
        for a in finding["attachments"]
    ) or "<tr><td colspan='5'><em>No attachments.</em></td></tr>"

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Email Forensics Report — {_escape(finding['subject'])}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; color: #222; background: #fafafa; }}
  h1 {{ font-size: 1.4rem; }}
  .verdict {{ display: inline-block; padding: 0.4rem 1rem; border-radius: 6px; color: white;
              background: {color}; font-weight: bold; font-size: 1.1rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; background: white; }}
  th, td {{ border: 1px solid #ddd; padding: 0.5rem 0.7rem; text-align: left; font-size: 0.9rem; }}
  th {{ background: #eef3ef; }}
  .meta td:first-child {{ font-weight: bold; width: 160px; background: #f5f5f5; }}
  section {{ margin-bottom: 2rem; }}
  code {{ font-size: 0.85em; }}
</style>
</head>
<body>
  <h1>Email Forensics &amp; Phishing Analyzer — Verdict Report</h1>
  <p><span class="verdict">{finding['risk_level']} risk — score {finding['score']}</span></p>

  <section>
    <h2>Message Metadata</h2>
    <table class="meta">
      <tr><td>File</td><td>{_escape(finding['file'])}</td></tr>
      <tr><td>Subject</td><td>{_escape(finding['subject'])}</td></tr>
      <tr><td>From</td><td>{_escape(finding['from'])}</td></tr>
      <tr><td>Date</td><td>{_escape(finding['date'])}</td></tr>
      <tr><td>Message-ID</td><td>{_escape(finding['message_id'])}</td></tr>
    </table>
  </section>

  <section>
    <h2>Authentication Results (SPF / DKIM / DMARC)</h2>
    <table>
      <tr><th>SPF</th><th>DKIM</th><th>DMARC</th><th>Source</th></tr>
      <tr>
        <td>{finding['authentication'].get('spf', 'not_present')}</td>
        <td>{finding['authentication'].get('dkim', 'not_present')}</td>
        <td>{finding['authentication'].get('dmarc', 'not_present')}</td>
        <td>{_escape(finding['authentication'].get('source', '-'))}</td>
      </tr>
    </table>
  </section>

  <section>
    <h2>Routing Analysis (Received chain)</h2>
    <p><strong>Hop count:</strong> {finding['routing'].get('hop_count', 0)}</p>
    <table>
      <tr><th>From host</th><th>By host</th><th>IP</th><th>Timestamp</th></tr>
      {hop_rows}
    </table>
    <p><strong>Flags:</strong></p>
    <ul>{routing_flags}</ul>
  </section>

  <section>
    <h2>Attachments</h2>
    <table>
      <tr><th>Filename</th><th>Declared ext.</th><th>True type</th><th>Size</th><th>SHA-256</th></tr>
      {attach_rows}
    </table>
  </section>

  <section>
    <h2>Triggered Phishing Indicators</h2>
    <table>
      <tr><th>Signal</th><th>Weight</th><th>Detail</th></tr>
      {signal_rows}
    </table>
  </section>

</body>
</html>"""

    with open(out_path, "w") as f:
        f.write(html)


def _escape(text) -> str:
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

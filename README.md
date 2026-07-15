# Project 10 — Email Forensics & Phishing Analyzer

A tool that parses `.eml` files, analyses headers for spoofing and routing
anomalies, and scores messages for phishing indicators with a clear,
per-signal explanation.

## Status

This is the working v1 skeleton: full pipeline is implemented and runnable
end-to-end against `.eml` files. `.msg` (Outlook) support, live DNS/WHOIS
checks, and the Streamlit demo UI are stubbed as documented next steps
(see "Roadmap" below).

## Setup

```bash
cd project10
pip install -r requirements.txt --break-system-packages   # optional deps only
```

The tool runs with **zero external dependencies** using just the Python
standard library. `requirements.txt` lists *optional* packages that unlock
extra checks (live SPF/DKIM/DMARC re-verification, WHOIS domain-age lookups,
`.msg` parsing) — the tool detects at runtime whether they're installed and
skips those checks gracefully if not, noting it in the report.

## Usage

Analyse every `.eml` file in a folder:

```bash
python src/main.py --input samples/ --output reports/
```

Analyse a single file:

```bash
python src/main.py --input samples/phishing_sample_1.eml --output reports/
```

Each run produces, per message, in `reports/`:
- `<name>.report.html` — human-readable verdict report
- `<name>.report.json` — machine-readable findings (for batch analysis / IOC extraction)

A `summary.json` is also written to the output folder, ranking all analysed
messages by phishing score (useful for the "batch mode" stretch goal / triage).

## Project layout

```
src/
  main.py         CLI entry point — orchestrates the pipeline
  ingest.py       Stage 1: load .eml / .msg files
  parsing.py      Stage 2: extract headers, body, attachments
  auth_checks.py  Stage 3-4: SPF/DKIM/DMARC verdicts
  routing.py      Stage 5: Received-header chain analysis
  scoring.py      Stage 6: weighted phishing-indicator scoring
  report.py       Stage 7: HTML + JSON report generation
  utils.py        shared helpers (hashing, domain parsing, signature sniffing)
samples/          synthetic test .eml files (phishing + legitimate)
reports/          generated output (created on first run)
```

## Sample data

`samples/` includes two synthetic `.eml` files for testing:
- `phishing_sample_1.eml` — a constructed lookalike-domain / SPF-fail / risky-link example
- `legit_sample_1.eml` — a constructed clean example that should score Low risk

These are fabricated for testing only — no real sender data.

## Roadmap (next steps for the team)

- [ ] `.msg` (Outlook) ingestion via `extract-msg`
- [ ] Live SPF/DKIM/DMARC re-verification via `dnspython` + `dkimpy` (currently reads `Authentication-Results` header if present)
- [ ] WHOIS domain-age lookup via `python-whois`
- [ ] VirusTotal API check for attachment hashes / URLs
- [ ] Streamlit dashboard for the live Week 8 demo
- [ ] Expand the lookalike-brand-domain list and swap the naive similarity check for a proper Levenshtein/confusable-character comparison
- [ ] Config file (YAML) for scoring weights so they can be tuned without editing code

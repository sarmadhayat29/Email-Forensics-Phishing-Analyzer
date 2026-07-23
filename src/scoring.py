"""Stage 6 — Phishing Indicator Scoring Engine.

Evaluates email messages across 15 distinct threat categories and outputs
transparent, weighted risk signals with evidence for SOC analysts.
"""

import re
from typing import Optional, List
from models import ParsedMessage, AuthVerdict, RoutingVerdict, PhishingSignal, ScoringVerdict, HeaderAnalysisVerdict, URLAnalysisVerdict
from utils import (
    extract_domain, extract_address, extract_display_name,
    looks_like_lookalike, is_punycode_or_unicode,
    detect_redirect_param, has_double_extension, RISKY_EXTENSIONS,
    KNOWN_BRAND_DOMAINS
)
from logger import get_logger

logger = get_logger(__name__)

# High-risk TLDs
HIGH_RISK_TLDS = {"xyz", "top", "work", "buzz", "click", "country", "tk", "ml", "ga", "cf", "gq", "fit", "surf", "icu"}

# Pattern matcher sets
CREDENTIAL_PATTERNS = [
    r"\bconfirm\s+(?:your\s+)?password\b", r"\bverify\s+(?:your\s+)?account\b",
    r"\blogin\s+to\s+(?:restore|verify|update)\b", r"\bupdate\s+billing\b",
    r"\baccount\s+suspended\b", r"\bsecurity\s+checkpoint\b", r"\benter\s+credentials\b"
]

URGENCY_PATTERNS = [
    r"\bimmediate\s+action\s+required\b", r"\bwithin\s+24\s+hours\b",
    r"\baccount\s+will\s+be\s+(?:closed|terminated|suspended)\b",
    r"\burgent\s+notice\b", r"\brespond\s+immediately\b", r"\bfinal\s+warning\b"
]

FINANCIAL_PATTERNS = [
    r"\bwire\s+transfer\b", r"\bbitcoin\b", r"\bcrypto\s+payment\b",
    r"\bgift\s+card\b", r"\boverdue\s+payment\b", r"\bpayment\s+confirmation\b",
    r"\bbank\s+deposit\b", r"\btransfer\s+funds\b"
]

INVOICE_PATTERNS = [
    r"\binvoice\s*#?\s*\d+\b", r"\bpurchase\s+order\s*#?\s*\d+\b",
    r"\bremittance\s+advice\b", r"\breceipt\s+for\s+your\s+payment\b",
    r"\battached\s+invoice\b", r"\bpayment\s+due\b"
]

PASSWORD_RESET_PATTERNS = [
    r"\bpassword\s+expired\b", r"\breset\s+password\b",
    r"\bunauthorized\s+login\s+attempt\b", r"\bsecurity\s+alert:\s+password\b",
    r"\bpassword\s+change\s+request\b"
]

RISK_BUCKETS = [
    (0, 29, "Low"),
    (30, 69, "Medium"),
    (70, 10**9, "High"),
]





def _bucket(score: int) -> str:
    if score < 0:
        return "Low"
    for low, high, label in RISK_BUCKETS:
        if low <= score <= high:
            return label
    return "High"


def score_message(
    parsed: ParsedMessage,
    auth: AuthVerdict,
    routing: RoutingVerdict,
    header_verdict: Optional[HeaderAnalysisVerdict] = None,
    url_verdict: Optional[URLAnalysisVerdict] = None
) -> ScoringVerdict:
    logger.debug("Executing 15-category Phishing Indicator Scoring Engine.")
    signals: List[PhishingSignal] = []

    from_domain = extract_domain(parsed.from_raw)
    from_address = extract_address(parsed.from_raw)
    display_name = extract_display_name(parsed.from_raw)
    subject = parsed.subject or ""
    body = (parsed.body_plain or "") + "\n" + (parsed.body_html or "")

    # --- URL Analysis Signals ---
    if url_verdict and url_verdict.urls:
        for u in url_verdict.urls:
            if u.is_mismatched_anchor:
                signals.append(PhishingSignal(
                    indicator="Deceptive / Mismatched Hyperlink",
                    weight=30,
                    explanation="Link anchor text displays a domain different from actual target destination.",
                    evidence=f"Anchor: '{u.anchor_text}' | Target: '{u.domain}'"
                ))
            if u.is_ip_based:
                signals.append(PhishingSignal(
                    indicator="IP-Based Link Target",
                    weight=25,
                    explanation="Link target uses a raw IP address instead of a domain name.",
                    evidence=f"Target: '{u.raw_url}'"
                ))
            if u.is_shortener:
                signals.append(PhishingSignal(
                    indicator="URL Shortener Link",
                    weight=15,
                    explanation="Link uses a URL shortener service to conceal destination URL.",
                    evidence=f"Shortener URL: '{u.raw_url}'"
                ))
            if u.is_suspicious_domain:
                signals.append(PhishingSignal(
                    indicator="Suspicious Link Domain",
                    weight=20,
                    explanation="Link targets a domain with high-risk TLD, Punycode, or lookalike patterns.",
                    evidence=f"Domain: '{u.domain}'"
                ))
            if detect_redirect_param(u.raw_url) and not any(sig.indicator == "Multiple / Open Redirect Link Parameter" for sig in signals):
                signals.append(PhishingSignal(
                    indicator="Multiple / Open Redirect Link Parameter",
                    weight=20,
                    explanation="Link contains embedded redirect query parameters pointing to a secondary destination.",
                    evidence=f"Link URL: '{u.raw_url}'"
                ))


    # 1. Display Name Impersonation
    if display_name and from_address:
        display_lc = display_name.lower()
        for brand_domain in KNOWN_BRAND_DOMAINS:
            brand = brand_domain.split(".")[0]
            if brand in display_lc and from_domain and brand not in from_domain:
                signals.append(PhishingSignal(
                    indicator="Display Name Impersonation",
                    weight=25,
                    explanation=f"Display name references known brand '{brand}', but actual sending domain is '{from_domain}'.",
                    evidence=f"Display Name: '{display_name}' | From: '{from_address}'"
                ))
                break

    # 2. Lookalike Domains & 3. Typosquatting
    if from_domain:
        brand = looks_like_lookalike(from_domain)
        if brand:
            signals.append(PhishingSignal(
                indicator="Lookalike / Typosquatted Domain",
                weight=25,
                explanation=f"Sender domain '{from_domain}' closely resembles target brand domain '{brand}'.",
                evidence=f"Sender Domain: '{from_domain}' -> Resembles: '{brand}'"
            ))

    # 4. Suspicious TLDs
    if from_domain:
        tld = from_domain.rsplit(".", 1)[-1].lower()
        if tld in HIGH_RISK_TLDS:
            signals.append(PhishingSignal(
                indicator="High-Risk Top-Level Domain (TLD)",
                weight=20,
                explanation=f"Sender domain uses high-risk top-level domain '.{tld}'.",
                evidence=f"Domain: '{from_domain}'"
            ))

    # 5. Unicode / Punycode Domains
    if from_domain:
        unicode_reason = is_punycode_or_unicode(from_domain)
        if unicode_reason:
            signals.append(PhishingSignal(
                indicator="Punycode / Unicode Domain",
                weight=20,
                explanation="Sender domain uses Punycode or non-ASCII characters, commonly exploited for IDN homograph spoofing.",
                evidence=unicode_reason
            ))

    # 6. Mismatched Sender Domains
    sender_domain = extract_domain(parsed.sender_raw)
    reply_to_domain = extract_domain(parsed.reply_to_raw)
    return_path_domain = extract_domain(parsed.return_path_raw)

    mismatches = []
    if sender_domain and from_domain and sender_domain != from_domain:
        mismatches.append(f"Sender ('{sender_domain}')")
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        mismatches.append(f"Reply-To ('{reply_to_domain}')")
    if return_path_domain and from_domain and return_path_domain != from_domain:
        mismatches.append(f"Return-Path ('{return_path_domain}')")

    if mismatches:
        signals.append(PhishingSignal(
            indicator="Mismatched Sender Domains",
            weight=20,
            explanation="Header From domain does not align with transmitter or bounce address domains.",
            evidence=f"From Domain: '{from_domain}' | Mismatches: {', '.join(mismatches)}"
        ))



    # 10. Suspicious Keywords in Subject / Body
    suspicious_kw = ["confidential", "security alert", "suspicious activity", "action required", "account notice"]
    found_kws = [kw for kw in suspicious_kw if kw in subject.lower() or kw in body.lower()]
    if found_kws:
        signals.append(PhishingSignal(
            indicator="Suspicious Keywords",
            weight=15,
            explanation="Subject or body contains high-risk threat keywords.",
            evidence=f"Matched Keywords: {', '.join(found_kws)}"
        ))

    # 11. Credential Harvesting Language
    for pat in CREDENTIAL_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(PhishingSignal(
                indicator="Credential Harvesting Language",
                weight=30,
                explanation="Email uses phrasing aimed at tricking recipients into revealing account credentials.",
                evidence=f"Matched Phrase: '{match.group(0)}'"
            ))
            break

    # 12. Urgency Language
    for pat in URGENCY_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(PhishingSignal(
                indicator="Urgent Pressure Tactics",
                weight=25,
                explanation="Email employs artificial time pressure to incite immediate action without due verification.",
                evidence=f"Matched Phrase: '{match.group(0)}'"
            ))
            break

    # 13. Financial Scam Language
    for pat in FINANCIAL_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(PhishingSignal(
                indicator="Financial Scam Language",
                weight=25,
                explanation="Email contains phrasing associated with wire fraud, cryptocurrency, or payment scams.",
                evidence=f"Matched Phrase: '{match.group(0)}'"
            ))
            break

    # 14. Fake Invoice Indicators
    for pat in INVOICE_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(PhishingSignal(
                indicator="Fake Invoice / BEC Indicators",
                weight=30,
                explanation="Email references fake invoices or purchase orders typical of Business Email Compromise (BEC).",
                evidence=f"Matched Phrase: '{match.group(0)}'"
            ))
            break

    # 15. Password Reset Scams
    for pat in PASSWORD_RESET_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(PhishingSignal(
                indicator="Password Reset Scam Language",
                weight=30,
                explanation="Email pretends to be an automated password reset or security alert.",
                evidence=f"Matched Phrase: '{match.group(0)}'"
            ))
            break

    # --- Authentication Signals ---
    if auth.spf == "fail":
        signals.append(PhishingSignal(
            indicator="SPF Authentication Failure",
            weight=30,
            explanation=f"SPF check failed for sender domain '{from_domain}'.",
            evidence=f"SPF Verdict: FAIL | Details: {auth.spf_details}"
        ))
    if auth.dkim == "fail":
        signals.append(PhishingSignal(
            indicator="DKIM Signature Failure",
            weight=30,
            explanation="DKIM cryptographic signature failed verification.",
            evidence=f"DKIM Verdict: FAIL | Details: {auth.dkim_details}"
        ))
    if auth.dmarc == "fail":
        signals.append(PhishingSignal(
            indicator="DMARC Policy Violation",
            weight=25,
            explanation="DMARC alignment failed — message violates domain policy.",
            evidence=f"DMARC Verdict: FAIL | Details: {auth.dmarc_details}"
        ))
    if auth.inconsistencies:
        for inc in auth.inconsistencies:
            signals.append(PhishingSignal(
                indicator="Authentication Inconsistency",
                weight=20,
                explanation="Detected conflicting authentication headers or domain misalignment.",
                evidence=inc
            ))

    # --- Header Forensics Signals ---
    if header_verdict and header_verdict.findings:
        for hf in header_verdict.findings:
            weight_map = {"Critical": 35, "High": 25, "Medium": 15, "Low": 5}
            w = weight_map.get(hf.risk_level, 15)
            signals.append(PhishingSignal(
                indicator=f"Header Forensics: {hf.title}",
                weight=w,
                explanation=hf.description,
                evidence=f"[{hf.risk_level}] {hf.evidence}"
            ))

    # --- Risky Attachments ---
    for att in parsed.attachments:
        filename = att.filename
        ext = att.declared_extension
        reasons = []
        if ext in RISKY_EXTENSIONS:
            reasons.append(f"executable/script extension '.{ext}'")
        if has_double_extension(filename):
            reasons.append("double extension (e.g. invoice.pdf.exe)")
        if att.true_type == "exe" and ext not in {"exe", "dll", "scr", "com"}:
            reasons.append(f"true file signature is executable but extension is '.{ext}'")
        if reasons:
            signals.append(PhishingSignal(
                indicator="Executable / Suspicious Attachment",
                weight=30,
                explanation="Attachment contains risky extensions or signature mismatch.",
                evidence=f"Filename: '{filename}' | Issues: {'; '.join(reasons)}"
            ))

    total = sum(s.weight for s in signals)
    logger.info(f"Message scored {total} ({_bucket(total)} risk).")

    return ScoringVerdict(
        total_score=total,
        risk_level=_bucket(total),
        signals=signals,
    )




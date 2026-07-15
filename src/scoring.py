"""Stage 6 — Indicator scoring.

Combines the outputs of the earlier stages into a transparent, weighted
score. Every point added carries a plain-English reason, so the final
report explains *why* a message got its verdict instead of handing back an
opaque number.

Weights are intentionally centralised here as constants so the team can
tune them without touching logic (README roadmap notes moving these to a
YAML config file as a stretch goal).
"""

from utils import (
    extract_domain, extract_address, extract_display_name,
    looks_like_lookalike, url_is_risky, has_double_extension, RISKY_EXTENSIONS,
)
import re

WEIGHTS = {
    "spf_fail": 30,
    "dkim_fail": 30,
    "dmarc_fail": 25,
    "lookalike_domain": 25,
    "display_name_mismatch": 15,
    "reply_to_mismatch": 10,
    "suspicious_routing": 15,
    "risky_link": 15,
    "risky_attachment": 25,
}

RISK_BUCKETS = [
    (0, 20, "Low"),
    (21, 50, "Medium"),
    (51, 10**9, "High"),
]

URL_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
LINK_TEXT_RE = re.compile(r'href=["\']([^"\']+)["\'][^>]*>([^<]+)<', re.IGNORECASE)


def _bucket(score: int) -> str:
    for low, high, label in RISK_BUCKETS:
        if low <= score <= high:
            return label
    return "High"


def score_message(parsed: dict, auth: dict, routing: dict) -> dict:
    signals = []  # list of {"signal", "weight", "detail"}

    from_domain = extract_domain(parsed.get("from_raw", ""))
    from_address = extract_address(parsed.get("from_raw", ""))
    display_name = extract_display_name(parsed.get("from_raw", ""))
    reply_to_address = extract_address(parsed.get("reply_to_raw", ""))

    # --- Authentication signals ---
    if auth.get("spf") == "fail":
        signals.append(_sig("spf_fail", f"SPF check failed for sender domain '{from_domain}'."))
    if auth.get("dkim") == "fail":
        signals.append(_sig("dkim_fail", "DKIM signature failed verification."))
    if auth.get("dmarc") == "fail":
        signals.append(_sig("dmarc_fail", "DMARC alignment failed — message does not meet the domain's stated policy."))

    # --- Lookalike domain ---
    if from_domain:
        brand = looks_like_lookalike(from_domain)
        if brand:
            signals.append(_sig(
                "lookalike_domain",
                f"Sender domain '{from_domain}' closely resembles the known brand domain '{brand}'."
            ))

    # --- Display name / address mismatch ---
    if display_name and from_address:
        # crude check: does the display name mention a brand that doesn't
        # match the actual sending domain?
        for brand in ["paypal", "microsoft", "apple", "amazon", "bank", "hbl", "ubl"]:
            if brand in display_name.lower() and from_domain and brand not in from_domain:
                signals.append(_sig(
                    "display_name_mismatch",
                    f"Display name ('{display_name}') references '{brand}', but the actual "
                    f"sending address is '{from_address}' — mismatch suggests impersonation."
                ))
                break

    # --- Reply-To mismatch ---
    if reply_to_address and from_address and reply_to_address != from_address:
        signals.append(_sig(
            "reply_to_mismatch",
            f"Reply-To ('{reply_to_address}') differs from From ('{from_address}') — "
            f"replies would be silently redirected."
        ))

    # --- Routing anomalies ---
    if routing.get("flags"):
        signals.append(_sig(
            "suspicious_routing",
            "; ".join(routing["flags"])
        ))

    # --- Risky links (from HTML body) ---
    html_body = parsed.get("body_html", "") or ""
    for href, text in LINK_TEXT_RE.findall(html_body):
        reason = url_is_risky(href)
        if reason:
            signals.append(_sig("risky_link", f"Link '{text.strip()[:40]}' -> {href}: {reason}."))
            break  # one representative flag is enough to score; all links listed in report raw data
    if not LINK_TEXT_RE.findall(html_body):
        for href in URL_RE.findall(html_body):
            reason = url_is_risky(href)
            if reason:
                signals.append(_sig("risky_link", f"Link target {href}: {reason}."))
                break

    # --- Risky attachments ---
    for att in parsed.get("attachments", []):
        filename = att["filename"]
        ext = att["declared_extension"]
        reasons = []
        if ext in RISKY_EXTENSIONS:
            reasons.append(f"declared extension '.{ext}' is executable/script type")
        if has_double_extension(filename):
            reasons.append("filename uses a double extension (e.g. invoice.pdf.exe)")
        true_type = att.get("true_type")
        if true_type == "exe" and ext not in {"exe", "dll", "scr", "com"}:
            reasons.append(f"true file signature is a Windows executable but extension is '.{ext}'")
        if reasons:
            signals.append(_sig(
                "risky_attachment",
                f"Attachment '{filename}': " + "; ".join(reasons) + "."
            ))

    total = sum(s["weight"] for s in signals)
    return {
        "total_score": total,
        "risk_level": _bucket(total),
        "signals": signals,
    }


def _sig(name: str, detail: str) -> dict:
    return {"signal": name, "weight": WEIGHTS.get(name, 0), "detail": detail}

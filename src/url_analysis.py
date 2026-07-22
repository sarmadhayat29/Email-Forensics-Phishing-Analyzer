"""URL Analysis & Normalization Engine.

Extracts, normalizes, inspects, and flags suspicious or deceptive URLs
in HTML and plain-text email bodies offline.
"""

import html
import re
from typing import List
from urllib.parse import urlparse, unquote

from models import ParsedMessage, ExtractedURL, URLAnalysisVerdict
from utils import (
    extract_domain,
    is_punycode_or_unicode,
    looks_like_lookalike,
    detect_redirect_param,
    IP_HOST_RE,
    SHORTENER_DOMAINS,
)
from logger import get_logger

logger = get_logger(__name__)

HIGH_RISK_TLDS = {"xyz", "top", "work", "buzz", "click", "country", "tk", "ml", "ga", "cf", "gq", "fit", "surf", "icu"}

HTML_LINK_RE = re.compile(r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
PLAIN_URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


def analyze_urls(parsed: ParsedMessage) -> URLAnalysisVerdict:
    logger.debug("Executing URL extraction, normalization, and forensics.")
    extracted_urls: List[ExtractedURL] = []
    seen_raw = set()
    flags: List[str] = []

    body_html = parsed.body_html or ""
    body_plain = parsed.body_plain or ""

    # 1. Extract HTML links with anchor texts
    for match in HTML_LINK_RE.finditer(body_html):
        raw_url = match.group(1).strip()
        raw_anchor = _strip_tags(match.group(2)).strip()
        if raw_url not in seen_raw:
            seen_raw.add(raw_url)
            url_obj = _analyze_single_url(raw_url, anchor_text=raw_anchor)
            if url_obj:
                extracted_urls.append(url_obj)

    # 2. Extract plain text URLs from body_plain
    if body_plain:
        for match in PLAIN_URL_RE.finditer(body_plain):
            raw_url = match.group(0).strip()
            if raw_url not in seen_raw:
                seen_raw.add(raw_url)
                url_obj = _analyze_single_url(raw_url, anchor_text="")
                if url_obj:
                    extracted_urls.append(url_obj)


    suspicious_count = sum(1 for u in extracted_urls if u.findings)

    for u in extracted_urls:
        if u.findings:
            flags.append(f"URL '{u.raw_url[:40]}...': {'; '.join(u.findings)}")

    return URLAnalysisVerdict(
        urls=extracted_urls,
        total_urls=len(extracted_urls),
        suspicious_count=suspicious_count,
        flags=flags
    )


def _analyze_single_url(raw_url: str, anchor_text: str = "") -> ExtractedURL | None:
    if not raw_url or raw_url.startswith("javascript:") or raw_url.startswith("mailto:"):
        return None

    # Unescape HTML entities (e.g. &amp; -> &)
    clean_url = html.unescape(raw_url)
    
    try:
        parsed_url = urlparse(clean_url)
    except Exception:
        return ExtractedURL(
            raw_url=raw_url,
            normalized_url=clean_url,
            domain="Unknown",
            anchor_text=anchor_text,
            findings=["Unparseable malformed URL structure"]
        )

    host = (parsed_url.hostname or "").lower()
    scheme = (parsed_url.scheme or "http").lower()
    path = parsed_url.path or ""
    query = f"?{parsed_url.query}" if parsed_url.query else ""
    
    normalized_url = f"{scheme}://{host}{path.rstrip('/')}{query}"
    findings: List[str] = []

    is_ip = False
    is_shortener = False
    is_suspicious_domain = False
    is_mismatched = False
    is_hidden = False

    # Check 1: IP-based URL
    if IP_HOST_RE.match(host):
        is_ip = True
        findings.append(f"Link target is a raw IP address ({host})")

    # Check 2: URL Shortener
    if host in SHORTENER_DOMAINS:
        is_shortener = True
        findings.append(f"Link uses URL shortener ({host})")

    # Check 3: Suspicious TLD / Punycode / Lookalike
    if host:
        tld = host.rsplit(".", 1)[-1]
        if tld in HIGH_RISK_TLDS:
            is_suspicious_domain = True
            findings.append(f"Link domain uses high-risk TLD (.{tld})")
        
        unicode_res = is_punycode_or_unicode(host)
        if unicode_res:
            is_suspicious_domain = True
            findings.append(f"Link domain uses Punycode/Unicode ({unicode_res})")

        lookalike_brand = looks_like_lookalike(host)
        if lookalike_brand:
            is_suspicious_domain = True
            findings.append(f"Link domain '{host}' is a lookalike of '{lookalike_brand}'")

    # Check 4: Multiple / Open Redirect
    redirect_res = detect_redirect_param(clean_url)
    if redirect_res:
        findings.append(f"Link contains open-redirect parameter ({redirect_res})")

    # Check 5: Mismatched Hyperlink Anchor Text (Deceptive link)
    if anchor_text:
        anchor_domain = extract_domain(anchor_text) or _extract_host_from_text(anchor_text)
        if anchor_domain and host and anchor_domain.lower() != host:
            is_mismatched = True
            findings.append(f"Mismatched Hyperlink: Anchor text displays '{anchor_text}' but link targets '{host}'")

    return ExtractedURL(
        raw_url=raw_url,
        normalized_url=normalized_url,
        domain=host,
        anchor_text=anchor_text,
        is_ip_based=is_ip,
        is_shortener=is_shortener,
        is_suspicious_domain=is_suspicious_domain,
        is_mismatched_anchor=is_mismatched,
        is_hidden=is_hidden,
        findings=findings
    )


def _strip_tags(text: str) -> str:
    return re.sub(r'<[^>]+>', '', text)


def _extract_host_from_text(text: str) -> str | None:
    match = re.search(r'\b([a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)\b', text)
    return match.group(1).lower() if match else None

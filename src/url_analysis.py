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
    is_plausible_hostname,
    registrable_domain,
    IP_HOST_RE,
    SHORTENER_DOMAINS,
    HIGH_RISK_TLDS,
)
from logger import get_logger

logger = get_logger(__name__)

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
    if anchor_text and host:
        anchor_host = _extract_anchor_host(anchor_text)
        # Compare registrable domains so www./links. subdomains of the same
        # organisation are not reported as deceptive.
        if anchor_host and registrable_domain(anchor_host) != registrable_domain(host):
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


HOSTNAME_CANDIDATE_RE = re.compile(
    r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+)\b'
)


def _extract_anchor_host(anchor_text: str) -> str | None:
    """Extract the hostname an anchor *claims* to point at, if it claims one.

    Returns None for ordinary link text ('Click here', 'invoice.pdf',
    'Release 2.1') so only genuine domain claims can trigger a mismatch.
    """
    text = (anchor_text or "").strip()
    if not text:
        return None

    if "://" in text:
        try:
            host = (urlparse(text).hostname or "").lower()
        except ValueError:
            host = ""
        if host and (is_plausible_hostname(host) or IP_HOST_RE.match(host)):
            return host

    email_domain = extract_domain(text)
    if email_domain and is_plausible_hostname(email_domain):
        return email_domain

    for match in HOSTNAME_CANDIDATE_RE.finditer(text):
        candidate = match.group(1).lower()
        if is_plausible_hostname(candidate):
            return candidate

    return None

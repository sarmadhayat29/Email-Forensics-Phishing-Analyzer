"""Shared helpers: hashing, domain parsing, file-signature sniffing."""

import hashlib
import re
from urllib.parse import urlparse

# --- Hashing -----------------------------------------------------------

def hash_bytes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# --- Domain helpers ------------------------------------------------------

EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+\.[\w.-]+)")


def extract_domain(address: str) -> str | None:
    """Pull the domain out of a raw email address / From-header string."""
    if not address:
        return None
    match = EMAIL_RE.search(address)
    return match.group(1).lower() if match else None


def extract_address(header_value: str) -> str | None:
    """Pull just the bare email address out of a 'Display Name <addr>' string."""
    if not header_value:
        return None
    match = re.search(r"<([^>]+)>", header_value)
    if match:
        return match.group(1).strip().lower()
    match = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", header_value)
    return match.group(0).lower() if match else None


def extract_display_name(header_value: str) -> str:
    if not header_value:
        return ""
    match = re.match(r'\s*"?([^"<]*)"?\s*<', header_value)
    return match.group(1).strip() if match else ""


TARGET_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "linkedin", "docusign", "office365",
    "outlook", "bankofamerica", "chase", "wellsfargo", "citibank",
    "dhl", "fedex", "ups", "usps", "coinbase", "binance",
    "quickbooks", "xero", "dropbox", "adobe", "stripe", "square",
    "barclays", "hsbc", "schwab", "fidelity", "verizon", "att"
]

KNOWN_BRAND_DOMAINS = [f"{b}.com" for b in TARGET_BRANDS]



def looks_like_lookalike(domain: str) -> str | None:
    """Check if domain is a lookalike of a target brand using Levenshtein & homoglyph distance."""
    if not domain:
        return None
    d = domain.lower().split(".")[0]
    
    # Character substitutions (homoglyphs)
    normalized = (
        d.replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("8", "b")
        .replace("@", "a")
        .replace("-", "")
    )

    for brand in TARGET_BRANDS:
        if d == brand:
            continue
        
        # Exact match after character substitution (e.g., paypa1 -> paypal, micros0ft -> microsoft)
        if normalized == brand:
            return brand

        # Levenshtein distance check for typosquatting (1 or 2 character edits)
        dist = _levenshtein(d, brand)
        if 1 <= dist <= 2 and len(brand) >= 5:
            return brand

        dist_norm = _levenshtein(normalized, brand)
        if 1 <= dist_norm <= 2 and len(brand) >= 5:
            return brand

    return None


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]



# --- URL & Domain helpers -------------------------------------------------

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"}

IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
REDIRECT_PARAM_RE = re.compile(r"[?&](?:url|redirect|dest|goto|target|link|next|r)=https?%3A%2F%2F|[?&](?:url|redirect|dest|goto|target|link|next|r)=https?://", re.IGNORECASE)


def is_punycode_or_unicode(domain: str) -> str | None:
    """Check if domain uses Internationalized Domain Names (IDN) / Punycode or non-ASCII characters."""
    if not domain:
        return None
    if "xn--" in domain.lower():
        return f"Punycode encoded domain ({domain})"
    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        return f"Non-ASCII Unicode characters in domain ({domain})"
    return None


def detect_redirect_param(url: str) -> str | None:
    """Check if URL contains open-redirect query parameters pointing to another URL."""
    if not url:
        return None
    match = REDIRECT_PARAM_RE.search(url)
    if match:
        return f"URL contains open-redirect parameter ({match.group(0)})"
    return None


def url_is_risky(url: str) -> str | None:
    """Return a short reason string if the URL looks risky, else None."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return "unparsable URL"
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    if IP_HOST_RE.match(host):
        return f"link target is a raw IP address ({host})"
    if host in SHORTENER_DOMAINS:
        return f"link uses a URL shortener ({host})"
    redirect = detect_redirect_param(url)
    if redirect:
        return redirect
    return None


# --- Attachment signature sniffing (no external deps) --------------------


MAGIC_SIGNATURES = [
    (b"MZ", "exe"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip/office"),
    (b"\xff\xd8\xff", "jpg"),
    (b"\x89PNG", "png"),
    (b"%!PS", "ps"),
    (b"\xd0\xcf\x11\xe0", "ole/doc-xls-ppt"),
]

RISKY_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe",
    "ws", "wsf", "msi", "jar", "ps1", "hta",
}


def sniff_true_type(data: bytes) -> str:
    for sig, label in MAGIC_SIGNATURES:
        if data.startswith(sig):
            return label
    return "unknown"


def has_double_extension(filename: str) -> bool:
    parts = filename.lower().rsplit(".", 2)
    if len(parts) < 3:
        return False
    return parts[1] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"} and \
        parts[2] in RISKY_EXTENSIONS


def file_extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()

"""Shared helpers: hashing, domain parsing, file-signature sniffing."""

import hashlib
import re
from urllib.parse import urlparse

# --- Hashing -----------------------------------------------------------

def hash_bytes(data: bytes) -> dict:
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


# A small, illustrative list of commonly-spoofed brand domains.
# Expand this list for real use (see README roadmap).
KNOWN_BRAND_DOMAINS = [
    "paypal.com", "microsoft.com", "apple.com", "google.com", "amazon.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "dhl.com", "fedex.com",
    "hbl.com", "ubl.com.pk", "meezanbank.com",
]


def looks_like_lookalike(domain: str) -> str | None:
    """Very simple heuristic: flag domains that are a near-miss of a known
    brand domain (digit-for-letter swaps, added hyphens/suffixes, extra
    subdomains). Returns the brand it resembles, or None.

    This is intentionally simple — see README roadmap for a proper
    Levenshtein/confusable-character upgrade.
    """
    if not domain:
        return None

    def deleet(s: str) -> str:
        return (
            s.replace("0", "o")
            .replace("1", "l")
            .replace("3", "e")
            .replace("5", "s")
        )

    domain_norm = deleet(domain)
    domain_first_label = deleet(domain.split(".")[0]).replace("-", "")

    for brand in KNOWN_BRAND_DOMAINS:
        if domain == brand:
            continue  # exact match is fine, not a lookalike
        brand_root = brand.split(".")[0]  # e.g. "paypal" from "paypal.com"
        brand_no_hyphen = brand.replace("-", "")

        # Full-domain near-miss (digit/letter swap across the whole domain).
        if domain_norm.replace("-", "") == brand_no_hyphen:
            return brand

        # Brand name embedded as a prefix of the first label, with extra
        # suffix tacked on — e.g. "paypa1-secure.com", "paypalverify.com".
        if domain_first_label.startswith(brand_root) and domain_first_label != brand_root:
            return brand

    return None


# --- URL helpers ---------------------------------------------------------

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"}

IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


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

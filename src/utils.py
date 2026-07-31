"""Shared helpers: hashing, domain parsing, file-signature sniffing."""

import hashlib
import html
import re
from email.utils import parseaddr
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
BARE_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def extract_address(header_value: str) -> str | None:
    """Pull just the bare email address out of a 'Display Name <addr>' string.

    Uses RFC 5322 address parsing so a display name that itself contains an
    email address (e.g. '"billing@paypal.com" <thief@evil.tk>') resolves to
    the real address in angle brackets rather than the decoy.
    """
    if not header_value:
        return None

    _, addr = parseaddr(header_value)
    if addr and "@" in addr:
        return addr.strip().strip("<>").lower()

    # Fall back to raw extraction for malformed headers parseaddr gives up on.
    match = re.search(r"<([^>]*@[^>]*)>", header_value)
    if match:
        return match.group(1).strip().lower()
    match = BARE_EMAIL_RE.search(header_value)
    return match.group(0).lower() if match else None


def extract_domain(address: str) -> str | None:
    """Pull the domain out of a raw email address / From-header string.

    Derived from :func:`extract_address` so display-name spoofing cannot flip
    domain-alignment checks in the attacker's favour.
    """
    if not address:
        return None
    addr = extract_address(address)
    if not addr or "@" not in addr:
        return None
    domain = addr.rsplit("@", 1)[-1].strip().strip("<>[]").rstrip(".").lower()
    return domain or None


def extract_display_name(header_value: str) -> str:
    if not header_value:
        return ""
    name, _ = parseaddr(header_value)
    if name:
        return name.strip()
    match = re.match(r'\s*"?([^"<]*)"?\s*<', header_value)
    return match.group(1).strip() if match else ""


# --- Text normalisation for keyword / phrase matching --------------------

_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
# Zero-width, bidi controls, word joiner, BOM and soft hyphen: all invisible
# separators used to break up keywords without changing how a human reads them.
_INVISIBLE_CHARS_RE = re.compile(r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
_HORIZONTAL_WS_RE = re.compile(r"[ \t\r\f\v\u00a0]+")


def strip_html_tags(text: str, tag_replacement: str = " ") -> str:
    """Remove HTML markup, dropping script/style bodies and comments first."""
    if not text:
        return ""
    text = _SCRIPT_STYLE_RE.sub(" ", text)
    text = _HTML_COMMENT_RE.sub(" ", text)
    return _HTML_TAG_RE.sub(tag_replacement, text)


def normalize_text(text: str) -> str:
    """Decode entities and strip invisible characters used to evade matching."""
    if not text:
        return ""
    text = html.unescape(text)
    text = _INVISIBLE_CHARS_RE.sub("", text)
    return _HORIZONTAL_WS_RE.sub(" ", text)


def build_match_text(body_plain: str, body_html: str) -> str:
    """Build the normalised text used for keyword/phrase matching.

    The HTML part is contributed twice: once with tags replaced by a space
    (so block markup does not glue words together) and once with tags removed
    outright (so ``pass<b>word</b>`` still reads as ``password``).
    """
    parts: list[str] = []
    plain = normalize_text(body_plain or "")
    if plain:
        parts.append(plain)

    if body_html:
        spaced = normalize_text(strip_html_tags(body_html, " "))
        if spaced:
            parts.append(spaced)
        compact = normalize_text(strip_html_tags(body_html, ""))
        if compact and compact not in parts:
            parts.append(compact)

    return "\n".join(parts)


# --- Hostname plausibility helpers ---------------------------------------

# Union of the TLD blocklists that previously lived separately in
# scoring.py, url_analysis.py and header_analysis.py.
HIGH_RISK_TLDS = {
    "xyz", "top", "work", "buzz", "click", "country", "tk", "ml", "ga", "cf",
    "gq", "fit", "surf", "icu", "rest", "monster", "live", "cam", "zip",
    "mov", "quest", "cyou", "sbs", "lol", "bar", "loan", "review", "gdn",
    "kim", "men", "party", "racing", "stream", "download", "support",
}

# Public suffixes that need three labels to reach a registrable domain.
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "com.mx", "com.ar", "com.co", "com.pe", "com.ve",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.za", "org.za", "com.tr", "com.sg", "com.my", "com.hk", "com.tw",
    "co.kr", "or.kr", "com.sa", "com.eg", "com.ng", "co.il", "com.ua",
    "com.ru", "com.pl", "com.es", "com.it", "com.fr", "com.de",
}

# Deliberately not exhaustive: enough coverage to tell a hostname apart from a
# filename or a version number without pulling in a public-suffix dependency.
COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "name",
    "pro", "coop", "aero", "museum", "jobs", "mobi", "travel", "tel", "asia",
    "cat", "post", "xxx", "app", "dev", "io", "ai", "co", "me", "tv", "cc",
    "ly", "gg", "sh", "to", "vc", "ws", "site", "online", "store", "shop",
    "tech", "space", "website", "cloud", "email", "team", "group", "world",
    "life", "today", "news", "blog", "page", "link", "one", "run", "zone",
    "digital", "agency", "solutions", "services", "systems", "network",
    "media", "studio", "design", "software", "finance", "capital", "bank",
    "insurance", "health", "care", "law", "legal", "academy", "school",
    "university", "institute", "foundation", "charity", "church", "global",
    "expert", "consulting", "management", "partners", "ventures", "holdings",
    "us", "uk", "ca", "au", "nz", "de", "fr", "es", "it", "nl", "be", "ch",
    "at", "se", "no", "dk", "fi", "ie", "pt", "pl", "cz", "sk", "hu", "ro",
    "bg", "gr", "tr", "ru", "ua", "by", "kz", "il", "ae", "sa", "qa", "kw",
    "eg", "za", "ng", "ke", "gh", "ma", "tn", "in", "pk", "bd", "lk", "np",
    "cn", "jp", "kr", "hk", "tw", "sg", "my", "th", "vn", "ph", "id", "br",
    "mx", "ar", "cl", "pe", "eu",
} | HIGH_RISK_TLDS

_HOSTNAME_CANDIDATE_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)\b", re.IGNORECASE)


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 using a small multi-label public-suffix list."""
    if not host:
        return ""
    labels = [p for p in host.lower().strip(".").split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_plausible_hostname(candidate: str) -> bool:
    """True when the string looks like a real hostname rather than a filename.

    Rejects things like ``invoice.pdf``, ``report.v2.1`` or ``Inc.We`` that a
    naive dotted-token regex would otherwise treat as a domain.
    """
    if not candidate or len(candidate) > 253:
        return False
    labels = candidate.lower().strip(".").split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return False
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        return False
    return labels[-1] in COMMON_TLDS


TARGET_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "linkedin", "docusign", "office365",
    "outlook", "bankofamerica", "chase", "wellsfargo", "citibank",
    "dhl", "fedex", "ups", "usps", "coinbase", "binance",
    "quickbooks", "xero", "dropbox", "adobe", "stripe", "square",
    "barclays", "hsbc", "schwab", "fidelity", "verizon", "attcom",
]

# Brands requiring whole-word matching to prevent substring false positives
# e.g. "att" matches "Attention", "Attachment" — use "attcom" to represent AT&T
BRAND_WORD_BOUNDARY_REQUIRED = {"attcom"}

KNOWN_BRAND_DOMAINS = [f"{b}.com" for b in TARGET_BRANDS]

# Registrable domains genuinely operated by the brands above. Needed so that
# brand-token containment does not flag real brand infrastructure such as
# 'outlook.office.com' or 'paypal.me'.
BRAND_OWNED_DOMAINS = {
    "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
    "live.com", "outlook.com", "hotmail.com", "msn.com", "sharepoint.com",
    "onedrive.com", "azure.com", "windows.com", "skype.com", "xbox.com",
    "google.com", "gmail.com", "googlemail.com", "youtube.com",
    "googleapis.com", "gstatic.com", "withgoogle.com",
    "apple.com", "icloud.com", "me.com",
    "amazon.com", "amazon.co.uk", "amazon.de", "amazonses.com",
    "amazonaws.com", "awsapps.com", "amazon.jobs",
    "paypal.com", "paypal.me", "paypalobjects.com", "paypal-corp.com",
    "facebook.com", "facebookmail.com", "instagram.com",
    "linkedin.com", "licdn.com",
    "netflix.com", "nflxext.com",
    "docusign.com", "docusign.net",
    "dropbox.com", "dropboxmail.com",
    "adobe.com", "adobesign.com",
    "stripe.com", "square.com", "squareup.com",
    "intuit.com", "quickbooks.com", "xero.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com",
    "coinbase.com", "binance.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "barclays.co.uk", "hsbc.com", "schwab.com", "fidelity.com",
    "verizon.com", "att.com",
}

# Brand tokens shorter than this are skipped by containment matching: short
# tokens like 'ups' or 'dhl' collide with ordinary words ('follow-ups').
BRAND_CONTAINMENT_MIN_LEN = 6

# Brand names that are also common English words, where containment matching
# would produce more noise than signal.
BRAND_CONTAINMENT_EXEMPT = {"square"}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "8": "b", "@": "a"})
_LABEL_SPLIT_RE = re.compile(r"[.\-_]+")


def _dehomoglyph(text: str) -> str:
    """Fold common digit/symbol homoglyph substitutions back to letters."""
    return text.translate(_HOMOGLYPHS).replace("-", "")


def looks_like_lookalike(domain: str) -> str | None:
    """Return the impersonated brand if ``domain`` mimics a known brand.

    Covers three families:
      * homoglyph substitution  — ``paypa1.com``, ``micros0ft.com``
      * edit-distance typosquat — ``payapl.com``, ``linkedln.com``
      * brand-token containment — ``paypal-secure.com``, ``login.paypal.evil.tk``

    Domains genuinely owned by the brand are exempt.
    """
    if not domain:
        return None

    host = domain.lower().strip(".")
    if not host:
        return None

    registrable = registrable_domain(host)
    registrable_label = registrable.split(".")[0] if registrable else ""

    # 'paypal.com', 'amazon.co.uk', 'paypal.me' and known brand infrastructure
    # are the brand, not an imitation of it.
    if registrable in BRAND_OWNED_DOMAINS or registrable_label in TARGET_BRANDS:
        return None

    leading_label = host.split(".")[0]
    normalized = _dehomoglyph(leading_label)

    for brand in TARGET_BRANDS:
        if leading_label == brand:
            continue

        # Exact match after character substitution (e.g. paypa1 -> paypal)
        if normalized == brand:
            return brand

        if len(brand) >= 5:
            # Levenshtein distance check for typosquatting (1 or 2 edits)
            if 1 <= _levenshtein(leading_label, brand) <= 2:
                return brand
            if 1 <= _levenshtein(normalized, brand) <= 2:
                return brand

    # Brand token used as a standalone word anywhere in the hostname. Matching
    # whole dot/dash/underscore-separated tokens (rather than raw substrings)
    # keeps 'pineapple-farm.com' from being read as an Apple lookalike.
    tokens = set()
    for token in _LABEL_SPLIT_RE.split(host):
        if token:
            tokens.add(token)
            tokens.add(_dehomoglyph(token))

    for brand in TARGET_BRANDS:
        if len(brand) < BRAND_CONTAINMENT_MIN_LEN or brand in BRAND_CONTAINMENT_EXEMPT:
            continue
        if brand in tokens:
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

SHORTENER_DOMAINS = {
    "bit.ly", "bit.do", "tinyurl.com", "tiny.cc", "goo.gl", "t.co", "ow.ly",
    "is.gd", "v.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
    "rb.gy", "t.ly", "s.id", "short.io", "bl.ink", "soo.gd", "u.to",
    "clck.ru", "clik.pw", "adf.ly", "shorte.st", "po.st", "tr.im",
    "urlz.fr", "lnkd.in", "trib.al", "mcaf.ee", "x.co", "qr.ae", "chilp.it",
    "ity.im", "q.gs", "1link.in", "shrtco.de", "gg.gg", "8fw.ru",
}

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
    # Native executables & installers
    "exe", "scr", "com", "pif", "msi", "msix", "appx", "dll", "cpl", "gadget",
    "application", "appref-ms", "apk",
    # Shell & script interpreters
    "bat", "cmd", "js", "jse", "vbs", "vbe", "ws", "wsf", "wsh", "ps1",
    "ps2", "psc1", "psm1", "sct", "hta", "jar", "jnlp", "pyz",
    # Shortcut / loader files abused to launch payloads
    "lnk", "url", "scf", "reg", "inf", "msc", "msp", "mst", "chm",
    # Container formats used to bypass mark-of-the-web / gateway scanning
    "iso", "img", "vhd", "vhdx",
    # Office data-connection & add-in formats that execute on open
    "iqy", "slk", "xll", "xlam",
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

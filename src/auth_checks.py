"""Stage 3-4 — Authentication analysis.

v1 reads the Authentication-Results header (added by the receiving mail
server) to get SPF/DKIM/DMARC verdicts — this works on any already-delivered
email and needs no network access, so it's the reliable default.

Live re-verification (querying DNS directly) is offered as an optional
upgrade path when dnspython/dkimpy/checkdmarc are installed — see
`live_reverify()` stub below for where the team should plug that in.
"""

import re

VERDICT_RE = {
    "spf": re.compile(r"spf=(\w+)", re.IGNORECASE),
    "dkim": re.compile(r"dkim=(\w+)", re.IGNORECASE),
    "dmarc": re.compile(r"dmarc=(\w+)", re.IGNORECASE),
}


def analyse_authentication(parsed: dict) -> dict:
    """Return {'spf': 'pass'|'fail'|'none'|'not_present', ...} plus raw text."""
    auth_headers = parsed.get("authentication_results", [])
    combined = " ".join(auth_headers) if auth_headers else ""

    result = {"raw": combined, "source": "Authentication-Results header"}
    for mechanism, pattern in VERDICT_RE.items():
        match = pattern.search(combined)
        result[mechanism] = match.group(1).lower() if match else "not_present"

    if not auth_headers:
        result["note"] = (
            "No Authentication-Results header found. This can mean the "
            "receiving server didn't check authentication, or the header "
            "was stripped. Consider live DNS re-verification for a "
            "definitive answer (see auth_checks.live_reverify)."
        )

    return result


def live_reverify(parsed: dict) -> dict | None:
    """Optional live SPF/DKIM/DMARC check via DNS.

    Returns None (and the caller should fall back to the header-based
    result) unless dnspython/dkimpy/checkdmarc are installed. This is a
    deliberate stub — wiring in a real sending-IP + envelope-from based
    SPF check, a DKIM signature re-verification against the raw message,
    and a DMARC policy lookup is next-phase work (see README roadmap).
    """
    try:
        import dns.resolver  # noqa: F401
    except ImportError:
        return None
    # TODO (team): implement live SPF (pyspf/checkdmarc), DKIM (dkimpy against
    # the raw message bytes), and DMARC (checkdmarc) here, keyed off the
    # domain in parsed['from_raw'] and the sending IP from the first
    # Received: header. Return a dict shaped like analyse_authentication()'s
    # output so scoring.py can consume either source interchangeably.
    return None

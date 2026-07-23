"""Stage 3-4 — Authentication analysis.

Parses Authentication-Results headers offline to extract SPF, DKIM, and DMARC verdicts,
generates human-readable SOC explanations, and detects authentication inconsistencies.
"""

import re
from typing import Optional, List
from models import ParsedMessage, AuthVerdict
from utils import extract_domain
from logger import get_logger

logger = get_logger(__name__)

SPF_RE = re.compile(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", re.IGNORECASE)
DKIM_RE = re.compile(r"dkim=(pass|fail|neutral|none|policy|temperror|permerror)", re.IGNORECASE)
DMARC_RE = re.compile(r"dmarc=(pass|fail|none)", re.IGNORECASE)

MAILFROM_RE = re.compile(r"smtp\.mailfrom=([^\s;]+)", re.IGNORECASE)
HEADER_I_RE = re.compile(r"header\.(?:i|from)=([^\s;]+)", re.IGNORECASE)
ACTION_RE = re.compile(r"(?:action|p)=([^\s;]+)", re.IGNORECASE)


def analyse_authentication(parsed: ParsedMessage) -> AuthVerdict:
    """Evaluate authentication results offline from existing headers."""
    logger.debug("Analysing authentication from headers.")
    auth_headers = parsed.authentication_results
    combined = " ".join(auth_headers) if auth_headers else ""

    spf = "not_present"
    dkim = "not_present"
    dmarc = "not_present"

    spf_match = SPF_RE.search(combined)
    if spf_match:
        spf = spf_match.group(1).lower()

    dkim_match = DKIM_RE.search(combined)
    if dkim_match:
        dkim = dkim_match.group(1).lower()

    dmarc_match = DMARC_RE.search(combined)
    if dmarc_match:
        dmarc = dmarc_match.group(1).lower()

    # Extract details
    mailfrom_match = MAILFROM_RE.search(combined)
    header_i_match = HEADER_I_RE.search(combined)
    action_match = ACTION_RE.search(combined)

    spf_details = f"smtp.mailfrom={mailfrom_match.group(1)}" if mailfrom_match else ""
    dkim_details = f"header.i={header_i_match.group(1)}" if header_i_match else ""
    dmarc_details = f"action={action_match.group(1)}" if action_match else ""

    inconsistencies = _detect_inconsistencies(parsed, auth_headers, spf, dkim, dmarc, mailfrom_match.group(1) if mailfrom_match else None, header_i_match.group(1) if header_i_match else None)
    explanation = _generate_explanation(spf, dkim, dmarc, inconsistencies)

    note = None
    if not auth_headers:
        note = (
            "No Authentication-Results header found. This can mean the "
            "receiving server didn't check authentication, or the header "
            "was stripped."
        )
        logger.warning("No Authentication-Results header found in message.")

    return AuthVerdict(
        raw=combined,
        source="Authentication-Results header",
        spf=spf,
        spf_details=spf_details,
        dkim=dkim,
        dkim_details=dkim_details,
        dmarc=dmarc,
        dmarc_details=dmarc_details,
        explanation=explanation,
        inconsistencies=inconsistencies,
        note=note,
    )


def _detect_inconsistencies(
    parsed: ParsedMessage,
    auth_headers: List[str],
    spf: str,
    dkim: str,
    dmarc: str,
    mailfrom: Optional[str],
    header_i: Optional[str]
) -> List[str]:
    inconsistencies: List[str] = []
    from_domain = extract_domain(parsed.from_raw)

    # 1. Multiple conflicting Authentication-Results headers
    if len(auth_headers) > 1:
        spfs = [m.group(1).lower() for h in auth_headers for m in [SPF_RE.search(h)] if m]
        if len(set(spfs)) > 1:
            inconsistencies.append(f"Conflicting SPF verdicts across multiple headers: {spfs}")

        dkims = [m.group(1).lower() for h in auth_headers for m in [DKIM_RE.search(h)] if m]
        if len(set(dkims)) > 1:
            inconsistencies.append(f"Conflicting DKIM verdicts across multiple headers: {dkims}")

    # 2. SPF Pass but DMARC Fail (SPF Alignment Failure)
    if spf == "pass" and dmarc == "fail":
        mailfrom_domain = extract_domain(mailfrom) if mailfrom and "@" in mailfrom else (mailfrom.lower() if mailfrom else None)
        if mailfrom_domain and from_domain and mailfrom_domain != from_domain:
            inconsistencies.append(
                f"SPF Alignment Failure: Envelope MAIL FROM domain '{mailfrom_domain}' "
                f"passed SPF, but does not align with header From domain '{from_domain}'."
            )
        else:
            inconsistencies.append("DMARC failed despite SPF passing (domain alignment mismatch).")

    # 3. DKIM Pass but Domain Misalignment
    if dkim == "pass" and from_domain:
        header_i_domain = extract_domain(header_i) if header_i and "@" in header_i else (header_i.lower() if header_i else None)
        if header_i_domain and header_i_domain != from_domain:
            inconsistencies.append(
                f"DKIM Alignment Warning: DKIM signature passed for domain '{header_i_domain}', "
                f"which differs from header From domain '{from_domain}'."
            )

    # 4. Total authentication failure
    if spf in {"fail", "softfail"} and dkim in {"fail", "none"} and dmarc == "fail":
        inconsistencies.append("Complete Authentication Failure: Both SPF and DKIM failed, violating DMARC policy.")

    return inconsistencies


def _generate_explanation(spf: str, dkim: str, dmarc: str, inconsistencies: List[str]) -> str:
    parts = []

    # SPF explanation
    if spf == "pass":
        parts.append("SPF: PASS (Sending server IP is authorized by the domain's SPF record).")
    elif spf in {"fail", "softfail"}:
        parts.append(f"SPF: {spf.upper()} (Sending server IP is NOT authorized to send mail on behalf of the domain).")
    elif spf == "none":
        parts.append("SPF: NONE (No SPF record found for sending domain).")

    # DKIM explanation
    if dkim == "pass":
        parts.append("DKIM: PASS (Cryptographic signature is valid and email content was unaltered in transit).")
    elif dkim == "fail":
        parts.append("DKIM: FAIL (Cryptographic signature failed or body/headers were modified).")
    elif dkim == "none":
        parts.append("DKIM: NONE (Message was not signed with a DKIM signature).")

    # DMARC explanation
    if dmarc == "pass":
        parts.append("DMARC: PASS (Message satisfies DMARC policy requirements and domain alignment).")
    elif dmarc == "fail":
        parts.append("DMARC: FAIL (Message failed alignment or authentication, violating domain policy).")

    if inconsistencies:
        parts.append("ANOMALIES DETECTED: " + " ".join(inconsistencies))

    return " ".join(parts) if parts else "No authentication headers available to explain."


def live_reverify(parsed: ParsedMessage) -> Optional[AuthVerdict]:
    """Optional live SPF/DKIM/DMARC check via DNS (Disabled in offline mode)."""
    return None



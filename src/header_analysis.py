"""Header Forensics Analysis Engine.

Performs offline structural, syntactic, and semantic forensic checks on email headers
to detect spoofing, header injection, anomalies, and mailer artifacts.
"""

import re
from typing import List, Optional
from email.utils import parsedate_to_datetime

from models import ParsedMessage, HeaderFinding, HeaderAnalysisVerdict
from utils import (
    extract_address,
    extract_domain,
    extract_display_name,
    looks_like_lookalike,
    registrable_domain,
    domain_relationship,
    is_legitimate_esp,
    same_organization,
    KNOWN_BRAND_DOMAINS,
    HIGH_RISK_TLDS,
)
from logger import get_logger

logger = get_logger(__name__)

# Known automated script/spam mailers
SUSPICIOUS_MAILERS = [
    "phpmailer", "python-urllib", "go-http-client", "darkmailer",
    "massmail", "anonymouse", "libwww", "curl", "sendgrid-php",
    "custom-script", "smtp-client"
]


def analyze_headers(parsed: ParsedMessage) -> HeaderAnalysisVerdict:
    logger.debug("Executing offline Header Forensics Analysis.")
    findings: List[HeaderFinding] = []

    _check_display_name_spoofing(parsed, findings)
    _check_from_vs_sender(parsed, findings)
    _check_from_vs_reply_to(parsed, findings)
    _check_from_vs_return_path(parsed, findings)
    _check_message_id_presence(parsed, findings)
    _check_message_id_format(parsed, findings)
    _check_duplicate_message_id(parsed, findings)
    _check_suspicious_x_headers(parsed, findings)
    _check_forged_auth_results(parsed, findings)
    _check_header_anomalies(parsed, findings)
    _check_missing_mandatory_headers(parsed, findings)
    _check_suspicious_sender_domain(parsed, findings)

    return HeaderAnalysisVerdict(findings=findings)


def _check_display_name_spoofing(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    display_name = extract_display_name(parsed.from_raw)
    from_addr = extract_address(parsed.from_raw)
    from_domain = extract_domain(parsed.from_raw)

    if not display_name or not from_addr or not from_domain:
        return

    display_name_lc = display_name.lower()

    # 1. Display name contains an embedded email address mismatching actual address
    embedded_email_match = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", display_name)
    if embedded_email_match:
        embedded_email = embedded_email_match.group(0).lower()
        if embedded_email != from_addr:
            findings.append(HeaderFinding(
                title="Display Name Email Spoofing",
                description="The display name contains an embedded email address that differs from the actual envelope From address.",
                risk_level="High",
                evidence=f"Display Name: '{display_name}' | Envelope From: '{from_addr}'",
                recommendation="Treat message as high-risk impersonation attempting to deceive human readers."
            ))
            return

    # 2. Display name references a well-known brand, but sending domain is unassociated
    for brand_domain in KNOWN_BRAND_DOMAINS:
        brand = brand_domain.split(".")[0]
        if brand in display_name_lc and brand not in from_domain:
            findings.append(HeaderFinding(
                title="Display Name Brand Impersonation",
                description=f"The display name references brand '{brand}', but the actual sending domain is '{from_domain}'.",
                risk_level="High",
                evidence=f"Display Name: '{display_name}' | Sending Domain: '{from_domain}'",
                recommendation="Verify sender identity out-of-band; domain does not belong to the referenced brand."
            ))
            break


def _check_from_vs_sender(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    if not parsed.sender_raw:
        return

    from_addr = extract_address(parsed.from_raw)
    sender_addr = extract_address(parsed.sender_raw)
    from_domain = extract_domain(parsed.from_raw)
    sender_domain = extract_domain(parsed.sender_raw)

    if not (from_addr and sender_addr and from_addr != sender_addr):
        return

    relation = domain_relationship(from_domain or "", sender_domain or "")
    if relation in ("same_org", "trusted_esp") or (
        sender_domain and is_legitimate_esp(sender_domain)
    ) or (from_domain and sender_domain and same_organization(from_domain, sender_domain)):
        findings.append(HeaderFinding(
            title="From vs. Sender Delegate",
            description="The message was transmitted by the same organisation or a recognized mail/CRM provider.",
            risk_level="Low",
            evidence=f"From: '{from_addr}' | Delegate Sender: '{sender_addr}'",
            recommendation="Normal transactional mail delegation. Verify SPF/DKIM authentication."
        ))
        return

    if relation == "suspicious":
        findings.append(HeaderFinding(
            title="From vs. Sender Mismatch",
            description="The Sender domain shows deception indicators relative to the From identity (free-mail diversion, high-risk TLD, or lookalike).",
            risk_level="High",
            evidence=f"From: '{from_addr}' | Sender: '{sender_addr}'",
            recommendation="Treat as high-risk; verify the transmitting domain out-of-band."
        ))
        return

    # Different organisation without clear deception — weak informational only.
    findings.append(HeaderFinding(
        title="From vs. Sender Domain Difference",
        description="Author and transmitter domains differ. This is common with mailing platforms but warrants a glance at SPF/DKIM alignment.",
        risk_level="Low",
        evidence=f"From: '{from_addr}' | Sender: '{sender_addr}'",
        recommendation="Confirm the Sender is an authorized mailing delegate for the From domain."
    ))


def _check_from_vs_reply_to(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    if not parsed.reply_to_raw:
        return

    from_addr = extract_address(parsed.from_raw)
    reply_to_addr = extract_address(parsed.reply_to_raw)
    from_domain = extract_domain(parsed.from_raw)
    reply_to_domain = extract_domain(parsed.reply_to_raw)

    if not (from_addr and reply_to_addr and from_addr != reply_to_addr):
        return

    # Same address local-part difference on the same host, or same org /
    # trusted ESP / helpdesk — legitimate operational pattern. No risk bump.
    relation = domain_relationship(from_domain or "", reply_to_domain or "")
    if relation in ("same_org", "trusted_esp"):
        return

    if relation == "suspicious":
        findings.append(HeaderFinding(
            title="Suspicious Reply-To Destination",
            description=(
                "Replies are diverted to a destination with strong deception indicators "
                "(consumer free-mail, high-risk TLD, or lookalike domain) relative to the From identity."
            ),
            risk_level="High",
            evidence=f"From: '{from_addr}' | Reply-To: '{reply_to_addr}'",
            recommendation="Do not reply; verify the intended contact channel through a known official source."
        ))
        return

    # Unrelated organisational domains without free-mail / TLD / lookalike evidence.
    # Different ≠ suspicious: keep as a weak Medium for BEC review, not High.
    findings.append(HeaderFinding(
        title="From vs. Reply-To Domain Difference",
        description=(
            "Reply-To points to a different organisation than From. This can be legitimate "
            "(partners, ticketing) or reply diversion — treat as context, not proof of phishing."
        ),
        risk_level="Medium",
        evidence=f"From: '{from_addr}' | Reply-To: '{reply_to_addr}'",
        recommendation="Confirm the Reply-To recipient through an independent channel before responding."
    ))


def _check_from_vs_return_path(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    if not parsed.return_path_raw:
        return

    from_domain = extract_domain(parsed.from_raw)
    return_path_domain = extract_domain(parsed.return_path_raw)

    if not (from_domain and return_path_domain and from_domain != return_path_domain):
        return

    relation = domain_relationship(from_domain, return_path_domain)
    if relation in ("same_org", "trusted_esp") or is_legitimate_esp(return_path_domain):
        findings.append(HeaderFinding(
            title="From vs. Return-Path ESP Bounce Domain",
            description="Return-Path points to the same organisation or an authorized ESP bounce domain.",
            risk_level="Low",
            evidence=f"From Domain: '{from_domain}' | Return-Path Domain: '{return_path_domain}'",
            recommendation="Standard bounce processing. Verify DKIM/DMARC alignment."
        ))
        return

    if relation == "suspicious":
        findings.append(HeaderFinding(
            title="From vs. Return-Path Domain Mismatch",
            description="Envelope bounce domain shows deception indicators relative to the From domain.",
            risk_level="High",
            evidence=f"From Domain: '{from_domain}' | Return-Path Domain: '{return_path_domain}'",
            recommendation="Verify SPF/DMARC; bounce domain may be attacker-controlled."
        ))
        return

    findings.append(HeaderFinding(
        title="From vs. Return-Path Domain Difference",
        description="Return-Path domain differs from From without clear ESP or same-org alignment.",
        risk_level="Low",
        evidence=f"From Domain: '{from_domain}' | Return-Path Domain: '{return_path_domain}'",
        recommendation="Check DMARC alignment; third-party bounce handling is often legitimate."
    ))



def _check_message_id_presence(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    if not parsed.message_id or not parsed.message_id.strip():
        findings.append(HeaderFinding(
            title="Missing Message-ID Header",
            description="The mandatory Message-ID header is missing from the message.",
            risk_level="Medium",
            evidence="Message-ID header absent.",
            recommendation="Legitimate MTAs automatically generate a Message-ID. Absence suggests custom spam tools."
        ))


def _check_message_id_format(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    msg_id = parsed.message_id.strip()
    if not msg_id:
        return

    reasons = []
    if not (msg_id.startswith("<") and msg_id.endswith(">")):
        reasons.append("Missing outer angle brackets '<...>'")

    clean_id = msg_id.strip("<>")
    if "@" not in clean_id:
        reasons.append("Missing '@' separator in Message-ID payload")
    else:
        domain_part = clean_id.split("@", 1)[1].lower()
        if domain_part in {"localhost", "localdomain", "127.0.0.1"} or domain_part.startswith("192.168."):
            reasons.append(f"Generic or local host domain '{domain_part}'")
        elif "." not in domain_part:
            reasons.append(f"Non-fully qualified domain name (non-FQDN) '{domain_part}'")

    if reasons:
        findings.append(HeaderFinding(
            title="Suspicious Message-ID Format",
            description="The Message-ID header violates RFC 5322 structural syntax standards.",
            risk_level="Medium",
            evidence=f"Message-ID: '{msg_id}' | Anomalies: {'; '.join(reasons)}",
            recommendation="Inspect email headers for automated mass-mailers or custom script generation."
        ))


def _check_duplicate_message_id(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    raw_msg_ids = parsed.headers.get("Message-ID")
    if isinstance(raw_msg_ids, list) and len(raw_msg_ids) > 1:
        findings.append(HeaderFinding(
            title="Duplicate Message-ID Headers Detected",
            description="Multiple Message-ID header lines were detected in a single email.",
            risk_level="High",
            evidence=f"Found {len(raw_msg_ids)} Message-ID headers: {raw_msg_ids}",
            recommendation="Investigate for header injection attacks or mail transfer agent tampering."
        ))


def _check_suspicious_x_headers(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    flagged: List[str] = []

    for k, v in parsed.headers.items():
        k_lower = k.lower()
        v_str = str(v).lower()

        if k_lower in {"x-php-originating-script", "x-php-script"}:
            flagged.append(f"{k}: {v}")
        elif k_lower in {"x-spam-flag", "x-spam-status"} and "yes" in v_str:
            flagged.append(f"{k}: {v}")
        elif k_lower in {"x-mailer", "user-agent", "x-user-agent"}:
            for mailer in SUSPICIOUS_MAILERS:
                if mailer in v_str:
                    flagged.append(f"{k}: {v}")
                    break

    if flagged:
        findings.append(HeaderFinding(
            title="Suspicious X-Headers Detected",
            description="Detected non-standard X-headers associated with automated scripts, spam flags, or suspicious mailers.",
            risk_level="Medium",
            evidence="; ".join(flagged),
            recommendation="Audit sending software and user-agent details for potential automated spam or attack tools."
        ))


AUTHSERV_ID_RE = re.compile(r"^\s*([A-Za-z0-9_.:\[\]-]+)\s*;")
RECEIVED_BY_RE = re.compile(r"\bby\s+([A-Za-z0-9._-]+)", re.IGNORECASE)


def _received_by_hosts(parsed: ParsedMessage) -> set[str]:
    """Hostnames that claimed to receive the message ('by' clauses)."""
    hosts: set[str] = set()
    for raw in parsed.received_chain or []:
        match = RECEIVED_BY_RE.search(str(raw))
        if match:
            hosts.add(match.group(1).lower().strip("."))
    return hosts


def _check_forged_auth_results(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    auth_results = parsed.authentication_results
    if not auth_results:
        return

    # Check if Authentication-Results header appears multiple times unexpectedly
    if len(auth_results) > 2:
        findings.append(HeaderFinding(
            title="Multiple Authentication-Results Headers",
            description="An unusually high count of Authentication-Results headers was detected.",
            risk_level="Medium",
            evidence=f"Count: {len(auth_results)} headers",
            recommendation="Verify if previous hops or attackers injected false Authentication-Results headers."
        ))

    # An Authentication-Results header is only trustworthy if its authserv-id
    # identifies a host that actually handled the message. Rather than pattern
    # matching MTA brand names (which flagged most legitimate mail), compare the
    # authserv-id against the receiving hops in the Received chain.
    by_hosts = _received_by_hosts(parsed)

    for ar in auth_results:
        ar_str = str(ar).strip()
        if "pass" not in ar_str.lower():
            continue

        match = AUTHSERV_ID_RE.match(ar_str)
        authserv_id = match.group(1).lower().strip(".") if match else ""

        if not authserv_id or "." not in authserv_id:
            findings.append(HeaderFinding(
                title="Authentication-Results Missing Authserv-ID",
                description="The Authentication-Results header claims a PASS but does not identify the verifying host with a fully-qualified authserv-id (RFC 8601).",
                risk_level="Medium",
                evidence=f"Header: '{ar_str[:120]}'",
                recommendation="Cross-examine the Received header chain; an unattributed PASS cannot be trusted."
            ))
            break

        # Without a Received chain there is nothing to corroborate against;
        # the missing chain itself is already reported by routing analysis.
        if not by_hosts:
            break

        aligned = any(
            authserv_id == host
            or host.endswith("." + authserv_id)
            or authserv_id.endswith("." + host)
            or registrable_domain(authserv_id) == registrable_domain(host)
            for host in by_hosts
        )
        if not aligned:
            findings.append(HeaderFinding(
                title="Unattributed Authentication-Results Header",
                description="The Authentication-Results header claims a PASS but its authserv-id does not correspond to any host in the Received chain.",
                risk_level="Medium",
                evidence=f"Authserv-ID: '{authserv_id}' | Received 'by' hosts: {sorted(by_hosts)}",
                recommendation="Verify whether an upstream hop or the sender injected a forged Authentication-Results header."
            ))
            break


def _check_header_anomalies(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    anomalies: List[str] = []

    # 1. Duplicate mandatory single-instance headers (From, Subject, Date)
    for single_header in ["From", "Subject", "Date"]:
        val = parsed.headers.get(single_header)
        if isinstance(val, list):
            anomalies.append(f"Multiple '{single_header}' headers detected ({len(val)} instances)")

    # 2. Control characters / Non-ASCII in header names or critical values
    for k, v in parsed.headers.items():
        if re.search(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", k):
            anomalies.append(f"Control characters detected in header name '{k}'")
            break

    # 3. Invalid Date header formatting
    if parsed.date:
        try:
            parsedate_to_datetime(parsed.date)
        except Exception:
            anomalies.append(f"Unparseable Date header format '{parsed.date}'")

    if anomalies:
        findings.append(HeaderFinding(
            title="Header Structural Anomalies Detected",
            description="Detected structural syntax violations or duplicate single-instance headers.",
            risk_level="High",
            evidence="; ".join(anomalies),
            recommendation="Inspect for header injection attempts or malformed mail client generators."
        ))


def _check_missing_mandatory_headers(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    missing: List[str] = []

    if not parsed.date:
        missing.append("Date")
    if not parsed.from_raw:
        missing.append("From")
    if not parsed.subject:
        missing.append("Subject")
    if not parsed.to_raw and not parsed.cc_raw and not parsed.bcc_raw:
        missing.append("Recipient (To/Cc/Bcc)")

    if missing:
        findings.append(HeaderFinding(
            title="Missing Mandatory Email Headers",
            description=f"Message is missing RFC-compliant mandatory header fields: {', '.join(missing)}.",
            risk_level="Medium",
            evidence=f"Missing: {', '.join(missing)}",
            recommendation="Flag email for suspicious origin; standard clients always populate mandatory headers."
        ))


def _check_suspicious_sender_domain(parsed: ParsedMessage, findings: List[HeaderFinding]) -> None:
    from_domain = extract_domain(parsed.from_raw)
    if not from_domain:
        return

    # 1. Raw IP address in sender domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", from_domain):
        findings.append(HeaderFinding(
            title="Raw IP Address Sender Domain",
            description="The sender email address uses a raw IP address instead of a valid domain name.",
            risk_level="High",
            evidence=f"From Domain: '{from_domain}'",
            recommendation="Block message; legitimate senders use domain names with proper DNS configurations."
        ))
        return

    # 2. High-risk top-level domain
    tld = from_domain.rsplit(".", 1)[-1].lower()
    if tld in HIGH_RISK_TLDS:
        findings.append(HeaderFinding(
            title="High-Risk Top-Level Domain (TLD)",
            description=f"The sender domain uses top-level domain '.{tld}', which is statistically associated with high spam/phishing volume.",
            risk_level="Medium",
            evidence=f"Domain: '{from_domain}' | TLD: '.{tld}'",
            recommendation="Exercise elevated caution when opening attachments or links from this domain."
        ))

    # 3. Lookalike brand domain
    brand = looks_like_lookalike(from_domain)
    if brand:
        findings.append(HeaderFinding(
            title="Lookalike Brand Domain (Typosquatting)",
            description=f"The sender domain '{from_domain}' is a lookalike/typosquatted version of known brand domain '{brand}'.",
            risk_level="High",
            evidence=f"Sender Domain: '{from_domain}' | Target Brand: '{brand}'",
            recommendation="Treat email as an active brand impersonation / phishing attempt."
        ))

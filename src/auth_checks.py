"""Stage 3-4 — Authentication analysis.

Parses Authentication-Results headers offline to extract SPF, DKIM, and DMARC verdicts,
generates human-readable SOC explanations, and detects authentication inconsistencies.

``live_reverify`` additionally re-checks those claims against live DNS and the
message's own DKIM signatures (see :mod:`live_auth`), because an
Authentication-Results header is only ever a claim made by whoever wrote it.
"""

import re
from typing import Optional, List, Tuple
from models import ParsedMessage, AuthVerdict
from utils import extract_domain, registrable_domain
from logger import get_logger

logger = get_logger(__name__)

SPF_RE = re.compile(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)", re.IGNORECASE)
DKIM_RE = re.compile(r"dkim=(pass|fail|neutral|none|policy|temperror|permerror)", re.IGNORECASE)
DMARC_RE = re.compile(r"dmarc=(pass|fail|none)", re.IGNORECASE)

MAILFROM_RE = re.compile(r"smtp\.mailfrom=([^\s;]+)", re.IGNORECASE)
#: The DKIM signing domain is the ``d=`` tag (reported as ``header.d=`` in
#: RFC 8601 results); ``header.i=`` is the finer-grained AUID and only used as a
#: fallback. ``header.from=`` must never be read here — it is the From domain
#: itself, so comparing it against From could never detect a misalignment.
DKIM_SIGNING_DOMAIN_RE = re.compile(r"header\.d=([^\s;]+)", re.IGNORECASE)
DKIM_IDENTITY_RE = re.compile(r"header\.i=([^\s;]+)", re.IGNORECASE)
ACTION_RE = re.compile(r"(?:action|p)=([^\s;]+)", re.IGNORECASE)


def dkim_signing_domain(combined: str) -> Tuple[Optional[str], Optional[str]]:
    """Signing domain claimed by an Authentication-Results header.

    Returns ``(domain, tag)`` where ``tag`` records which tag it came from, so
    evidence strings can stay honest about the source.
    """
    match = DKIM_SIGNING_DOMAIN_RE.search(combined or "")
    if match:
        return match.group(1).strip().rstrip(".").lower(), "header.d"
    match = DKIM_IDENTITY_RE.search(combined or "")
    if match:
        identity = match.group(1).strip().lstrip("@").rstrip(".").lower()
        return (extract_domain(identity) or identity or None), "header.i"
    return None, None


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
    signing_domain, signing_tag = dkim_signing_domain(combined)
    action_match = ACTION_RE.search(combined)

    spf_details = f"smtp.mailfrom={mailfrom_match.group(1)}" if mailfrom_match else ""
    dkim_details = f"{signing_tag}={signing_domain}" if signing_domain else ""
    dmarc_details = f"action={action_match.group(1)}" if action_match else ""

    inconsistencies = _detect_inconsistencies(parsed, auth_headers, spf, dkim, dmarc, mailfrom_match.group(1) if mailfrom_match else None, signing_domain)
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
    dkim_domain: Optional[str]
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
    # Compared under DMARC relaxed alignment: a signature from a subdomain of
    # the From domain (mail.example.com signing for example.com) is legitimate,
    # so only a different organisational domain is worth reporting.
    if dkim == "pass" and from_domain and dkim_domain:
        if not _domains_aligned(dkim_domain, from_domain):
            inconsistencies.append(
                f"DKIM Alignment Warning: DKIM signature passed for signing domain '{dkim_domain}', "
                f"which does not align with header From domain '{from_domain}'."
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


def _domains_aligned(child: Optional[str], parent: Optional[str]) -> bool:
    """DMARC relaxed alignment: equal, or sharing an organisational domain."""
    if not child or not parent:
        return False
    child = child.strip().rstrip(".").lower()
    parent = parent.strip().rstrip(".").lower()
    return child == parent or registrable_domain(child) == registrable_domain(parent)


LIVE_SOURCE_PREFIX = "Live re-verification"

#: Live verdicts strong enough to call a claimed PASS a forgery. Deliberately
#: excludes ``none``/``neutral``: an absent DKIM signature or SPF record can also
#: mean a downstream relay stripped the signature or that the upstream verifier
#: evaluated a different envelope identity, so those only change the verdict
#: rather than adding a spoofing finding.
_CONTRADICTS_A_PASS_CLAIM = {"fail", "softfail"}


def live_reverify(parsed: ParsedMessage) -> Optional[AuthVerdict]:
    """Re-verify SPF, DKIM and DMARC against live DNS and the raw signature.

    Returns an :class:`AuthVerdict` whose live results take precedence over
    anything the Authentication-Results header claimed, so an injected
    ``spf=pass`` cannot survive a live ``fail``. Mechanisms that could not be
    checked (no sending IP, no raw bytes, resolver timeout, optional dependency
    absent) keep their header-derived value.

    Returns ``None`` when live verification is switched off or unavailable, so
    the caller falls back to :func:`analyse_authentication`. This function never
    raises into the pipeline.
    """
    try:
        import live_auth
    except Exception as exc:  # optional dependency chain unavailable
        logger.info(f"Live authentication re-verification unavailable: {exc}")
        return None

    if not live_auth.live_auth_enabled():
        logger.debug("Live authentication re-verification disabled via LIVE_AUTH_ENABLED.")
        return None

    try:
        return _live_reverify(parsed, live_auth)
    except Exception as exc:
        # Analysis must never fail because DNS did. Fall back to headers.
        logger.warning(f"Live authentication re-verification failed, using header-derived results: {exc}")
        return None


def _live_reverify(parsed: ParsedMessage, live_auth) -> AuthVerdict:
    header_verdict = analyse_authentication(parsed)
    from_domain = extract_domain(parsed.from_raw)
    combined = header_verdict.raw

    mailfrom_match = MAILFROM_RE.search(combined)
    envelope = extract_domain(parsed.return_path_raw)
    if not envelope and mailfrom_match:
        claimed = mailfrom_match.group(1).strip("<>")
        envelope = extract_domain(claimed) or claimed.lower() or None
    mailfrom_domain = envelope or from_domain

    client_ip = live_auth.sending_ip(parsed)
    dns_client = live_auth.DnsClient()

    spf_result = None
    if mailfrom_domain and client_ip:
        spf_result = live_auth.evaluate_spf(mailfrom_domain, client_ip, dns_client=dns_client)

    dkim_result = live_auth.verify_dkim(getattr(parsed, "raw_bytes", b"") or b"")

    dmarc_result = None
    if from_domain:
        dmarc_result = live_auth.evaluate_dmarc(
            from_domain,
            spf=spf_result if (spf_result and spf_result.definitive) else None,
            dkim=dkim_result if dkim_result.definitive else None,
            mailfrom_domain=mailfrom_domain,
            dns_client=dns_client,
        )

    checks: List[str] = []
    live_mechanisms: List[str] = []
    spf, spf_details = header_verdict.spf, header_verdict.spf_details
    if spf_result and spf_result.definitive:
        live_mechanisms.append("SPF")
        spf, spf_details = spf_result.verdict, _spf_details(spf_result)
        checks.append(f"SPF: live-verified ({spf}) — {spf_result.detail}")
    else:
        reason = spf_result.detail if spf_result else (
            "no routable sending IP found in the Received chain" if not client_ip
            else "no MAIL FROM domain available"
        )
        checks.append(f"SPF: header-derived ({spf}) — live check unavailable: {reason}")

    dkim, dkim_details = header_verdict.dkim, header_verdict.dkim_details
    dkim_domain = dkim_signing_domain(combined)[0]
    if dkim_result.definitive:
        live_mechanisms.append("DKIM")
        dkim = dkim_result.verdict
        signed = ", ".join(d for d in (dkim_result.passed_domains or dkim_result.signature_domains) if d)
        dkim_details = f"header.d={signed}" if signed else "no DKIM-Signature header"
        if dkim_result.passed_domains:
            dkim_domain = dkim_result.passed_domains[0]
        elif dkim_result.signature_domains:
            dkim_domain = dkim_result.signature_domains[0] or dkim_domain
        checks.append(f"DKIM: live-verified ({dkim}) — {dkim_result.detail}")
    else:
        checks.append(f"DKIM: header-derived ({dkim}) — live check unavailable: {dkim_result.detail}")

    dmarc, dmarc_details = header_verdict.dmarc, header_verdict.dmarc_details
    dmarc_policy = None
    if dmarc_result and dmarc_result.definitive:
        live_mechanisms.append("DMARC")
        dmarc = dmarc_result.verdict
        dmarc_policy = dmarc_result.policy
        dmarc_details = f"p={dmarc_policy}" if dmarc_policy else "no DMARC record published"
        if dmarc_result.record:
            dmarc_details += f" | aligned SPF: {'yes' if dmarc_result.spf_aligned else 'no'}, " \
                             f"aligned DKIM: {'yes' if dmarc_result.dkim_aligned else 'no'}"
        detail = " ".join([dmarc_result.detail, *dmarc_result.notes])
        checks.append(f"DMARC: live-verified ({dmarc}) — {detail}")
    else:
        reason = dmarc_result.detail if dmarc_result else "no header From domain available"
        checks.append(f"DMARC: header-derived ({dmarc}) — live check unavailable: {reason}")

    live_verified = bool(live_mechanisms)

    # Structural and alignment findings are recomputed from the final, live-preferred
    # verdicts rather than inherited from the header pass, so a mechanism the live
    # check overrode cannot leave a stale (or duplicated) finding behind.
    inconsistencies = _detect_inconsistencies(
        parsed, parsed.authentication_results or [], spf, dkim, dmarc, mailfrom_domain, dkim_domain
    )
    inconsistencies.extend(_live_contradictions(header_verdict, spf, dkim, dmarc))
    if dmarc_policy in {"reject", "quarantine"} and dmarc == "fail":
        inconsistencies.append(
            f"DMARC failure under an enforcing policy (p={dmarc_policy}) published by '{from_domain}' — "
            f"a conforming receiver would have {'rejected' if dmarc_policy == 'reject' else 'quarantined'} this message."
        )
    inconsistencies = list(dict.fromkeys(inconsistencies))

    explanation = _generate_explanation(spf, dkim, dmarc, inconsistencies)
    if live_verified:
        explanation = "LIVE RE-VERIFICATION: " + explanation

    note_parts = [
        f"{', '.join(live_mechanisms)} {'was' if len(live_mechanisms) == 1 else 'were'} independently "
        "re-verified against live DNS and the raw message signature, taking precedence over the "
        "Authentication-Results header; any remaining mechanism is header-derived."
        if live_verified else
        "Live re-verification was attempted but no mechanism could be confirmed "
        "(offline, resolver failure, or nothing to check); results below are header-derived.",
    ]
    if client_ip:
        note_parts.append(f"Sending IP evaluated: {client_ip}.")
    if header_verdict.note:
        note_parts.append(header_verdict.note)

    return AuthVerdict(
        raw=combined,
        source=(f"{LIVE_SOURCE_PREFIX} ({'/'.join(live_mechanisms)}) + Authentication-Results header"
                if live_verified else header_verdict.source),
        spf=spf,
        spf_details=spf_details,
        dkim=dkim,
        dkim_details=dkim_details,
        dmarc=dmarc,
        dmarc_details=dmarc_details,
        explanation=explanation,
        inconsistencies=inconsistencies,
        note=" ".join(note_parts),
        live_attempted=True,
        live_verified=live_verified,
        live_checks=checks,
        dmarc_policy=dmarc_policy,
    )


def _spf_details(spf_result) -> str:
    details = f"smtp.mailfrom={spf_result.domain}"
    if spf_result.ip:
        details += f" | sending IP={spf_result.ip}"
    return details


def _live_contradictions(header_verdict: AuthVerdict, spf: str, dkim: str, dmarc: str) -> List[str]:
    """Report every claimed PASS that live verification did not reproduce."""
    findings: List[str] = []
    for mechanism, claimed, live in (
        ("SPF", header_verdict.spf, spf),
        ("DKIM", header_verdict.dkim, dkim),
        ("DMARC", header_verdict.dmarc, dmarc),
    ):
        if claimed == "pass" and live in _CONTRADICTS_A_PASS_CLAIM:
            findings.append(
                f"Forged or stale Authentication-Results: the header claims {mechanism.lower()}=pass, "
                f"but live re-verification returned {mechanism.lower()}={live}."
            )
    return findings





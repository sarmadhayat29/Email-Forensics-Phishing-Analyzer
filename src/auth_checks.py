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
# Include temperror/permerror so they are not silently treated as not_present.
DMARC_RE = re.compile(r"dmarc=(pass|fail|none|temperror|permerror)", re.IGNORECASE)

MAILFROM_RE = re.compile(r"smtp\.mailfrom=([^\s;]+)", re.IGNORECASE)
#: The DKIM signing domain is the ``d=`` tag (reported as ``header.d=`` in
#: RFC 8601 results); ``header.i=`` is the finer-grained AUID and only used as a
#: fallback. ``header.from=`` must never be read here — it is the From domain
#: itself, so comparing it against From could never detect a misalignment.
DKIM_SIGNING_DOMAIN_RE = re.compile(r"header\.d=([^\s;]+)", re.IGNORECASE)
DKIM_IDENTITY_RE = re.compile(r"header\.i=([^\s;]+)", re.IGNORECASE)
# Prefer DMARC policy tags (p=) over the ambiguous bare ``action=``.
DMARC_POLICY_RE = re.compile(r"(?:\bdmarc=[^\s;]*\s+)?(?:\([^\)]*\bp=|\bp=)([a-z]+)", re.IGNORECASE)
AUTHSERV_ID_RE = re.compile(r"^\s*([A-Za-z0-9_.:\[\]-]+)\s*;")
RECEIVED_BY_RE = re.compile(r"\bby\s+([A-Za-z0-9._\-]+)", re.IGNORECASE)
#: IP often quoted inside Authentication-Results SPF commentary.
AR_DESIGNATED_IP_RE = re.compile(
    r"designates\s+(\d{1,3}(?:\.\d{1,3}){3})\s+as\s+permitted\s+sender",
    re.IGNORECASE,
)

#: Header verdicts that represent a real authentication answer (not absence).
_HEADER_DEFINITIVE = {"pass", "fail", "softfail", "neutral", "none", "policy", "permerror"}
_LIVE_HARD_FAIL = {"fail", "softfail"}


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
    policy_match = DMARC_POLICY_RE.search(combined)

    spf_details = f"smtp.mailfrom={mailfrom_match.group(1)}" if mailfrom_match else ""
    dkim_details = f"{signing_tag}={signing_domain}" if signing_domain else ""
    dmarc_details = f"p={policy_match.group(1)}" if policy_match else ""

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
        # Use DMARC relaxed alignment — subdomain bounce addresses are normal.
        if mailfrom_domain and from_domain and not _domains_aligned(mailfrom_domain, from_domain):
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

#: Live verdicts that contradict a claimed PASS strongly enough to record a
#: mismatch finding. Deliberately excludes ``none``/``neutral``: an absent DKIM
#: signature often means a downstream relay stripped it after the border MTA
#: already recorded dkim=pass.
_CONTRADICTS_A_PASS_CLAIM = {"fail", "softfail"}


def _received_by_hosts(parsed: ParsedMessage) -> set:
    hosts = set()
    for raw in parsed.received_chain or []:
        match = RECEIVED_BY_RE.search(str(raw))
        if match:
            hosts.add(match.group(1).lower().strip("."))
    return hosts


def authentication_results_attributed(parsed: ParsedMessage) -> bool:
    """True when at least one Authentication-Results authserv-id matches a Received hop.

    An attributed AR header is the receiving MTA's own verdict (RFC 8601). It
    already evaluated SPF against the real connecting IP — reconstructing that
    IP from Received text is error-prone and must not silently override a
    legitimate PASS.
    """
    auth_headers = parsed.authentication_results or []
    if not auth_headers:
        return False
    by_hosts = _received_by_hosts(parsed)
    if not by_hosts:
        # No Received chain to corroborate against — treat as unattributed so
        # live checks (when available) can still challenge bare claims.
        return False

    for ar in auth_headers:
        ar_str = str(ar).strip()
        match = AUTHSERV_ID_RE.match(ar_str)
        if not match:
            continue
        authserv_id = match.group(1).lower().strip(".")
        if "." not in authserv_id:
            continue
        aligned = any(
            authserv_id == host
            or host.endswith("." + authserv_id)
            or authserv_id.endswith("." + host)
            or registrable_domain(authserv_id) == registrable_domain(host)
            for host in by_hosts
        )
        if aligned:
            return True
    return False


def designated_sending_ip_from_ar(auth_headers: List[str]) -> Optional[str]:
    """Extract the IP the border MTA said it SPF-checked, when present in commentary."""
    combined = " ".join(auth_headers or [])
    match = AR_DESIGNATED_IP_RE.search(combined)
    return match.group(1) if match else None


def live_reverify(parsed: ParsedMessage) -> Optional[AuthVerdict]:
    """Re-verify SPF, DKIM and DMARC against live DNS and the raw signature.

    Live checks *corroborate* Authentication-Results; they do not blindly replace
    an attributed border-MTA PASS. Unattributed or missing AR headers still yield
    to definitive live results so injected ``spf=pass`` claims cannot survive.

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


def _merge_mechanism(
    mechanism: str,
    header_verdict: str,
    live_verdict: Optional[str],
    live_definitive: bool,
    ar_attributed: bool,
    *,
    prefer_live_crypto_fail: bool = False,
) -> Tuple[str, str, Optional[str]]:
    """Decide the scored verdict for one mechanism.

    Returns ``(final_verdict, provenance, mismatch_note_or_None)``.
    """
    header = (header_verdict or "not_present").lower()
    live = (live_verdict or "").lower() if live_verdict else ""

    if not live_definitive or not live:
        return header, "header-derived", None

    # Cryptographic DKIM failure on a present signature is strong evidence the
    # body/headers changed — always prefer live fail over a claimed pass.
    if prefer_live_crypto_fail and live == "fail":
        note = None
        if header == "pass":
            note = (
                f"Verification mismatch: Authentication-Results claims {mechanism}=pass, "
                f"but live cryptographic verification returned {mechanism}=fail."
            )
        return live, "live-verified", note

    # Attributed AR from the receiving MTA is authoritative for scoring.
    if ar_attributed and header in _HEADER_DEFINITIVE:
        if header == live:
            return live, "live-confirmed", None
        if header == "pass" and live in _LIVE_HARD_FAIL:
            return header, "header-authoritative", (
                f"Verification mismatch: Authentication-Results claims {mechanism}=pass, "
                f"but live re-verification returned {mechanism}={live}. "
                f"The attributed header result is retained because reconstructing the "
                f"connecting IP from Received headers is unreliable."
            )
        if header == "pass" and live in {"none", "neutral", "permerror"}:
            # e.g. DKIM stripped after the border MTA recorded pass.
            return header, "header-authoritative", (
                f"Verification mismatch: Authentication-Results claims {mechanism}=pass, "
                f"but live re-verification returned {mechanism}={live}. "
                f"The attributed header result is retained."
            )
        if live == "pass" and header in _LIVE_HARD_FAIL:
            # Live cleared a header failure — prefer the independent pass.
            return live, "live-verified", None
        # Other disagreements: keep attributed header, note the mismatch.
        if header != live:
            return header, "header-authoritative", (
                f"Verification mismatch: Authentication-Results has {mechanism}={header}, "
                f"live re-verification returned {mechanism}={live}. "
                f"The attributed header result is retained."
            )
        return header, "header-authoritative", None

    # Unattributed / missing AR — live definitive results take precedence.
    note = None
    if header == "pass" and live in _CONTRADICTS_A_PASS_CLAIM:
        note = (
            f"Verification mismatch: unattributed Authentication-Results claims "
            f"{mechanism}=pass, but live re-verification returned {mechanism}={live}."
        )
    return live, "live-verified", note


def _live_reverify(parsed: ParsedMessage, live_auth) -> AuthVerdict:
    header_verdict = analyse_authentication(parsed)
    from_domain = extract_domain(parsed.from_raw)
    combined = header_verdict.raw
    ar_attributed = authentication_results_attributed(parsed)

    mailfrom_match = MAILFROM_RE.search(combined)
    # Prefer smtp.mailfrom from AR (what the MTA checked), then Return-Path, then From.
    envelope = None
    if mailfrom_match:
        claimed = mailfrom_match.group(1).strip("<>")
        envelope = extract_domain(claimed) or claimed.lower() or None
    if not envelope:
        envelope = extract_domain(parsed.return_path_raw)
    mailfrom_domain = envelope or from_domain

    # Prefer the IP the border MTA documented in AR commentary, then Received.
    client_ip = designated_sending_ip_from_ar(parsed.authentication_results or [])
    if not client_ip:
        client_ip = live_auth.sending_ip(parsed)
    dns_client = live_auth.DnsClient()

    logger.info(
        "Auth live-reverify start: from=%s mailfrom=%s ip=%s ar_attributed=%s "
        "header(spf=%s dkim=%s dmarc=%s)",
        from_domain, mailfrom_domain, client_ip, ar_attributed,
        header_verdict.spf, header_verdict.dkim, header_verdict.dmarc,
    )

    spf_result = None
    if mailfrom_domain and client_ip:
        spf_result = live_auth.evaluate_spf(mailfrom_domain, client_ip, dns_client=dns_client)
        logger.info(
            "Auth SPF live: domain=%s ip=%s verdict=%s definitive=%s detail=%s",
            mailfrom_domain, client_ip,
            getattr(spf_result, "verdict", None),
            bool(spf_result and spf_result.definitive),
            getattr(spf_result, "detail", ""),
        )
    else:
        logger.info(
            "Auth SPF live skipped: mailfrom=%s ip=%s", mailfrom_domain, client_ip,
        )

    raw_bytes = getattr(parsed, "raw_bytes", b"") or b""
    dkim_result = live_auth.verify_dkim(raw_bytes)
    logger.info(
        "Auth DKIM live: verdict=%s definitive=%s signatures=%s passed=%s detail=%s",
        dkim_result.verdict, dkim_result.definitive,
        dkim_result.signature_domains, dkim_result.passed_domains, dkim_result.detail,
    )

    # Feed DMARC only with live results we will actually trust for scoring, so a
    # speculative SPF fail cannot manufacture a DMARC fail while SPF stays PASS.
    spf_for_dmarc = None
    dkim_for_dmarc = None
    if spf_result and spf_result.definitive:
        # Preview merge for SPF to decide what DMARC should see.
        preview_spf, _, _ = _merge_mechanism(
            "spf", header_verdict.spf, spf_result.verdict, True, ar_attributed,
        )
        if preview_spf == spf_result.verdict:
            spf_for_dmarc = spf_result
        elif preview_spf == "pass":
            spf_for_dmarc = live_auth.SpfResult(
                verdict="pass", detail="header-authoritative PASS retained for DMARC alignment",
                domain=mailfrom_domain or "", ip=client_ip or "",
            )
    if dkim_result.definitive:
        has_signatures = bool(dkim_result.signature_domains)
        preview_dkim, _, _ = _merge_mechanism(
            "dkim", header_verdict.dkim, dkim_result.verdict, True, ar_attributed,
            prefer_live_crypto_fail=has_signatures and dkim_result.verdict == "fail",
        )
        if preview_dkim == dkim_result.verdict:
            dkim_for_dmarc = dkim_result
        elif preview_dkim == "pass":
            dkim_for_dmarc = live_auth.DkimResult(
                verdict="pass",
                detail="header-authoritative PASS retained for DMARC alignment",
                signature_domains=dkim_result.signature_domains,
                passed_domains=dkim_result.passed_domains or dkim_result.signature_domains,
            )

    dmarc_result = None
    if from_domain:
        dmarc_result = live_auth.evaluate_dmarc(
            from_domain,
            spf=spf_for_dmarc,
            dkim=dkim_for_dmarc,
            mailfrom_domain=mailfrom_domain,
            dns_client=dns_client,
        )
        logger.info(
            "Auth DMARC live: verdict=%s policy=%s definitive=%s spf_aligned=%s dkim_aligned=%s detail=%s",
            getattr(dmarc_result, "verdict", None),
            getattr(dmarc_result, "policy", None),
            bool(dmarc_result and dmarc_result.definitive),
            getattr(dmarc_result, "spf_aligned", False),
            getattr(dmarc_result, "dkim_aligned", False),
            getattr(dmarc_result, "detail", ""),
        )

    checks: List[str] = []
    live_mechanisms: List[str] = []
    mismatch_notes: List[str] = []

    # --- SPF ---
    spf, spf_details = header_verdict.spf, header_verdict.spf_details
    if spf_result and spf_result.definitive:
        spf, provenance, note = _merge_mechanism(
            "spf", header_verdict.spf, spf_result.verdict, True, ar_attributed,
        )
        spf_details = _spf_details(spf_result) if provenance.startswith("live") else (
            header_verdict.spf_details or _spf_details(spf_result)
        )
        if provenance.startswith("live"):
            live_mechanisms.append("SPF")
        checks.append(f"SPF: {provenance} ({spf}) — live={spf_result.verdict}; {spf_result.detail}")
        if note:
            mismatch_notes.append(note)
    else:
        reason = spf_result.detail if spf_result else (
            "no routable sending IP found in the Received chain" if not client_ip
            else "no MAIL FROM domain available"
        )
        checks.append(f"SPF: header-derived ({spf}) — live check unavailable: {reason}")

    # --- DKIM ---
    dkim, dkim_details = header_verdict.dkim, header_verdict.dkim_details
    dkim_domain = dkim_signing_domain(combined)[0]
    has_signatures = bool(getattr(dkim_result, "signature_domains", None))
    if dkim_result.definitive:
        dkim, provenance, note = _merge_mechanism(
            "dkim", header_verdict.dkim, dkim_result.verdict, True, ar_attributed,
            prefer_live_crypto_fail=has_signatures and dkim_result.verdict == "fail",
        )
        signed = ", ".join(
            d for d in (dkim_result.passed_domains or dkim_result.signature_domains) if d
        )
        if provenance.startswith("live"):
            live_mechanisms.append("DKIM")
            dkim_details = f"header.d={signed}" if signed else "no DKIM-Signature header"
            if dkim_result.passed_domains:
                dkim_domain = dkim_result.passed_domains[0]
            elif dkim_result.signature_domains:
                dkim_domain = dkim_result.signature_domains[0] or dkim_domain
        checks.append(f"DKIM: {provenance} ({dkim}) — live={dkim_result.verdict}; {dkim_result.detail}")
        if note:
            mismatch_notes.append(note)
    else:
        checks.append(f"DKIM: header-derived ({dkim}) — live check unavailable: {dkim_result.detail}")

    # --- DMARC ---
    dmarc, dmarc_details = header_verdict.dmarc, header_verdict.dmarc_details
    dmarc_policy = None
    if dmarc_result and dmarc_result.definitive:
        dmarc, provenance, note = _merge_mechanism(
            "dmarc", header_verdict.dmarc, dmarc_result.verdict, True, ar_attributed,
        )
        dmarc_policy = dmarc_result.policy
        if provenance.startswith("live"):
            live_mechanisms.append("DMARC")
            dmarc_details = f"p={dmarc_policy}" if dmarc_policy else "no DMARC record published"
            if dmarc_result.record:
                dmarc_details += (
                    f" | aligned SPF: {'yes' if dmarc_result.spf_aligned else 'no'}, "
                    f"aligned DKIM: {'yes' if dmarc_result.dkim_aligned else 'no'}"
                )
        detail = " ".join([dmarc_result.detail, *dmarc_result.notes])
        checks.append(f"DMARC: {provenance} ({dmarc}) — live={dmarc_result.verdict}; {detail}")
        if note:
            mismatch_notes.append(note)
    else:
        reason = dmarc_result.detail if dmarc_result else "no header From domain available"
        checks.append(f"DMARC: header-derived ({dmarc}) — live check unavailable: {reason}")

    live_verified = bool(live_mechanisms)

    logger.info(
        "Auth final verdict: spf=%s dkim=%s dmarc=%s live_mechanisms=%s mismatches=%d",
        spf, dkim, dmarc, live_mechanisms, len(mismatch_notes),
    )

    inconsistencies = _detect_inconsistencies(
        parsed, parsed.authentication_results or [], spf, dkim, dmarc, mailfrom_domain, dkim_domain
    )
    inconsistencies.extend(mismatch_notes)
    # Enforcing-policy note only when the *scored* DMARC verdict is fail.
    if dmarc_policy in {"reject", "quarantine"} and dmarc == "fail":
        inconsistencies.append(
            f"DMARC failure under an enforcing policy (p={dmarc_policy}) published by '{from_domain}' — "
            f"a conforming receiver would have {'rejected' if dmarc_policy == 'reject' else 'quarantined'} this message."
        )
    inconsistencies = list(dict.fromkeys(inconsistencies))

    explanation = _generate_explanation(spf, dkim, dmarc, inconsistencies)
    if live_verified or any("live-confirmed" in c or "header-authoritative" in c for c in checks):
        explanation = "LIVE RE-VERIFICATION: " + explanation

    note_parts = []
    if ar_attributed:
        note_parts.append(
            "Authentication-Results authserv-id aligns with the Received chain; "
            "attributed header verdicts are authoritative for scoring when they conflict "
            "with reconstructed live checks."
        )
    if live_mechanisms:
        note_parts.append(
            f"{', '.join(live_mechanisms)} "
            f"{'was' if len(live_mechanisms) == 1 else 'were'} independently "
            "re-verified and used for scoring."
        )
    elif any("live-confirmed" in c or "header-authoritative" in c for c in checks):
        note_parts.append(
            "Live re-verification ran; attributed Authentication-Results were retained where they disagreed."
        )
    else:
        note_parts.append(
            "Live re-verification was attempted but no mechanism could be confirmed "
            "(offline, resolver failure, or nothing to check); results below are header-derived."
        )
    if client_ip:
        note_parts.append(f"Sending IP evaluated: {client_ip}.")
    if header_verdict.note:
        note_parts.append(header_verdict.note)

    source = header_verdict.source
    if live_mechanisms:
        source = f"{LIVE_SOURCE_PREFIX} ({'/'.join(live_mechanisms)}) + Authentication-Results header"
    elif ar_attributed and any("header-authoritative" in c for c in checks):
        source = "Attributed Authentication-Results (live-corroborated)"

    return AuthVerdict(
        raw=combined,
        source=source,
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

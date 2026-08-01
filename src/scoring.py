"""Stage 6 — Phishing Indicator Scoring Engine.

Evaluates email messages across 15 distinct threat categories and outputs
transparent, weighted risk signals with evidence for SOC analysts.
"""

import re
from typing import Optional, List
from models import (
    ParsedMessage, AuthVerdict, RoutingVerdict, PhishingSignal, ScoringVerdict,
    HeaderAnalysisVerdict, URLAnalysisVerdict, DomainAgeFinding, HtmlFinding,
)
from html_analysis import (
    ACTIVE_CONTENT, COMMENT_OBFUSCATION, CREDENTIAL_FORM, DATA_URI_HTML, DATA_URI_OTHER,
    ENTITY_OBFUSCATION, EVENT_HANDLER, FORM_CREDENTIAL_FIELDS, FORM_EXTERNAL_ACTION,
    HIDDEN_TEXT, IFRAME, IMAGE_ONLY_BODY, JAVASCRIPT_URI, META_REFRESH, SCRIPT,
)
from utils import (
    extract_domain, extract_address, extract_display_name,
    looks_like_lookalike, is_punycode_or_unicode,
    detect_redirect_param, has_double_extension, RISKY_EXTENSIONS,
    KNOWN_BRAND_DOMAINS, build_match_text, normalize_text,
    HIGH_RISK_TLDS,
)
from logger import get_logger

logger = get_logger(__name__)

# Pattern matcher sets
CREDENTIAL_PATTERNS = [
    r"\bconfirm\s+(?:your\s+)?password\b", r"\bverify\s+(?:your\s+)?account\b",
    r"\blogin\s+to\s+(?:restore|verify|update)\b", r"\bupdate\s+billing\b",
    r"\baccount\s+suspended\b", r"\bsecurity\s+checkpoint\b", r"\benter\s+credentials\b"
]

URGENCY_PATTERNS = [
    r"\bimmediate\s+action\s+required\b", r"\bwithin\s+24\s+hours\b",
    r"\baccount\s+will\s+be\s+(?:closed|terminated|suspended)\b",
    r"\burgent\s+notice\b", r"\brespond\s+immediately\b", r"\bfinal\s+warning\b"
]

FINANCIAL_PATTERNS = [
    r"\bwire\s+transfer\b", r"\bbitcoin\b", r"\bcrypto\s+payment\b",
    r"\bgift\s+card\b", r"\boverdue\s+payment\b", r"\bpayment\s+confirmation\b",
    r"\bbank\s+deposit\b", r"\btransfer\s+funds\b"
]

INVOICE_PATTERNS = [
    r"\binvoice\s*#?\s*\d+\b", r"\bpurchase\s+order\s*#?\s*\d+\b",
    r"\bremittance\s+advice\b", r"\breceipt\s+for\s+your\s+payment\b",
    r"\battached\s+invoice\b", r"\bpayment\s+due\b"
]

PASSWORD_RESET_PATTERNS = [
    r"\bpassword\s+expired\b", r"\breset\s+password\b",
    r"\bunauthorized\s+login\s+attempt\b", r"\bsecurity\s+alert:\s+password\b",
    r"\bpassword\s+change\s+request\b"
]

# Buckets are evaluated against the 0-100 display score.
RISK_BUCKETS = [
    (0, 29, "Low"),
    (30, 69, "Medium"),
    (70, 89, "High"),
    (90, 10**9, "Critical"),
]

# Anchors of the raw -> display mapping. Below RAW_LINEAR_CEILING the mapping is
# the identity, which keeps the historical Low/Medium/High cut-offs (30 and 70)
# meaningful and leaves existing behaviour untouched for ordinary messages.
RAW_LINEAR_CEILING = 70
RAW_COMPRESSED_CEILING = 150
DISPLAY_COMPRESSED_CEILING = 90


def to_display_score(raw_score: int) -> int:
    """Map an unbounded raw weight total onto a 0-100 presentation scale.

    The mapping is monotone, so ranking between messages is preserved:

    * ``0 - 70``    identity, so the Low (<30) and Medium (<70) cut-offs hold
    * ``70 - 150``  compressed 4:1 into the 70-90 High band
    * ``> 150``     approaches but never reaches 100, so a genuinely worse
                    message always outranks a merely very bad one
    """
    raw = max(0, int(raw_score))
    if raw <= RAW_LINEAR_CEILING:
        return raw

    if raw <= RAW_COMPRESSED_CEILING:
        span_raw = RAW_COMPRESSED_CEILING - RAW_LINEAR_CEILING
        span_display = DISPLAY_COMPRESSED_CEILING - RAW_LINEAR_CEILING
        return int(round(RAW_LINEAR_CEILING + (raw - RAW_LINEAR_CEILING) * span_display / span_raw))

    # Asymptotic tail: 150 -> 90, 300 -> 95, 1500 -> 99, never 100.
    tail = 10 * (1 - RAW_COMPRESSED_CEILING / raw)
    return min(99, int(round(DISPLAY_COMPRESSED_CEILING + tail)))


# Signals are grouped into independent evidence families so that, for example,
# three authentication signals count as one line of evidence rather than three.
# Evaluated in order; the first matching family wins.
SIGNAL_FAMILIES = [
    # Must precede the families below: an HTML indicator may mention a form or
    # a redirect but belongs to body forensics, not to those families.
    ("html body forensics", ("html forensics",)),
    ("header forensics", ("header forensics",)),
    ("routing forensics", ("routing forensics",)),
    ("attachment forensics", ("attachment",)),
    ("authentication", ("spf", "dkim", "dmarc", "authentication")),
    # Must precede "link forensics": a linked-domain age indicator says "link"
    # but belongs to the reputation family, not to link analysis.
    ("domain reputation", ("domain reputation",)),
    ("link forensics", ("link", "hyperlink", "redirect", "shortener")),
    ("sender identity", ("display name", "lookalike", "typosquat", "top-level domain",
                         "punycode", "mismatched sender")),
]
DEFAULT_SIGNAL_FAMILY = "message content"


def _signal_family(indicator: str) -> str:
    indicator_lc = (indicator or "").lower()
    for family, needles in SIGNAL_FAMILIES:
        if any(needle in indicator_lc for needle in needles):
            return family
    return DEFAULT_SIGNAL_FAMILY


CONFIDENCE_LABELS = [
    (85, "Very High Confidence"),
    (70, "High Confidence"),
    (55, "Moderate Confidence"),
    (0, "Low Confidence"),
]

# An offline-only engine should never claim certainty, so confidence is bounded.
CONFIDENCE_FLOOR = 30
CONFIDENCE_CEILING = 90


def assess_confidence(
    parsed: ParsedMessage,
    auth: AuthVerdict,
    routing: RoutingVerdict,
    signals: List[PhishingSignal],
    domain_age_findings: Optional[List[DomainAgeFinding]] = None,
    html_findings: Optional[List[HtmlFinding]] = None,
) -> tuple[Optional[int], str]:
    """Estimate how much verifiable evidence backs the verdict.

    This is a measure of *evidence coverage*, not of threat severity: it answers
    "how much did we have to work with", for a clean verdict as much as for a
    malicious one. It is deliberately capped at 90 because even live DNS
    re-verification cannot establish intent. Returns ``(None, ...)`` when there
    was effectively nothing to analyse.
    """
    factors: List[tuple[str, bool]] = [
        (
            "authentication results",
            any((getattr(auth, mech, None) or "not_present") != "not_present"
                for mech in ("spf", "dkim", "dmarc")),
        ),
        ("verifiable routing chain", bool(routing) and routing.hop_count >= 2),
        ("message body", bool(parsed.body_plain or parsed.body_html)),
    ]

    # Independently re-verified authentication is materially stronger evidence
    # than a relay's own claim about itself. The factor is only weighed when
    # live re-verification actually ran, so a deliberately offline deployment is
    # not penalised for a check it never attempted.
    if getattr(auth, "live_attempted", False):
        factors.append(("independently re-verified authentication (live DNS/DKIM)",
                        bool(getattr(auth, "live_verified", False))))

    # A resolved registration date is externally verifiable evidence, so it
    # raises coverage. As with live auth the factor is only weighed when the
    # check actually ran, so an offline deployment is not penalised for it.
    if domain_age_findings:
        assessable = [f for f in domain_age_findings if getattr(f, "source", "") != "disabled"]
        if assessable:
            factors.append((
                "domain registration age (WHOIS)",
                any(getattr(f, "age_days", None) is not None for f in assessable),
            ))

    # A body that was structurally analysed is better covered than one read as
    # flat text. The factor is only added when the analysis actually ran on an
    # HTML part, so it can raise coverage but never penalise a plain-text
    # message or a caller that does not run the stage.
    if html_findings is not None and parsed.body_html:
        factors.append(("structural analysis of the HTML body", True))

    # Corroboration only applies when something actually fired; a message with
    # no indicators is not "less certain" for lacking them.
    if signals:
        families = {_signal_family(s.indicator) for s in signals}
        factors.append(("indicators corroborated across multiple analysis families",
                        len(families) >= 3))

    satisfied = [name for name, ok in factors if ok]
    missing = [name for name, ok in factors if not ok]

    if not satisfied:
        return None, "Insufficient evidence"

    score = int(round(CONFIDENCE_FLOOR + (CONFIDENCE_CEILING - CONFIDENCE_FLOOR) * len(satisfied) / len(factors)))
    label = next(text for threshold, text in CONFIDENCE_LABELS if score >= threshold)
    if missing:
        label += " - limited by missing " + ", ".join(missing)
    return score, label

# Authentication verdicts, graded by how strongly they indicate spoofing.
# Hard failures are heavily weighted; soft, absent or unknown results carry a
# small weight so that legitimately unsigned mail (plenty of small-business and
# marketing senders) cannot reach High on authentication alone. The combined
# weight of spf=none + dkim=none + dmarc=none stays inside the Low band.
# Verdicts not listed here (notably "pass") contribute nothing.
AUTH_RESULT_WEIGHTS: dict[str, dict[str, tuple[int, str, str]]] = {
    "spf": {
        "fail": (30, "SPF Authentication Failure",
                 "SPF check failed for sender domain '{domain}' — the sending server is not authorised."),
        "softfail": (15, "Weak SPF Result (SoftFail)",
                     "SPF soft-failed for sender domain '{domain}': the domain owner marks this server as probably unauthorised."),
        "permerror": (5, "SPF Record Error",
                      "The SPF record for '{domain}' could not be evaluated (permanent error), so sender authorisation is unverified."),
        "neutral": (5, "SPF Neutral Result",
                    "The SPF record for '{domain}' explicitly asserts nothing about this server."),
        "none": (8, "No SPF Record Published",
                 "Sender domain '{domain}' publishes no SPF record, so sending servers cannot be verified."),
        "not_present": (8, "SPF Result Absent",
                        "No SPF result was recorded for '{domain}'; authentication was not checked or the header was stripped."),
    },
    "dkim": {
        "fail": (30, "DKIM Signature Failure",
                 "DKIM cryptographic signature failed verification — the message was altered or signed by an impostor."),
        "policy": (5, "DKIM Signature Rejected by Policy",
                   "A DKIM signature was present but rejected by local policy."),
        "neutral": (5, "DKIM Neutral Result",
                    "A DKIM signature was present but could not be evaluated."),
        "none": (8, "Unsigned Message (No DKIM)",
                 "The message carries no DKIM signature, so its integrity and origin cannot be cryptographically confirmed."),
        "not_present": (8, "DKIM Result Absent",
                        "No DKIM result was recorded; authentication was not checked or the header was stripped."),
    },
    "dmarc": {
        "fail": (25, "DMARC Policy Violation",
                 "DMARC alignment failed — message violates the policy published by '{domain}'."),
        "none": (8, "No DMARC Enforcement",
                 "Sender domain '{domain}' publishes no enforcing DMARC policy, so spoofing of this domain is not rejected."),
        "not_present": (5, "DMARC Result Absent",
                        "No DMARC result was recorded for '{domain}'."),
    },
}

# Routing forensics produces free-text flags. Each rule maps a family of flags
# onto a single scored signal, so a chain with five discontinuities is counted
# once rather than five times. Weights are deliberately modest: routing
# anomalies are corroborating evidence, not standalone verdicts.
ROUTING_FLAG_RULES = [
    (
        "time_travel", ("time travel", "before hop"), 20,
        "Impossible Routing Sequence",
        "A relay recorded receiving the message before the hop that sent it, which is only possible with a forged Received header.",
    ),
    (
        "no_received", ("no received: headers",), 12,
        "Missing Received Chain",
        "No Received headers are present, so the delivery path cannot be verified (header stripping or direct injection).",
    ),
    (
        "future_timestamp", ("future timestamp",), 12,
        "Forged / Skewed Hop Timestamp",
        "A relay is timestamped in the future, indicating a forged header or a badly misconfigured clock.",
    ),
    (
        "private_after_public", ("private ip", "appearing after public"), 10,
        "Private IP After Public Transit",
        "A private/loopback address appears after public internet transit, a common artefact of fabricated Received headers.",
    ),
    (
        "discontinuity", ("discontinuity",), 8,
        "Routing Chain Discontinuity",
        "The receiving host of one hop does not match the sending host of the next, suggesting a removed or fabricated relay.",
    ),
    (
        "single_hop", ("only one received hop",), 8,
        "Single-Hop Delivery Chain",
        "Only one Received hop was recorded, which is unusually short for internet-delivered mail and suggests direct injection.",
    ),
    (
        "unparseable_timestamp", ("unparseable timestamp",), 5,
        "Malformed Hop Timestamp",
        "A Received header carries a timestamp that does not parse, typical of hand-crafted or script-generated headers.",
    ),
    (
        "excessive_delay", ("excessive transit delay",), 4,
        "Excessive Transit Delay",
        "The message sat at a relay for an unusually long time, which can indicate a staging or spam relay.",
    ),
]

# Routing evidence should corroborate, never dominate: only the strongest few
# anomalies are scored.
MAX_ROUTING_SIGNALS = 3


def _score_routing_flags(routing: RoutingVerdict) -> List[PhishingSignal]:
    if not routing or not routing.flags:
        return []

    matched: dict[str, tuple[int, str, str, List[str]]] = {}
    for flag in routing.flags:
        flag_lc = str(flag).lower()
        for key, needles, weight, indicator, explanation in ROUTING_FLAG_RULES:
            if any(needle in flag_lc for needle in needles):
                entry = matched.setdefault(key, (weight, indicator, explanation, []))
                entry[3].append(str(flag))
                break

    ranked = sorted(matched.values(), key=lambda item: item[0], reverse=True)
    signals: List[PhishingSignal] = []
    for weight, indicator, explanation, evidence in ranked[:MAX_ROUTING_SIGNALS]:
        detail = "; ".join(evidence[:3])
        if len(evidence) > 3:
            detail += f" (+{len(evidence) - 3} more)"
        signals.append(PhishingSignal(
            indicator=f"Routing Forensics: {indicator}",
            weight=weight,
            explanation=explanation,
            evidence=detail,
        ))
    return signals





# --- Domain reputation (registration age) --------------------------------
#
# WHOIS age is corroborating evidence, never a verdict. Three deliberate
# safeguards keep an unknown or newly registered domain from dominating:
#
#   * only *resolved* ages score — a failed, disabled or rate-limited lookup
#     contributes nothing, because "we could not ask" is not "guilty";
#   * a sender-domain hit outweighs a linked-domain hit, since the From domain
#     is the identity being asserted;
#   * the family total is capped, so a message linking twelve fresh domains
#     scores the same as one linking two.
#
# A newly registered *sender* domain (25) plus a hard SPF or DKIM failure (30)
# lands mid-High rather than Critical, which is the intended balance.
DOMAIN_AGE_WEIGHTS = {
    ("sender", "newly_registered"): (
        25, "Newly Registered Sender Domain",
        "The sender's domain was registered within the newly-registered-domain window. "
        "Disposable domains registered days before use are a hallmark of phishing infrastructure.",
    ),
    ("sender", "young"): (
        12, "Recently Registered Sender Domain",
        "The sender's domain is young. Legitimate correspondents usually write from long-established "
        "domains, so this warrants corroboration rather than action on its own.",
    ),
    ("link", "newly_registered"): (
        15, "Newly Registered Link Domain",
        "A link in the message points at a domain registered within the newly-registered-domain window, "
        "typical of throwaway credential-harvesting infrastructure.",
    ),
    ("link", "young"): (
        8, "Recently Registered Link Domain",
        "A link in the message points at a recently registered domain.",
    ),
}

#: Hard ceiling on the combined weight of all domain-age signals.
MAX_DOMAIN_AGE_SCORE = 30
#: At most this many domain-age signals are reported, strongest first.
MAX_DOMAIN_AGE_SIGNALS = 2


def _score_domain_age(findings: Optional[List[DomainAgeFinding]]) -> List[PhishingSignal]:
    if not findings:
        return []

    candidates: List[tuple[int, PhishingSignal]] = []
    for finding in findings:
        if getattr(finding, "age_days", None) is None:
            continue  # unknown / exempt / failed lookup: no penalty
        origin = "link" if getattr(finding, "origin", "sender") == "link" else "sender"
        rule = DOMAIN_AGE_WEIGHTS.get((origin, getattr(finding, "classification", "")))
        if not rule:
            continue
        weight, indicator, explanation = rule
        evidence = f"Domain: '{finding.domain}' | Registered: {finding.created or 'unknown'} " \
                   f"| Age: {finding.age_days} day(s)"
        if getattr(finding, "registrar", ""):
            evidence += f" | Registrar: {finding.registrar}"
        candidates.append((weight, PhishingSignal(
            indicator=f"Domain Reputation: {indicator}",
            weight=weight,
            explanation=explanation,
            evidence=evidence,
        )))

    candidates.sort(key=lambda item: item[0], reverse=True)

    signals: List[PhishingSignal] = []
    budget = MAX_DOMAIN_AGE_SCORE
    for weight, signal in candidates[:MAX_DOMAIN_AGE_SIGNALS]:
        if budget <= 0:
            break
        if weight > budget:
            signal.weight = budget
        budget -= signal.weight
        signals.append(signal)
    return signals


# --- HTML body forensics -------------------------------------------------
#
# Structural HTML threats are strong evidence, but the family is capped for the
# same reason routing and reputation are: a single stage must not be able to
# decide a verdict on its own. Two properties keep the cap honest:
#
#   * weights are graded by severity, so a preheader-length hidden block (Low)
#     costs 4 while a filter-poisoning one (High) costs 20;
#   * the family total is capped and only the strongest few signals are
#     reported, so a heavily templated marketing message that trips several
#     soft detectors cannot accumulate its way into Critical.
#
# A password form (30) plus a hard SPF failure (30) lands in High, which is the
# intended balance: an in-body credential form is close to conclusive on its
# own, but still needs corroboration to reach the top of the scale.
HTML_SIGNAL_WEIGHTS: dict[str, dict[str, int]] = {
    CREDENTIAL_FORM: {"High": 30, "Medium": 18},
    DATA_URI_HTML: {"High": 25},
    META_REFRESH: {"High": 22},
    JAVASCRIPT_URI: {"High": 20},
    HIDDEN_TEXT: {"High": 20, "Medium": 10, "Low": 4},
    IFRAME: {"High": 20, "Medium": 15},
    FORM_EXTERNAL_ACTION: {"Medium": 15},
    SCRIPT: {"Medium": 12},
    ACTIVE_CONTENT: {"Medium": 12},
    FORM_CREDENTIAL_FIELDS: {"Medium": 12},
    COMMENT_OBFUSCATION: {"Medium": 12},
    DATA_URI_OTHER: {"Medium": 10},
    ENTITY_OBFUSCATION: {"Medium": 8},
    EVENT_HANDLER: {"Medium": 8},
    IMAGE_ONLY_BODY: {"Low": 5},
}

#: Applied when a detector reports a severity the table does not list, so a new
#: detector can never score more than its severity band allows.
HTML_DEFAULT_WEIGHTS = {"High": 20, "Medium": 10, "Low": 4}

#: Hard ceiling on the combined weight of all HTML body signals.
MAX_HTML_SCORE = 30
#: At most this many HTML signals are scored, strongest first.
MAX_HTML_SIGNALS = 4


def _html_weight(category: str, severity: str) -> int:
    by_severity = HTML_SIGNAL_WEIGHTS.get(category, {})
    if severity in by_severity:
        return by_severity[severity]
    return HTML_DEFAULT_WEIGHTS.get(severity, 0)


def _score_html_findings(findings: Optional[List[HtmlFinding]]) -> List[PhishingSignal]:
    if not findings:
        return []

    candidates: List[tuple[int, PhishingSignal]] = []
    for finding in findings:
        severity = getattr(finding, "severity", "Medium") or "Medium"
        weight = _html_weight(getattr(finding, "category", ""), severity)
        if weight <= 0:
            continue
        evidence = f"[{severity}] {getattr(finding, 'evidence', '') or '-'}"
        if getattr(finding, "detail", ""):
            evidence += f" | {finding.detail}"
        candidates.append((weight, PhishingSignal(
            indicator=f"HTML Forensics: {finding.indicator}",
            weight=weight,
            explanation=getattr(finding, "explanation", ""),
            evidence=evidence,
            severity=severity,
        )))

    candidates.sort(key=lambda item: item[0], reverse=True)

    signals: List[PhishingSignal] = []
    budget = MAX_HTML_SCORE
    for weight, signal in candidates[:MAX_HTML_SIGNALS]:
        if budget <= 0:
            break
        if signal.weight > budget:
            signal.weight = budget
        budget -= signal.weight
        signals.append(signal)
    return signals


def _bucket(display_score: int) -> str:
    if display_score < 0:
        return "Low"
    for low, high, label in RISK_BUCKETS:
        if low <= display_score <= high:
            return label
    return "Critical"


def score_message(
    parsed: ParsedMessage,
    auth: AuthVerdict,
    routing: RoutingVerdict,
    header_verdict: Optional[HeaderAnalysisVerdict] = None,
    url_verdict: Optional[URLAnalysisVerdict] = None,
    domain_age_findings: Optional[List[DomainAgeFinding]] = None,
    html_findings: Optional[List[HtmlFinding]] = None,
) -> ScoringVerdict:
    logger.debug("Executing 15-category Phishing Indicator Scoring Engine.")
    signals: List[PhishingSignal] = []

    from_domain = extract_domain(parsed.from_raw)
    from_address = extract_address(parsed.from_raw)
    display_name = extract_display_name(parsed.from_raw)
    subject = normalize_text(parsed.subject or "")
    # HTML markup, entities and zero-width characters are stripped so keyword
    # and phrase matching sees the text a human actually reads.
    body = build_match_text(parsed.body_plain, parsed.body_html)

    # --- URL Analysis Signals ---
    if url_verdict and url_verdict.urls:
        for u in url_verdict.urls:
            if u.is_mismatched_anchor:
                signals.append(PhishingSignal(
                    indicator="Deceptive / Mismatched Hyperlink",
                    weight=30,
                    explanation="Link anchor text displays a domain different from actual target destination.",
                    evidence=f"Anchor: '{u.anchor_text}' | Target: '{u.domain}'"
                ))
            if u.is_ip_based:
                signals.append(PhishingSignal(
                    indicator="IP-Based Link Target",
                    weight=25,
                    explanation="Link target uses a raw IP address instead of a domain name.",
                    evidence=f"Target: '{u.raw_url}'"
                ))
            if u.is_shortener:
                signals.append(PhishingSignal(
                    indicator="URL Shortener Link",
                    weight=15,
                    explanation="Link uses a URL shortener service to conceal destination URL.",
                    evidence=f"Shortener URL: '{u.raw_url}'"
                ))
            if u.is_suspicious_domain:
                signals.append(PhishingSignal(
                    indicator="Suspicious Link Domain",
                    weight=20,
                    explanation="Link targets a domain with high-risk TLD, Punycode, or lookalike patterns.",
                    evidence=f"Domain: '{u.domain}'"
                ))
            if detect_redirect_param(u.raw_url) and not any(sig.indicator == "Multiple / Open Redirect Link Parameter" for sig in signals):
                signals.append(PhishingSignal(
                    indicator="Multiple / Open Redirect Link Parameter",
                    weight=20,
                    explanation="Link contains embedded redirect query parameters pointing to a secondary destination.",
                    evidence=f"Link URL: '{u.raw_url}'"
                ))


    # --- Sender identity signals -----------------------------------------
    # Header Forensics already scores display-name impersonation, lookalike
    # domains, high-risk TLDs and From/Sender/Reply-To/Return-Path mismatches
    # via its own findings (with ESP allowlists and graded risk levels).
    # When a header verdict is supplied it is the single source of truth for
    # those four categories; the blocks below only run when scoring is invoked
    # standalone (e.g. unit tests, or callers without header forensics).
    score_sender_identity_here = header_verdict is None

    # 1. Display Name Impersonation
    if score_sender_identity_here and display_name and from_address:
        display_lc = display_name.lower()
        for brand_domain in KNOWN_BRAND_DOMAINS:
            brand = brand_domain.split(".")[0]
            if brand in display_lc and from_domain and brand not in from_domain:
                signals.append(PhishingSignal(
                    indicator="Display Name Impersonation",
                    weight=25,
                    explanation=f"Display name references known brand '{brand}', but actual sending domain is '{from_domain}'.",
                    evidence=f"Display Name: '{display_name}' | From: '{from_address}'"
                ))
                break

    # 2. Lookalike Domains & 3. Typosquatting
    if score_sender_identity_here and from_domain:
        brand = looks_like_lookalike(from_domain)
        if brand:
            signals.append(PhishingSignal(
                indicator="Lookalike / Typosquatted Domain",
                weight=25,
                explanation=f"Sender domain '{from_domain}' closely resembles target brand domain '{brand}'.",
                evidence=f"Sender Domain: '{from_domain}' -> Resembles: '{brand}'"
            ))

    # 4. Suspicious TLDs
    if score_sender_identity_here and from_domain:
        tld = from_domain.rsplit(".", 1)[-1].lower()
        if tld in HIGH_RISK_TLDS:
            signals.append(PhishingSignal(
                indicator="High-Risk Top-Level Domain (TLD)",
                weight=20,
                explanation=f"Sender domain uses high-risk top-level domain '.{tld}'.",
                evidence=f"Domain: '{from_domain}'"
            ))

    # 5. Unicode / Punycode Domains (not covered by header forensics)
    if from_domain:
        unicode_reason = is_punycode_or_unicode(from_domain)
        if unicode_reason:
            signals.append(PhishingSignal(
                indicator="Punycode / Unicode Domain",
                weight=20,
                explanation="Sender domain uses Punycode or non-ASCII characters, commonly exploited for IDN homograph spoofing.",
                evidence=unicode_reason
            ))

    # 6. Mismatched Sender Domains
    if score_sender_identity_here:
        sender_domain = extract_domain(parsed.sender_raw)
        reply_to_domain = extract_domain(parsed.reply_to_raw)
        return_path_domain = extract_domain(parsed.return_path_raw)

        mismatches = []
        if sender_domain and from_domain and sender_domain != from_domain:
            mismatches.append(f"Sender ('{sender_domain}')")
        if reply_to_domain and from_domain and reply_to_domain != from_domain:
            mismatches.append(f"Reply-To ('{reply_to_domain}')")
        if return_path_domain and from_domain and return_path_domain != from_domain:
            mismatches.append(f"Return-Path ('{return_path_domain}')")

        if mismatches:
            signals.append(PhishingSignal(
                indicator="Mismatched Sender Domains",
                weight=20,
                explanation="Header From domain does not align with transmitter or bounce address domains.",
                evidence=f"From Domain: '{from_domain}' | Mismatches: {', '.join(mismatches)}"
            ))



    # 10. Suspicious Keywords in Subject / Body
    # "confidential" was removed: it is boilerplate in corporate email footers
    # and disclaimers, and was the single largest source of false positives.
    suspicious_kw = ["security alert", "suspicious activity", "action required", "account notice"]
    found_kws = [kw for kw in suspicious_kw if kw in subject.lower() or kw in body.lower()]
    if found_kws:
        signals.append(PhishingSignal(
            indicator="Suspicious Keywords",
            weight=15,
            explanation="Subject or body contains high-risk threat keywords.",
            evidence=f"Matched Keywords: {', '.join(found_kws)}"
        ))

    # 11. Credential Harvesting Language
    for pat in CREDENTIAL_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(PhishingSignal(
                indicator="Credential Harvesting Language",
                weight=30,
                explanation="Email uses phrasing aimed at tricking recipients into revealing account credentials.",
                evidence=f"Matched Phrase: '{match.group(0)}'"
            ))
            break

    # 12. Urgency Language
    for pat in URGENCY_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(PhishingSignal(
                indicator="Urgent Pressure Tactics",
                weight=25,
                explanation="Email employs artificial time pressure to incite immediate action without due verification.",
                evidence=f"Matched Phrase: '{match.group(0)}'"
            ))
            break

    # 13. Financial Scam Language
    for pat in FINANCIAL_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(PhishingSignal(
                indicator="Financial Scam Language",
                weight=25,
                explanation="Email contains phrasing associated with wire fraud, cryptocurrency, or payment scams.",
                evidence=f"Matched Phrase: '{match.group(0)}'"
            ))
            break

    # 14. Fake Invoice Indicators
    for pat in INVOICE_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(PhishingSignal(
                indicator="Fake Invoice / BEC Indicators",
                weight=30,
                explanation="Email references fake invoices or purchase orders typical of Business Email Compromise (BEC).",
                evidence=f"Matched Phrase: '{match.group(0)}'"
            ))
            break

    # 15. Password Reset Scams
    for pat in PASSWORD_RESET_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(PhishingSignal(
                indicator="Password Reset Scam Language",
                weight=30,
                explanation="Email pretends to be an automated password reset or security alert.",
                evidence=f"Matched Phrase: '{match.group(0)}'"
            ))
            break

    # --- Authentication Signals ---
    for mechanism, verdict, details in (
        ("spf", auth.spf, auth.spf_details),
        ("dkim", auth.dkim, auth.dkim_details),
        ("dmarc", auth.dmarc, auth.dmarc_details),
    ):
        rule = AUTH_RESULT_WEIGHTS.get(mechanism, {}).get((verdict or "").lower())
        if not rule:
            continue
        weight, indicator, explanation = rule
        signals.append(PhishingSignal(
            indicator=indicator,
            weight=weight,
            explanation=explanation.format(domain=from_domain or "unknown"),
            evidence=f"{mechanism.upper()} Verdict: {(verdict or '').upper()} | Details: {details or '-'}"
        ))

    if auth.inconsistencies:
        for inc in auth.inconsistencies:
            signals.append(PhishingSignal(
                indicator="Authentication Inconsistency",
                weight=20,
                explanation="Detected conflicting authentication headers or domain misalignment.",
                evidence=inc
            ))

    # --- Header Forensics Signals ---
    if header_verdict and header_verdict.findings:
        for hf in header_verdict.findings:
            weight_map = {"Critical": 35, "High": 25, "Medium": 15, "Low": 5}
            w = weight_map.get(hf.risk_level, 15)
            signals.append(PhishingSignal(
                indicator=f"Header Forensics: {hf.title}",
                weight=w,
                explanation=hf.description,
                evidence=f"[{hf.risk_level}] {hf.evidence}"
            ))

    # --- Routing Forensics Signals ---
    signals.extend(_score_routing_flags(routing))

    # --- Domain Reputation (registration age) ---
    signals.extend(_score_domain_age(domain_age_findings))

    # --- HTML Body Forensics (capped contribution) ---
    signals.extend(_score_html_findings(html_findings))

    # --- Risky Attachments ---
    # Consumes the flags computed by the Attachment Forensics Engine, falling
    # back to a local re-check when scoring runs before/without that stage.
    # Each attachment contributes at most one signal, weighted by its worst
    # property, so a macro-enabled executable is not counted twice.
    for att in parsed.attachments:
        filename = att.filename
        ext = att.declared_extension or ""
        reasons: List[tuple[int, str]] = []

        if getattr(att, "has_double_extension", False) or has_double_extension(filename):
            reasons.append((35, "double extension masking the real file type (e.g. invoice.pdf.exe)"))
        if getattr(att, "is_executable", False) or ext in RISKY_EXTENSIONS:
            reasons.append((30, f"executable/script payload (extension '.{ext}', signature '{att.true_type}')"))
        elif getattr(att, "is_script", False):
            reasons.append((30, f"script payload (extension '.{ext}')"))
        if att.true_type == "exe" and ext not in {"exe", "dll", "scr", "com"}:
            reasons.append((30, f"true file signature is executable but extension is '.{ext}'"))
        if getattr(att, "is_macro_enabled", False):
            reasons.append((25, f"macro-enabled Office document (extension '.{ext}')"))
        if getattr(att, "is_password_protected", False):
            reasons.append((20, "password-protected archive that cannot be scanned"))
        if getattr(att, "suspicious_name_flag", False):
            reasons.append((10, "social-engineering lure or randomised filename"))

        if not reasons:
            continue

        weight = max(w for w, _ in reasons)
        detail = "; ".join(text for _, text in reasons)
        engine_findings = getattr(att, "findings", None) or []
        if engine_findings:
            detail += f" | Engine: {'; '.join(engine_findings[:4])}"

        signals.append(PhishingSignal(
            indicator="Executable / Suspicious Attachment",
            weight=weight,
            explanation="Attachment forensics flagged a risky payload, masked extension, macro container, or unscannable archive.",
            evidence=f"Filename: '{filename}' | Issues: {detail}"
        ))

    total = sum(s.weight for s in signals)
    display = to_display_score(total)
    confidence, confidence_label = assess_confidence(
        parsed, auth, routing, signals, domain_age_findings, html_findings
    )
    logger.info(f"Message scored {display}/100 ({_bucket(display)} risk, raw weight total {total}).")

    return ScoringVerdict(
        total_score=total,
        risk_level=_bucket(display),
        signals=signals,
        display_score=display,
        confidence=confidence,
        confidence_label=confidence_label,
    )




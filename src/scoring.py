"""Stage 6 — Phishing Indicator Scoring Engine.

Evaluates email messages across 15 distinct threat categories and outputs
transparent, weighted risk signals with evidence for SOC analysts.
"""

import re
from collections import defaultdict
from typing import Optional, List
from models import (
    ParsedMessage, AuthVerdict, RoutingVerdict, PhishingSignal, ScoringVerdict,
    HeaderAnalysisVerdict, URLAnalysisVerdict, DomainAgeFinding, HtmlFinding,
    SenderHistory,
)
from attachment_content import (
    ARCHIVE_CONTAINS_EXECUTABLE, ARCHIVE_DOUBLE_EXTENSION_ENTRY, ARCHIVE_ENCRYPTED,
    ARCHIVE_NESTED, OFFICE_ENCRYPTED, OFFICE_VBA_MACRO, PDF_EMBEDDED_FILE,
    PDF_JAVASCRIPT, PDF_LAUNCH_ACTION, PDF_OPEN_ACTION, TYPE_MISMATCH,
)
from html_analysis import (
    ACTIVE_CONTENT, COMMENT_OBFUSCATION, CREDENTIAL_FORM, DATA_URI_HTML, DATA_URI_OTHER,
    ENTITY_OBFUSCATION, EVENT_HANDLER, FORM_CREDENTIAL_FIELDS, FORM_EXTERNAL_ACTION,
    HIDDEN_TEXT, IFRAME, IMAGE_ONLY_BODY, JAVASCRIPT_URI, META_REFRESH, SCRIPT,
)
from utils import (
    extract_domain, extract_address, extract_display_name,
    looks_like_lookalike, is_punycode_or_unicode,
    domain_relationship, display_name_brand_conflict,
    detect_redirect_param, has_double_extension, RISKY_EXTENSIONS,
    KNOWN_BRAND_DOMAINS, build_match_text, normalize_text,
    HIGH_RISK_TLDS, CORE_ABUSE_TLDS, registrable_domain, TRUSTED_TRANSACTIONAL_DOMAINS,
)
from logger import get_logger

logger = get_logger(__name__)

# Pattern matcher sets
# Credential language is strong: it asks the reader to surrender secrets.
CREDENTIAL_PATTERNS = [
    r"\bconfirm\s+(?:your\s+)?password\b", r"\bverify\s+(?:your\s+)?account\b",
    r"\blogin\s+to\s+(?:restore|verify|update)\b", r"\bupdate\s+billing\b",
    r"\baccount\s+suspended\b", r"\bsecurity\s+checkpoint\b", r"\benter\s+credentials\b"
]

# Urgency alone is weak — legitimate business mail uses deadlines constantly.
URGENCY_PATTERNS = [
    r"\bimmediate\s+action\s+required\b", r"\bwithin\s+24\s+hours\b",
    r"\baccount\s+will\s+be\s+(?:closed|terminated|suspended)\b",
    r"\burgent\s+notice\b", r"\brespond\s+immediately\b", r"\bfinal\s+warning\b"
]

# Keep only phrases that imply *outbound payment fraud*, not ordinary receipts.
# Removed: "payment confirmation", "bank deposit", "overdue payment" (AR/billing FP).
FINANCIAL_SCAM_PATTERNS = [
    r"\bwire\s+transfer\b", r"\bbitcoin\b", r"\bcrypto\s+payment\b",
    r"\bgift\s+card\b", r"\btransfer\s+funds\b",
]

# Ordinary billing language — weak corroborator only (never High alone).
INVOICE_PATTERNS = [
    r"\binvoice\s*#?\s*\d+\b", r"\bpurchase\s+order\s*#?\s*\d+\b",
    r"\bremittance\s+advice\b",
    r"\battached\s+invoice\b", r"\bpayment\s+due\b",
    r"\boverdue\s+payment\b",
]

# Back-compat alias for older imports / tests.
FINANCIAL_PATTERNS = FINANCIAL_SCAM_PATTERNS


# Bare "reset password" fires on every legitimate IdP email. Prefer scam-shaped
# variants that claim compromise or forced expiry.
PASSWORD_RESET_PATTERNS = [
    r"\bpassword\s+expired\b",
    r"\bunauthorized\s+login\s+attempt\b",
    r"\bsecurity\s+alert:\s+password\b",
    r"\bpassword\s+change\s+request\b",
    r"\breset\s+your\s+password\s+immediately\b",
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
    # Must precede "sender identity": a first-contact indicator is about the
    # relationship with the sender, not about how the sender looks.
    ("sender history", ("sender history",)),
    ("sender identity", ("display name", "lookalike", "typosquat", "top-level domain",
                         "punycode", "mismatched sender", "reply / sender diversion",
                         "suspicious reply", "different sender header")),
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
    sender_history: Optional[SenderHistory] = None,
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

    # Knowing whether this recipient has corresponded with this sender before is
    # evidence the message itself cannot supply. Only weighed when a baseline was
    # actually available, so the CLI (which keeps no history) is not penalised.
    if sender_history is not None and getattr(sender_history, "available", False):
        factors.append(("prior correspondence baseline for this recipient", True))

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
        # Time-travel / forged Received is strong; soft routing quirks are weak.
        strength = "strong" if weight >= 20 else "weak"
        signals.append(_make_signal(
            f"Routing Forensics: {indicator}", weight, explanation, detail,
            strength=strength,
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
        15, "Newly Registered Sender Domain",
        "The sender's domain was registered within the newly-registered-domain window. "
        "Disposable domains registered days before use are a hallmark of phishing infrastructure, "
        "but age alone is not proof of malice.",
    ),
    ("sender", "young"): (
        8, "Recently Registered Sender Domain",
        "The sender's domain is young. Legitimate correspondents usually write from long-established "
        "domains, so this warrants corroboration rather than action on its own.",
    ),
    ("link", "newly_registered"): (
        10, "Newly Registered Link Domain",
        "A link in the message points at a domain registered within the newly-registered-domain window, "
        "typical of throwaway credential-harvesting infrastructure.",
    ),
    ("link", "young"): (
        5, "Recently Registered Link Domain",
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
        candidates.append((weight, _make_signal(
            f"Domain Reputation: {indicator}", weight, explanation, evidence,
            # NRD is corroborating evidence — never alone enough for High.
            strength="weak",
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
    SCRIPT: {"Medium": 6},
    ACTIVE_CONTENT: {"Medium": 6},
    FORM_CREDENTIAL_FIELDS: {"Medium": 12},
    COMMENT_OBFUSCATION: {"Medium": 12},
    DATA_URI_OTHER: {"Medium": 10},
    ENTITY_OBFUSCATION: {"Medium": 8},
    EVENT_HANDLER: {"Medium": 6},
    IMAGE_ONLY_BODY: {"Low": 2},
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
        candidates.append((weight, _make_signal(
            f"HTML Forensics: {finding.indicator}", weight,
            getattr(finding, "explanation", ""),
            evidence,
            strength="strong" if weight >= 18 else "weak",
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


# --- Attachment content forensics ----------------------------------------
#
# Weights for the observations that come from reading an attachment's bytes
# rather than its name (see :mod:`attachment_content`). Content-verified
# evidence outweighs the equivalent name-based guess, because "the ZIP
# encryption flag is set" and "the filename contains the word encrypted" are not
# the same claim. As with every other family the total is capped, so a single
# archive cannot decide a verdict on its own.
CONTENT_FEATURE_WEIGHTS: dict[str, tuple[int, str]] = {
    ARCHIVE_CONTAINS_EXECUTABLE: (
        35, "archive contains an executable or script entry (verified from the archive directory)"),
    ARCHIVE_DOUBLE_EXTENSION_ENTRY: (
        35, "archive entry uses double-extension masking (verified from the archive directory)"),
    OFFICE_VBA_MACRO: (
        30, "a VBA macro project is physically present in the document"),
    PDF_LAUNCH_ACTION: (
        30, "PDF carries a /Launch action that starts an external program"),
    ARCHIVE_ENCRYPTED: (
        25, "archive encryption flag is set, so the payload cannot be scanned"),
    OFFICE_ENCRYPTED: (
        25, "document is password-protected (OLE EncryptedPackage), so it cannot be scanned"),
    TYPE_MISMATCH: (
        25, "the file signature contradicts the declared extension"),
    PDF_JAVASCRIPT: (
        20, "PDF embeds JavaScript"),
    PDF_OPEN_ACTION: (
        15, "PDF runs an action automatically when opened"),
    PDF_EMBEDDED_FILE: (
        15, "PDF carries an embedded file payload"),
    ARCHIVE_NESTED: (
        15, "archive is nested inside another archive, a common gateway-evasion layering"),
}


# --- Sender history (BEC first-contact baselining) -------------------------
#
# A first contact is only interesting in context: on its own it describes every
# legitimate new correspondent, so the standalone weight is deliberately token.
# The combination that matters is a first-contact domain *plus* payment or
# credential language already detected in the body, which is the shape of vendor
# impersonation and invoice fraud.
#
# The signal is only produced when a real baseline exists (see
# :data:`sender_history.MIN_PRIOR_MESSAGES`), and the family cap keeps it firmly
# in corroborating territory: it can lift a suspicious message into the next
# band but can never carry a verdict by itself.
SENDER_HISTORY_BEC_INDICATORS = {
    "Fake Invoice / BEC Indicators",
    "Financial Scam Language",
    "Credential Harvesting Language",
    "Password Reset Scam Language",
}

FIRST_CONTACT_WITH_PAYMENT_WEIGHT = 15
FIRST_CONTACT_DOMAIN_WEIGHT = 5
FIRST_CONTACT_ADDRESS_WEIGHT = 3

#: Hard ceiling on the combined weight of all sender-history signals.
MAX_SENDER_HISTORY_SCORE = 15


def _score_sender_history(
    history: Optional[SenderHistory],
    fired_indicators: set,
) -> List[PhishingSignal]:
    if not history or not getattr(history, "available", False):
        return []

    evidence = getattr(history, "detail", "") or ""
    financial_context = sorted(fired_indicators & SENDER_HISTORY_BEC_INDICATORS)

    if history.first_time_domain and financial_context:
        return [_make_signal(
            "Sender History: First Contact Requesting Payment or Credentials",
            FIRST_CONTACT_WITH_PAYMENT_WEIGHT,
            "This recipient has never received mail from this domain, yet the message "
            "asks for payment or credentials. That combination is the standard shape of "
            "vendor impersonation and invoice fraud.",
            f"{evidence} | Corroborating content: {', '.join(financial_context)}",
            strength="strong",
        )]

    if history.first_time_domain:
        return [_make_signal(
            "Sender History: First Contact from Unfamiliar Domain",
            FIRST_CONTACT_DOMAIN_WEIGHT,
            "No previously analysed message for this recipient came from this domain. "
            "Ordinary for a genuine new correspondent, so this is context rather than "
            "an accusation.",
            evidence,
            strength="weak",
        )]

    if history.first_time_address:
        return [_make_signal(
            "Sender History: First Contact from New Address at a Known Domain",
            FIRST_CONTACT_ADDRESS_WEIGHT,
            "The domain is an established correspondent but this individual address is "
            "new, which is what both a new colleague and a look-alike mailbox look like.",
            evidence,
            strength="weak",
        )]

    return []


# --- Per-family saturation ------------------------------------------------
#
# Evidence within one family is heavily correlated: five header findings about
# the same forged From are one observation reported five times, and a message
# with thirty links can trip the same link detector thirty times. Summing them
# lets a single stage — or a single verbose detector — accumulate its way to
# Critical from one line of evidence.
#
# Each family therefore saturates at a cap. Budget is allocated strongest-signal
# first, so the most severe evidence in a family is always the part that scores;
# weaker signals above the cap remain in the report (analysts still need to see
# them) but stop contributing weight.
#
# Caps are chosen so that no single family can reach Critical (90 display) on its
# own, while leaving realistic single-family evidence untouched:
#
#   * authentication 75 — SPF+DKIM+DMARC hard failures (85) saturate to High,
#     and an unbounded list of inconsistency lines can no longer pile on;
#   * header forensics 70 — one forged identity produces several findings;
#   * link forensics 60 and message content 60 — a link farm or a
#     keyword-dense body needs corroboration from another family to escalate;
#   * sender identity 45 and attachment forensics 45 — strong but never
#     conclusive alone;
#   * routing, HTML, domain reputation and sender history keep the caps their
#     own stages already enforce.
FAMILY_SCORE_CAPS: dict[str, int] = {
    "authentication": 75,
    "header forensics": 70,
    "link forensics": 60,
    "message content": 60,
    "sender identity": 45,
    "attachment forensics": 45,
    "routing forensics": 45,
    "html body forensics": MAX_HTML_SCORE,
    "domain reputation": MAX_DOMAIN_AGE_SCORE,
    "sender history": MAX_SENDER_HISTORY_SCORE,
}

# --- Signal strength & High-risk corroboration ---------------------------
#
# Root cause of prior false High verdicts: many weak, everyday indicators
# (urgency wording, "security alert", invoice language, soft auth, missing
# headers) summed past the High threshold without any strong phishing
# evidence. High/Critical now requires strong corroboration.

#: Soft content / structural indicators that are common in legitimate mail.
#: When the sender is a known authenticated brand these contribute nothing.
TRUSTED_SENDER_SUPPRESSED_INDICATORS = {
    "Suspicious Keywords",
    "Urgent Pressure Tactics",
    "Financial Scam Language",
    "Fake Invoice / BEC Indicators",
    "Password Reset Scam Language",
    "Credential Harvesting Language",
    "URL Shortener Link",
    "Multiple / Open Redirect Link Parameter",
}

#: Hard authentication failures are strong spoofing evidence.
AUTH_STRONG_VERDICTS = {"fail"}

#: Minimum distinct strong families to allow High/Critical.
#: Single-family piles (billing language, soft auth) must not reach High alone.
MIN_STRONG_FAMILIES_FOR_HIGH = 2


def _make_signal(
    indicator: str,
    weight: int,
    explanation: str,
    evidence: str,
    *,
    strength: str = "weak",
    severity: str = "",
) -> PhishingSignal:
    return PhishingSignal(
        indicator=indicator,
        weight=weight,
        explanation=explanation,
        evidence=evidence,
        strength=strength,
        severity=severity,
        original_weight=weight,
        family=_signal_family(indicator),
    )


def is_trusted_authenticated_sender(from_domain: str, auth: AuthVerdict) -> bool:
    """True when From is a known brand/ESP domain and auth did not fail.

    Soft content signals from these senders (password reset, invoices, security
    alerts) are expected legitimate language, not phishing evidence.
    """
    if not from_domain:
        return False
    spf = (auth.spf or "").lower()
    dkim = (auth.dkim or "").lower()
    dmarc = (auth.dmarc or "").lower()
    if "fail" in (spf, dkim, dmarc):
        return False
    if spf != "pass" and dkim != "pass":
        return False
    reg = registrable_domain(from_domain.lower().strip("."))
    if not reg:
        return False
    return reg in TRUSTED_TRANSACTIONAL_DOMAINS


def has_suspicious_reply_diversion(parsed: ParsedMessage) -> bool:
    """True when Reply-To / Sender / Return-Path shows deception vs From.

    Brand From with free-mail or high-risk Reply-To must not receive trusted-sender
    content dampening — that pattern is classic reply diversion.
    """
    from_domain = extract_domain(parsed.from_raw)
    if not from_domain:
        return False
    for raw in (parsed.reply_to_raw, parsed.sender_raw, parsed.return_path_raw):
        other = extract_domain(raw or "")
        if other and domain_relationship(from_domain, other) == "suspicious":
            return True
    return False


def _apply_trusted_sender_dampening(
    signals: List[PhishingSignal],
    trusted: bool,
) -> List[PhishingSignal]:
    """Zero out soft content signals from authenticated known-good senders."""
    if not trusted:
        return signals
    for signal in signals:
        if signal.indicator in TRUSTED_SENDER_SUPPRESSED_INDICATORS:
            if signal.weight > 0:
                signal.explanation = (
                    f"{signal.explanation} [Suppressed: authenticated trusted sender — "
                    "this language is expected from this provider.]"
                )
            signal.weight = 0
    return signals


def _annotate_contributions(signals: List[PhishingSignal], total: int) -> None:
    for signal in signals:
        if not signal.family:
            signal.family = _signal_family(signal.indicator)
        if total > 0 and signal.weight > 0:
            signal.contribution_pct = round(100.0 * signal.weight / total, 1)
        else:
            signal.contribution_pct = 0.0


def _apply_high_risk_gate(
    display_score: int,
    signals: List[PhishingSignal],
) -> tuple[str, str, str]:
    """Map display score to a risk bucket, requiring strong evidence for High+.

    Returns ``(risk_level, classification_reason, rationale)``.
    """
    provisional = _bucket(display_score)
    active = [s for s in signals if s.weight > 0]
    strong = [s for s in active if s.strength == "strong"]
    weak = [s for s in active if s.strength != "strong"]
    strong_weight = sum(s.weight for s in strong)
    strong_families = {_signal_family(s.indicator) for s in strong}

    strong_names = [s.indicator for s in sorted(strong, key=lambda x: -x.weight)[:5]]
    weak_names = [s.indicator for s in sorted(weak, key=lambda x: -x.weight)[:5]]

    evidence_summary = (
        f"Display score {display_score}/100 from {len(active)} active signal(s) "
        f"({len(strong)} strong across {len(strong_families)} family(ies), "
        f"{len(weak)} weak). "
        f"Strong: {', '.join(strong_names) or 'none'}. "
        f"Weak: {', '.join(weak_names) or 'none'}."
    )

    # High/Critical require ≥2 independent strong families. Promote from
    # upper-Medium (≥55) when that bar is met — evidence over raw score band.
    if (
        len(strong_families) >= MIN_STRONG_FAMILIES_FOR_HIGH
        and display_score >= 55
        and strong_families != {"authentication"}
    ):
        level = "Critical" if display_score >= 90 else "High"
        reason = (
            f"{level}: {len(strong_families)} independent strong evidence "
            f"families (required >={MIN_STRONG_FAMILIES_FOR_HIGH})."
        )
        return level, reason, evidence_summary + " " + reason

    if provisional in {"Low", "Medium"}:
        reason = f"Score in {provisional} band ({display_score})."
        return provisional, reason, evidence_summary + " " + reason

    if strong_families == {"authentication"}:
        reason = (
            f"Demoted from {provisional} to Medium: authentication failures alone "
            f"(strong weight={strong_weight}) require corroborating evidence from "
            f"another analysis family before High risk."
        )
        return "Medium", reason, evidence_summary + " " + reason

    reason = (
        f"Demoted from {provisional} to Medium: score {display_score} lacked "
        f"multiple independent strong families (strong weight={strong_weight}, "
        f"strong families={len(strong_families)})."
    )
    return "Medium", reason, evidence_summary + " " + reason


def _cross_domain_redirect(url: str) -> bool:
    """True only when a redirect parameter points at a *different* registrable host.

    Same-site tracking redirects (newsletter → article on the same domain) are
    not open redirects and must not score.
    """
    from urllib.parse import urlparse, parse_qs, unquote

    if not detect_redirect_param(url):
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    host_reg = registrable_domain(host)
    redirect_keys = {
        "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
        "return_url", "continue", "next", "url", "dest", "destination",
        "goto", "target", "rurl", "u",
    }
    qs = parse_qs(parsed.query)
    for key, values in qs.items():
        if key.lower() not in redirect_keys:
            continue
        for value in values:
            target = unquote(value or "")
            if not target.startswith(("http://", "https://", "//")):
                continue
            candidate = target if "://" in target else "http:" + target
            try:
                target_host = (urlparse(candidate).hostname or "").lower()
            except ValueError:
                continue
            if not target_host:
                continue
            if target_host != host and registrable_domain(target_host) != host_reg:
                return True
    return False


def _apply_family_caps(signals: List[PhishingSignal]) -> List[PhishingSignal]:
    """Saturate each evidence family at its cap, strongest signal first.

    Signals are mutated in place and the list order (which drives report
    ordering) is preserved, so capping changes what a signal *contributes*, never
    whether the analyst sees it.
    """
    grouped: dict[str, List[tuple[int, PhishingSignal]]] = defaultdict(list)
    for position, signal in enumerate(signals):
        grouped[_signal_family(signal.indicator)].append((position, signal))

    for family, entries in grouped.items():
        cap = FAMILY_SCORE_CAPS.get(family)
        if cap is None:
            continue
        total = sum(signal.weight for _, signal in entries)
        if total <= cap:
            continue
        budget = cap
        for _, signal in sorted(entries, key=lambda entry: (-entry[1].weight, entry[0])):
            allowed = max(0, min(signal.weight, budget))
            signal.weight = allowed
            budget -= allowed
        logger.debug(f"Family '{family}' saturated at its {cap}-point cap (raw total {total}).")

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
    sender_history: Optional[SenderHistory] = None,
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
    trusted = (
        is_trusted_authenticated_sender(from_domain or "", auth)
        and not has_suspicious_reply_diversion(parsed)
    )

    # --- URL Analysis Signals ---
    if url_verdict and url_verdict.urls:
        for u in url_verdict.urls:
            if u.is_mismatched_anchor:
                signals.append(_make_signal(
                    "Deceptive / Mismatched Hyperlink", 30,
                    "Link anchor text displays a domain different from actual target destination.",
                    f"Anchor: '{u.anchor_text}' | Target: '{u.domain}'",
                    strength="strong",
                ))
            if u.is_ip_based:
                signals.append(_make_signal(
                    "IP-Based Link Target", 25,
                    "Link target uses a raw IP address instead of a domain name.",
                    f"Target: '{u.raw_url}'",
                    strength="strong",
                ))
            if u.is_shortener:
                signals.append(_make_signal(
                    "URL Shortener Link", 10,
                    "Link uses a URL shortener service to conceal destination URL.",
                    f"Shortener URL: '{u.raw_url}'",
                    strength="weak",
                ))
            if u.is_suspicious_domain:
                findings_blob = " ".join(u.findings or []).lower()
                # Lookalike / punycode are strong; risky TLD alone is weak.
                if any(k in findings_blob for k in ("lookalike", "punycode", "unicode")):
                    signals.append(_make_signal(
                        "Suspicious Link Domain", 25,
                        "Link targets a lookalike or Punycode/Unicode domain.",
                        f"Domain: '{u.domain}' | {'; '.join(u.findings or [])}",
                        strength="strong",
                    ))
                else:
                    signals.append(_make_signal(
                        "Suspicious Link Domain", 10,
                        "Link uses a high-risk top-level domain. Common on phishing hosts but also on some legitimate sites.",
                        f"Domain: '{u.domain}'",
                        strength="weak",
                    ))
            if (_cross_domain_redirect(u.raw_url)
                    and not any(sig.indicator == "Multiple / Open Redirect Link Parameter"
                                for sig in signals)):
                signals.append(_make_signal(
                    "Multiple / Open Redirect Link Parameter", 15,
                    "Link contains a redirect parameter pointing to a different host, "
                    "which can hide the final destination.",
                    f"Link URL: '{u.raw_url}'",
                    strength="weak",
                ))

    # --- Sender identity signals -----------------------------------------
    # Header Forensics already scores display-name impersonation, lookalike
    # domains, high-risk TLDs and From/Sender/Reply-To/Return-Path mismatches
    # via its own findings (with ESP allowlists and graded risk levels).
    # When a header verdict is supplied it is the single source of truth for
    # those four categories; the blocks below only run when scoring is invoked
    # standalone (e.g. unit tests, or callers without header forensics).
    score_sender_identity_here = header_verdict is None

    # 1. Display Name Impersonation — whole-word brand tokens only
    if score_sender_identity_here and display_name and from_address:
        brand = display_name_brand_conflict(display_name, from_domain or "")
        if brand:
            signals.append(_make_signal(
                "Display Name Impersonation", 25,
                f"Display name references known brand '{brand}', but actual sending domain is '{from_domain}'.",
                f"Display Name: '{display_name}' | From: '{from_address}'",
                strength="strong",
            ))

    # 2. Lookalike Domains & 3. Typosquatting
    if score_sender_identity_here and from_domain:
        brand = looks_like_lookalike(from_domain)
        if brand:
            signals.append(_make_signal(
                "Lookalike / Typosquatted Domain", 25,
                f"Sender domain '{from_domain}' closely resembles target brand domain '{brand}'.",
                f"Sender Domain: '{from_domain}' -> Resembles: '{brand}'",
                strength="strong",
            ))

    # 4. Suspicious TLDs — strong only for core free/abuse TLDs (.tk/.ml/…)
    if score_sender_identity_here and from_domain:
        tld = from_domain.rsplit(".", 1)[-1].lower()
        if tld in CORE_ABUSE_TLDS:
            signals.append(_make_signal(
                "High-Risk Top-Level Domain (TLD)", 20,
                f"Sender domain uses free/abuse-prone top-level domain '.{tld}'.",
                f"Domain: '{from_domain}'",
                strength="strong",
            ))
        elif tld in HIGH_RISK_TLDS:
            signals.append(_make_signal(
                "High-Risk Top-Level Domain (TLD)", 10,
                f"Sender domain uses high-risk top-level domain '.{tld}'. "
                f"Corroborating evidence is required before treating this as phishing.",
                f"Domain: '{from_domain}'",
                strength="weak",
            ))

    # 5. Unicode / Punycode Domains (not covered by header forensics)
    if from_domain:
        unicode_reason = is_punycode_or_unicode(from_domain)
        if unicode_reason:
            signals.append(_make_signal(
                "Punycode / Unicode Domain", 20,
                "Sender domain uses Punycode or non-ASCII characters, commonly exploited for IDN homograph spoofing.",
                unicode_reason,
                strength="strong",
            ))

    # 6. Suspicious sender-header diversion (Reply-To / Sender / Return-Path)
    # Same-org subdomains and trusted ESPs are not mismatches. Only deception
    # evidence (free-mail diversion, high-risk TLD, lookalike) raises a strong
    # signal; plain organisational differences stay weak or are ignored.
    if score_sender_identity_here and from_domain:
        sender_domain = extract_domain(parsed.sender_raw)
        reply_to_domain = extract_domain(parsed.reply_to_raw)
        return_path_domain = extract_domain(parsed.return_path_raw)

        suspicious_parts: list[str] = []
        unrelated_parts: list[str] = []
        for label, other in (
            ("Sender", sender_domain),
            ("Reply-To", reply_to_domain),
            ("Return-Path", return_path_domain),
        ):
            if not other or other == from_domain:
                continue
            relation = domain_relationship(from_domain, other)
            if relation in ("same_org", "trusted_esp"):
                continue
            if relation == "suspicious":
                suspicious_parts.append(f"{label} ('{other}')")
            else:
                unrelated_parts.append(f"{label} ('{other}')")

        if suspicious_parts:
            signals.append(_make_signal(
                "Suspicious Reply / Sender Diversion", 25,
                "Header fields divert replies or bounce handling to a free-mail, "
                "high-risk, or lookalike domain relative to From.",
                f"From Domain: '{from_domain}' | Suspicious: {', '.join(suspicious_parts)}",
                strength="strong",
            ))
        elif unrelated_parts:
            signals.append(_make_signal(
                "Different Sender Header Domains", 8,
                "From differs from Sender/Reply-To/Return-Path without same-org or "
                "trusted-ESP alignment. Different is not automatically malicious.",
                f"From Domain: '{from_domain}' | Different: {', '.join(unrelated_parts)}",
                strength="weak",
            ))

    # 10. Suspicious Keywords — weak; common in corporate and IdP mail
    # "confidential" was removed earlier (corporate disclaimer FP).
    # "security alert" / "action required" alone must never drive High.
    suspicious_kw = ["suspicious activity", "account notice"]
    found_kws = [kw for kw in suspicious_kw if kw in subject.lower() or kw in body.lower()]
    if found_kws:
        signals.append(_make_signal(
            "Suspicious Keywords", 8,
            "Subject or body contains threat-oriented keywords that warrant review.",
            f"Matched Keywords: {', '.join(found_kws)}",
            strength="weak",
        ))

    # 11. Credential Harvesting Language — strong
    for pat in CREDENTIAL_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(_make_signal(
                "Credential Harvesting Language", 30,
                "Email uses phrasing aimed at tricking recipients into revealing account credentials.",
                f"Matched Phrase: '{match.group(0)}'",
                strength="strong",
            ))
            break

    # 12. Urgency Language — weak corroborator
    for pat in URGENCY_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(_make_signal(
                "Urgent Pressure Tactics", 12,
                "Email employs time pressure. Common in both phishing and legitimate business mail.",
                f"Matched Phrase: '{match.group(0)}'",
                strength="weak",
            ))
            break

    # 13. Financial scam language — wire / crypto / gift-card only (strong)
    for pat in FINANCIAL_SCAM_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(_make_signal(
                "Financial Scam Language", 25,
                "Email contains phrasing associated with wire fraud, cryptocurrency, or gift-card scams.",
                f"Matched Phrase: '{match.group(0)}'",
                strength="strong",
            ))
            break

    # 14. Invoice / billing language — weak; ordinary in legitimate AR mail
    for pat in INVOICE_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(_make_signal(
                "Fake Invoice / BEC Indicators", 10,
                "Email references invoices or payment due dates. Common in legitimate billing; "
                "treat as phishing only with corroborating spoofing or malware evidence.",
                f"Matched Phrase: '{match.group(0)}'",
                strength="weak",
            ))
            break

    # 15. Password Reset Scams — strong scam-shaped variants only
    for pat in PASSWORD_RESET_PATTERNS:
        match = re.search(pat, body, re.I) or re.search(pat, subject, re.I)
        if match:
            signals.append(_make_signal(
                "Password Reset Scam Language", 25,
                "Email uses compromise/expiry password-reset phrasing typical of phishing lures.",
                f"Matched Phrase: '{match.group(0)}'",
                strength="strong",
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
        strength = "strong" if (verdict or "").lower() in AUTH_STRONG_VERDICTS else "weak"
        signals.append(_make_signal(
            indicator, weight,
            explanation.format(domain=from_domain or "unknown"),
            f"{mechanism.upper()} Verdict: {(verdict or '').upper()} | Details: {details or '-'}",
            strength=strength,
        ))

    if auth.inconsistencies:
        for inc in auth.inconsistencies:
            # Live vs attributed AR "verification mismatch" is reconstruction noise,
            # not proof of forgery — keep weak. Hard conflicts stay strong.
            soft = "verification mismatch" in (inc or "").lower()
            signals.append(_make_signal(
                "Authentication Inconsistency",
                8 if soft else 20,
                (
                    "Attributed Authentication-Results disagree with live re-check; "
                    "often caused by Received-IP reconstruction limits, not spoofing."
                    if soft else
                    "Detected conflicting authentication headers or domain misalignment."
                ),
                inc,
                strength="weak" if soft else "strong",
            ))

    # --- Header Forensics Signals ---
    if header_verdict and header_verdict.findings:
        for hf in header_verdict.findings:
            title_lc = (hf.title or "").lower()
            # Missing/structural completeness findings are weak and cheap — they
            # describe incomplete messages, not spoofing.
            if "missing" in title_lc:
                w, strength = 8, "weak"
            elif hf.risk_level == "Critical":
                w, strength = 35, "strong"
            elif hf.risk_level == "High":
                w, strength = 25, "strong"
            elif hf.risk_level == "Low":
                w, strength = 5, "weak"
            else:
                # Medium: lookalike TLD etc. already High; remaining Medium is weak
                if any(k in title_lc for k in ("lookalike", "typosquat", "impersonation", "spoofing")):
                    w, strength = 25, "strong"
                elif "high-risk top-level" in title_lc or "raw ip" in title_lc:
                    if "raw ip" in title_lc:
                        w, strength = 20, "strong"
                    else:
                        evidence_lc = (hf.evidence or "").lower()
                        core = any(
                            f".{t}" in evidence_lc or f"'.{t}'" in evidence_lc
                            for t in CORE_ABUSE_TLDS
                        )
                        if core:
                            w, strength = 20, "strong"
                        else:
                            w, strength = 10, "weak"
                elif "reply-to" in title_lc or "return-path" in title_lc or "sender domain difference" in title_lc:
                    # Org/header domain differences without deception evidence.
                    w, strength = 8, "weak"
                else:
                    w, strength = 10, "weak"
            signals.append(_make_signal(
                f"Header Forensics: {hf.title}", w,
                hf.description,
                f"[{hf.risk_level}] {hf.evidence}",
                strength=strength,
            ))

    # --- Routing Forensics Signals ---
    signals.extend(_score_routing_flags(routing))

    # --- Domain Reputation (registration age) ---
    signals.extend(_score_domain_age(domain_age_findings))

    # --- HTML Body Forensics (capped contribution) ---
    signals.extend(_score_html_findings(html_findings))

    # --- Risky Attachments ---
    for att in parsed.attachments:
        filename = att.filename
        ext = att.declared_extension or ""
        reasons: List[tuple[int, str]] = []
        content_features = set(getattr(att, "risky_features", None) or [])

        if getattr(att, "has_double_extension", False) or has_double_extension(filename):
            reasons.append((35, "double extension masking the real file type (e.g. invoice.pdf.exe)"))
        if getattr(att, "is_executable", False) or ext in RISKY_EXTENSIONS:
            reasons.append((30, f"executable/script payload (extension '.{ext}', signature '{att.true_type}')"))
        elif getattr(att, "is_script", False):
            reasons.append((30, f"script payload (extension '.{ext}')"))
        if att.true_type == "exe" and ext not in {"exe", "dll", "scr", "com"}:
            reasons.append((30, f"true file signature is executable but extension is '.{ext}'"))
        if getattr(att, "is_macro_enabled", False) and OFFICE_VBA_MACRO not in content_features:
            reasons.append((25, f"macro-enabled Office document (extension '.{ext}')"))
        if (getattr(att, "is_password_protected", False)
                and not content_features & {ARCHIVE_ENCRYPTED, OFFICE_ENCRYPTED}):
            reasons.append((20, "password-protected archive that cannot be scanned"))
        for feature in getattr(att, "risky_features", None) or []:
            rule = CONTENT_FEATURE_WEIGHTS.get(feature)
            if rule:
                reasons.append(rule)
        if getattr(att, "suspicious_name_flag", False):
            reasons.append((10, "social-engineering lure or randomised filename"))

        if not reasons:
            continue

        weight = max(w for w, _ in reasons)
        detail = "; ".join(text for _, text in reasons)
        engine_findings = getattr(att, "findings", None) or []
        if engine_findings:
            detail += f" | Engine: {'; '.join(engine_findings[:4])}"

        # Executables / double-ext / macros are strong; lure names alone are weak.
        strength = "strong" if weight >= 20 else "weak"
        signals.append(_make_signal(
            "Executable / Suspicious Attachment", weight,
            "Attachment forensics flagged a risky payload, masked extension, macro container, or unscannable archive.",
            f"Filename: '{filename}' | Issues: {detail}",
            strength=strength,
        ))

    # --- Sender history (first contact, BEC baselining) ---
    signals.extend(_score_sender_history(sender_history, {s.indicator for s in signals}))

    # Suppress soft content signals from authenticated known-good brands so that
    # Google/Microsoft/PayPal/Amazon transactional mail cannot accumulate into High.
    _apply_trusted_sender_dampening(signals, trusted)

    # --- Per-family saturation (applied to every family at once) ---
    _apply_family_caps(signals)

    total = sum(s.weight for s in signals)
    display = to_display_score(total)
    _annotate_contributions(signals, total)
    risk_level, classification_reason, rationale = _apply_high_risk_gate(display, signals)

    confidence, confidence_label = assess_confidence(
        parsed, auth, routing, signals, domain_age_findings, html_findings, sender_history
    )
    strong_count = sum(1 for s in signals if s.strength == "strong" and s.weight > 0)
    weak_count = sum(1 for s in signals if s.strength != "strong" and s.weight > 0)

    logger.info(
        f"Message scored {display}/100 ({risk_level} risk, raw weight total {total}"
        f"{', trusted sender' if trusted else ''}). {classification_reason}"
    )

    return ScoringVerdict(
        total_score=total,
        risk_level=risk_level,
        signals=signals,
        display_score=display,
        confidence=confidence,
        confidence_label=confidence_label,
        rationale=rationale,
        classification_reason=classification_reason,
        strong_signal_count=strong_count,
        weak_signal_count=weak_count,
        trusted_sender=trusted,
    )

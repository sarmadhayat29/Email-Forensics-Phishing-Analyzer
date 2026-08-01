"""Domain models for the Email Forensics & Phishing Analyzer.

Replaces loose dictionaries with strict data classes to ensure type safety
and a clean architecture across modules.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Attachment:
    filename: str
    declared_extension: str
    true_type: str
    size_bytes: int
    hashes: dict[str, str] = field(default_factory=dict)
    content_id: Optional[str] = None
    mime_type: str = "application/octet-stream"
    is_executable: bool = False
    is_script: bool = False
    is_macro_enabled: bool = False
    has_double_extension: bool = False
    is_password_protected: bool = False
    suspicious_name_flag: bool = False
    findings: list[str] = field(default_factory=list)


@dataclass
class ExtractedURL:
    raw_url: str
    normalized_url: str
    domain: str
    anchor_text: str = ""
    is_ip_based: bool = False
    is_shortener: bool = False
    is_suspicious_domain: bool = False
    is_mismatched_anchor: bool = False
    is_hidden: bool = False
    findings: list[str] = field(default_factory=list)


@dataclass
class URLAnalysisVerdict:
    urls: list[ExtractedURL] = field(default_factory=list)
    total_urls: int = 0
    suspicious_count: int = 0
    flags: list[str] = field(default_factory=list)


@dataclass
class Hop:
    hop_number: int = 0
    raw: str = ""
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    ip: Optional[str] = None
    ip_type: str = "Unknown"  # Public, Private, Loopback, CGNAT
    timestamp: Optional[str] = None
    delay_seconds: float = 0.0
    protocol: Optional[str] = None
    for_recipient: Optional[str] = None
    flags: list[str] = field(default_factory=list)


@dataclass
class RoutingTimelineEntry:
    hop_number: int
    timestamp: str
    delay_display: str
    from_host: str
    by_host: str
    ip_info: str
    summary: str


@dataclass
class RoutingVerdict:
    hops: list[Hop] = field(default_factory=list)
    hop_count: int = 0
    timeline: list[RoutingTimelineEntry] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


@dataclass
class AuthVerdict:
    raw: str
    source: str
    spf: str = "not_present"
    spf_details: str = ""
    dkim: str = "not_present"
    dkim_details: str = ""
    dmarc: str = "not_present"
    dmarc_details: str = ""
    explanation: str = ""
    inconsistencies: list[str] = field(default_factory=list)
    note: Optional[str] = None
    #: True when live re-verification was attempted for this message, whether or
    #: not it succeeded; ``live_verified`` is True only when at least one
    #: mechanism was independently confirmed against DNS / the signature.
    live_attempted: bool = False
    live_verified: bool = False
    #: Per-mechanism provenance lines ("live-verified" vs "header-derived").
    live_checks: list[str] = field(default_factory=list)
    #: DMARC ``p=`` (or ``sp=``) policy when a record was read live.
    dmarc_policy: Optional[str] = None


@dataclass
class DomainAgeFinding:
    """Registration age of one domain observed in a message.

    ``classification`` is the only field scoring reads:

    * ``newly_registered`` — younger than ``NRD_DAYS``
    * ``young``            — younger than ``YOUNG_DOMAIN_DAYS``
    * ``established``      — older than that
    * ``exempt``           — brand-owned, so never looked up or scored
    * ``unknown``          — disabled, skipped, or the lookup did not answer;
      explicitly *not* evidence of anything.
    """
    domain: str
    classification: str = "unknown"
    age_days: Optional[int] = None
    created: Optional[str] = None
    registrar: str = ""
    #: Where the domain was seen: "sender" (header From) or "link" (URL host).
    origin: str = "sender"
    #: Provenance of the answer: whois / cache / exempt / disabled / skipped / error.
    source: str = ""
    detail: str = ""

    @property
    def resolved(self) -> bool:
        """True when a registration date was actually established."""
        return self.age_days is not None


@dataclass
class HtmlFinding:
    """One structural threat observed in the HTML part of a message body.

    ``category`` is the only field scoring reads; it is a stable machine key
    from :mod:`html_analysis` (``hidden_text``, ``credential_form``, ...).
    ``severity`` grades the same category by how strongly it indicates abuse,
    so a preheader-length hidden block and a filter-poisoning one are the same
    category at different severities.
    """
    category: str
    indicator: str
    severity: str = "Medium"  # High | Medium | Low
    #: Truncated snippet of the offending markup or text.
    evidence: str = ""
    explanation: str = ""
    #: Supplementary measurement or threshold note for the analyst.
    detail: str = ""


@dataclass
class PhishingSignal:
    indicator: str
    weight: int
    explanation: str
    evidence: str
    signal: str = ""
    detail: str = ""
    title: str = ""
    severity: str = "High"
    recommendation: str = "Investigate signal evidence and block malicious sender/domain if verified."

    def __post_init__(self):
        if not self.title:
            self.title = self.indicator
        if not self.signal:
            self.signal = self.indicator
        if not self.detail:
            self.detail = f"{self.explanation} (Evidence: {self.evidence})"
        if not self.severity:
            if self.weight >= 30:
                self.severity = "Critical"
            elif self.weight >= 20:
                self.severity = "High"
            elif self.weight >= 10:
                self.severity = "Medium"
            else:
                self.severity = "Low"



@dataclass
class ScoringVerdict:
    #: Raw sum of triggered signal weights. Unbounded; used internally and for
    #: analyst transparency.
    total_score: int
    risk_level: str
    signals: list[PhishingSignal] = field(default_factory=list)
    #: Raw score mapped onto a 0-100 presentation scale (rank preserving).
    display_score: int = 0
    #: How much verifiable evidence backed the verdict, 0-100, or None when
    #: there was too little evidence to make a claim.
    confidence: Optional[int] = None
    confidence_label: str = "Unknown"


@dataclass
class ParsedMessage:
    headers: dict[str, str | list[str]] = field(default_factory=dict)
    from_raw: str = ""
    to_raw: str = ""
    sender_raw: str = ""
    cc_raw: str = ""
    bcc_raw: str = ""
    subject: str = ""
    reply_to_raw: str = ""
    return_path_raw: str = ""
    message_id: str = ""
    date: str = ""
    received_chain: list[str] = field(default_factory=list)
    authentication_results: list[str] = field(default_factory=list)
    body_plain: str = ""
    body_html: str = ""
    mime_structure: str = ""
    attachments: list[Attachment] = field(default_factory=list)
    embedded_images: list[Attachment] = field(default_factory=list)
    #: Untouched bytes of the source file, when the ingest stage could preserve
    #: them. Required for DKIM verification, which is byte-exact — a
    #: re-serialised message would produce a bogus body hash. Never part of a
    #: Finding, so reports and API payloads stay JSON-serialisable.
    raw_bytes: bytes = b""


@dataclass
class HeaderFinding:
    title: str
    description: str
    risk_level: str
    evidence: str
    recommendation: str


@dataclass
class HeaderAnalysisVerdict:
    findings: list[HeaderFinding] = field(default_factory=list)


@dataclass
class Finding:
    file: str
    subject: str
    from_addr: str
    sender_addr: str
    to_addr: str
    cc_addr: str
    bcc_addr: str
    reply_to: str
    return_path: str
    date: str
    message_id: str
    authentication: AuthVerdict
    routing: RoutingVerdict
    attachments: list[Attachment]
    embedded_images: list[Attachment]
    mime_structure: str
    header_findings: list[HeaderFinding]
    url_analysis: URLAnalysisVerdict
    #: Presentation risk score on a 0-100 scale.
    score: int
    risk_level: str
    signals: list[PhishingSignal]
    #: Raw weighted-evidence total behind ``score``, kept for analyst audit.
    raw_score: int = 0
    confidence: Optional[int] = None
    confidence_label: str = "Unknown"
    #: Registration age of the sender and linked domains, when WHOIS answered.
    domain_age: list[DomainAgeFinding] = field(default_factory=list)
    #: Structural threats found in the HTML body, when one was present.
    html_findings: list[HtmlFinding] = field(default_factory=list)




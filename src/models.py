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
    total_score: int
    risk_level: str
    signals: list[PhishingSignal] = field(default_factory=list)


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
    score: int
    risk_level: str
    signals: list[PhishingSignal]




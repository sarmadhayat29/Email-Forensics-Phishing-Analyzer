"""HTML body forensics — structural threats hidden in the HTML part.

The HTML part of a message is an attacker's richest canvas: text can be cloaked
from the reader while still poisoning content filters, credentials can be
harvested inline, and a redirect can fire without a click. This module inspects
the *structure* of that markup and reports what it observes. It deliberately
decides nothing about overall risk — mapping observations onto weights is
:mod:`scoring`'s job.

Design constraints mirror :mod:`live_auth` and :mod:`domain_age`:

1. **Never break the pipeline.** Every entry point is wrapped, so a malformed
   body, a hostile document or a parser bug yields an empty finding list rather
   than an exception.
2. **Bounded work.** The body is truncated before parsing, so a multi-megabyte
   document cannot stall an analysis.
3. **Stdlib only.** ``html.parser`` plus narrowly scoped regular expressions;
   no new dependency, and nothing is fetched or executed.
4. **Conservative by construction.** Legitimate bulk mail hides preheader text,
   paints white text over dark banners, ships zero-height spacer cells and
   wraps Outlook conditional comments. Each detector is written so ordinary
   marketing markup either lands at Low severity or does not fire at all.
"""

import re
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

from models import HtmlFinding
from logger import get_logger

logger = get_logger(__name__)


# --------------------------------------------------------------------------- #
# Category keys — the stable contract scoring depends on
# --------------------------------------------------------------------------- #

HIDDEN_TEXT = "hidden_text"
CREDENTIAL_FORM = "credential_form"
FORM_EXTERNAL_ACTION = "form_external_action"
FORM_CREDENTIAL_FIELDS = "form_credential_fields"
SCRIPT = "script"
IFRAME = "iframe"
ACTIVE_CONTENT = "active_content"
EVENT_HANDLER = "event_handler"
META_REFRESH = "meta_refresh"
DATA_URI_HTML = "data_uri_html"
DATA_URI_OTHER = "data_uri_other"
JAVASCRIPT_URI = "javascript_uri"
COMMENT_OBFUSCATION = "comment_obfuscation"
ENTITY_OBFUSCATION = "entity_obfuscation"
IMAGE_ONLY_BODY = "image_only_body"

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


# --------------------------------------------------------------------------- #
# Thresholds
# --------------------------------------------------------------------------- #

#: Parsing is linear, but a hostile body should still not be unbounded work.
MAX_HTML_BYTES = 2_000_000

#: Evidence snippets are truncated: a report is read by humans.
EVIDENCE_CHARS = 160

#: Bulk senders put a short "preheader" in a display:none block for the inbox
#: preview line. Up to this much cloaked text is treated as that convention.
PREHEADER_CHARS = 200

#: Cloaked text this long is a filter-poisoning / cloaking payload, not a
#: preview line.
HIDDEN_HIGH_CHARS = 600

#: An "image-only" body needs both a near-empty HTML part and a near-empty
#: plain-text alternative before it is worth mentioning at all.
IMAGE_ONLY_TEXT_CHARS = 80
IMAGE_ONLY_PLAIN_CHARS = 200

#: Numeric character references that decode to plain ASCII letters/digits are
#: an evasion tactic, but a handful occur naturally; only a sustained run counts.
MIN_OBFUSCATED_ENTITIES = 20

#: A single credential-looking text field (an unsubscribe form's e-mail box) is
#: not evidence; a cluster of them is.
MIN_CREDENTIAL_FIELDS = 2

DEFAULT_PAGE_BG = "#ffffff"

_VOID_TAGS = {
    "area", "base", "basefont", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}

_TRANSPARENT = {"", "transparent", "none", "inherit", "initial", "unset"}

#: Near-white foreground/background tokens. Kept deliberately small: the check
#: only fires on an (almost) exact match, so tinted text is never called hidden.
_WHITEISH = ("#ffffff", "#fff", "white", "rgb(255,255,255)", "#fefefe", "#fcfcfc", "#fdfdfd")


# --------------------------------------------------------------------------- #
# CSS helpers
# --------------------------------------------------------------------------- #

# Declarations that take content out of the reader's view. Matching one is
# cheap and low-consequence: hidden-ness only matters once text is found
# inside the element, so a mis-classified empty spacer costs nothing.
_HIDING_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"display:none"), "display:none"),
    (re.compile(r"visibility:(?:hidden|collapse)"), "visibility:hidden"),
    (re.compile(r"opacity:0(?![.\d])"), "opacity:0"),
    (re.compile(r"font-size:0(?:\.0+)?(?:px|pt|em|rem|%)?(?![.\d])"), "font-size:0"),
    (re.compile(r"font-size:1(?:px|pt)(?![.\d])"), "font-size:1px"),
    (re.compile(r"mso-hide:all"), "mso-hide:all"),
    (re.compile(r"max-height:0(?:px|pt|em|rem|%)?(?![.\d])"), "max-height:0"),
    (re.compile(r"line-height:0(?:px|pt|em|rem|%)?(?![.\d])"), "line-height:0"),
    (re.compile(r"(?:^|;)(?:height|width):0(?:px|pt|em|rem|%)?(?![.\d])"), "zero dimension"),
    (re.compile(r"text-indent:-\d{3,}"), "off-canvas text-indent"),
    (re.compile(r"(?:left|top|margin-left|margin-top):-\d{3,}"), "off-canvas positioning"),
    (re.compile(r"clip:rect\(0[a-z]*,0[a-z]*,0[a-z]*,0[a-z]*\)"), "clipped to zero"),
]

_CSS_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_STYLE_BLOCK_RE = re.compile(r"<style[^>]*>(.*?)</style>", re.I | re.S)
_SELECTOR_TOKEN_RE = re.compile(r"([.#])([a-z0-9_-]+)")
_COLOR_DECL_RE = re.compile(r"(?:^|;)color:([^;]+)")
_BACKGROUND_DECL_RE = re.compile(r"(?:^|;)background(?:-color)?:([^;]+)")


def _norm_css(value: str) -> str:
    """Lower-case a style value and drop all whitespace and CSS comments."""
    if not value:
        return ""
    return re.sub(r"\s+", "", _CSS_COMMENT_RE.sub("", value.lower()))


def _is_whiteish(colour: str) -> bool:
    value = (colour or "").strip().strip(";")
    return any(value.startswith(token) for token in _WHITEISH)


def _declared_background(css: str) -> str:
    match = _BACKGROUND_DECL_RE.search(css)
    return match.group(1) if match else ""


def _colour_cloaked(css: str, background: str) -> str:
    """Detect same-colour-as-background text (the classic white-on-white).

    ``background`` is the *effective* background inherited down the element
    stack, so white text inside a dark hero banner — extremely common in real
    marketing templates — is correctly left alone.
    """
    match = _COLOR_DECL_RE.search(css)
    if not match or not _is_whiteish(match.group(1)):
        return ""
    effective = background if background not in _TRANSPARENT else DEFAULT_PAGE_BG
    if not _is_whiteish(effective):
        return ""
    return "white text on a white background"


def _hidden_selectors(body_html: str) -> Tuple[set, set]:
    """Class and id names that a ``<style>`` block hides.

    Bulk-mail templates hide their preheader through a stylesheet class far more
    often than through an inline style, so the sheet is read in a cheap pre-pass
    before the document is walked.
    """
    classes: set = set()
    ids: set = set()
    for block in _STYLE_BLOCK_RE.findall(body_html):
        css = _norm_css(block)
        for chunk in css.split("}"):
            if "{" not in chunk:
                continue
            selector, _, declarations = chunk.rpartition("{")
            if not any(pattern.search(declarations) for pattern, _label in _HIDING_PATTERNS):
                continue
            # Drop any @media / @supports prelude still attached to the selector.
            selector = selector.rsplit("{", 1)[-1]
            for token in _SELECTOR_TOKEN_RE.finditer(selector):
                (classes if token.group(1) == "." else ids).add(token.group(2))
    return classes, ids


# --------------------------------------------------------------------------- #
# Text helpers
# --------------------------------------------------------------------------- #

# Whitespace, non-breaking spaces and zero-width characters carry no meaning.
# Excluding them is the single most important false-positive guard for cloaked
# text: preheaders are routinely padded with hundreds of &zwnj;/&nbsp; pairs to
# push real content out of the inbox preview line.
_INSIGNIFICANT_RE = re.compile(r"[\s\u00a0\u00ad\u200b-\u200f\u2028\u2029\u2060\ufeff]+")


def _meaningful_length(text: str) -> int:
    return len(_INSIGNIFICANT_RE.sub("", text or ""))


def _snippet(text: str, limit: int = EVIDENCE_CHARS) -> str:
    """Collapse a fragment of markup or text onto one truncated line."""
    collapsed = " ".join(str(text or "").split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit].rstrip() + "..."


def _attr_dict(attrs) -> Dict[str, str]:
    return {(name or "").lower(): (value if value is not None else "") for name, value in attrs}


def _is_external_action(action: str) -> bool:
    value = (action or "").strip().lower()
    return value.startswith(("http://", "https://", "//", "mailto:", "ftp://"))


def _is_hostile_uri(uri: str) -> bool:
    value = _norm_css(uri or "")
    return value.startswith(("javascript:", "vbscript:", "data:text/html", "data:application"))


def _zero_dimension(attributes: Dict[str, str]) -> bool:
    return any((attributes.get(name) or "").strip().lower() in {"0", "0px", "0%"}
               for name in ("width", "height"))


_STRONG_CREDENTIAL_FIELD_RE = re.compile(
    r"(pass\s*wo?r?d|passcode|current-password|new-password|cc-number|card\s*number|"
    r"cvv|cvc|security\s*code|ssn|social\s*security|sort\s*code|routing|iban|otp|"
    r"one\s*time|mfa|2fa|token|pin\b)", re.I
)
_CREDENTIAL_FIELD_RE = re.compile(
    r"(user(name|id)?|login|signin|e?-?mail|account|customer\s*id|dob|birth)", re.I
)


# --------------------------------------------------------------------------- #
# Document walker
# --------------------------------------------------------------------------- #


class _BodyScanner(HTMLParser):
    """Single-pass structural scan of an HTML body.

    Collects observations only; no thresholds and no verdicts live here. The
    parser is intentionally forgiving — unbalanced tags are common in real mail
    and must not derail the walk.
    """

    def __init__(self, hidden_classes: set, hidden_ids: set):
        super().__init__(convert_charrefs=True)
        self.hidden_classes = hidden_classes
        self.hidden_ids = hidden_ids

        self._stack: List[dict] = []
        self._hidden_depth = 0
        self._raw_mode: Optional[str] = None
        self._form_depth = 0
        self._text_tail = ""
        self._comment_pending = False

        self.hidden_chars = 0
        self.hidden_reasons: List[str] = []
        self.hidden_sample = ""
        self.visible_chars = 0
        self.image_count = 0
        self.form_count = 0
        self.scripts: List[str] = []
        self.frames: List[str] = []
        self.hostile_frames: List[str] = []
        self.active_objects: List[str] = []
        self.event_handlers: List[str] = []
        self.meta_refresh: List[str] = []
        self.password_fields: List[str] = []
        self.strong_credential_fields: List[str] = []
        self.credential_fields: List[str] = []
        self.external_actions: List[str] = []
        self.comment_splits: List[str] = []

    # -- structural observations -------------------------------------------

    def handle_starttag(self, tag, attrs):
        attributes = _attr_dict(attrs)
        self._text_tail = ""

        if tag in ("script", "style"):
            self._raw_mode = tag

        if tag == "script":
            src = attributes.get("src", "").strip()
            self.scripts.append(f'<script src="{_snippet(src, 80)}">' if src
                                else "inline <script> block")
        elif tag in ("iframe", "frame"):
            src = (attributes.get("src") or attributes.get("srcdoc") or "").strip()
            entry = f'<{tag} src="{_snippet(src, 80)}">' if src else f"<{tag}> without a source"
            self.frames.append(entry)
            if _is_hostile_uri(src) or "srcdoc" in attributes:
                self.hostile_frames.append(entry)
        elif tag in ("object", "embed", "applet"):
            target = (attributes.get("data") or attributes.get("src") or "").strip()
            self.active_objects.append(f'<{tag} {_snippet(target, 60)}>'.replace(" >", ">"))
        elif tag == "meta":
            if (attributes.get("http-equiv") or "").strip().lower() == "refresh":
                self.meta_refresh.append(_snippet(attributes.get("content", ""), 120))
        elif tag == "form":
            self.form_count += 1
            self._form_depth += 1
            action = (attributes.get("action") or "").strip()
            if _is_external_action(action):
                self.external_actions.append(_snippet(action, 100))
        elif tag in ("input", "textarea", "select"):
            self._record_field(tag, attributes)
        elif tag == "img":
            self.image_count += 1

        for name, value in attributes.items():
            if name.startswith("on") and len(name) > 2:
                self.event_handlers.append(f'{name}="{_snippet(value, 60)}"')

        reason, background = self._presentation(tag, attributes)
        if tag not in _VOID_TAGS:
            self._stack.append({"tag": tag, "reason": reason, "bg": background})
            if reason:
                self._hidden_depth += 1

    def handle_endtag(self, tag):
        self._text_tail = ""
        if self._raw_mode == tag:
            self._raw_mode = None
        if tag == "form" and self._form_depth:
            self._form_depth -= 1

        # Unwind to the matching open tag; an end tag that was never opened is
        # ignored rather than allowed to corrupt the stack.
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index]["tag"] == tag:
                for entry in self._stack[index:]:
                    if entry["reason"]:
                        self._hidden_depth -= 1
                del self._stack[index:]
                return

    def handle_data(self, data):
        if not data:
            return

        if self._comment_pending:
            self._comment_pending = False
            if data[:1].isalnum() and self._text_tail[-1:].isalnum():
                self.comment_splits.append(f"{self._text_tail[-14:]}<!-- -->{data[:14]}")

        if self._raw_mode:
            return

        length = _meaningful_length(data)
        if self._hidden_depth > 0:
            self.hidden_chars += length
            if length:
                self._note_hidden_reasons()
                if len(self.hidden_sample) < EVIDENCE_CHARS:
                    self.hidden_sample = _snippet(f"{self.hidden_sample} {data}")
        else:
            self.visible_chars += length

        tail = data.rstrip()
        if tail:
            self._text_tail = (self._text_tail + tail)[-24:]

    def handle_comment(self, data):
        text = (data or "").strip().lower()
        # Outlook conditional comments wrap whole blocks in every commercial
        # template; they are markup, not obfuscation.
        if text.startswith(("[if", "<![", "[endif")) or "endif" in text:
            self._comment_pending = False
            self._text_tail = ""
            return
        self._comment_pending = bool(self._text_tail) and self._text_tail[-1].isalnum()

    # -- helpers ------------------------------------------------------------

    def _note_hidden_reasons(self) -> None:
        for entry in self._stack:
            if entry["reason"] and entry["reason"] not in self.hidden_reasons:
                self.hidden_reasons.append(entry["reason"])

    def _record_field(self, tag: str, attributes: Dict[str, str]) -> None:
        field_type = (attributes.get("type") or ("text" if tag == "input" else tag)).strip().lower()
        if field_type in {"hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file"}:
            return

        label = _snippet(attributes.get("name") or attributes.get("id")
                         or attributes.get("placeholder") or "(unnamed)", 40)
        if field_type == "password":
            self.password_fields.append(label)
            return

        haystack = " ".join(attributes.get(name, "") for name in
                            ("name", "id", "placeholder", "autocomplete", "aria-label"))
        if _STRONG_CREDENTIAL_FIELD_RE.search(haystack):
            self.strong_credential_fields.append(label)
        elif _CREDENTIAL_FIELD_RE.search(haystack):
            self.credential_fields.append(label)

    def _presentation(self, tag: str, attributes: Dict[str, str]) -> Tuple[str, str]:
        """Return ``(hidden_reason, effective_background)`` for one element."""
        parent_bg = self._stack[-1]["bg"] if self._stack else DEFAULT_PAGE_BG
        css = _norm_css(attributes.get("style", ""))
        own_bg = _declared_background(css) or _norm_css(attributes.get("bgcolor", ""))
        background = parent_bg if own_bg in _TRANSPARENT else own_bg

        if tag in {"head", "title", "style", "script", "meta", "link", "base"}:
            return "", background

        reasons: List[str] = []
        for pattern, label in _HIDING_PATTERNS:
            if pattern.search(css):
                reasons.append(f"inline CSS {label}")
                break

        if "hidden" in attributes and (attributes["hidden"] or "").strip().lower() in {"", "hidden", "true"}:
            reasons.append("HTML5 hidden attribute")

        cloaked = _colour_cloaked(css, background)
        if cloaked:
            reasons.append(cloaked)

        for name in (attributes.get("class") or "").lower().split():
            if name in self.hidden_classes:
                reasons.append(f"stylesheet class '.{name}' hides its content")
                break

        element_id = (attributes.get("id") or "").strip().lower()
        if element_id and element_id in self.hidden_ids:
            reasons.append(f"stylesheet id '#{element_id}' hides its content")

        if _zero_dimension(attributes):
            reasons.append("zero width/height attribute")

        return "; ".join(reasons), background


# --------------------------------------------------------------------------- #
# Raw-text detectors
# --------------------------------------------------------------------------- #

_DATA_URI_RE = re.compile(r"data:([a-z0-9][a-z0-9!#$&^_+./-]*)?\s*[;,]", re.I)
_URI_TERMINATOR_RE = re.compile(r"""["'<>\s)]""")
_SCRIPT_URI_RE = re.compile(
    r"""(href|src|action|formaction|background|data|xlink:href)\s*=\s*["']?\s*(javascript|vbscript):([^"'>\s]{0,60})""",
    re.I,
)
_NUMERIC_ENTITY_RE = re.compile(r"&#(x[0-9a-f]{1,4}|\d{1,5});", re.I)


def _uri_snippet(body_html: str, start: int, limit: int = 90) -> str:
    """Quote one URI from the source without dragging in the markup around it."""
    window = body_html[start:start + limit]
    terminator = _URI_TERMINATOR_RE.search(window)
    if terminator and terminator.start():
        return _snippet(window[:terminator.start()], limit)
    return _snippet(window, limit)


def _obfuscated_entity_count(body_html: str) -> int:
    """Count numeric character references that decode to plain ASCII alphanumerics.

    ``&#8217;`` (smart quote) and ``&#160;`` (nbsp) are ordinary typography and
    are not counted; ``&#112;&#97;&#115;&#115;`` for "pass" is evasion.
    """
    count = 0
    for match in _NUMERIC_ENTITY_RE.finditer(body_html):
        token = match.group(1)
        try:
            code = int(token[1:], 16) if token[0].lower() == "x" else int(token)
        except ValueError:
            continue
        if code < 128 and chr(code).isalnum():
            count += 1
    return count


def _raw_findings(body_html: str) -> List[HtmlFinding]:
    """Detectors that read the markup as text rather than as a document tree.

    Data and script URIs can hide in inline CSS, in attributes the tree walk
    does not model, and in malformed markup, so they are matched on the source.
    """
    findings: List[HtmlFinding] = []

    executable_uris: List[str] = []
    other_uris: List[str] = []
    for match in _DATA_URI_RE.finditer(body_html):
        mime = (match.group(1) or "").lower()
        # Inline images and fonts are how HTML mail legitimately embeds media.
        if mime.startswith(("image/", "font/", "audio/", "video/")):
            continue
        snippet = _uri_snippet(body_html, match.start())
        if (mime in {"text/html", "text/xml", "application/xhtml+xml", "image/svg+xml"}
                or "javascript" in mime or "ecmascript" in mime):
            executable_uris.append(snippet)
        else:
            other_uris.append(snippet)

    if executable_uris:
        findings.append(HtmlFinding(
            category=DATA_URI_HTML,
            indicator="Executable data: URI Payload",
            severity="High",
            evidence=_snippet(" | ".join(executable_uris[:2])),
            explanation="The body embeds a document or script inline as a data: URI. Because the "
                        "payload never touches a web server it bypasses URL reputation entirely, and "
                        "'data:text/html' phishing pages render a full credential form from the "
                        "message itself.",
            detail=f"{len(executable_uris)} executable data: URI(s) present.",
        ))
    elif other_uris:
        findings.append(HtmlFinding(
            category=DATA_URI_OTHER,
            indicator="Inline data: URI Payload",
            severity="Medium",
            evidence=_snippet(" | ".join(other_uris[:2])),
            explanation="A non-image payload is embedded inline as a data: URI, which delivers "
                        "content without any URL for a gateway or proxy to inspect.",
            detail=f"{len(other_uris)} data: URI(s) present.",
        ))

    script_uris = [f"{m.group(1).lower()}=\"{m.group(2).lower()}:{_snippet(m.group(3), 40)}\""
                   for m in _SCRIPT_URI_RE.finditer(body_html)]
    if script_uris:
        findings.append(HtmlFinding(
            category=JAVASCRIPT_URI,
            indicator="Script URI in Markup Attribute",
            severity="High",
            evidence=_snippet(" | ".join(script_uris[:2])),
            explanation="An attribute targets a 'javascript:' or 'vbscript:' URI. Legitimate mail "
                        "never does this; it is used to obscure a link's real destination or to "
                        "execute code in clients that still permit it.",
            detail=f"{len(script_uris)} script URI(s) present.",
        ))

    entities = _obfuscated_entity_count(body_html)
    if entities >= MIN_OBFUSCATED_ENTITIES:
        findings.append(HtmlFinding(
            category=ENTITY_OBFUSCATION,
            indicator="Character-Entity Obfuscation",
            severity="Medium",
            evidence=f"{entities} numeric character references decode to ASCII letters/digits.",
            explanation="Ordinary words are written as numeric character references so that keyword "
                        "matching sees markup where the reader sees text — a deliberate attempt to "
                        "evade content inspection.",
            detail=f"Threshold for reporting is {MIN_OBFUSCATED_ENTITIES} references.",
        ))

    return findings


# --------------------------------------------------------------------------- #
# Structural findings
# --------------------------------------------------------------------------- #


def _hidden_text_finding(scanner: _BodyScanner) -> Optional[HtmlFinding]:
    """Grade cloaked text, treating preheader-length blocks as the convention.

    Padding (whitespace, nbsp, zero-width characters) is excluded from the
    count, so a legitimate preheader stuffed with hundreds of ``&zwnj;`` pairs
    is measured on its real content.
    """
    hidden = scanner.hidden_chars
    if hidden <= 0:
        return None

    reasons = _snippet("; ".join(scanner.hidden_reasons[:3]), 100) or "hidden by CSS"
    evidence = (f"{hidden} cloaked character(s) vs {scanner.visible_chars} visible "
                f"| Technique: {reasons} | Text: \"{_snippet(scanner.hidden_sample, 90)}\"")

    if hidden <= PREHEADER_CHARS:
        return HtmlFinding(
            category=HIDDEN_TEXT,
            indicator="Preheader-Length Hidden Text",
            severity="Low",
            evidence=evidence,
            explanation="A short block of text is hidden from the reader. Bulk senders legitimately "
                        "use this for the inbox preview line, so at this length it is noted for "
                        "completeness rather than treated as evidence of phishing.",
            detail=f"Up to {PREHEADER_CHARS} cloaked characters is treated as a normal preheader.",
        )

    if hidden < HIDDEN_HIGH_CHARS:
        severity, indicator = "Medium", "Cloaked Text Block"
    else:
        severity, indicator = "High", "Substantial Cloaked Text"

    return HtmlFinding(
        category=HIDDEN_TEXT,
        indicator=indicator,
        severity=severity,
        evidence=evidence,
        explanation="The body hides substantially more text than a preview line from the reader "
                    "while still presenting it to automated filters. This is used to dilute "
                    "spam/phishing scoring with innocuous words and to conceal content the "
                    "recipient never sees.",
        detail=f"Graded Medium above {PREHEADER_CHARS} and High from {HIDDEN_HIGH_CHARS} "
               f"cloaked characters.",
    )


def _form_findings(scanner: _BodyScanner) -> List[HtmlFinding]:
    findings: List[HtmlFinding] = []

    if scanner.password_fields or scanner.strong_credential_fields:
        fields = scanner.password_fields + scanner.strong_credential_fields
        destination = (f" submitting to '{scanner.external_actions[0]}'"
                       if scanner.external_actions else " (submission target not declared in markup)")
        findings.append(HtmlFinding(
            category=CREDENTIAL_FORM,
            indicator="Credential Harvesting Form In Message Body",
            severity="High" if scanner.password_fields else "Medium",
            evidence=_snippet(f"Field(s): {', '.join(fields[:4])}{destination}"),
            explanation="The body contains an input form asking for a password or other secret. "
                        "Genuine providers direct users to their own website and never collect "
                        "credentials inside an e-mail, so this is a direct harvesting attempt.",
            detail=f"{len(fields)} sensitive field(s) across {scanner.form_count} form(s).",
        ))
    elif len(scanner.credential_fields) >= MIN_CREDENTIAL_FIELDS:
        findings.append(HtmlFinding(
            category=FORM_CREDENTIAL_FIELDS,
            indicator="Identity Fields In Message Body Form",
            severity="Medium",
            evidence=_snippet(f"Field(s): {', '.join(scanner.credential_fields[:4])}"),
            explanation="A form in the body collects identity details such as a username, account "
                        "number or date of birth. A single e-mail address box (an unsubscribe form) "
                        "is not reported; a cluster of identity fields is.",
            detail=f"{len(scanner.credential_fields)} identity field(s) detected.",
        ))

    if scanner.external_actions and not (scanner.password_fields or scanner.strong_credential_fields):
        findings.append(HtmlFinding(
            category=FORM_EXTERNAL_ACTION,
            indicator="Form Posting To An External Destination",
            severity="Medium",
            evidence=_snippet(f"Action: {scanner.external_actions[0]}"),
            explanation="An in-body form submits whatever the recipient types to an external "
                        "address. Whatever the field labels claim, the destination — not the "
                        "message — decides where the data goes.",
            detail=f"{len(scanner.external_actions)} external form action(s).",
        ))

    return findings


def _structural_findings(scanner: _BodyScanner, body_plain: str) -> List[HtmlFinding]:
    findings: List[HtmlFinding] = []

    hidden = _hidden_text_finding(scanner)
    if hidden:
        findings.append(hidden)

    findings.extend(_form_findings(scanner))

    if scanner.meta_refresh:
        findings.append(HtmlFinding(
            category=META_REFRESH,
            indicator="Automatic Meta-Refresh Redirect",
            severity="High",
            evidence=_snippet(f"<meta http-equiv=\"refresh\" content=\"{scanner.meta_refresh[0]}\">"),
            explanation="The body carries a meta-refresh directive, which navigates the reader to "
                        "another location with no click and no visible link. It is a standard way "
                        "to launder a redirect chain past link inspection.",
            detail=f"{len(scanner.meta_refresh)} refresh directive(s).",
        ))

    if scanner.hostile_frames:
        findings.append(HtmlFinding(
            category=IFRAME,
            indicator="Inline Frame With Executable Source",
            severity="High",
            evidence=_snippet(" | ".join(scanner.hostile_frames[:2])),
            explanation="An inline frame renders script or inline HTML from within the message, "
                        "which is how a credential page or exploit is delivered without hosting it "
                        "anywhere a reputation service can see.",
            detail=f"{len(scanner.frames)} frame(s) total.",
        ))
    elif scanner.frames:
        findings.append(HtmlFinding(
            category=IFRAME,
            indicator="Inline Frame In Message Body",
            severity="Medium",
            evidence=_snippet(" | ".join(scanner.frames[:2])),
            explanation="The body embeds an inline frame. Mail clients block these, but their "
                        "presence indicates markup written for a browser-rendered attack page "
                        "rather than for e-mail.",
            detail=f"{len(scanner.frames)} frame(s) detected.",
        ))

    if scanner.scripts:
        findings.append(HtmlFinding(
            category=SCRIPT,
            indicator="Script Block In Message Body",
            severity="Medium",
            evidence=_snippet(" | ".join(scanner.scripts[:2])),
            explanation="The body contains a script element. No legitimate mail template ships "
                        "JavaScript: modern clients strip it, so its presence points at markup "
                        "lifted from a phishing page or aimed at a permissive client or webmail "
                        "preview.",
            detail=f"{len(scanner.scripts)} script element(s).",
        ))

    if scanner.active_objects:
        findings.append(HtmlFinding(
            category=ACTIVE_CONTENT,
            indicator="Embedded Active Content",
            severity="Medium",
            evidence=_snippet(" | ".join(scanner.active_objects[:2])),
            explanation="An <object>, <embed> or <applet> element attempts to load active content "
                        "such as Flash, a plug-in or an external binary from inside the message.",
            detail=f"{len(scanner.active_objects)} active-content element(s).",
        ))

    if scanner.event_handlers:
        findings.append(HtmlFinding(
            category=EVENT_HANDLER,
            indicator="Inline Event-Handler Attributes",
            severity="Medium",
            evidence=_snippet(" | ".join(scanner.event_handlers[:3])),
            explanation="Markup carries inline event handlers (onclick, onerror, onload). These are "
                        "script hooks, and in mail they usually survive from a copied web page or "
                        "are used to rewrite a link target after rendering.",
            detail=f"{len(scanner.event_handlers)} handler attribute(s).",
        ))

    if scanner.comment_splits:
        findings.append(HtmlFinding(
            category=COMMENT_OBFUSCATION,
            indicator="Comment-Split Words",
            severity="Medium",
            evidence=_snippet(" | ".join(scanner.comment_splits[:3])),
            explanation="Words are broken apart by HTML comments so that keyword matching sees "
                        "fragments while the reader sees whole words. Outlook conditional comments, "
                        "which every commercial template uses, are excluded from this check.",
            detail=f"{len(scanner.comment_splits)} split word(s).",
        ))

    if (scanner.image_count >= 1
            and scanner.visible_chars < IMAGE_ONLY_TEXT_CHARS
            and _meaningful_length(body_plain) < IMAGE_ONLY_PLAIN_CHARS):
        findings.append(HtmlFinding(
            category=IMAGE_ONLY_BODY,
            indicator="Image-Only Body (Low Text-to-Image Ratio)",
            severity="Low",
            evidence=f"{scanner.image_count} image(s) with only {scanner.visible_chars} "
                     f"character(s) of readable text.",
            explanation="Almost all of the message is carried in images, leaving nothing for text "
                        "analysis to read. This is a long-standing way to evade content filters, "
                        "though some legitimate campaigns are built the same way — hence a soft "
                        "signal only.",
            detail="Reported only when the plain-text alternative is also effectively empty.",
        ))

    return findings


# --------------------------------------------------------------------------- #
# Pipeline entry point
# --------------------------------------------------------------------------- #


def analyse_html(body_html: str, body_plain: str = "") -> List[HtmlFinding]:
    """Inspect an HTML body for structural phishing threats. Never raises.

    Returns findings ordered strongest-first, or an empty list when there is no
    HTML part, when nothing was observed, or when analysis could not complete.
    An empty list therefore means "nothing to report", never "safe".
    """
    try:
        if not body_html or not body_html.strip():
            return []

        markup = body_html[:MAX_HTML_BYTES]
        if len(body_html) > MAX_HTML_BYTES:
            logger.debug(f"HTML body truncated to {MAX_HTML_BYTES} bytes for structural analysis.")

        findings: List[HtmlFinding] = []

        hidden_classes, hidden_ids = _hidden_selectors(markup)
        scanner = _BodyScanner(hidden_classes, hidden_ids)
        try:
            scanner.feed(markup)
            scanner.close()
        except Exception as exc:  # a hostile or badly broken document
            logger.debug(f"HTML tree walk stopped early ({type(exc).__name__}: {exc}); "
                         f"reporting what was already observed.")
        findings.extend(_structural_findings(scanner, body_plain or ""))

        findings.extend(_raw_findings(markup))
        findings.sort(key=lambda item: SEVERITY_ORDER.get(item.severity, 3))
        if findings:
            logger.debug(f"HTML forensics reported {len(findings)} structural finding(s).")
        return findings
    except Exception as exc:  # defensive: HTML analysis must never break analysis
        logger.warning(f"HTML forensics failed and was skipped: {exc}")
        return []

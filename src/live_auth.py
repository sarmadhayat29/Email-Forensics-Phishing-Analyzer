"""Live DNS-backed re-verification primitives for SPF, DKIM and DMARC.

The header-derived analysis in :mod:`auth_checks` only reports what an upstream
relay *claimed*. This module independently re-checks those claims against live
DNS and, for DKIM, against the message signature itself.

Design constraints, in priority order:

1. **Never break the offline pipeline.** Optional third-party packages
   (``dnspython``, ``dkimpy``) are imported lazily, and every DNS failure is
   reported as a value (``temperror``) rather than raised at the caller.
2. **Bounded work.** Every lookup uses a short timeout (``AUTH_DNS_TIMEOUT``)
   and SPF evaluation honours the RFC 7208 ten-lookup limit, so a hostile or
   misconfigured record cannot stall an analysis.
3. **Testable without a network.** The DNS layer is a small injectable client
   (:class:`DnsClient`) and DKIM verification takes an injectable verifier, so
   unit tests substitute fakes instead of reaching the internet.

Verdict strings deliberately match the vocabulary the scoring engine already
understands (``pass``/``fail``/``softfail``/``neutral``/``none``/
``temperror``/``permerror``/``not_present``).
"""

import ipaddress
import os
import re
import time
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesHeaderParser
from typing import Callable, List, Optional

from utils import registrable_domain
from logger import get_logger

logger = get_logger(__name__)

TEMPERROR = "temperror"
PERMERROR = "permerror"
NOT_PRESENT = "not_present"

#: Kept short so a stalled resolver can never dominate request latency on a
#: small dyno; overridable with AUTH_DNS_TIMEOUT (seconds).
DEFAULT_DNS_TIMEOUT = 4.0
MIN_DNS_TIMEOUT = 1.0
MAX_DNS_TIMEOUT = 15.0

#: RFC 7208 section 4.6.4 — mechanisms that cost a DNS lookup are capped.
SPF_MAX_DNS_LOOKUPS = 10
SPF_MAX_RECURSION = 5
#: An `mx` mechanism may not expand into an unbounded number of A lookups.
SPF_MAX_MX_HOSTS = 10

_FALSEY = {"0", "false", "no", "off", "disabled", "none"}


def dns_timeout() -> float:
    """Per-query DNS timeout in seconds, clamped to a sane range."""
    raw = os.environ.get("AUTH_DNS_TIMEOUT", "")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_DNS_TIMEOUT
    return max(MIN_DNS_TIMEOUT, min(MAX_DNS_TIMEOUT, value))


def live_auth_enabled() -> bool:
    """Whether live re-verification may run at all (LIVE_AUTH_ENABLED)."""
    raw = os.environ.get("LIVE_AUTH_ENABLED", "true").strip().lower()
    return raw not in _FALSEY


class DnsTemporaryError(Exception):
    """Timeout, SERVFAIL, or a missing/unusable resolver — retryable."""


class DnsPermanentError(Exception):
    """NXDOMAIN / NoAnswer — the name definitively has no such record."""


#: On a host with no working resolver every lookup costs a full timeout. After a
#: few consecutive failures the resolver is presumed unreachable and live checks
#: short-circuit for a cooldown, so an air-gapped deployment that forgot to set
#: LIVE_AUTH_ENABLED=false does not pay seconds of latency per message.
DNS_FAILURE_THRESHOLD = 3
DNS_COOLDOWN_SECONDS = 300.0

_dns_health = {"consecutive_failures": 0, "unavailable_until": 0.0}


def reset_dns_health() -> None:
    """Forget recorded resolver failures (used by tests and after config changes)."""
    _dns_health["consecutive_failures"] = 0
    _dns_health["unavailable_until"] = 0.0


def dns_available() -> bool:
    return time.monotonic() >= _dns_health["unavailable_until"]


def _record_dns_success() -> None:
    _dns_health["consecutive_failures"] = 0
    _dns_health["unavailable_until"] = 0.0


def _record_dns_failure() -> None:
    _dns_health["consecutive_failures"] += 1
    if _dns_health["consecutive_failures"] >= DNS_FAILURE_THRESHOLD:
        _dns_health["unavailable_until"] = time.monotonic() + DNS_COOLDOWN_SECONDS
        logger.warning(
            f"Suspending live DNS re-verification for {int(DNS_COOLDOWN_SECONDS)}s after "
            f"{_dns_health['consecutive_failures']} consecutive resolver failures; "
            f"analysis continues with header-derived authentication."
        )


class DnsClient:
    """Minimal dnspython wrapper.

    Only the three record types SPF/DMARC evaluation needs are exposed. Tests
    substitute an object with the same ``txt``/``a``/``mx`` methods.
    """

    def __init__(self, timeout: Optional[float] = None):
        self.timeout = timeout if timeout is not None else dns_timeout()
        self._resolver = None

    def _resolve(self, name: str, rdtype: str):
        if not dns_available():
            raise DnsTemporaryError("resolver presumed unreachable after repeated failures")

        try:
            import dns.exception  # type: ignore
            import dns.resolver  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise DnsTemporaryError("dnspython is not installed") from exc

        if self._resolver is None:
            self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = self.timeout
        self._resolver.lifetime = self.timeout

        try:
            answer = self._resolver.resolve(name, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
            # The resolver answered, so it is healthy; the name simply has no
            # record of this type.
            _record_dns_success()
            raise DnsPermanentError(f"{rdtype} {name}: {type(exc).__name__}") from exc
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            _record_dns_failure()
            raise DnsTemporaryError(f"{rdtype} {name}: {type(exc).__name__}") from exc
        except Exception as exc:  # resolver misconfiguration, bad name, ...
            _record_dns_failure()
            raise DnsTemporaryError(f"{rdtype} {name}: {exc}") from exc
        _record_dns_success()
        return answer

    def txt(self, name: str) -> List[str]:
        records: List[str] = []
        for rdata in self._resolve(name, "TXT"):
            chunks = getattr(rdata, "strings", None)
            if chunks is None:
                records.append(str(rdata).strip('"'))
                continue
            records.append("".join(
                chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else str(chunk)
                for chunk in chunks
            ))
        return records

    def a(self, name: str) -> List[str]:
        """A and AAAA addresses; an absent record type is not an error."""
        addresses: List[str] = []
        permanent = 0
        for rdtype in ("A", "AAAA"):
            try:
                addresses.extend(str(rdata) for rdata in self._resolve(name, rdtype))
            except DnsPermanentError:
                permanent += 1
        if permanent == 2 and not addresses:
            return []
        return addresses

    def mx(self, name: str) -> List[str]:
        try:
            answers = self._resolve(name, "MX")
        except DnsPermanentError:
            return []
        return [str(getattr(rdata, "exchange", rdata)).rstrip(".") for rdata in answers]


# --------------------------------------------------------------------------- #
# SPF
# --------------------------------------------------------------------------- #

SPF_QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
_SPF_MODIFIER_RE = re.compile(r"^[a-z][a-z0-9_.-]*=", re.IGNORECASE)
_UNSUPPORTED_MACRO_RE = re.compile(r"%\{(?!d\}|i\})", re.IGNORECASE)


@dataclass
class SpfResult:
    verdict: str = NOT_PRESENT
    detail: str = ""
    record: str = ""
    domain: str = ""
    ip: str = ""

    @property
    def definitive(self) -> bool:
        """True when the evaluation reached a real SPF answer."""
        return self.verdict in {"pass", "fail", "softfail", "neutral", "none", PERMERROR}


class _BudgetExceeded(Exception):
    pass


class _SpfPermanentError(Exception):
    """A structural defect that invalidates the whole SPF evaluation."""


class _LookupBudget:
    def __init__(self, limit: int = SPF_MAX_DNS_LOOKUPS):
        self.limit = limit
        self.used = 0

    def spend(self) -> None:
        self.used += 1
        if self.used > self.limit:
            raise _BudgetExceeded(f"exceeded {self.limit} DNS lookups")


def evaluate_spf(domain: str, ip: str, dns_client: Optional[DnsClient] = None) -> SpfResult:
    """Check whether ``ip`` is authorised to send for ``domain``.

    A self-contained RFC 7208 evaluator: it walks the published record's
    mechanisms (``ip4``/``ip6``/``a``/``mx``/``include``/``exists``/``all``,
    plus the ``redirect`` modifier) under a hard DNS-lookup budget. Anything it
    cannot evaluate safely — macros it does not expand, resolver failures — is
    reported as ``temperror`` so the caller keeps the header-derived verdict
    rather than accusing a legitimate sender.
    """
    if not domain:
        return SpfResult(detail="No MAIL FROM / From domain available for SPF evaluation.")
    try:
        ip_obj = ipaddress.ip_address(str(ip))
    except ValueError:
        return SpfResult(
            verdict=TEMPERROR,
            detail=f"Sending IP '{ip}' is missing or unparseable; SPF could not be evaluated.",
            domain=domain,
            ip=str(ip),
        )

    client = dns_client or DnsClient()
    budget = _LookupBudget()
    try:
        verdict, detail, record = _evaluate_spf_domain(domain, ip_obj, client, budget, depth=0)
    except DnsTemporaryError as exc:
        return SpfResult(TEMPERROR, f"SPF lookup for '{domain}' failed: {exc}", "", domain, str(ip_obj))
    except _BudgetExceeded as exc:
        return SpfResult(
            PERMERROR,
            f"SPF record of '{domain}' {exc} (RFC 7208 limit); evaluation abandoned.",
            "",
            domain,
            str(ip_obj),
        )
    except _SpfPermanentError as exc:
        return SpfResult(PERMERROR, f"SPF record of '{domain}' is invalid: {exc}", "", domain, str(ip_obj))
    return SpfResult(verdict, detail, record, domain, str(ip_obj))


def _evaluate_spf_domain(domain, ip_obj, client, budget, depth):
    if depth > SPF_MAX_RECURSION:
        raise _SpfPermanentError(
            f"include/redirect nesting at '{domain}' exceeded {SPF_MAX_RECURSION} levels"
        )

    try:
        txt_records = client.txt(domain)
    except DnsPermanentError:
        return "none", f"'{domain}' publishes no TXT records, so no SPF policy exists.", ""

    records = [r.strip() for r in txt_records if r.strip().lower().startswith("v=spf1")]
    if not records:
        return "none", f"'{domain}' publishes no SPF record.", ""
    if len(records) > 1:
        return PERMERROR, f"'{domain}' publishes {len(records)} conflicting SPF records.", records[0]

    record = records[0]
    if _UNSUPPORTED_MACRO_RE.search(record):
        raise DnsTemporaryError(f"SPF record of '{domain}' uses macros this evaluator does not expand")

    redirect: Optional[str] = None
    for term in record.split()[1:]:
        if not term:
            continue
        lowered = term.lower()
        if lowered.startswith("redirect="):
            redirect = _expand_macros(term.split("=", 1)[1], domain, ip_obj)
            continue
        if _SPF_MODIFIER_RE.match(term):
            continue  # exp=, unknown modifiers: no effect on the result

        qualifier = "+"
        body = term
        if body[0] in SPF_QUALIFIERS:
            qualifier, body = body[0], body[1:]
        if not body:
            return PERMERROR, f"SPF record of '{domain}' contains an empty mechanism.", record

        name, _, argument = body.partition(":")
        name = name.lower()
        cidr4 = cidr6 = None
        if "/" in name:
            name, cidr4, cidr6 = _split_cidr(name)
        # An ip4/ip6 argument keeps its prefix: it *is* the network.
        if name not in {"ip4", "ip6"} and "/" in argument:
            argument, cidr4, cidr6 = _split_cidr(argument)
        argument = _expand_macros(argument, domain, ip_obj)

        try:
            matched = _mechanism_matches(
                name, argument, cidr4, cidr6, domain, ip_obj, client, budget, depth
            )
        except _UnknownMechanism:
            return PERMERROR, f"SPF record of '{domain}' contains unknown mechanism '{term}'.", record

        if matched:
            return (
                SPF_QUALIFIERS[qualifier],
                f"Sending IP {ip_obj} matched '{term}' in the SPF record of '{domain}'.",
                record,
            )

    if redirect:
        budget.spend()
        verdict, detail, _ = _evaluate_spf_domain(redirect, ip_obj, client, budget, depth + 1)
        return verdict, f"{detail} (via redirect= from '{domain}')", record

    return (
        "neutral",
        f"Sending IP {ip_obj} matched no mechanism in the SPF record of '{domain}' "
        f"and the record has no 'all' term.",
        record,
    )


class _UnknownMechanism(Exception):
    pass


def _mechanism_matches(name, argument, cidr4, cidr6, domain, ip_obj, client, budget, depth) -> bool:
    if name == "all":
        return True

    if name in {"ip4", "ip6"}:
        return _ip_in_network(ip_obj, argument)

    if name == "a":
        budget.spend()
        target = argument or domain
        return any(_ip_matches(ip_obj, addr, cidr4, cidr6) for addr in _safe_a(client, target))

    if name == "mx":
        budget.spend()
        target = argument or domain
        for host in _safe_mx(client, target)[:SPF_MAX_MX_HOSTS]:
            if any(_ip_matches(ip_obj, addr, cidr4, cidr6) for addr in _safe_a(client, host)):
                return True
        return False

    if name == "include":
        budget.spend()
        if not argument:
            raise _UnknownMechanism("include without domain")
        verdict, detail, _ = _evaluate_spf_domain(argument, ip_obj, client, budget, depth + 1)
        if verdict == PERMERROR:
            raise _SpfPermanentError(f"include:{argument} is unevaluable — {detail}")
        # RFC 7208: only an inner 'pass' makes include match. An inner 'none'
        # is formally a permerror, but treating it as "no match" keeps a broken
        # third-party record from turning into an accusation of forgery.
        return verdict == "pass"

    if name == "exists":
        budget.spend()
        return bool(argument) and bool(_safe_a(client, argument))

    if name == "ptr":
        # Deprecated by RFC 7208 and unreliable to evaluate; costs a lookup but
        # never matches here.
        budget.spend()
        return False

    raise _UnknownMechanism(name)


def _safe_a(client, name: str) -> List[str]:
    if not name:
        return []
    try:
        return client.a(name)
    except DnsPermanentError:
        return []


def _safe_mx(client, name: str) -> List[str]:
    if not name:
        return []
    try:
        return client.mx(name)
    except DnsPermanentError:
        return []


def _split_cidr(token: str):
    """Split ``value/4prefix[//6prefix]`` into its three parts."""
    value, _, rest = token.partition("/")
    cidr4 = cidr6 = None
    if rest.startswith("/"):
        cidr6 = _as_int(rest[1:])
    else:
        prefix4, _, prefix6 = rest.partition("//")
        cidr4 = _as_int(prefix4)
        cidr6 = _as_int(prefix6)
    return value, cidr4, cidr6


def _as_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _expand_macros(value: str, domain: str, ip_obj) -> str:
    if not value or "%" not in value:
        return value
    return (value.replace("%{d}", domain).replace("%{D}", domain)
                 .replace("%{i}", str(ip_obj)).replace("%{I}", str(ip_obj)))


def _ip_in_network(ip_obj, spec: str) -> bool:
    if not spec:
        return False
    try:
        network = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return False
    return network.version == ip_obj.version and ip_obj in network


def _ip_matches(ip_obj, address: str, cidr4: Optional[int], cidr6: Optional[int]) -> bool:
    try:
        candidate = ipaddress.ip_address(str(address))
    except ValueError:
        return False
    if candidate.version != ip_obj.version:
        return False
    prefix = cidr4 if candidate.version == 4 else cidr6
    if prefix is None:
        return candidate == ip_obj
    try:
        network = ipaddress.ip_network(f"{candidate}/{prefix}", strict=False)
    except ValueError:
        return candidate == ip_obj
    return ip_obj in network


# --------------------------------------------------------------------------- #
# DKIM
# --------------------------------------------------------------------------- #

_DKIM_TAG_RE = re.compile(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", re.IGNORECASE)
_DKIM_SELECTOR_RE = re.compile(r"(?:^|;)\s*s\s*=\s*([^;\s]+)", re.IGNORECASE)
#: Substrings that mean "we could not check", as opposed to "the signature is
#: invalid". Misclassifying the former as a failure would let a DNS outage look
#: like a forged signature.
_DKIM_TEMPORARY_HINTS = (
    "timeout", "timed out", "dns", "servfail", "temporar", "unavailable",
    "missing public key", "name or service not known", "no answer",
)


@dataclass
class DkimResult:
    verdict: str = NOT_PRESENT
    detail: str = ""
    signature_domains: List[str] = field(default_factory=list)
    passed_domains: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def definitive(self) -> bool:
        return self.verdict in {"pass", "fail", "none"}


def dkim_signature_domains(raw_bytes: bytes) -> List[str]:
    """``d=`` of every DKIM-Signature header, in header order."""
    if not raw_bytes:
        return []
    try:
        headers = BytesHeaderParser(policy=policy.compat32).parsebytes(raw_bytes)
        signatures = headers.get_all("DKIM-Signature") or []
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"Could not read DKIM-Signature headers: {exc}")
        return []

    domains: List[str] = []
    for signature in signatures:
        match = _DKIM_TAG_RE.search(str(signature))
        domains.append(match.group(1).strip().rstrip(".").lower() if match else "")
    return domains


def dkim_selectors(raw_bytes: bytes) -> List[str]:
    if not raw_bytes:
        return []
    try:
        headers = BytesHeaderParser(policy=policy.compat32).parsebytes(raw_bytes)
        signatures = headers.get_all("DKIM-Signature") or []
    except Exception:  # pragma: no cover - defensive
        return []
    selectors = []
    for signature in signatures:
        match = _DKIM_SELECTOR_RE.search(str(signature))
        selectors.append(match.group(1).strip() if match else "")
    return selectors


def _default_dkim_verifier(timeout: float) -> Optional[Callable[[bytes, int], bool]]:
    try:
        import dkim as dkim_module  # type: ignore
    except ImportError:
        return None

    def _verify(raw: bytes, index: int) -> bool:
        return bool(dkim_module.DKIM(raw, timeout=timeout).verify(idx=index))

    return _verify


def verify_dkim(
    raw_bytes: bytes,
    timeout: Optional[float] = None,
    verifier: Optional[Callable[[bytes, int], bool]] = None,
) -> DkimResult:
    """Cryptographically verify every DKIM signature on the raw message.

    ``verifier(raw_bytes, index)`` is injectable so tests never need a network
    or a real key. Without raw bytes (e.g. a reconstructed ``.msg``) or without
    ``dkimpy`` installed the result is ``not_present``, which tells the caller
    to keep whatever the headers claimed instead of inventing a verdict.
    """
    if not raw_bytes:
        return DkimResult(detail="Raw message bytes are unavailable, so DKIM could not be re-verified.")

    domains = dkim_signature_domains(raw_bytes)
    if not domains:
        return DkimResult(verdict="none", detail="Message carries no DKIM-Signature header.")

    verify = verifier or _default_dkim_verifier(timeout if timeout is not None else dns_timeout())
    if verify is None:
        return DkimResult(
            detail="dkimpy is not installed, so DKIM signatures could not be re-verified.",
            signature_domains=domains,
        )

    passed: List[str] = []
    failed: List[str] = []
    temporary: List[str] = []
    for index, domain in enumerate(domains):
        label = domain or f"signature #{index + 1}"
        try:
            ok = verify(raw_bytes, index)
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}".lower()
            if any(hint in message for hint in _DKIM_TEMPORARY_HINTS):
                temporary.append(f"{label} could not be checked ({exc})")
            else:
                failed.append(f"{label} failed verification ({exc})")
            continue
        if ok:
            passed.append(domain)
        else:
            failed.append(f"{label} failed verification")

    if passed:
        detail = "DKIM signature verified for " + ", ".join(sorted({d for d in passed if d}) or ["unknown domain"])
        return DkimResult("pass", detail, domains, passed, failed + temporary)
    if failed:
        return DkimResult("fail", "; ".join(failed), domains, [], temporary)
    return DkimResult(
        TEMPERROR,
        "; ".join(temporary) or "DKIM verification was inconclusive.",
        domains,
        [],
        temporary,
    )


# --------------------------------------------------------------------------- #
# DMARC
# --------------------------------------------------------------------------- #


@dataclass
class DmarcResult:
    verdict: str = NOT_PRESENT
    policy: Optional[str] = None
    detail: str = ""
    record: str = ""
    domain: str = ""
    spf_aligned: bool = False
    dkim_aligned: bool = False
    notes: List[str] = field(default_factory=list)

    @property
    def definitive(self) -> bool:
        return self.verdict in {"pass", "fail", "none", PERMERROR}


def parse_dmarc_record(record: str) -> dict:
    tags: dict = {}
    for part in (record or "").split(";"):
        key, _, value = part.partition("=")
        key = key.strip().lower()
        if key:
            tags[key] = value.strip()
    return tags


def fetch_dmarc_record(domain: str, dns_client: Optional[DnsClient] = None):
    """Return ``(record, queried_domain)``, falling back to the org domain."""
    client = dns_client or DnsClient()
    candidates = [domain]
    organisational = registrable_domain(domain)
    if organisational and organisational != domain:
        candidates.append(organisational)

    for candidate in candidates:
        try:
            txt_records = client.txt(f"_dmarc.{candidate}")
        except DnsPermanentError:
            continue
        for record in txt_records:
            if record.strip().lower().startswith("v=dmarc1"):
                return record.strip(), candidate
    return None, domain


def domains_aligned(child: Optional[str], parent: Optional[str], mode: str = "r") -> bool:
    """DMARC identifier alignment; relaxed (default) allows subdomains."""
    if not child or not parent:
        return False
    child = child.strip().rstrip(".").lower()
    parent = parent.strip().rstrip(".").lower()
    if child == parent:
        return True
    if mode == "s":
        return False
    return registrable_domain(child) == registrable_domain(parent)


def evaluate_dmarc(
    from_domain: str,
    spf: Optional[SpfResult] = None,
    dkim: Optional[DkimResult] = None,
    mailfrom_domain: Optional[str] = None,
    dns_client: Optional[DnsClient] = None,
) -> DmarcResult:
    """Fetch the DMARC policy and evaluate alignment of the live SPF/DKIM results."""
    if not from_domain:
        return DmarcResult(detail="No header From domain available for DMARC evaluation.")

    try:
        record, queried = fetch_dmarc_record(from_domain, dns_client)
    except DnsTemporaryError as exc:
        return DmarcResult(TEMPERROR, None, f"DMARC lookup for '{from_domain}' failed: {exc}", domain=from_domain)

    if not record:
        return DmarcResult(
            "none",
            None,
            f"'{from_domain}' publishes no DMARC record, so spoofing of this domain is not rejected.",
            domain=from_domain,
        )

    tags = parse_dmarc_record(record)
    policy_tag = (tags.get("p") or "").lower() or None
    if queried != from_domain and tags.get("sp"):
        policy_tag = tags["sp"].lower()

    aspf = (tags.get("aspf") or "r").lower()[:1]
    adkim = (tags.get("adkim") or "r").lower()[:1]

    notes: List[str] = []
    spf_aligned = False
    if spf is not None and spf.verdict == "pass":
        spf_aligned = domains_aligned(mailfrom_domain or spf.domain, from_domain, aspf)
        if not spf_aligned:
            notes.append(
                f"SPF passed for '{mailfrom_domain or spf.domain}' but that does not align "
                f"({'strict' if aspf == 's' else 'relaxed'}) with From domain '{from_domain}'."
            )

    dkim_aligned = False
    if dkim is not None and dkim.verdict == "pass":
        aligned_domains = [d for d in dkim.passed_domains if domains_aligned(d, from_domain, adkim)]
        dkim_aligned = bool(aligned_domains)
        if not dkim_aligned and dkim.passed_domains:
            notes.append(
                f"DKIM signature verified for '{', '.join(dkim.passed_domains)}' but that does not align "
                f"({'strict' if adkim == 's' else 'relaxed'}) with From domain '{from_domain}'."
            )

    if spf_aligned or dkim_aligned:
        passing = "SPF" if spf_aligned else ""
        passing += ("+" if spf_aligned and dkim_aligned else "") + ("DKIM" if dkim_aligned else "")
        return DmarcResult(
            "pass",
            policy_tag,
            f"DMARC passes on aligned {passing} against the policy published by '{queried}'.",
            record,
            from_domain,
            spf_aligned,
            dkim_aligned,
            notes,
        )

    # DMARC passes on *either* aligned identifier, so a failure may only be
    # declared once both were actually evaluated. Concluding "fail" while SPF or
    # DKIM is unknown would manufacture a policy violation out of missing data.
    unknown = [name for name, result in (("SPF", spf), ("DKIM", dkim)) if result is None]
    if unknown:
        return DmarcResult(
            TEMPERROR,
            policy_tag,
            f"DMARC record found for '{queried}' (p={policy_tag or 'none'}) but "
            f"{' and '.join(unknown)} could not be evaluated, so alignment is undetermined.",
            record,
            from_domain,
            spf_aligned,
            dkim_aligned,
            notes,
        )

    return DmarcResult(
        "fail",
        policy_tag,
        f"No aligned, passing SPF or DKIM identifier for '{from_domain}'; "
        f"DMARC policy of '{queried}' is p={policy_tag or 'none'}.",
        record,
        from_domain,
        spf_aligned,
        dkim_aligned,
        notes,
    )


# --------------------------------------------------------------------------- #
# Sending IP extraction
# --------------------------------------------------------------------------- #

_BRACKETED_IP_RE = re.compile(r"\[([0-9a-fA-F:.]+)\]")
_BARE_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_ORIGINATING_IP_HEADERS = ("x-originating-ip", "x-sender-ip", "x-source-ip", "x-real-ip")


def sending_ip(parsed) -> Optional[str]:
    """Best guess at the IP that handed the message to the receiving MTA.

    The Received chain is walked newest-first — the border MTA that accepted the
    external connection is the one whose verdict SPF is meant to reproduce — and
    the first routable (non-private) address is used. Internal relay hops with
    private or absent addresses are therefore skipped.
    """
    for raw in list(getattr(parsed, "received_chain", None) or []):
        for candidate in _candidate_ips(str(raw)):
            if _is_routable(candidate):
                return candidate

    headers = getattr(parsed, "headers", None) or {}
    for key, value in headers.items():
        if str(key).lower() not in _ORIGINATING_IP_HEADERS:
            continue
        for item in (value if isinstance(value, list) else [value]):
            for candidate in _candidate_ips(str(item)):
                if _is_routable(candidate):
                    return candidate
    return None


def _candidate_ips(text: str) -> List[str]:
    return _BRACKETED_IP_RE.findall(text) + _BARE_IPV4_RE.findall(text)


def _is_routable(candidate: str) -> bool:
    """Whether an address could really have opened a connection from the internet.

    Python counts the RFC 5737 documentation ranges (192.0.2.0/24 and friends)
    as private, so hand-written training samples using them yield no sending IP
    and fall back to header-derived SPF — the safe outcome.
    """
    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified)

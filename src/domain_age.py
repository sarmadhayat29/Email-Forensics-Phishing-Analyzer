"""Domain registration age (newly-registered-domain) reputation checks.

Phishing infrastructure is disposable: a large share of credential-harvesting
domains are used within days of registration. Registration age is therefore a
useful *corroborating* signal — and a dangerous standalone one, because the
answer comes from WHOIS, a service that is rate-limited, inconsistently
formatted, absent for many TLDs, and frequently unreachable.

Design constraints mirror :mod:`live_auth`:

1. **Never break the pipeline.** ``python-whois`` is imported lazily and every
   failure is returned as a value (``classification="unknown"``) rather than
   raised. A lookup that fails is *not* evidence of wrongdoing and carries no
   score.
2. **Bounded work.** Each query runs in a daemon thread with a hard timeout, a
   circuit breaker suspends lookups after repeated failures, a rolling window
   limits query volume, and only the first few domains of a message are
   resolved. A hostile message with 200 links cannot stall an analysis.
3. **Cached.** Registration dates are effectively static, so answers are held
   in an in-memory TTL cache with optional JSON persistence. Repeat senders
   cost nothing.
4. **Testable offline.** The WHOIS callable is injectable, so unit tests never
   touch the network.
"""

import json
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable, List, Optional
from urllib.parse import urlparse

from models import DomainAgeFinding
from utils import BRAND_OWNED_DOMAINS, KNOWN_BRAND_DOMAINS, TARGET_BRANDS, registrable_domain
from logger import get_logger

logger = get_logger(__name__)

NEWLY_REGISTERED = "newly_registered"
YOUNG = "young"
ESTABLISHED = "established"
EXEMPT = "exempt"
UNKNOWN = "unknown"

_FALSEY = {"0", "false", "no", "off", "disabled", "none"}

#: Industry convention (CISA, most secure-mail gateways) treats a domain under
#: 30 days old as "newly registered". 90 days is the wider "young domain"
#: window where legitimate businesses have usually established a footprint but
#: throwaway phishing infrastructure has typically already been burned.
DEFAULT_NRD_DAYS = 30
DEFAULT_YOUNG_DAYS = 90

#: WHOIS is slower than DNS but must still not dominate request latency.
DEFAULT_WHOIS_TIMEOUT = 5.0
MIN_WHOIS_TIMEOUT = 1.0
MAX_WHOIS_TIMEOUT = 30.0

#: Only the first few distinct domains of a message are resolved: the sender is
#: what matters, and a link farm should not multiply lookup cost.
DEFAULT_MAX_LOOKUPS = 4

#: Successful answers are near-static; failures are re-tried much sooner so a
#: transient outage does not blind the check for a week.
CACHE_TTL_SECONDS = 7 * 24 * 3600
NEGATIVE_CACHE_TTL_SECONDS = 3600

#: Repeated WHOIS failures (no network, blocked port 43) would otherwise cost a
#: full timeout per domain per message.
WHOIS_FAILURE_THRESHOLD = 3
WHOIS_COOLDOWN_SECONDS = 300.0

#: Crude global rate limit so a busy deployment does not get its IP banned by
#: registry WHOIS servers.
RATE_LIMIT_MAX_QUERIES = 30
RATE_LIMIT_WINDOW_SECONDS = 60.0


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def domain_age_enabled() -> bool:
    """Whether WHOIS-backed age checks may run at all (DOMAIN_AGE_ENABLED)."""
    raw = os.environ.get("DOMAIN_AGE_ENABLED", "true").strip().lower()
    return raw not in _FALSEY


def whois_timeout() -> float:
    return _clamped_float("WHOIS_TIMEOUT", DEFAULT_WHOIS_TIMEOUT, MIN_WHOIS_TIMEOUT, MAX_WHOIS_TIMEOUT)


def nrd_days() -> int:
    return int(_clamped_float("NRD_DAYS", DEFAULT_NRD_DAYS, 1, 365))


def young_domain_days() -> int:
    """Upper bound of the "young domain" band; never below the NRD threshold."""
    value = int(_clamped_float("YOUNG_DOMAIN_DAYS", DEFAULT_YOUNG_DAYS, 1, 3650))
    return max(value, nrd_days())


def max_lookups_per_message() -> int:
    return int(_clamped_float("DOMAIN_AGE_MAX_LOOKUPS", DEFAULT_MAX_LOOKUPS, 0, 25))


def _clamped_float(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(os.environ.get(name, ""))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def cache_file_path() -> Optional[str]:
    """Path of the optional on-disk cache, or ``None`` when persistence is off.

    Defaults to a gitignored file beside the generated reports. On an ephemeral
    filesystem (Railway) the file simply disappears between deploys, which is
    harmless — the in-memory cache is the primary one.
    """
    raw = os.environ.get("WHOIS_CACHE_FILE")
    if raw is not None:
        raw = raw.strip()
        return raw or None
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "server_reports", ".whois_cache.json")


# --------------------------------------------------------------------------- #
# Circuit breaker + rate limiting
# --------------------------------------------------------------------------- #

_health = {"consecutive_failures": 0, "unavailable_until": 0.0}
_recent_queries: deque = deque()
_lock = threading.Lock()


def reset_whois_health() -> None:
    """Forget recorded failures and rate-limit history (tests, config changes)."""
    with _lock:
        _health["consecutive_failures"] = 0
        _health["unavailable_until"] = 0.0
        _recent_queries.clear()


def whois_available() -> bool:
    return time.monotonic() >= _health["unavailable_until"]


def _record_success() -> None:
    with _lock:
        _health["consecutive_failures"] = 0
        _health["unavailable_until"] = 0.0


def _record_failure() -> None:
    with _lock:
        _health["consecutive_failures"] += 1
        if _health["consecutive_failures"] >= WHOIS_FAILURE_THRESHOLD:
            _health["unavailable_until"] = time.monotonic() + WHOIS_COOLDOWN_SECONDS
            logger.warning(
                f"Suspending WHOIS domain-age lookups for {int(WHOIS_COOLDOWN_SECONDS)}s after "
                f"{_health['consecutive_failures']} consecutive failures; analysis continues "
                f"without registration-age evidence."
            )


def _rate_limit_allows() -> bool:
    now = time.monotonic()
    with _lock:
        while _recent_queries and now - _recent_queries[0] > RATE_LIMIT_WINDOW_SECONDS:
            _recent_queries.popleft()
        if len(_recent_queries) >= RATE_LIMIT_MAX_QUERIES:
            return False
        _recent_queries.append(now)
        return True


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #

_cache: dict = {}
_cache_loaded = False


def clear_cache() -> None:
    """Drop cached answers (tests, and after a threshold change)."""
    global _cache_loaded
    with _lock:
        _cache.clear()
        _cache_loaded = False


def _load_cache() -> None:
    global _cache_loaded
    if _cache_loaded:
        return
    _cache_loaded = True
    path = cache_file_path()
    if not path or not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as handle:
            stored = json.load(handle)
        if isinstance(stored, dict):
            now = time.time()
            for domain, entry in stored.items():
                if isinstance(entry, dict) and float(entry.get("expires", 0)) > now:
                    _cache[str(domain)] = entry
    except Exception as exc:  # corrupt file, permissions, ...
        logger.debug(f"WHOIS cache could not be read from {path}: {exc}")


def _persist_cache() -> None:
    path = cache_file_path()
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(_cache, handle)
    except Exception as exc:  # read-only FS, quota, ...
        logger.debug(f"WHOIS cache could not be written to {path}: {exc}")


def _cache_get(domain: str) -> Optional[dict]:
    _load_cache()
    entry = _cache.get(domain)
    if not entry:
        return None
    if float(entry.get("expires", 0)) <= time.time():
        _cache.pop(domain, None)
        return None
    return entry


def _cache_put(domain: str, created: Optional[str], registrar: str, ok: bool, detail: str) -> None:
    ttl = CACHE_TTL_SECONDS if ok else NEGATIVE_CACHE_TTL_SECONDS
    _cache[domain] = {
        "expires": time.time() + ttl,
        "created": created,
        "registrar": registrar,
        "ok": ok,
        "detail": detail,
    }
    _persist_cache()


# --------------------------------------------------------------------------- #
# WHOIS access
# --------------------------------------------------------------------------- #


class WhoisTimeout(Exception):
    """The WHOIS query did not answer inside the configured budget."""


def _default_whois_func() -> Optional[Callable[[str], object]]:
    try:
        import whois as whois_module  # type: ignore
    except Exception:  # ImportError, or a broken install
        return None
    return lambda domain: whois_module.whois(domain)


def _run_with_timeout(func: Callable[[], object], timeout: float):
    """Run ``func`` in a daemon thread and abandon it if it overruns.

    ``python-whois`` exposes no timeout parameter and can block on a socket for
    far longer than a request should last. The worker thread is a daemon, so an
    abandoned query can never keep the process alive.
    """
    box: dict = {}

    def target():
        try:
            box["value"] = func()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller's thread
            box["error"] = exc

    thread = threading.Thread(target=target, name="whois-lookup", daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise WhoisTimeout(f"no answer within {timeout:g}s")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _first_datetime(value) -> Optional[datetime]:
    """Coerce a WHOIS creation-date field into a naive UTC datetime.

    Registries return a datetime, a list of datetimes (one per registrar
    record), or a free-text string; when several are present the earliest is
    the conservative choice.
    """
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        candidates = [_first_datetime(item) for item in value]
        resolved = [item for item in candidates if item is not None]
        return min(resolved) if resolved else None
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return _first_datetime(datetime.fromisoformat(text.replace("Z", "+00:00")))
        except ValueError:
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d",
                    "%d-%b-%Y", "%d.%m.%Y", "%Y.%m.%d", "%Y/%m/%d"):
            for candidate in (text, text[:19], text[:10]):
                try:
                    return datetime.strptime(candidate, fmt)
                except ValueError:
                    continue
    return None


def _extract_creation(record) -> tuple[Optional[datetime], str]:
    """Pull ``(creation_date, registrar)`` out of whatever WHOIS returned."""
    if record is None:
        return None, ""

    def field(name):
        if isinstance(record, dict):
            return record.get(name)
        return getattr(record, name, None)

    created = _first_datetime(field("creation_date") or field("created") or field("registered"))
    registrar = field("registrar")
    if isinstance(registrar, (list, tuple)):
        registrar = next((str(item) for item in registrar if item), "")
    return created, str(registrar or "").strip()


# --------------------------------------------------------------------------- #
# Exemptions
# --------------------------------------------------------------------------- #


def is_exempt(domain: str) -> bool:
    """Whether a domain is known-good infrastructure that need not be aged.

    Reuses the brand ownership lists so that real brand mail (which routinely
    uses long-lived but obscure sending domains) is never queried or scored.
    """
    registrable = registrable_domain(domain)
    if not registrable:
        return False
    if registrable in BRAND_OWNED_DOMAINS or registrable in KNOWN_BRAND_DOMAINS:
        return True
    return registrable.split(".")[0] in TARGET_BRANDS


# --------------------------------------------------------------------------- #
# Lookup
# --------------------------------------------------------------------------- #


def lookup_domain_age(
    domain: str,
    origin: str = "sender",
    whois_func: Optional[Callable[[str], object]] = None,
) -> DomainAgeFinding:
    """Resolve the registration age of one domain. Never raises.

    Every unhappy path — disabled, exempt, no dependency, suspended breaker,
    rate limited, timeout, unparseable date, future date — yields
    ``classification="unknown"`` with an explanatory ``detail``, which scoring
    treats as "no information", not as an accusation.
    """
    registrable = registrable_domain((domain or "").strip().lower().rstrip("."))
    if not registrable or "." not in registrable:
        return DomainAgeFinding(domain=domain or "", origin=origin, source="skipped",
                                detail="No registrable domain could be derived.")

    if not domain_age_enabled():
        return DomainAgeFinding(domain=registrable, origin=origin, source="disabled",
                                detail="Domain-age checks are disabled (DOMAIN_AGE_ENABLED=false).")

    if is_exempt(registrable):
        return DomainAgeFinding(
            domain=registrable, classification=EXEMPT, origin=origin, source="exempt",
            detail=f"'{registrable}' is known brand-owned infrastructure; registration age is not assessed.",
        )

    cached = _cache_get(registrable)
    if cached is not None:
        return _finding_from_parts(
            registrable, origin, "cache",
            _first_datetime(cached.get("created")), cached.get("registrar") or "",
            cached.get("detail") or "",
        )

    if not whois_available():
        return DomainAgeFinding(domain=registrable, origin=origin, source="error",
                                detail="WHOIS lookups are temporarily suspended after repeated failures.")

    query = whois_func or _default_whois_func()
    if query is None:
        return DomainAgeFinding(domain=registrable, origin=origin, source="error",
                                detail="python-whois is not installed, so registration age is unknown.")

    if not _rate_limit_allows():
        return DomainAgeFinding(domain=registrable, origin=origin, source="error",
                                detail="WHOIS query rate limit reached; registration age was not checked.")

    try:
        record = _run_with_timeout(lambda: query(registrable), whois_timeout())
    except BaseException as exc:  # noqa: BLE001
        # BaseException on purpose: this only ever re-raises what the WHOIS
        # library threw on the worker thread. A real interrupt is delivered to
        # the main thread, so anything arriving here is a misbehaving
        # dependency and must not take the analysis down with it.
        _record_failure()
        detail = f"WHOIS lookup for '{registrable}' failed: {type(exc).__name__}: {exc}"
        logger.debug(detail)
        _cache_put(registrable, None, "", ok=False, detail=detail)
        return DomainAgeFinding(domain=registrable, origin=origin, source="error", detail=detail)

    _record_success()
    created, registrar = _extract_creation(record)
    if created is None:
        detail = f"WHOIS answered for '{registrable}' but published no usable creation date."
        _cache_put(registrable, None, registrar, ok=False, detail=detail)
        return DomainAgeFinding(domain=registrable, origin=origin, source="whois",
                                registrar=registrar, detail=detail)

    _cache_put(registrable, created.isoformat(), registrar, ok=True, detail="")
    return _finding_from_parts(registrable, origin, "whois", created, registrar, "")


def _finding_from_parts(domain, origin, source, created, registrar, cached_detail) -> DomainAgeFinding:
    if created is None:
        return DomainAgeFinding(
            domain=domain, origin=origin, source=source, registrar=registrar or "",
            detail=cached_detail or f"No registration date is available for '{domain}'.",
        )

    age = (datetime.now(timezone.utc).replace(tzinfo=None) - created).days
    if age < 0:
        # A registry clock skew or a misparsed field; not evidence of anything.
        return DomainAgeFinding(
            domain=domain, origin=origin, source=source, registrar=registrar or "",
            created=created.date().isoformat(),
            detail=f"WHOIS reports a future creation date ({created.date()}) for '{domain}'; ignored.",
        )

    threshold_new, threshold_young = nrd_days(), young_domain_days()
    if age < threshold_new:
        classification = NEWLY_REGISTERED
        detail = (f"'{domain}' was registered {age} day(s) ago ({created.date()}), inside the "
                  f"{threshold_new}-day newly-registered-domain window.")
    elif age < threshold_young:
        classification = YOUNG
        detail = (f"'{domain}' was registered {age} day(s) ago ({created.date()}), still within the "
                  f"{threshold_young}-day young-domain window.")
    else:
        classification = ESTABLISHED
        detail = f"'{domain}' has been registered for {age} day(s) (since {created.date()})."

    return DomainAgeFinding(
        domain=domain, classification=classification, age_days=age,
        created=created.date().isoformat(), registrar=registrar or "",
        origin=origin, source=source, detail=detail,
    )


# --------------------------------------------------------------------------- #
# Pipeline entry point
# --------------------------------------------------------------------------- #


def collect_domains(parsed, url_verdict=None) -> List[tuple]:
    """Distinct registrable domains worth ageing, sender first.

    The header From domain is always the first candidate; link hosts follow in
    the order they appeared, deduplicated against the sender.
    """
    from utils import extract_domain  # local import keeps module import cheap

    ordered: List[tuple] = []
    seen = set()

    def add(host: str, origin: str) -> None:
        registrable = registrable_domain((host or "").strip().lower().rstrip("."))
        if registrable and "." in registrable and registrable not in seen:
            seen.add(registrable)
            ordered.append((registrable, origin))

    add(extract_domain(getattr(parsed, "from_raw", "")) or "", "sender")

    for url in getattr(url_verdict, "urls", None) or []:
        host = getattr(url, "domain", "") or ""
        if not host or host.lower() == "unknown":
            host = urlparse(getattr(url, "raw_url", "") or "").hostname or ""
        add(host, "link")

    return ordered


def analyse_domain_age(
    parsed,
    url_verdict=None,
    whois_func: Optional[Callable[[str], object]] = None,
) -> List[DomainAgeFinding]:
    """Age the sender and linked domains of a message. Never raises.

    Returns an empty list when the check is switched off, so callers can treat
    "no findings" and "nothing to say" identically.
    """
    try:
        if not domain_age_enabled():
            return []
        candidates = collect_domains(parsed, url_verdict)
        if not candidates:
            return []

        budget = max_lookups_per_message()
        findings: List[DomainAgeFinding] = []
        spent = 0
        for domain, origin in candidates:
            # Over budget, only answers that cost nothing (cached / exempt) are
            # still collected.
            if spent >= budget and _cache_get(domain) is None and not is_exempt(domain):
                continue
            finding = lookup_domain_age(domain, origin=origin, whois_func=whois_func)
            if finding.source == "whois":
                spent += 1
            findings.append(finding)
        return findings
    except Exception as exc:  # defensive: reputation must never break analysis
        logger.warning(f"Domain-age analysis failed and was skipped: {exc}")
        return []

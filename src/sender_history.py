"""Sender-history baselining for Business Email Compromise detection.

The strongest BEC signal is not in the message at all: it is the absence of any
prior relationship. An invoice from a domain this recipient has corresponded
with for two years is ordinary business; the same invoice from a domain never
seen before is the classic vendor-impersonation pattern.

The module is deliberately arranged so the analysis pipeline never depends on a
database:

* :func:`build_history` is pure. It takes the current ``From`` header and an
  iterable of previously observed sender addresses and returns a
  :class:`~models.SenderHistory`. Anything can supply that iterable, which is
  what makes it testable without Postgres.
* :func:`history_provider` wraps a loader callable into the optional provider
  the pipeline accepts. Any failure inside the loader yields ``None``, i.e. "no
  history information", never an exception.
* The CLI supplies no provider at all, so it stays entirely offline and every
  sender-history signal is simply absent.

Two guards keep the signal conservative:

1. **A baseline is required.** Below :data:`MIN_PRIOR_MESSAGES` prior analyses,
   "first contact" is meaningless — for a new account every sender is new — so
   the history is reported as unavailable and scores nothing.
2. **Comparison is on the registrable domain.** ``billing@mail.acme.com`` and
   ``ap@acme.com`` count as the same known correspondent, so ordinary
   subdomain/ESP variation does not read as a first contact.
"""

from typing import Callable, Iterable, List, Optional

from models import SenderHistory
from utils import extract_address, extract_domain, registrable_domain
from logger import get_logger

logger = get_logger(__name__)

#: Prior analyses required before first-contact reasoning means anything.
MIN_PRIOR_MESSAGES = 5

#: Upper bound on prior senders a caller should load. Enough to characterise a
#: correspondent set, small enough to stay a cheap indexed query.
MAX_PRIOR_ROWS = 500


def build_history(from_raw: str, prior_senders: Iterable[Optional[str]]) -> SenderHistory:
    """Compare this message's sender against previously seen senders.

    ``prior_senders`` may contain raw ``From`` header strings, bare addresses,
    ``None`` or blanks; unparseable entries are ignored rather than counted.
    """
    address = extract_address(from_raw or "") or ""
    domain = registrable_domain(extract_domain(from_raw or "") or "")
    if not address or not domain:
        return SenderHistory(detail="No sender address could be derived, so no baseline was compared.")

    prior_messages = 0
    address_count = 0
    domain_count = 0
    for entry in prior_senders or []:
        prior_address = extract_address(str(entry or ""))
        if not prior_address:
            continue
        prior_messages += 1
        if prior_address == address:
            address_count += 1
        prior_domain = registrable_domain(prior_address.rsplit("@", 1)[-1])
        if prior_domain and prior_domain == domain:
            domain_count += 1

    if prior_messages < MIN_PRIOR_MESSAGES:
        return SenderHistory(
            address=address, domain=domain, prior_messages=prior_messages,
            detail=(f"Only {prior_messages} prior analysed message(s) for this account: too little "
                    f"history for first-contact reasoning (needs {MIN_PRIOR_MESSAGES})."),
        )

    if address_count:
        detail = (f"'{address}' has been seen in {address_count} of the last {prior_messages} "
                  f"analysed messages for this account.")
    elif domain_count:
        detail = (f"'{address}' is new, but domain '{domain}' has been seen in {domain_count} of the "
                  f"last {prior_messages} analysed messages for this account.")
    else:
        detail = (f"Neither '{address}' nor domain '{domain}' appears in the last {prior_messages} "
                  f"analysed messages for this account.")

    return SenderHistory(
        available=True,
        address=address,
        domain=domain,
        prior_messages=prior_messages,
        address_count=address_count,
        domain_count=domain_count,
        first_time_address=address_count == 0,
        first_time_domain=domain_count == 0,
        detail=detail,
    )


def history_provider(
    loader: Callable[[], Iterable[Optional[str]]],
) -> Callable[[object], Optional[SenderHistory]]:
    """Adapt a "load prior senders" callable into a pipeline provider.

    The returned callable takes the parsed message and never raises: a database
    that is unreachable, a dialect that cannot answer the query, or a loader bug
    all degrade to ``None``, which scoring reads as no information.
    """
    def provider(parsed) -> Optional[SenderHistory]:
        try:
            history = build_history(getattr(parsed, "from_raw", "") or "", loader())
        except Exception as exc:  # unreachable DB, query error, bad loader, ...
            logger.warning(f"Sender-history baseline unavailable and skipped: {exc}")
            return None
        logger.debug(f"Sender-history baseline: {history.detail}")
        return history

    return provider


def senders_from_records(records: Iterable[object]) -> List[str]:
    """Pull sender strings out of stored analysis records.

    Accepts rows of ``(from_addr,)``, bare strings, mappings holding a
    ``from_addr`` key, or objects exposing ``finding_json``, so the same helper
    serves a projected SQL query and a test double.
    """
    senders: List[str] = []
    for record in records or []:
        senders.append(_sender_from_record(record))
    return [sender for sender in senders if sender]


def _sender_from_record(record) -> str:
    if record is None:
        return ""
    if isinstance(record, str):
        return record
    if isinstance(record, dict):
        return str(record.get("from_addr") or "")
    finding = getattr(record, "finding_json", None)
    if isinstance(finding, dict):
        return str(finding.get("from_addr") or "")
    # Single-column query results: a tuple, or a driver row object that merely
    # behaves like one.
    try:
        return str(record[0] or "")
    except (TypeError, IndexError, KeyError):
        return ""

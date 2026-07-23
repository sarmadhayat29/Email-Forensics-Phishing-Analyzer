"""Stage 5 — Routing analysis & Timeline Engine.

Walks the Received: header chain, classifies IP addresses, calculates transit delays,
generates a chronological delivery timeline, and flags forensic routing anomalies.
"""

import re
import ipaddress
from typing import List, Optional, Tuple
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from models import ParsedMessage, Hop, RoutingTimelineEntry, RoutingVerdict
from logger import get_logger

logger = get_logger(__name__)

IP_RE = re.compile(r"\[([0-9a-fA-F:.]+)\]|(?:\b(\d{1,3}(?:\.\d{1,3}){3})\b)")
BY_HOST_RE = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)
FROM_HOST_RE = re.compile(r"\bfrom\s+([^\s;]+)", re.IGNORECASE)
WITH_RE = re.compile(r"\bwith\s+([^\s;]+)", re.IGNORECASE)
FOR_RE = re.compile(r"\bfor\s+<([^>]+)>", re.IGNORECASE)


def classify_ip(ip_str: str) -> str:
    """Classify IP as Public, Private (RFC 1918), Loopback, CGNAT, or Unknown."""
    if not ip_str:
        return "Unknown"
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback:
            return "Loopback"
        if ip_obj.is_private:
            return "Private (RFC 1918)"
        # Check Carrier-Grade NAT (100.64.0.0/10)
        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in ipaddress.IPv4Network("100.64.0.0/10"):
            return "CGNAT"
        return "Public"
    except ValueError:
        return "Invalid IP"


def _parse_hop(raw: str) -> Hop:
    from_match = FROM_HOST_RE.search(raw)
    by_match = BY_HOST_RE.search(raw)
    ip_match = IP_RE.search(raw)
    with_match = WITH_RE.search(raw)
    for_match = FOR_RE.search(raw)

    ip_val = None
    if ip_match:
        ip_val = ip_match.group(1) or ip_match.group(2)

    ip_type = classify_ip(ip_val) if ip_val else "Unknown"


    dt_obj = None
    timestamp_str = None
    if ";" in raw:
        date_part = raw.rsplit(";", 1)[-1].strip()
        try:
            dt_obj = parsedate_to_datetime(date_part)
            timestamp_str = dt_obj.isoformat()
        except Exception:
            dt_obj = None
            timestamp_str = f"Unparseable ({date_part[:30]})"

    hop = Hop(
        raw=raw,
        from_host=from_match.group(1) if from_match else None,
        by_host=by_match.group(1) if by_match else None,
        ip=ip_val,
        ip_type=ip_type,
        timestamp=timestamp_str,
        protocol=with_match.group(1) if with_match else None,
        for_recipient=for_match.group(1) if for_match else None,
    )
    hop._dt_obj = dt_obj
    return hop


def analyse_routing(parsed: ParsedMessage) -> RoutingVerdict:
    logger.debug("Analysing routing chain & constructing delivery timeline.")
    raw_chain = parsed.received_chain
    parsed_hops = [_parse_hop(h) for h in raw_chain]

    flags: List[str] = []

    if not parsed_hops:
        flags.append("No Received: headers present — cannot verify routing path (possible header stripping or local injection).")
        return RoutingVerdict(hops=[], hop_count=0, timeline=[], flags=flags)

    # Re-order chronologically (oldest hop / origin = Hop 1, newest = Hop N)
    # RFC 5321 convention: raw_chain[0] is newest (top of email), raw_chain[-1] is oldest (bottom)
    chronological_hops = list(reversed(parsed_hops))
    for idx, h in enumerate(chronological_hops, start=1):
        h.hop_number = idx

    # Calculate delays between consecutive chronological hops
    for h1, h2 in zip(chronological_hops, chronological_hops[1:]):
        dt1, dt2 = getattr(h1, '_dt_obj', None), getattr(h2, '_dt_obj', None)
        if dt1 and dt2:
            h2.delay_seconds = (dt2 - dt1).total_seconds()
        else:
            h2.delay_seconds = 0.0

    # Build Delivery Timeline & Detect Anomalies
    timeline: List[RoutingTimelineEntry] = []
    has_seen_public_ip = False

    now_utc = datetime.now(timezone.utc)

    for h in chronological_hops:
        dt = getattr(h, '_dt_obj', None)
        
        # 1. Invalid or Future Timestamps
        if dt is not None:
            # Guard: localize naive datetimes to UTC before comparison
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt > now_utc and (dt - now_utc).total_seconds() > 300:
                msg = f"Hop #{h.hop_number} has a future timestamp ({h.timestamp}) — clock skew or forged header."
                flags.append(msg)
                h.flags.append(msg)
        elif h.timestamp and "Unparseable" in h.timestamp:
            msg = f"Hop #{h.hop_number} has an unparseable timestamp format."
            flags.append(msg)
            h.flags.append(msg)

        # 2. Impossible Routing Sequences (Negative Delays / Time Travel)
        if h.delay_seconds < -5.0:
            msg = f"Hop #{h.hop_number} occurred {int(abs(h.delay_seconds))}s BEFORE Hop #{h.hop_number - 1} (time travel anomaly / forged header)."
            flags.append(msg)
            h.flags.append(msg)

        # 3. Excessive Delays
        if h.delay_seconds > 86400:  # > 24 hours
            hours = int(h.delay_seconds // 3600)
            msg = f"Hop #{h.hop_number} experienced excessive transit delay (~{hours} hours)."
            flags.append(msg)
            h.flags.append(msg)

        # 4. Suspicious Private IPs in WAN Transit
        if h.ip_type == "Public":
            has_seen_public_ip = True
        elif h.ip_type in {"Private (RFC 1918)", "Loopback"} and has_seen_public_ip:
            msg = f"Hop #{h.hop_number} contains private IP ({h.ip}) appearing after public WAN transit."
            flags.append(msg)
            h.flags.append(msg)

        # Create Timeline Entry
        delay_disp = _format_delay(h.delay_seconds) if h.hop_number > 1 else "Origin"
        summary_parts = []
        if h.protocol:
            summary_parts.append(f"via {h.protocol}")
        if h.flags:
            summary_parts.append(f"⚠️ {'; '.join(h.flags)}")

        timeline.append(RoutingTimelineEntry(
            hop_number=h.hop_number,
            timestamp=h.timestamp or "Unknown",
            delay_display=delay_disp,
            from_host=h.from_host or "Unknown",
            by_host=h.by_host or "Unknown",
            ip_info=f"{h.ip or 'No IP'} ({h.ip_type})",
            summary=" ".join(summary_parts) if summary_parts else "Normal transit"
        ))

    # 5. Missing Hops / Discontinuity Check
    for h1, h2 in zip(chronological_hops, chronological_hops[1:]):
        if h1.by_host and h2.from_host:
            b1 = h1.by_host.lower().split(".")[0]
            f2 = h2.from_host.lower().split(".")[0]
            if b1 != f2 and not _is_related_hostname(h1.by_host, h2.from_host):
                flags.append(f"Discontinuity between Hop #{h1.hop_number} (by '{h1.by_host}') and Hop #{h2.hop_number} (from '{h2.from_host}') — possible missing intermediate relay hop.")

    # 6. Single Hop Warning
    if len(chronological_hops) == 1:
        flags.append("Only one Received hop found — unusually short chain for internet-delivered mail; suggests direct injection.")

    # Clean up temporary _dt_obj
    for h in chronological_hops:
        if hasattr(h, '_dt_obj'):
            delattr(h, '_dt_obj')

    return RoutingVerdict(
        hops=chronological_hops,
        hop_count=len(chronological_hops),
        timeline=timeline,
        flags=flags
    )


def _format_delay(seconds: float) -> str:
    if seconds < 0:
        return f"-{int(abs(seconds))}s ⚠️"
    if seconds < 60:
        return f"+{int(seconds)}s"
    if seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"+{mins}m {secs}s"
    hours = int(seconds // 3600)
    mins = int((seconds % 3600) // 60)
    return f"+{hours}h {mins}m"


def _is_related_hostname(h1: str, h2: str) -> bool:
    d1 = ".".join(h1.lower().rsplit(".", 2)[-2:])
    d2 = ".".join(h2.lower().rsplit(".", 2)[-2:])
    return d1 == d2



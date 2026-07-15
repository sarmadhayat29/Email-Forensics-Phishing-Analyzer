"""Stage 5 — Routing analysis.

Walks the Received: header chain (oldest hop last, newest first, per RFC
5321 convention) and flags structural anomalies. This is deliberately
conservative: it flags patterns worth a human look rather than asserting
certainty, since legitimate mail infrastructure varies a lot.
"""

import re
from email.utils import parsedate_to_datetime

IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
BY_HOST_RE = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)
FROM_HOST_RE = re.compile(r"\bfrom\s+([^\s;]+)", re.IGNORECASE)


def _parse_hop(raw: str) -> dict:
    from_match = FROM_HOST_RE.search(raw)
    by_match = BY_HOST_RE.search(raw)
    ip_match = IP_RE.search(raw)

    timestamp = None
    if ";" in raw:
        date_part = raw.rsplit(";", 1)[-1].strip()
        try:
            timestamp = parsedate_to_datetime(date_part)
        except (ValueError, TypeError):
            timestamp = None

    return {
        "raw": raw,
        "from_host": from_match.group(1) if from_match else None,
        "by_host": by_match.group(1) if by_match else None,
        "ip": ip_match.group(1) if ip_match else None,
        "timestamp": timestamp.isoformat() if timestamp else None,
        "_timestamp_obj": timestamp,
    }


def analyse_routing(parsed: dict) -> dict:
    raw_chain = parsed.get("received_chain", [])
    hops = [_parse_hop(h) for h in raw_chain]

    flags = []

    if not hops:
        flags.append("No Received: headers present — cannot verify routing path "
                      "(may have been stripped, or this is a locally-composed test message).")

    # Check chronological ordering: each hop should be at or after the
    # previous one in real transit time (oldest hop is last in the list).
    timestamps = [h["_timestamp_obj"] for h in hops if h["_timestamp_obj"]]
    for earlier, later in zip(timestamps, timestamps[1:]):
        # hops list is newest-first, so "earlier" here is actually the later
        # hop chronologically; later var is an older hop. They should satisfy
        # later <= earlier (older hop happened before the newer one).
        if later > earlier:
            flags.append(
                "Timestamp inconsistency in Received chain: a hop appears to "
                "occur before an earlier hop in transit — possible header "
                "forgery or clock skew."
            )
            break

    # Large time gaps between consecutive hops can indicate delayed relay /
    # holding (used in some spoofing/relay-abuse setups).
    for h1, h2 in zip(hops, hops[1:]):
        t1, t2 = h1["_timestamp_obj"], h2["_timestamp_obj"]
        if t1 and t2:
            delta = abs((t1 - t2).total_seconds())
            if delta > 3600:
                flags.append(
                    f"Large time gap (~{int(delta // 60)} min) between two "
                    f"hops in the Received chain — worth reviewing."
                )

    if len(hops) == 1:
        flags.append(
            "Only one Received hop found — unusually short chain for "
            "internet-delivered mail; may indicate direct injection."
        )

    for h in hops:
        del h["_timestamp_obj"]

    return {"hops": hops, "hop_count": len(hops), "flags": flags}

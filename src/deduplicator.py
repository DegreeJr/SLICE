"""
deduplicator.py
Stage 3: Collapse identical log lines into a single row with a counter.

Deduplication is what removes the massive repetition in security logs. For
plaintext logs we deduplicate on the `_template` (produced by templatizer.py),
so lines that share a pattern but differ only in PID/IP collapse together.

Reference: the count-aggregation idea is standard in log-analysis toolkits such
as Loghub / LogPAI (He et al., ISSRE 2023).
"""

from typing import List, Tuple


# Fields used as the "signature" to detect duplicates.
# `_template` comes first: for plaintext logs, lines with the same pattern
# (different PID/IP) share a template and therefore collapse into one.
SIGNATURE_FIELDS = [
    "_template",
    "EventID", "event_id",
    "src_ip", "source_ip",
    "dst_ip", "dest_ip",
    "user", "username", "User", "TargetUserName",
    "action", "status",
    "Image", "ProcessName",
    "message", "msg", "_raw",
]


def make_signature(log: dict) -> tuple:
    """Build a fingerprint of a log from its important fields (ignoring timestamp)."""
    # If a template exists (plaintext log), use only that as the signature so
    # PID/IP variation does not prevent grouping.
    if log.get("_template"):
        return ("_tmpl", log["_template"])
    return tuple(
        str(log.get(f, ""))
        for f in SIGNATURE_FIELDS
    )


def deduplicate(logs: List[dict]) -> List[dict]:
    """
    Take a list of normalized, filtered logs and return the deduplicated list,
    with a `_count` field giving how many times each log occurred.
    """
    seen: dict[tuple, Tuple[dict, int]] = {}  # signature -> (log, count)
    order: List[tuple] = []  # preserve first-seen order

    for log in logs:
        sig = make_signature(log)
        if sig in seen:
            entry, count = seen[sig]
            seen[sig] = (entry, count + 1)
        else:
            seen[sig] = (log, 1)
            order.append(sig)

    result = []
    for sig in order:
        log, count = seen[sig]
        out = dict(log)
        out["_count"] = count
        result.append(out)

    return result

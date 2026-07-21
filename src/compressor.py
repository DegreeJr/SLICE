"""
compressor.py
Stage 4: Convert logs into a pipe-delimited columnar format.

Instead of repeating JSON keys on every line, the field names are written once
in a header and each row only contains the values, separated by "|". This
removes the per-line key overhead of JSON and is noticeably cheaper in tokens.

Output format:
    FIELDS: field1|field2|field3|...
    [xN] val1|val2|val3|...      (the [xN] prefix means this row occurred N times)
    val1|val2|val3|...
"""

from typing import List


# Fields shown in the columnar header (fixed order)
COLUMN_ORDER = [
    "_count",
    "EventID", "event_id",
    "timestamp",
    "src_ip", "source_ip",
    "dst_ip", "dest_ip",
    "src_port", "dst_port",
    "user", "username", "User", "TargetUserName",
    "action", "status", "severity",
    "Image", "CommandLine", "ProcessName",
    "message", "msg", "_template", "_raw",
]


def compress_to_columnar(logs: List[dict]) -> str:
    """
    Convert a list of logs into pipe-delimited columnar text.
    Field names are written once in the header; values follow, one row per log.
    """
    if not logs:
        return ""

    # Collect every field that appears across all logs
    all_fields = []
    seen_fields = set()
    for col in COLUMN_ORDER:
        if col not in seen_fields:
            if any(col in log for log in logs):
                all_fields.append(col)
                seen_fields.add(col)

    # Add any remaining fields not covered by COLUMN_ORDER
    for log in logs:
        for key in log:
            if key not in seen_fields and not key.startswith("_format"):
                all_fields.append(key)
                seen_fields.add(key)

    # Build output
    lines = []
    lines.append("FIELDS: " + "|".join(all_fields))

    for log in logs:
        count = log.get("_count", 1)
        prefix = f"[x{count}] " if count > 1 else ""
        values = []
        for field in all_fields:
            val = log.get(field, "-")
            # Sanitize newlines and pipes inside values
            val = str(val).replace("\n", " ").replace("|", "/").replace("\r", "")
            values.append(val)
        lines.append(prefix + "|".join(values))

    return "\n".join(lines)

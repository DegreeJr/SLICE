"""
normalizer.py
Stage 1: Parse different log formats (JSON, Syslog) into a unified dict.

For JSON logs we keep the fields directly. For plaintext syslog we strip the
standard header (priority, timestamp, hostname) and keep the message body as
`_raw`, which is later turned into a template (see templatizer.py).
"""

import json
import re
from typing import Optional


# Fields we consider important and keep from a structured log
VITAL_FIELDS = [
    "timestamp", "EventID", "event_id",
    "src_ip", "dst_ip", "source_ip", "dest_ip",
    "user", "username", "User", "TargetUserName",
    "action", "status", "severity", "level",
    "message", "msg",
    "Image", "CommandLine", "ProcessName",
    "src_port", "dst_port",
]

# Regex to strip a syslog header: "<priority>Month Day HH:MM:SS hostname"
SYSLOG_HEADER = re.compile(
    r"^(?:<\d+>)?\s*\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+[\w.\-]+\s+"
)


def parse_line(raw_line: str) -> Optional[dict]:
    """
    Take one raw log line and return a unified dict.
    Return None for empty lines that cannot be parsed.
    """
    line = raw_line.strip()
    if not line:
        return None

    # --- Try to parse as JSON ---
    try:
        data = json.loads(line)
        if isinstance(data, dict):
            return _extract_vital(data)
    except (json.JSONDecodeError, ValueError):
        pass

    # --- Strip syslog header, then try JSON again ---
    stripped = SYSLOG_HEADER.sub("", line).strip()
    try:
        data = json.loads(stripped)
        if isinstance(data, dict):
            return _extract_vital(data)
    except (json.JSONDecodeError, ValueError):
        pass

    # --- Fallback: keep as raw plaintext message ---
    return {"_raw": stripped or line, "_format": "syslog"}


def _extract_vital(data: dict) -> dict:
    """Keep only meaningful fields, drop noisy metadata."""
    result = {}
    for field in VITAL_FIELDS:
        if field in data:
            result[field] = data[field]

    # Keep unknown fields that might still matter
    for key, val in data.items():
        if key not in result and key not in _NOISE_FIELDS:
            result[key] = val

    result["_format"] = "json"
    return result


# Fields that are always dropped (noisy metadata)
_NOISE_FIELDS = {
    "Version", "SchemaVersion", "ProviderGuid", "Channel",
    "Computer", "ProcessId", "ThreadId", "ProviderName",
    "Opcode", "Task", "Keywords", "TimeCreated",
    "ActivityID", "RelatedActivityID", "Execution",
    "RenderingInfo", "System",
}

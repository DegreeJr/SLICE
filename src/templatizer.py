"""
templatizer.py
Stage 2.5: Turn plaintext (syslog) logs into TEMPLATES by masking variable
tokens (IP, number, PID, hex, UUID, MAC) with placeholders.

This is the core "log parsing / templating" idea. Thousands of lines that share
the same pattern but differ in details (PID/IP) collapse into a single template
plus a count, which is where most of the token savings come from.

Reference: He et al., "Drain: An Online Log Parsing Approach with Fixed Depth
Tree", IEEE ICWS 2017. This module is a lightweight, regex-based variant of the
same masking-then-grouping principle.

Example:
    sshd[22493]: Did not receive identification string from 218.75.153.170
    sshd[22494]: Did not receive identification string from 218.75.153.170
    -> sshd[<PID>]: Did not receive identification string from <IP>   (xN)
"""

import re

# Order matters: most specific patterns first.
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                   r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b")
# PID in square brackets: sshd[1234] -> sshd[<PID>]
_PID = re.compile(r"\[\d+\]")
# Long numbers / ports / ids
_NUM = re.compile(r"\b\d+\b")


def make_template(text: str) -> str:
    """Return the templated version of a single plaintext log line."""
    t = text
    t = _UUID.sub("<UUID>", t)
    t = _MAC.sub("<MAC>", t)
    t = _IPV4.sub("<IP>", t)
    t = _IPV6.sub("<IP6>", t)
    t = _HEX.sub("<HEX>", t)
    t = _PID.sub("[<PID>]", t)
    t = _NUM.sub("<NUM>", t)
    return t


def apply_templates(logs: list) -> list:
    """
    For every plaintext log (has `_raw`), add a `_template` field.
    Structured JSON logs are left untouched (they already have fields to dedup on).
    """
    for log in logs:
        raw = log.get("_raw")
        if raw:
            log["_template"] = make_template(str(raw))
            # `_raw` is no longer needed (noise filter already ran); drop it so it
            # does not duplicate `_template` in the output.
            log.pop("_raw", None)
    return logs

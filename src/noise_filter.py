"""
noise_filter.py
Stage 2: Drop log lines that are not useful for security analysis.

Rule-based filtering of routine/low-signal events. The goal is to remove
"background noise" so the LLM only sees security-relevant lines. This mirrors
the noise-reduction step common in log-analysis pipelines (see README, Method).
"""

# Severity levels that are dropped immediately
LOW_SEVERITY = {"debug", "trace", "verbose", "info"}

# Message keywords that indicate routine / uninteresting events
NOISE_KEYWORDS = [
    "health check", "healthcheck", "heartbeat", "keep-alive",
    "keepalive", "ping", "uptime monitor", "liveness probe",
    "readiness probe", "metrics scraped", "connection accepted",
    "connection closed normally",
]

# Windows EventIDs known to be high-volume / low-signal
NOISY_EVENT_IDS = {
    5156,  # Windows Filtering Platform: connection allowed
    5157,  # Windows Filtering Platform: connection blocked (very high volume)
    4662,  # Operation on an AD object (too verbose)
    4688,  # Process creation - only noise for routine system processes
}

# Routine system processes safe to ignore in Event 4688
ROUTINE_PROCESSES = {
    "svchost.exe", "taskhostw.exe", "conhost.exe",
    "wuauclt.exe", "msiexec.exe", "SearchIndexer.exe",
}

# Firewall actions dropped when traffic is internal-to-internal
SKIP_FIREWALL_ACTIONS = {"allow", "permit", "accept"}


def is_noise(log: dict) -> bool:
    """
    Return True if this log is considered noise and should be dropped.
    Return False if the log should be kept.
    """
    # 1. Check severity / level
    sev = str(log.get("severity") or log.get("level") or "").lower()
    if sev in LOW_SEVERITY:
        return True

    # 2. Check noise keywords in the message
    msg = str(log.get("message") or log.get("msg") or log.get("_raw") or "").lower()
    for kw in NOISE_KEYWORDS:
        if kw in msg:
            return True

    # 3. Check high-noise Windows EventIDs
    eid = log.get("EventID") or log.get("event_id")
    if eid and str(eid).isdigit() and int(eid) in NOISY_EVENT_IDS:
        # Exception: EventID 4688 is only dropped for routine processes
        if int(eid) == 4688:
            image = str(log.get("Image") or log.get("ProcessName") or "").lower()
            image_name = image.split("\\")[-1]
            if image_name in ROUTINE_PROCESSES:
                return True
        else:
            return True

    # 4. Drop internal firewall "allow" traffic (not suspicious)
    action = str(log.get("action") or "").lower()
    src = str(log.get("src_ip") or log.get("source_ip") or "")
    dst = str(log.get("dst_ip") or log.get("dest_ip") or "")
    if action in SKIP_FIREWALL_ACTIONS and _is_internal(src) and _is_internal(dst):
        return True

    return False


def _is_internal(ip: str) -> bool:
    """Check whether an IP is in a private/internal range."""
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.2")
        or ip.startswith("172.3")
        or ip == "127.0.0.1"
    )

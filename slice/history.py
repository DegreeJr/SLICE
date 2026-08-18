"""
history.py
Persist analysis history to a local file (history.json) so the dashboard does
not reset when the app is stopped and started again.

Stored locally in the user's working directory; it never leaves the machine.
Only lightweight metadata is stored (statistics + verdict) - NOT the raw logs.
"""

import os
import json
import time
from datetime import datetime

HISTORY_PATH = os.environ.get("SLICE_HISTORY", "history.json")
MAX_RECORDS = 500


def _load_raw() -> list:
    if os.path.exists(HISTORY_PATH):
        try:
            with open(HISTORY_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except (OSError, json.JSONDecodeError):
            # Corrupt or unreadable history file: start with an empty history
            # rather than crashing the app.
            return []
    return []


def _save_raw(records: list) -> None:
    # Keep only the most recent MAX_RECORDS
    trimmed = records[-MAX_RECORDS:]
    with open(HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(trimmed, f, ensure_ascii=False, indent=2)


def add_record(rec: dict) -> str:
    """Append a new record. Returns its id."""
    records = _load_raw()
    rec_id = str(int(time.time() * 1000))
    rec["id"] = rec_id
    rec["ts"] = datetime.now().isoformat(timespec="seconds")
    records.append(rec)
    _save_raw(records)
    return rec_id


def update_record(rec_id: str, patch: dict) -> None:
    """Update a record by id (e.g. attach the verdict result)."""
    records = _load_raw()
    for rec in records:
        if rec.get("id") == rec_id:
            rec.update(patch)
            break
    _save_raw(records)


def list_records() -> list:
    """Return all records, most recent first."""
    return list(reversed(_load_raw()))


def clear() -> None:
    _save_raw([])


def summary() -> dict:
    """Cumulative statistics for the dashboard."""
    records = _load_raw()
    total = len(records)
    tokens_saved = sum(r.get("tokens_saved", 0) for r in records)
    cost_saved = sum(r.get("cost_saved", 0) for r in records)
    analyzed = sum(1 for r in records if r.get("verdict"))
    reductions = [r.get("token_reduction_pct", 0) for r in records if r.get("token_reduction_pct")]
    avg_reduction = round(sum(reductions) / len(reductions), 1) if reductions else 0
    return {
        "total_runs": total,
        "total_analyzed": analyzed,
        "total_tokens_saved": tokens_saved,
        "total_cost_saved": round(cost_saved, 4),
        "avg_reduction_pct": avg_reduction,
    }

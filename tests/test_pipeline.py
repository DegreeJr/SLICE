"""
Unit tests for the SLICE compression pipeline.
Run with:  pytest -q
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from normalizer import parse_line
from noise_filter import is_noise
from templatizer import make_template, apply_templates
from deduplicator import deduplicate, make_signature
from aggregator import aggregate_templates
from compressor import compress_to_columnar
from pipeline import run_pipeline, iter_pipeline, STAGES


# ---------- normalizer ----------
def test_parse_json_line():
    log = parse_line('{"EventID":4625,"src_ip":"1.2.3.4","status":"FAIL"}')
    assert log["EventID"] == 4625
    assert log["src_ip"] == "1.2.3.4"
    assert log["_format"] == "json"


def test_parse_syslog_line_becomes_raw():
    log = parse_line("Nov 30 06:39:00 host sshd[2211]: Invalid user admin from 1.2.3.4")
    assert log["_format"] == "syslog"
    assert "Invalid user admin" in log["_raw"]


def test_parse_empty_line_returns_none():
    assert parse_line("   ") is None


# ---------- noise filter ----------
def test_noise_filter_drops_debug():
    assert is_noise({"severity": "debug", "message": "x"}) is True


def test_noise_filter_keeps_warning():
    assert is_noise({"severity": "warning", "message": "failed login"}) is False


def test_noise_filter_drops_internal_firewall_allow():
    assert is_noise({"action": "allow", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}) is True


# ---------- templatizer ----------
def test_template_masks_ip_pid_and_number():
    tmpl = make_template("sshd[22493]: Received disconnect from 218.75.153.170: 11: Bye Bye")
    assert "<PID>" in tmpl
    assert "<IP>" in tmpl
    assert "<NUM>" in tmpl
    assert "22493" not in tmpl


def test_apply_templates_drops_raw():
    logs = [{"_raw": "sshd[1]: hello 1.2.3.4"}]
    out = apply_templates(logs)
    assert "_template" in out[0]
    assert "_raw" not in out[0]


# ---------- deduplicator ----------
def test_dedup_collapses_same_template():
    logs = [
        {"_template": "sshd[<PID>]: x from <IP>"},
        {"_template": "sshd[<PID>]: x from <IP>"},
        {"_template": "sshd[<PID>]: x from <IP>"},
    ]
    out = deduplicate(logs)
    assert len(out) == 1
    assert out[0]["_count"] == 3


def test_signature_uses_template_when_present():
    sig = make_signature({"_template": "abc", "src_ip": "9.9.9.9"})
    assert sig == ("_tmpl", "abc")


# ---------- aggregator ----------
def test_aggregate_merges_single_token_difference():
    logs = [
        {"_template": "Invalid user oracle from host", "_count": 5},
        {"_template": "Invalid user admin from host", "_count": 3},
        {"_template": "Invalid user test from host", "_count": 2},
    ]
    out = aggregate_templates(logs, min_group=3)
    merged = [l for l in out if "<VAR>" in l["_template"]]
    assert len(merged) == 1
    assert merged[0]["_count"] == 10
    assert "3 distinct" in merged[0]["_template"]


# ---------- compressor ----------
def test_columnar_has_header_and_count_prefix():
    out = compress_to_columnar([{"_count": 4, "EventID": 4625}])
    assert out.startswith("FIELDS:")
    assert "[x4]" in out


# ---------- full pipeline ----------
def test_full_pipeline_reduces_tokens():
    raw = "\n".join(
        f"Nov 30 06:00:{i:02d} host sshd[{1000+i}]: Invalid user admin from 203.0.113.5"
        for i in range(40)
    )
    compressed, stats = run_pipeline(raw)
    assert stats["compressed_tokens"] < stats["original_tokens"]
    assert stats["compressed_lines"] < stats["original_lines"]
    assert stats["token_reduction_pct"] > 0


def test_full_pipeline_json_roundtrip():
    raw = "\n".join(
        '{"EventID":4625,"src_ip":"203.0.113.5","User":"admin","status":"FAIL","severity":"warning"}'
        for _ in range(10)
    )
    compressed, stats = run_pipeline(raw)
    assert "FIELDS:" in compressed
    assert stats["duplicate_lines_collapsed"] > 0


# ---------- staged progress ----------
def test_iter_pipeline_emits_all_stages_then_done():
    raw = "\n".join(
        f"Nov 30 06:00:{i:02d} host sshd[{1000+i}]: Failed password for admin from 203.0.113.5 port {i} ssh2"
        for i in range(40)
    )
    events = list(iter_pipeline(raw))
    stages = [e["stage"] for e in events if "stage" in e]
    assert stages == [s for s, _ in STAGES]          # all six stages, in order
    done = [e for e in events if e.get("done")]
    assert len(done) == 1
    assert "compressed" in done[0] and "stats" in done[0]
    # run_pipeline returns exactly the streamed final result
    comp, stats = run_pipeline(raw)
    assert comp == done[0]["compressed"]
    assert stats["compressed_lines"] == done[0]["stats"]["compressed_lines"]

"""
Unit tests for the LLM layer: JSON extraction, validation, streaming split, and
the SSE streaming endpoint (with a fake provider, so no network is used).
Run with:  pytest -q
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from slice import llm


# ---------- JSON extraction ----------
def test_extract_plain_json():
    d = llm._extract_json('{"verdict":"BENIGN","confidence":0.2}')
    assert d["verdict"] == "BENIGN"


def test_extract_json_from_code_fence():
    raw = 'Here you go:\n```json\n{"verdict":"MALICIOUS","confidence":0.9}\n```'
    d = llm._extract_json(raw)
    assert d["verdict"] == "MALICIOUS"


def test_extract_json_with_surrounding_prose():
    raw = 'Analysis done. {"verdict":"SUSPICIOUS","confidence":0.5} thanks'
    d = llm._extract_json(raw)
    assert d["verdict"] == "SUSPICIOUS"


def test_extract_json_raises_when_absent():
    try:
        llm._extract_json("no json here")
        assert False, "expected ValueError"
    except ValueError:
        pass


# ---------- normalization / validation ----------
def test_normalize_rejects_unknown_verdict():
    r = llm._normalize_report({"verdict": "TOTALLY_SAFE", "confidence": 0.5})
    assert r["verdict"] == "UNKNOWN"


def test_normalize_clamps_confidence():
    assert llm._normalize_report({"verdict": "BENIGN", "confidence": 5})["confidence"] == 1.0
    assert llm._normalize_report({"verdict": "BENIGN", "confidence": -2})["confidence"] == 0.0


def test_normalize_handles_bad_confidence_type():
    assert llm._normalize_report({"verdict": "BENIGN", "confidence": "abc"})["confidence"] == 0.0


# ---------- streaming split / finalize ----------
def test_split_stream_text_with_sentinel():
    narrative, jtxt = llm.split_stream_text('Some analysis.\n@@VERDICT@@{"verdict":"BENIGN"}')
    assert narrative == "Some analysis."
    assert jtxt.startswith("{")


def test_split_stream_text_without_sentinel():
    narrative, jtxt = llm.split_stream_text("Just prose")
    assert narrative == "Just prose"
    assert jtxt == ""


def test_annotate_trust_flags_low_confidence():
    r = llm.annotate_trust({"verdict": "MALICIOUS", "confidence": 0.3})
    assert r["trust"]["low_confidence"] is True


def test_annotate_trust_flags_unknown_verdict():
    r = llm.annotate_trust({"verdict": "UNKNOWN", "confidence": 0.99})
    assert r["trust"]["low_confidence"] is True


def test_annotate_trust_passes_high_confidence():
    r = llm.annotate_trust({"verdict": "BENIGN", "confidence": 0.9})
    assert r["trust"]["low_confidence"] is False


def test_finalize_report_parses_and_keeps_narrative():
    full = 'Brute force from one IP.\n@@VERDICT@@{"verdict":"malicious","confidence":0.9,"mitre_technique":"T1110","summary":"SSH brute force"}'
    r = llm.finalize_report(full)
    assert r["verdict"] == "MALICIOUS"     # normalized to upper + validated
    assert r["mitre_technique"] == "T1110"
    assert r["analysis"] == "Brute force from one IP."


# ---------- streaming endpoint (fake provider, no network) ----------
def test_analyze_stream_endpoint(monkeypatch):
    from fastapi.testclient import TestClient
    from slice.server import app

    def fake_stream(text, provider):
        yield "SSH brute force detected across many usernames. "
        yield '@@VERDICT@@{"verdict":"MALICIOUS","confidence":0.92,"mitre_technique":"T1110","summary":"Brute force"}'

    monkeypatch.setattr(llm, "analyze_stream", fake_stream)

    client = TestClient(app)
    r = client.post("/api/analyze_stream", json={"text": "FIELDS: _count|_template\n[x8] 8|failed login"})
    assert r.status_code == 200
    body = r.text
    assert "event: delta" in body
    assert "event: done" in body
    assert '"verdict": "MALICIOUS"' in body

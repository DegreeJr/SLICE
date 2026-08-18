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


# ---------- chunking: split_payload / merge_reports ----------
def test_split_payload_single_when_small():
    assert len(llm.split_payload("FIELDS: a|b\n1|x", 8000)) == 1


def test_split_payload_multiple_and_preserves_rows():
    header = "FIELDS: _count|_template"
    rows = [f"{i}|row-data-value-{i:04d}-paddingxxxxxxxxxxxxxx" for i in range(400)]
    text = header + "\n" + "\n".join(rows)
    chunks = llm.split_payload(text, 1000)  # ~4000-char budget forces splitting
    assert len(chunks) > 1
    assert all(c.startswith(header) for c in chunks)  # header repeated on each chunk
    recovered = []
    for c in chunks:
        recovered.extend(c.split("\n")[1:])
    assert recovered == rows  # every row preserved, in order


def test_merge_reports_worst_case_verdict():
    r = llm.merge_reports([
        {"verdict": "BENIGN", "confidence": 0.9, "mitre_technique": "None", "summary": "clean"},
        {"verdict": "MALICIOUS", "confidence": 0.8, "mitre_technique": "T1110", "summary": "brute force"},
    ])
    assert r["verdict"] == "MALICIOUS"        # worst-case wins
    assert r["confidence"] == 0.8             # from the malicious chunk
    assert "T1110" in r["mitre_technique"]
    assert "brute force" in r["summary"]


def test_merge_reports_empty_is_unknown():
    assert llm.merge_reports([])["verdict"] == "UNKNOWN"


def test_analyze_endpoint_chunks_large_log(monkeypatch):
    from fastapi.testclient import TestClient
    from slice.server import app

    calls = {"n": 0}

    def fake_analyze(text, provider):
        calls["n"] += 1
        verdict = "MALICIOUS" if calls["n"] == 2 else "BENIGN"
        return {"verdict": verdict, "confidence": 0.7, "mitre_technique": "T1059", "summary": f"part {calls['n']}"}

    monkeypatch.setattr(llm, "analyze", fake_analyze)

    header = "FIELDS: _count|_template"
    rows = [f"{i}|padding-row-data-{i:05d}-" + ("x" * 40) for i in range(1000)]
    big = header + "\n" + "\n".join(rows)  # ~64k chars > groq 12k-token budget

    client = TestClient(app)
    r = client.post("/api/analyze", json={"text": big, "provider": "groq"})
    assert r.status_code == 200
    body = r.json()
    assert body["chunks"] > 1                 # was split into multiple chunks
    assert body["verdict"] == "MALICIOUS"     # merged worst-case

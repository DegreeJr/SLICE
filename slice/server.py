"""
server.py
SLICE FastAPI backend. Serves the static UI + a REST API.
All log processing runs locally; only the compressed result is sent to the LLM.
"""

import json
import os
import sys

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add the src/ folder to the path so the pipeline can be imported
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from pipeline import run_pipeline  # noqa: E402
import injection_guard  # noqa: E402
from . import config as cfg_mod  # noqa: E402
from . import llm as llm_mod  # noqa: E402
from . import history as hist_mod  # noqa: E402

# Bundled demo logs that the UI can run with one click.
_SAMPLES = {
    "ssh_bruteforce": {"file": "demo_ssh_bruteforce.log", "label": "SSH brute force"},
    "windows_events": {"file": "demo_windows_events.json", "label": "Windows events"},
    "prompt_injection": {"file": "demo_prompt_injection.log", "label": "Prompt injection (defense demo)"},
}
_SAMPLES_DIR = os.path.join(_ROOT, "samples")

app = FastAPI(title="SLICE", version="0.1.0")

_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


# ---------- Request models ----------
class AnalyzeRequest(BaseModel):
    text: str
    provider: str | None = None
    history_id: str | None = None


class ConfigUpdate(BaseModel):
    active_provider: str | None = None
    providers: dict | None = None


class SampleRequest(BaseModel):
    name: str


# ---------- Helpers ----------
def _cost_estimate(tokens: int, price_per_1m: float) -> float:
    """Estimated USD cost. Estimate only; the price is user-editable."""
    return round(tokens / 1_000_000 * float(price_per_1m or 0), 6)


def _truncate_to_budget(text: str, max_tokens: int) -> tuple[str, bool]:
    """
    Trim the compressed text so it fits inside the LLM context window.
    Keep the FIELDS header + aggregated ([xN]) rows first, then fill the rest of
    the budget with the remaining rows in order. Estimates ~4 chars per token.
    """
    budget_chars = max_tokens * 4
    if len(text) <= budget_chars:
        return text, False

    lines = text.split("\n")
    if not lines:
        return text, False
    header = lines[0]
    rows = lines[1:]

    # Prioritize aggregated rows (most repetition) first, then the rest
    aggregated = [r for r in rows if r.startswith("[x")]
    singles = [r for r in rows if not r.startswith("[x")]

    out = [header]
    used = len(header)
    for r in aggregated + singles:
        if used + len(r) + 1 > budget_chars:
            return "\n".join(out), True
        out.append(r)
        used += len(r) + 1
    return "\n".join(out), True


# ---------- API ----------
@app.get("/api/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/api/config")
def get_config():
    """Return the config with API keys masked."""
    return cfg_mod.redacted(cfg_mod.load_config())


@app.post("/api/config")
def update_config(update: ConfigUpdate):
    """Save config changes. An empty api_key means 'keep the existing key'."""
    current = cfg_mod.load_config()
    if update.active_provider:
        current["active_provider"] = update.active_provider
    if update.providers:
        for name, prov in update.providers.items():
            if name not in current["providers"]:
                current["providers"][name] = {}
            for k, v in prov.items():
                # Do not overwrite api_key with an empty string / redacted placeholder
                if k == "api_key" and (not v or "..." in str(v) or v == "***"):
                    continue
                current["providers"][name][k] = v
    try:
        cfg_mod.save_config(current)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    return cfg_mod.redacted(cfg_mod.load_config())


def _process_raw(raw: str, filename: str) -> dict:
    """Run the pipeline on raw log text, attach stats, log to history."""
    if not raw.strip():
        raise HTTPException(status_code=400, detail="The log file is empty.")
    compressed, stats = run_pipeline(raw)

    # Injection guard: count injection attempts hidden in the compressed payload.
    stats["injection_hits"] = len(injection_guard.scan(compressed))

    # Add a cost estimate based on the active provider
    cfg = cfg_mod.load_config()
    prov = cfg["providers"].get(cfg["active_provider"], {})
    price = prov.get("price_per_1m", 0)
    stats["cost_original"] = _cost_estimate(stats["original_tokens"], price)
    stats["cost_compressed"] = _cost_estimate(stats["compressed_tokens"], price)
    stats["cost_saved"] = round(stats["cost_original"] - stats["cost_compressed"], 6)
    stats["price_per_1m"] = price
    stats["active_provider"] = cfg["active_provider"]

    # Save to history (metadata only, not the log contents)
    rec_id = hist_mod.add_record({
        "filename": filename,
        "original_tokens": stats["original_tokens"],
        "compressed_tokens": stats["compressed_tokens"],
        "tokens_saved": stats["tokens_saved"],
        "token_reduction_pct": stats["token_reduction_pct"],
        "original_lines": stats["original_lines"],
        "compressed_lines": stats["compressed_lines"],
        "noise_lines_removed": stats.get("noise_lines_removed", 0),
        "duplicate_lines_collapsed": stats.get("duplicate_lines_collapsed", 0),
        "cost_saved": stats.get("cost_saved", 0),
        "provider": cfg["active_provider"],
    })

    return {"compressed": compressed, "stats": stats, "filename": filename, "history_id": rec_id}


@app.post("/api/compress")
async def compress(file: UploadFile = File(...)):
    """Upload a log file, run the local pipeline, return stats + compressed text."""
    raw = (await file.read()).decode("utf-8", errors="ignore")
    return _process_raw(raw, file.filename)


@app.get("/api/samples")
def list_samples():
    """List the bundled demo logs the UI can run with one click."""
    return {"samples": [{"id": k, "label": v["label"]} for k, v in _SAMPLES.items()]}


@app.post("/api/compress_sample")
def compress_sample(req: SampleRequest):
    """Run the pipeline on a bundled sample log (no upload needed)."""
    meta = _SAMPLES.get(req.name)
    if not meta:
        raise HTTPException(status_code=404, detail=f"Unknown sample: {req.name}")
    path = os.path.join(_SAMPLES_DIR, meta["file"])
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail=f"Sample file missing: {meta['file']}")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()
    return _process_raw(raw, meta["file"])


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    """Send compressed text to the LLM. Only this text leaves the machine."""
    cfg = cfg_mod.load_config()
    prov_name = req.provider or cfg["active_provider"]
    prov = cfg["providers"].get(prov_name)
    if not prov:
        raise HTTPException(status_code=400, detail=f"Provider '{prov_name}' does not exist.")

    budget = int(prov.get("max_context_tokens", 8000) or 8000)

    # Chunking: if the payload exceeds the budget, split it and analyze each part
    # instead of truncating, then merge the verdicts. Capped to bound cost.
    chunks = llm_mod.split_payload(req.text, budget)
    used = chunks[:llm_mod.MAX_CHUNKS]

    reports, all_findings = [], []
    try:
        for chunk in used:
            protected, findings = injection_guard.defend(chunk)
            all_findings.extend(findings)
            reports.append(llm_mod.analyze(protected, prov))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM error ({prov_name}): {e}")

    report = reports[0] if len(reports) == 1 else llm_mod.merge_reports(reports)
    report["provider"] = prov_name
    report["model"] = prov.get("model")
    report["injection"] = {
        "hits": len(all_findings),
        "neutralized": len(all_findings) > 0,
        "rules": sorted({f["rule"] for f in all_findings}),
        "samples": [f["match"] for f in all_findings[:5]],
    }
    report["chunks"] = len(used)
    if len(chunks) > 1:
        note = f"Large log analyzed in {len(used)} chunk(s) to avoid dropping data."
        if len(chunks) > len(used):
            note += (f" Only the first {len(used)} of {len(chunks)} chunks were analyzed "
                     f"to bound cost; raise max_context_tokens to cover more per call.")
        report["note"] = note
    llm_mod.annotate_trust(report)

    # Update history with the verdict result
    if req.history_id:
        hist_mod.update_record(req.history_id, {
            "verdict": report.get("verdict"),
            "confidence": report.get("confidence"),
            "mitre": report.get("mitre_technique"),
            "model": prov.get("model"),
        })
    return report


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@app.post("/api/analyze_stream")
def analyze_stream(req: AnalyzeRequest):
    """Stream the LLM analysis as it is written (realtime), then a final report."""
    cfg = cfg_mod.load_config()
    prov_name = req.provider or cfg["active_provider"]
    prov = cfg["providers"].get(prov_name)
    if not prov:
        raise HTTPException(status_code=400, detail=f"Provider '{prov_name}' does not exist.")

    budget = int(prov.get("max_context_tokens", 8000) or 8000)
    chunks = llm_mod.split_payload(req.text, budget)

    def _update_history(report):
        if req.history_id:
            hist_mod.update_record(req.history_id, {
                "verdict": report.get("verdict"),
                "confidence": report.get("confidence"),
                "mitre": report.get("mitre_technique"),
                "model": prov.get("model"),
            })

    def gen():
        # Large log: analyze in chunks (progress messages instead of a token stream).
        if len(chunks) > 1:
            used = chunks[:llm_mod.MAX_CHUNKS]
            reports, all_findings = [], []
            yield _sse("delta", {"text": f"Large log — analyzing in {len(used)} chunks...\n"})
            try:
                for i, chunk in enumerate(used, 1):
                    protected, findings = injection_guard.defend(chunk)
                    all_findings.extend(findings)
                    reports.append(llm_mod.analyze(protected, prov))
                    yield _sse("delta", {"text": f"Analyzed chunk {i}/{len(used)}.\n"})
            except Exception as e:
                yield _sse("error", {"detail": f"LLM error ({prov_name}): {e}"})
                return
            report = llm_mod.merge_reports(reports)
            report["provider"] = prov_name
            report["model"] = prov.get("model")
            report["injection"] = {
                "hits": len(all_findings),
                "neutralized": len(all_findings) > 0,
                "rules": sorted({f["rule"] for f in all_findings}),
                "samples": [f["match"] for f in all_findings[:5]],
            }
            report["chunks"] = len(used)
            note = f"Large log analyzed in {len(used)} chunk(s) to avoid dropping data."
            if len(chunks) > len(used):
                note += f" Only the first {len(used)} of {len(chunks)} chunks were analyzed to bound cost."
            report["note"] = note
            llm_mod.annotate_trust(report)
            _update_history(report)
            yield _sse("done", report)
            return

        # Fits in one call: stream the analysis live.
        protected, findings = injection_guard.defend(chunks[0])
        injection = {
            "hits": len(findings),
            "neutralized": len(findings) > 0,
            "rules": sorted({f["rule"] for f in findings}),
            "samples": [f["match"] for f in findings[:5]],
        }
        buf = []
        try:
            for delta in llm_mod.analyze_stream(protected, prov):
                buf.append(delta)
                yield _sse("delta", {"text": delta})
        except Exception as e:
            yield _sse("error", {"detail": f"LLM error ({prov_name}): {e}"})
            return

        report = llm_mod.finalize_report("".join(buf))
        report["provider"] = prov_name
        report["model"] = prov.get("model")
        report["injection"] = injection
        report["chunks"] = 1
        llm_mod.annotate_trust(report)
        _update_history(report)
        yield _sse("done", report)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/history")
def get_history():
    """Return the analysis history + cumulative statistics."""
    return {"records": hist_mod.list_records(), "summary": hist_mod.summary()}


@app.post("/api/history/clear")
def clear_history():
    hist_mod.clear()
    return {"status": "ok"}


# ---------- Static UI ----------
@app.get("/")
def index():
    return FileResponse(os.path.join(_STATIC_DIR, "index.html"))


if os.path.isdir(_STATIC_DIR):
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


def serve(host: str = "127.0.0.1", port: int = 7654):
    import uvicorn
    print(f"\n  SLICE running at  http://{host}:{port}\n")
    uvicorn.run(app, host=host, port=port, log_level="info")

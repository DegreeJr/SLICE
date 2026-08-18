"""
bench.py

Reproducible benchmark for the SLICE pipeline. Runs the pipeline over a set of
log files and reports compression ratio + injection findings per file, so a
reviewer can verify the headline numbers with one command instead of trusting a
screenshot.

    python main.py --bench                 # run over the bundled samples/
    python main.py --bench --bench-out metrics   # also write metrics/benchmark.{md,csv}

The verdict-accuracy column requires an LLM call and is intentionally left out of
the offline benchmark; run the Analyze page for that.
"""

import os
import glob

from pipeline import run_pipeline
import injection_guard


def bench_file(path: str) -> dict:
    """Run the pipeline on one file and return a row of metrics."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()
    compressed, stats = run_pipeline(raw)
    tin, tout = stats["original_tokens"], stats["compressed_tokens"]
    # Compute reduction here with 2 decimals so a 99.97% ratio is not rounded up
    # to a misleading "100%".
    reduction = round(100 * (1 - tout / tin), 2) if tin else 0.0
    return {
        "file": os.path.basename(path),
        "lines_in": stats["original_lines"],
        "lines_out": stats["compressed_lines"],
        "tokens_in": tin,
        "tokens_out": tout,
        "reduction_pct": reduction,
        "injection_hits": len(injection_guard.scan(compressed)),
    }


def collect_files(directory: str):
    """Return sorted log/json/txt files in a directory (non-recursive)."""
    files = []
    for ext in ("*.log", "*.json", "*.txt"):
        files.extend(glob.glob(os.path.join(directory, ext)))
    return sorted(set(files))


def run_bench(paths) -> list:
    """Benchmark each path; skip files that fail to process."""
    rows = []
    for p in paths:
        try:
            rows.append(bench_file(p))
        except Exception as e:  # keep going; a bad file shouldn't stop the run
            rows.append({"file": os.path.basename(p), "error": str(e)})
    return rows


def format_markdown(rows: list) -> str:
    header = (
        "| File | Lines in → out | Tokens in → out | Reduction | Injection hits |\n"
        "| --- | ---: | ---: | ---: | ---: |\n"
    )
    body = []
    for r in rows:
        if "error" in r:
            body.append(f"| {r['file']} | error: {r['error']} | | | |")
            continue
        body.append(
            f"| {r['file']} | {r['lines_in']:,} → {r['lines_out']:,} | "
            f"{r['tokens_in']:,} → {r['tokens_out']:,} | "
            f"−{r['reduction_pct']}% | {r['injection_hits']} |"
        )
    return header + "\n".join(body) + "\n"


def format_csv(rows: list) -> str:
    out = ["file,lines_in,lines_out,tokens_in,tokens_out,reduction_pct,injection_hits"]
    for r in rows:
        if "error" in r:
            out.append(f"{r['file']},,,,,,")
            continue
        out.append(
            f"{r['file']},{r['lines_in']},{r['lines_out']},{r['tokens_in']},"
            f"{r['tokens_out']},{r['reduction_pct']},{r['injection_hits']}"
        )
    return "\n".join(out) + "\n"

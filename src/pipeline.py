"""
pipeline.py
Orchestrates all stages:
  normalize -> noise filter -> templating -> dedup -> aggregate -> compress

iter_pipeline() yields a progress event after each stage so a UI can show how
far processing has gotten and what each stage did. run_pipeline() is a thin
wrapper that just returns the final result.
"""

from typing import Tuple

from normalizer import parse_line
from noise_filter import is_noise
from templatizer import apply_templates
from deduplicator import deduplicate
from aggregator import aggregate_templates
from compressor import compress_to_columnar
from token_counter import compute_stats


# Ordered list of stages, for a UI to render the steps up front.
STAGES = [
    ("normalize", "Parsing & normalizing"),
    ("noise_filter", "Filtering routine noise"),
    ("template", "Templating variable fields"),
    ("dedup", "Deduplicating repeated lines"),
    ("aggregate", "Aggregating near-identical events"),
    ("compress", "Columnar compression"),
]


def iter_pipeline(raw_text: str):
    """Run the pipeline, yielding a progress event after each stage.

    Each stage event is a dict: {"stage", "label", "rows"} where `rows` is the
    number of rows remaining after that stage. The final event is
    {"done": True, "compressed": <str>, "stats": <dict>}.
    """
    raw_lines = raw_text.strip().splitlines()
    total = len(raw_lines)

    # Stage 1: Normalize
    parsed = []
    for line in raw_lines:
        result = parse_line(line)
        if result is not None:
            parsed.append(result)
    yield {"stage": "normalize", "label": "Parsing & normalizing", "rows": len(parsed), "total": total}

    # Stage 2: Noise filter
    filtered = [log for log in parsed if not is_noise(log)]
    noise_removed = len(parsed) - len(filtered)
    yield {"stage": "noise_filter", "label": "Filtering routine noise", "rows": len(filtered), "total": total}

    # Stage 3: Templating (Drain-style)
    templated = apply_templates(filtered)
    yield {"stage": "template", "label": "Templating variable fields", "rows": len(templated), "total": total}

    # Stage 4: Deduplication
    deduped = deduplicate(templated)
    dupes_collapsed = len(filtered) - len(deduped)
    yield {"stage": "dedup", "label": "Deduplicating repeated lines", "rows": len(deduped), "total": total}

    # Stage 5: Aggregation
    aggregated = aggregate_templates(deduped)
    yield {"stage": "aggregate", "label": "Aggregating near-identical events", "rows": len(aggregated), "total": total}

    # Stage 6: Columnar compression
    compressed_text = compress_to_columnar(aggregated)
    stats = compute_stats(raw_text, compressed_text)
    stats["noise_lines_removed"] = noise_removed
    stats["duplicate_lines_collapsed"] = dupes_collapsed
    stats["lines_after_filter"] = len(filtered)
    stats["lines_after_dedup"] = len(deduped)
    yield {"stage": "compress", "label": "Columnar compression", "rows": stats["compressed_lines"], "total": total}

    yield {"done": True, "compressed": compressed_text, "stats": stats}


def run_pipeline(raw_text: str) -> Tuple[str, dict]:
    """Run the full pipeline and return (compressed_text, stats)."""
    compressed_text, stats = "", {}
    for event in iter_pipeline(raw_text):
        if event.get("done"):
            compressed_text, stats = event["compressed"], event["stats"]
    return compressed_text, stats

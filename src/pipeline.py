"""
pipeline.py
Orchestrates all stages:
  normalize -> noise filter -> templating -> dedup -> aggregate -> compress
"""

from typing import Tuple

from normalizer import parse_line
from noise_filter import is_noise
from templatizer import apply_templates
from deduplicator import deduplicate
from aggregator import aggregate_templates
from compressor import compress_to_columnar
from token_counter import compute_stats


def run_pipeline(raw_text: str) -> Tuple[str, dict]:
    """
    Run the full pipeline on raw log text.

    Returns:
        compressed_text: string ready to send to an LLM
        stats: dict of token-reduction metrics
    """
    raw_lines = raw_text.strip().splitlines()

    # === Stage 1: Normalize ===
    parsed = []
    for line in raw_lines:
        result = parse_line(line)
        if result is not None:
            parsed.append(result)

    # === Stage 2: Noise filter ===
    filtered = [log for log in parsed if not is_noise(log)]
    noise_removed = len(parsed) - len(filtered)

    # === Stage 2.5: Templating (Drain-style log parsing) ===
    # Mask variable parts (IP, PID, numbers) so plaintext logs with the same
    # pattern can be merged during dedup.
    templated = apply_templates(filtered)

    # === Stage 3: Deduplication ===
    deduped = deduplicate(templated)
    dupes_collapsed = len(filtered) - len(deduped)

    # === Stage 3.5: Super-template aggregation ===
    # Merge templates that differ by a single token (e.g. username) so the
    # output stays small enough for any model's context window.
    aggregated = aggregate_templates(deduped)

    # === Stage 4: Columnar compression ===
    compressed_text = compress_to_columnar(aggregated)

    # === Stage 5: Compute statistics ===
    stats = compute_stats(raw_text, compressed_text)
    stats["noise_lines_removed"] = noise_removed
    stats["duplicate_lines_collapsed"] = dupes_collapsed
    stats["lines_after_filter"] = len(filtered)
    stats["lines_after_dedup"] = len(deduped)

    return compressed_text, stats

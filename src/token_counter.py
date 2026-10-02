"""
token_counter.py
Count the number of tokens before and after compression.

Uses tiktoken (the OpenAI tokenizer) as an objective measurement standard. If
tiktoken is unavailable (e.g. offline), it falls back to a rough estimate of
1 token ~= 4 characters, which is good enough for relative comparison.
"""

import os
import sys

# tiktoken downloads its vocabulary on first use. Cache it inside the project
# (git-ignored) so one online run -- or `python scripts/warm_tiktoken.py` -- makes
# later runs work offline. An explicit TIKTOKEN_CACHE_DIR from the user wins.
CACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".cache", "tiktoken"
)
os.environ.setdefault("TIKTOKEN_CACHE_DIR", CACHE_DIR)

METHOD_TIKTOKEN = "tiktoken:cl100k_base"
METHOD_ESTIMATE = "estimate:chars/4"

_enc = None
_warned = False


def _get_encoder():
    global _enc, _warned
    if _enc is not None:
        return _enc
    try:
        import tiktoken
        _enc = tiktoken.get_encoding("cl100k_base")
        return _enc
    except Exception as e:
        if not _warned:
            _warned = True
            print(
                f"[!] tiktoken unavailable ({type(e).__name__}); token counts fall back "
                f"to {METHOD_ESTIMATE} (a rough estimate) and are NOT tiktoken-measured.",
                file=sys.stderr,
            )
        return None


def token_method() -> str:
    """Name of the tokenizer actually used for counts: tiktoken or the chars/4 estimate."""
    return METHOD_TIKTOKEN if _get_encoder() else METHOD_ESTIMATE


def count_tokens(text: str) -> int:
    enc = _get_encoder()
    if enc:
        return len(enc.encode(text))
    # Fallback: rough estimate (1 token ~= 4 chars)
    return max(1, len(text) // 4)


def compute_stats(original_text: str, compressed_text: str) -> dict:
    """
    Compute token-reduction statistics.
    Returns a dict with every metric shown in the UI / CLI.
    """
    original_tokens = count_tokens(original_text)
    compressed_tokens = count_tokens(compressed_text)

    saved = original_tokens - compressed_tokens
    reduction_pct = (saved / original_tokens * 100) if original_tokens > 0 else 0

    original_lines = len(original_text.strip().splitlines())
    compressed_lines = len(compressed_text.strip().splitlines())
    line_reduction_pct = (
        (original_lines - compressed_lines) / original_lines * 100
        if original_lines > 0 else 0
    )

    return {
        "original_tokens": original_tokens,
        "compressed_tokens": compressed_tokens,
        "tokens_saved": saved,
        "token_reduction_pct": round(reduction_pct, 1),
        "original_lines": original_lines,
        "compressed_lines": compressed_lines,
        "line_reduction_pct": round(line_reduction_pct, 1),
        "token_method": token_method(),
    }

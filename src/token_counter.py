"""
token_counter.py
Count the number of tokens before and after compression.

Uses tiktoken (the OpenAI tokenizer) as an objective measurement standard. If
tiktoken is unavailable (e.g. offline), it falls back to a rough estimate of
1 token ~= 4 characters, which is good enough for relative comparison.
"""

_enc = None


def _get_encoder():
    global _enc
    if _enc is not None:
        return _enc
    try:
        import tiktoken
        _enc = tiktoken.get_encoding("cl100k_base")
        return _enc
    except Exception:
        return None


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
    }

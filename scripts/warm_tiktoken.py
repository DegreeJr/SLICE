#!/usr/bin/env python3
"""Download the tiktoken vocabulary once so SLICE can count tokens offline.

SLICE measures tokens with tiktoken's `cl100k_base` encoding. tiktoken fetches that
vocabulary from the internet the first time it is used. Run this script once while
online (before a demo, or at Docker build time); the file is cached in `.cache/tiktoken/`
(or in $TIKTOKEN_CACHE_DIR if you set it) and later runs need no network.

    python scripts/warm_tiktoken.py

Exit code 0 if tiktoken is ready, 1 if it could not be loaded.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import token_counter  # noqa: E402  (importing it sets the default cache dir)


def main() -> int:
    cache = os.environ.get("TIKTOKEN_CACHE_DIR", token_counter.CACHE_DIR)
    print(f"Warming tiktoken cache in: {cache}")
    method = token_counter.token_method()
    print(f"Tokenizer: {method}")
    if method != token_counter.METHOD_TIKTOKEN:
        print("Failed: tiktoken could not load its vocabulary. Are you online?", file=sys.stderr)
        return 1
    print("OK: token counts will work offline from now on.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
__main__.py
SLICE command-line entry point.

Usage:
    python -m slice serve                 # http://127.0.0.1:7654
    python -m slice serve --host 0.0.0.0  # expose on the network / server
    python -m slice serve --port 8080
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(prog="slice", description="SLICE - SIEM Log Compression Engine")
    sub = parser.add_subparsers(dest="command")

    p_serve = sub.add_parser("serve", help="Run the web dashboard")
    p_serve.add_argument("--host", default="127.0.0.1", help="Bind host (use 0.0.0.0 for a server)")
    p_serve.add_argument("--port", type=int, default=7654, help="Port (default 7654)")

    args = parser.parse_args()

    if args.command == "serve":
        from .server import serve
        serve(host=args.host, port=args.port)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

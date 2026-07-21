"""
main.py
SLICE command-line interface.

Compress a log file and optionally send the result to an LLM for threat analysis.
Reuses the same pipeline and provider modules as the web app.

Examples:
    python main.py --input samples/demo_ssh_bruteforce.log
    python main.py --input samples/demo_windows_events.json --show-output
    python main.py --input samples/demo_ssh_bruteforce.log --analyze --provider groq
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from pipeline import run_pipeline  # noqa: E402
from slice import config as cfg_mod  # noqa: E402
from slice import llm as llm_mod  # noqa: E402


BANNER = r"""
+======================================================+
|   SLICE - SIEM Log Compression Engine  v0.1          |
|   Token-efficient log preprocessing for LLMs         |
+======================================================+
"""


def print_stats(stats: dict):
    print("\n" + "-" * 54)
    print("  COMPRESSION RESULT")
    print("-" * 54)
    print(f"  Lines  : {stats['original_lines']:>7}  ->  {stats['compressed_lines']:>7}  "
          f"(-{stats['line_reduction_pct']}%)")
    print(f"  Tokens : {stats['original_tokens']:>7}  ->  {stats['compressed_tokens']:>7}  "
          f"(-{stats['token_reduction_pct']}%)")
    print(f"  Tokens saved    : {stats['tokens_saved']:,}")
    print("-" * 54)
    print(f"  Noise removed   : {stats['noise_lines_removed']} lines")
    print(f"  Dupes collapsed : {stats['duplicate_lines_collapsed']} lines")
    print("-" * 54)


def print_report(report: dict):
    print("\n" + "=" * 54)
    print("  THREAT ANALYSIS REPORT")
    print("=" * 54)
    print(f"  Verdict      : {report.get('verdict')}")
    print(f"  Confidence   : {float(report.get('confidence', 0)) * 100:.0f}%")
    print(f"  MITRE ATT&CK : {report.get('mitre_technique')}")
    print("-" * 54)
    print(f"  {report.get('summary')}")
    print("=" * 54)


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="Compress SIEM logs for token-efficient LLM analysis")
    parser.add_argument("--input", "-i", required=True, help="Path to the log file (JSON or Syslog)")
    parser.add_argument("--output", "-o", default=None, help="Save the compressed result to a file")
    parser.add_argument("--analyze", "-a", action="store_true", help="Send the result to an LLM for analysis")
    parser.add_argument("--provider", "-p", default=None,
                        help="Provider from config.yaml (default: the active provider)")
    parser.add_argument("--show-output", "-s", action="store_true", help="Print the compressed result")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"  [!] File not found: {args.input}")
        sys.exit(1)

    print(f"  Reading: {args.input}")
    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw_text = f.read()
    print(f"  Input  : {len(raw_text.splitlines())} log lines")

    print("  Running pipeline...\n")
    compressed, stats = run_pipeline(raw_text)
    print_stats(stats)

    if args.show_output:
        print("\n  COMPRESSED OUTPUT:")
        print("-" * 54)
        print(compressed)
        print("-" * 54)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(compressed)
        print(f"\n  Saved to: {args.output}")

    if args.analyze:
        cfg = cfg_mod.load_config()
        prov_name = args.provider or cfg["active_provider"]
        prov = cfg["providers"].get(prov_name)
        if not prov:
            print(f"\n  [!] Provider '{prov_name}' not found in config.yaml")
            sys.exit(1)
        print(f"\n  Sending to '{prov_name}' ({prov.get('model')}) for analysis...")
        try:
            report = llm_mod.analyze(compressed, prov)
            print_report(report)
        except Exception as e:
            print(f"\n  [!] LLM error ({prov_name}): {e}")

    print()


if __name__ == "__main__":
    main()

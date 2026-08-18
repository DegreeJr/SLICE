#!/usr/bin/env bash
#
# security_scan.sh — audit SLICE's own code for security issues.
# Runs three checks and prints a summary. Intended as evidence that the team
# audits its own code, not just the logs it analyzes.
#
#   ./scripts/security_scan.sh
#
# Requires: python3. Installs bandit + pip-audit into the current environment
# if missing.
set -u
cd "$(dirname "$0")/.."

echo "== SLICE security scan =="
echo

python3 -m pip install -q bandit pip-audit >/dev/null 2>&1 || true

echo "1) Bandit — Python static security analysis"
python3 -m bandit -q -r src slice main.py 2>&1 | tail -n 20
echo

echo "2) Secret scan — API keys in git-tracked files"
if git ls-files | grep -qE '(^|/)config\.yaml$'; then
  echo "   WARNING: config.yaml is tracked by git (it holds API keys). It should be gitignored."
else
  echo "   OK: config.yaml is not tracked by git."
fi
hits=$(git ls-files | xargs grep -nE 'gsk_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}' 2>/dev/null \
        | grep -viE 'placeholder|example|your|sk-\.\.\.' || true)
if [ -n "$hits" ]; then
  echo "   WARNING: possible secrets found:"; echo "$hits"
else
  echo "   OK: no API-key patterns in tracked files."
fi
echo

echo "3) pip-audit — known CVEs in dependencies"
python3 -m pip_audit -r requirements.txt 2>&1 | tail -n 10 || echo "   (pip-audit needs network access to the advisory database)"
echo

echo "Done. Re-run any time; commit metrics/security-scan.md for the record."

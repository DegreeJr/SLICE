# SLICE Security Scan

We audit our own code, not just the logs it analyzes. Reproduce with:

```bash
./scripts/security_scan.sh
```

Latest run (2026-10-03), 1,571 lines of code scanned (`src`, `slice`, `main.py`):

| Check | Tool | Result |
| --- | --- | --- |
| Python static analysis | Bandit 1.9.4 | 0 high, 0 medium, 0 low (no issues identified)* |
| Secrets in git | grep over tracked files | No API-key patterns; `config.yaml` is not tracked |
| Dependency CVEs | pip-audit 2.10.1 (`requirements.txt`) | No known vulnerabilities found |

Run with Python 3.12.10 on Windows 11. pip-audit queries an online advisory database,
so its result is only valid for the date of the run.

\* The one low-severity finding from an earlier run (a silent
`try/except/pass` in `slice/history.py`) has been fixed by catching specific
exceptions.

Numbers reflect the code at the time of the run; re-run after changes. This is a
scan of SLICE's own source, separate from the threat analysis SLICE performs on
user logs.

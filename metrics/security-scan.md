# SLICE Security Scan

We audit our own code, not just the logs it analyzes. Reproduce with:

```bash
./scripts/security_scan.sh
```

Latest run (2026-08-18), 1,362 lines of code scanned:

| Check | Tool | Result |
| --- | --- | --- |
| Python static analysis | Bandit | 0 high, 0 medium, 0 low* |
| Secrets in git | grep over tracked files | None; `config.yaml` is gitignored |
| Dependency CVEs | pip-audit | No known vulnerabilities |

\* The one low-severity finding from an earlier run (a silent
`try/except/pass` in `slice/history.py`) has been fixed by catching specific
exceptions.

Numbers reflect the code at the time of the run; re-run after changes. This is a
scan of SLICE's own source, separate from the threat analysis SLICE performs on
user logs.

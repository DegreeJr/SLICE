# ADR 0001 — SLICE Web Architecture

Status: Accepted

## Context

SLICE started as a CLI. We wanted a web form (dashboard + visualization) that stays as easy
to install and run as infrastructure tools (Prometheus/Grafana): one command, runs locally
or on a server.

## Decision

1. **FastAPI (Python) as the backend**, reusing the existing pipeline.
2. **A single-file HTML + Tailwind (CDN) + Chart.js frontend** with **no build step**. The
   user only needs Python — no Node.js.
3. **FastAPI serves** the static frontend + the REST API in a single process.
4. **Self-hosted, privacy-first**: the app runs on the user's machine/server. Raw logs are
   processed locally; only the compressed result is sent to the external LLM API.
5. **Two deploy modes**: local (`python -m slice serve`) and Docker (`docker compose up`).
   Default port **7654**.

## Rationale

- Reusing the Python pipeline avoids rewriting the compression logic.
- A zero-build frontend removes the biggest installation hurdle (Node.js) for a SOC analyst.
- The self-hosted model is a security selling point and matches expectations for a
  Prometheus-class tool.

## Note on a revised decision

The original plan was React + Vite + Recharts, built into static files and bundled. We
changed to a single-file HTML + Chart.js frontend because it removes the Node.js build step
entirely — even the maintainer does not need Node. This is simpler and more robust than
bundling a compiled SPA, at the cost of a less component-structured frontend.

## Consequences

- Positive: very simple installation; strong privacy; modern UI; no build tooling.
- Negative: the frontend is a single large HTML file rather than a componentized app.
- Rejected alternatives: Streamlit (past issues), a separate React app requiring Node.js
  (harder to install for users).

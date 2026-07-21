# SLICE — Design Document

**SLICE** = *Security Log Intelligence & Compression Engine*

HackNusa 2026 — "AI vs AI: Cyber Defense" track.

---

## 1. Problem Statement

SOC analysts increasingly use LLMs to analyze security logs (network traffic, auth,
firewall, EDR). The problem: logs are large and highly repetitive, which causes:

- **Token bloat** — LLM API cost balloons and the context window fills up quickly.
- **Sensitivity** — raw logs contain internal IPs, usernames, and network structure that
  should not be sent around carelessly.

SLICE processes logs **locally** to remove noise, collapse duplicate lines, and compact the
format before anything is sent to an LLM. The result: far fewer tokens, and less sensitive
data leaving the analyst's machine.

> Honesty note: token-reduction figures come from our own test datasets. Real numbers vary
> with log characteristics. This is not a universal guarantee.

---

## 2. Primary Use Case

A SOC analyst has a network/auth log file they want to analyze with AI, but does not want to
waste tokens and does not want raw logs to leak. They run SLICE on their own machine (or an
internal server), upload the log, view the efficiency visualization, and SLICE sends the
compressed version to their chosen LLM API and shows a threat report.

---

## 3. Design Principles

1. **Self-hosted, privacy-first** — like Prometheus/Grafana. SLICE runs on the user's
   infrastructure. The maintainers never see anyone's logs.
2. **Raw logs never leave the machine** — only the compressed result is sent to the external
   LLM API.
3. **Easy to install** — one command to run locally; Docker for a server.
4. **Multi-provider** — the user picks the LLM (OpenAI, Anthropic, Groq, Gemini, or any
   OpenAI-compatible endpoint).
5. **Clear, informative UI** — a dashboard with legible efficiency charts, available in
   English and Indonesian.

---

## 4. Architecture

```
+-----------------------------------------------------------+
|  USER MACHINE / SERVER (self-hosted)                      |
|                                                           |
|  +--------------+      +----------------------------+     |
|  |  Browser UI  |<---->|  FastAPI backend           |     |
|  |  (single-    |      |                            |     |
|  |   file HTML) |      |  +----------------------+  |     |
|  +--------------+      |  |  Pipeline (local)    |  |     |
|                        |  |  normalize -> filter |  |     |
|                        |  |  -> template -> dedup|  |     |
|                        |  |  -> aggregate -> cols|  |     |
|                        |  +----------------------+  |     |
|                        |            |               |     |
|                        |  +----------------------+  |     |
|                        |  |  LLM client          |  |     |
|                        |  |  (multi-provider)    |  |     |
|                        |  +----------+-----------+  |     |
|                        +-------------+--------------+     |
+--------------------------------------+--------------------+
                                       | COMPRESSED logs only
                                       v
                            +---------------------+
                            |  External LLM API   |
                            |  (OpenAI/Groq/etc.) |
                            +---------------------+
```

Raw logs only travel inside the "user machine" box. Only the compressed result crosses to
the internet.

---

## 5. Tech Stack

| Layer | Choice | Reason |
|---|---|---|
| Backend | Python + FastAPI | Reuse the existing pipeline; lightweight; async |
| Frontend | Single-file HTML + Tailwind (CDN) + Chart.js | Attractive UI with **zero build step** — the user only needs Python, no Node.js |
| Charts | Chart.js | Interactive, lightweight, loaded from CDN |
| Packaging | `python -m slice serve` + Docker | Prometheus-style deployment |
| Token count | tiktoken (with a fallback estimate) | Objective token measurement |

> Design change from the original draft: an earlier plan used React/Vite/Recharts. We chose
> a single-file HTML + Chart.js frontend instead — it removes the Node.js build step
> entirely, which better serves the "user only needs Python" goal. See ADR 0001.

---

## 6. Pages / Features

1. **Dashboard** — cumulative stats (total analyses, total tokens saved, average reduction,
   estimated savings), before/after chart, reduction-source donut, and a persistent history
   table.
2. **Analyze / Upload** — upload a log file (Syslog/JSON), see compression stats, then send
   the compressed result to the LLM.
3. **Result** — threat report from the LLM (verdict, confidence, MITRE, summary) plus the
   compressed text.
4. **Settings** — manage API key / base URL / model / token price per provider (stored in
   local config, changeable any time).

The UI is bilingual (English default, Indonesian toggle).

---

## 7. Supported Log Formats

- **Syslog** — core (most universal)
- **JSON** — core (modern tools, cloud, EDR)
- **CEF** — roadmap (ArcSight/QRadar)

---

## 8. API Key Storage

- Stored in local config (`config.yaml` in the user's working directory).
- Changeable from the Settings page at any time.
- Safe because the config lives on the user's own machine and is never sent elsewhere.
- Multi-provider: one config can hold several keys (OpenAI, Anthropic, Groq, Gemini).
- `config.yaml` is git-ignored so keys are never committed.

---

## 9. Deployment

**Local:**
```bash
git clone https://github.com/DegreeJr/slice
cd slice
pip install -r requirements.txt
python -m slice serve      # open http://localhost:7654
```

**Server (Docker):**
```bash
docker compose up -d        # http://<server>:7654
```

Default port: **7654** (avoids clashing with Prometheus 9090 / Grafana 3000).

---

## 10. Out of Scope (Roadmap)

- Full CEF/LEEF format support
- RAG / attack-pattern knowledge base
- Agentic multi-step analysis (tool calling)
- Real-time log streaming
- Multi-user / auth (currently single-user, self-hosted)

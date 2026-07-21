# ADR 0002 — Data Privacy & API Key Storage

Status: Accepted

## Context

The target user is a SOC analyst who analyzes sensitive logs (internal IPs, usernames,
network structure) with the help of an LLM. Two concerns: (1) raw logs must not leak, and
(2) the LLM API key must be practical to use yet safe.

## Decision

1. **Local processing**: the pipeline (normalize, filter, template, dedup, aggregate,
   compress) runs entirely on the user's machine. Raw logs are never sent to the SLICE
   maintainers or to the internet.
2. **Only the compressed result is sent** to the user's chosen external LLM API. This both
   reduces sensitive-data exposure and saves tokens.
3. **API keys are stored in local config** (`config.yaml` in the user's working directory),
   changeable at any time via the Settings page.
4. **Multi-provider**: the config can hold several keys (OpenAI, Anthropic, Groq, Gemini)
   plus a base URL for OpenAI-compatible endpoints.

## Rationale

- Local processing + sending only a summary = double privacy + token savings, aligned with
  the product's core goal.
- Local config like a typical CLI tool: set once, no need to re-enter, and it stays under
  the user's control.

## Consequences

- Positive: a strong privacy selling point; users need not trust a third-party server.
- Negative: the user is responsible for guarding the config file (which holds the key).
  `config.yaml` is git-ignored so it is never committed.
- Note: the compressed result still leaves for the user's chosen LLM API — the user should
  be aware that provider sees the compressed data. This is documented clearly.

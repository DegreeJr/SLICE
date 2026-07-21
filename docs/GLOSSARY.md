# SLICE — Glossary

Domain terms used consistently across the code and docs.

| Term | Definition |
|---|---|
| **SLICE** | The application name. Security Log Intelligence & Compression Engine. |
| **Pipeline** | The chain of log-processing stages: normalize → noise filter → templating → dedup → aggregate → columnar. |
| **Normalize** | Turn a raw log line (Syslog/JSON) into a uniform dict, dropping unimportant fields. |
| **Noise filter** | Remove routine / uninformative logs (DEBUG/INFO, heartbeats, internal firewall allows). |
| **Templating (log parsing)** | Mask the variable parts of a plaintext log (IP, PID, numbers → `<IP>`, `<PID>`, `<NUM>`) into a template. Lines with the same pattern but different details become identical and can be merged. A lightweight variant of the Drain technique. |
| **Template** | The generalized form of a single log line after its variable parts are masked. |
| **Dedup (deduplication)** | Collapse identical (or same-template) log lines into one, with a `_count` marker for the number of occurrences. |
| **Super-template aggregation** | Merge templates that differ in only one token (e.g. username) into a single `<VAR>` line plus a "distinct" count. Keeps the output small enough to fit any model's context window. |
| **Compress / Columnar** | Pipe-delimited format: the `FIELDS: f1|f2|...` header once, then values per row. Cheaper in tokens than JSON. |
| **Token** | The smallest text unit an LLM counts for billing and the context window. |
| **Token reduction** | The percentage of tokens saved after the pipeline (tokens_saved / original_tokens). |
| **Verdict** | The LLM's conclusion: BENIGN / SUSPICIOUS / MALICIOUS. |
| **Confidence** | The LLM's confidence in the verdict (0.0–1.0). |
| **MITRE ATT&CK** | A framework of attack techniques (e.g. T1110 = Brute Force). |
| **Provider** | An LLM API provider: OpenAI, Anthropic (Claude), Groq, Gemini, or any OpenAI-compatible endpoint. |
| **Base URL** | The LLM API endpoint address; enables using OpenAI-compatible providers other than OpenAI itself. |
| **Self-hosted** | The app runs on the user's own machine/server, not on the maintainer's server. |
| **Cost estimate** | An estimate of the money saved, computed from tokens × model price (price is user-editable; estimate only). |

# SLICE on a real public dataset: OTRF LSASS campaign

Measured on 2026-10-03. Every number below comes from a command listed in
"Reproduce", run on one machine (Windows 11, 12 logical CPUs, Python 3.12.10).

## Dataset

- Source: [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets),
  folder [`datasets/compound/LSASS_campaign_01`](https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/LSASS_campaign_01).
- File used: `metasploit_logonpasswords_lsass_memory_dump.zip` (3,405,389 bytes),
  which contains one file, `metasploit_logonpasswords_lsass_memory_dump.json`
  (106,496,231 bytes, 53,698 Windows/Sysmon events, one JSON object per line).
- The folder also holds a `..._pcapng.zip` capture; that file is not used here.
- SHA-256 of the zip we used:
  `79045fcc5a8689efed8db4911cadc11b554ef8b0bed1428ee490bb8c3f2578e6`
- SHA-256 of the extracted JSON:
  `4bca511ef19fb759c31b7721e4b14a8d5462675eccdc9a5d7ef59c93f6481671`
- **Not included in this repository** (the JSON is 106 MB, above GitHub's 100 MB
  file limit). `sample_logs/` is git-ignored; download it as shown below.

## Results

Tokenizer: `tiktoken:cl100k_base` (real tokenizer, not the chars/4 estimate).

| Metric | Before | After |
| --- | ---: | ---: |
| Lines | 53,698 | 394 |
| Line reduction | | 99.3% |
| Tokens (CLI read, see note) | 38,372,240 | 206,901 |
| Token reduction | | 99.5% |
| Noise lines removed | 178 | |
| Duplicate lines collapsed | 53,127 | |
| Prompt-injection hits in compressed output | | 0 |

Note on the "before" token count. The CLI opens the file in text mode, which turns
`\r\n` into `\n` (the file has 53,698 `\r`). The web UI reads the raw bytes and keeps
`\r\n`, so it counts **38,425,153** tokens for the same file; this matches the entry
saved by the UI in `history.json` (id `1787153530420`) exactly. The compressed side is
identical in both cases: 394 lines, 206,901 tokens, 178 noise lines, 53,127 collapsed
duplicates.

### Processing time and memory

Measured with `time.perf_counter()` on the already-loaded text, three runs each:

| What was timed | Runs (s) |
| --- | --- |
| Compression stages only (token counting disabled) | 2.80, 2.16, 2.22 |
| `run_pipeline` including tiktoken counting of both sides | 173.49, 23.67, 20.64 |

- Reading the file takes about 0.7 s.
- Almost all of the extra time in the second row is tiktoken encoding the 106 MB
  original (about 18 s when timed alone). The 173 s first run is an outlier we did not
  investigate; treat the 20-24 s figure as typical and the 173 s as unexplained.
- Peak process memory (Windows peak working set): about 522 MB after reading the file,
  about 865 MB after the compression stages, about 1,917 MB when tiktoken counting is
  included. The whole file is held in memory; see Known Limitations in the README.

These are single-machine measurements; they will vary with hardware.

## Reproduce

```bash
# 1. Download and extract (about 3.4 MB download, 106 MB extracted)
mkdir -p sample_logs && cd sample_logs
curl -L -o metasploit_logonpasswords_lsass_memory_dump.zip \
  https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/LSASS_campaign_01/metasploit_logonpasswords_lsass_memory_dump.zip
unzip metasploit_logonpasswords_lsass_memory_dump.zip -d metasploit_logonpasswords_lsass_memory_dump
cd ..

# 2. Run the pipeline (prints lines, tokens, noise, duplicates, tokenizer)
python main.py --input sample_logs/metasploit_logonpasswords_lsass_memory_dump/metasploit_logonpasswords_lsass_memory_dump.json
```

On Windows, replace `unzip` with `Expand-Archive` in PowerShell.

## What this does not show

- The LLM verdict is not part of this benchmark. It comes from an external model, is
  not deterministic, and can differ between runs and providers.
- One dataset. Compression depends on how repetitive the logs are; here a single
  event type (Sysmon Event ID 10, process access) accounts for 30,414 of the 53,698
  events.

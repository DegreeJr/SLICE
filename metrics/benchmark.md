# SLICE Benchmark

Reproduce with: `python main.py --bench --bench-out metrics`

Tokenizer: `tiktoken:cl100k_base`

| File | Lines in → out | Tokens in → out | Reduction | Injection hits |
| --- | ---: | ---: | ---: | ---: |
| demo_prompt_injection.log | 11 → 5 | 401 → 130 | −67.58% | 5 |
| demo_ssh_bruteforce.log | 20 → 9 | 798 → 235 | −70.55% | 0 |
| demo_ssh_bruteforce_large.log | 12,001 → 5 | 435,809 → 136 | −99.97% | 0 |
| demo_windows_events.json | 10 → 6 | 591 → 272 | −53.98% | 0 |

# Contributing to SLICE

Thanks for your interest! SLICE is a small, focused project and contributions are welcome.

## Development setup

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install pytest            # for running tests
```

Run the app:

```bash
python -m slice serve
```

Run the tests:

```bash
pytest -q
```

## Project layout

- `src/` — the compression pipeline. Each stage is a small, standalone module with no
  framework dependencies, so it is easy to test and reuse. This is the heart of the project.
- `slice/` — the FastAPI web app and the single-file UI.
- `main.py` — the CLI, which reuses `src/` and `slice/`.

## Guidelines

- **Keep the pipeline framework-free.** Modules in `src/` should not import FastAPI or the web
  layer. This keeps them testable and embeddable.
- **Add a test** when you add or change pipeline behavior. See `tests/test_pipeline.py`.
- **Comments and code in English.** The UI is bilingual (English/Indonesian) via the `I18N`
  dictionary in `slice/static/index.html`; add both languages when you add UI strings.
- **Be honest about references and numbers.** Do not cite sources you have not verified, and
  label estimates as estimates.
- **Never commit secrets or large data.** `config.yaml`, `history.json`, and bulk log datasets
  are git-ignored. Only small demo logs belong in `samples/`.

## Ideas / roadmap

- CEF / LEEF format support
- Optional "detail mode" that keeps the full value list instead of aggregating
- Streaming / chunked analysis for logs larger than a single context window

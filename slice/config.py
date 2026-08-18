"""
config.py
Manage SLICE configuration: per-provider API key, base URL, model, token price.
Stored locally in config.yaml in the user's working directory. It never leaves
the machine.
"""

import os
from copy import deepcopy

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

CONFIG_PATH = os.environ.get("SLICE_CONFIG", "config.yaml")

# Default structure. price_per_1m = USD per 1M input tokens (editable by the user).
DEFAULT_CONFIG = {
    "active_provider": "groq",
    "providers": {
        "groq": {
            "api_key": "",
            "base_url": "https://api.groq.com/openai/v1",
            "model": "llama-3.3-70b-versatile",
            "kind": "openai",
            "price_per_1m": 0.59,
            "max_context_tokens": 12000,
        },
        "openai": {
            "api_key": "",
            "base_url": "",
            "model": "gpt-4o-mini",
            "kind": "openai",
            "price_per_1m": 0.15,
            "max_context_tokens": 100000,
        },
        "anthropic": {
            "api_key": "",
            "base_url": "",
            "model": "claude-haiku-4-5-20251001",
            "kind": "anthropic",
            "price_per_1m": 1.00,
            "max_context_tokens": 100000,
        },
        "gemini": {
            "api_key": "",
            "base_url": "",
            "model": "gemini-2.0-flash",
            "kind": "gemini",
            "price_per_1m": 0.10,
            "max_context_tokens": 200000,
        },
        "custom": {
            "api_key": "",
            "base_url": "",
            "model": "",
            "kind": "openai",
            "price_per_1m": 0.50,
            "max_context_tokens": 60000,
        },
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base without dropping default keys."""
    result = deepcopy(base)
    for key, val in (override or {}).items():
        if isinstance(val, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def load_config() -> dict:
    """Read config.yaml; fall back to defaults if missing or malformed."""
    cfg = deepcopy(DEFAULT_CONFIG)
    if _HAS_YAML and os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                user_cfg = yaml.safe_load(f) or {}
            if isinstance(user_cfg, dict):
                cfg = _deep_merge(DEFAULT_CONFIG, user_cfg)
        except Exception:
            cfg = deepcopy(DEFAULT_CONFIG)

    # Guard against a broken config blanking the UI: providers must be a
    # non-empty dict, and the active provider must exist.
    if not isinstance(cfg.get("providers"), dict) or not cfg["providers"]:
        cfg["providers"] = deepcopy(DEFAULT_CONFIG["providers"])
    if cfg.get("active_provider") not in cfg["providers"]:
        cfg["active_provider"] = next(iter(cfg["providers"]))
    return cfg


def save_config(cfg: dict) -> None:
    """Save config to config.yaml (local)."""
    if not _HAS_YAML:
        raise RuntimeError("PyYAML is not installed. Run: pip install pyyaml")
    merged = _deep_merge(DEFAULT_CONFIG, cfg)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(merged, f, sort_keys=False, allow_unicode=True)


def redacted(cfg: dict) -> dict:
    """Return a copy of the config with API keys masked, safe to send to the UI."""
    safe = deepcopy(cfg)
    for prov in safe.get("providers", {}).values():
        key = prov.get("api_key", "")
        if key:
            prov["api_key"] = key[:6] + "..." + key[-4:] if len(key) > 12 else "***"
            prov["_has_key"] = True
        else:
            prov["_has_key"] = False
    return safe

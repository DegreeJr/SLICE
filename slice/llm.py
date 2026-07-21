"""
llm.py
Multi-provider client for threat analysis.
Supports: OpenAI-compatible endpoints (OpenAI, Groq, custom), Anthropic (Claude),
and Google Gemini.

Only the COMPRESSED text is sent to the API - raw logs never leave the machine.
"""

import json

SYSTEM_PROMPT = (
    "You are a Tier-3 SOC analyst. Analyze the following compressed security "
    "logs. Format: FIELDS lists the column names, values are separated by | per "
    "row, and [xN] means the event occurred N times. Identify security threats. "
    "Reply ONLY in JSON with these fields: verdict (BENIGN/SUSPICIOUS/MALICIOUS), "
    "confidence (0.0-1.0), mitre_technique (string), summary (concise string). "
    "When numbers are available (counts, distinct values), cite them in the summary. "
    "Do not add any text outside the JSON."
)


def _parse_json_block(raw: str) -> dict:
    """Extract the first JSON block from a text response."""
    start = raw.find("{")
    end = raw.rfind("}") + 1
    if start == -1 or end <= start:
        raise ValueError(f"No JSON found in response: {raw[:200]}")
    return json.loads(raw[start:end])


def _normalize_report(data: dict) -> dict:
    return {
        "verdict": data.get("verdict", "UNKNOWN"),
        "confidence": float(data.get("confidence", 0) or 0),
        "mitre_technique": data.get("mitre_technique", "None"),
        "summary": data.get("summary", "-"),
    }


def analyze(compressed_text: str, provider: dict) -> dict:
    """
    Send compressed logs to an LLM provider.
    `provider` is a config dict: {api_key, base_url, model, kind}.
    Returns a threat-report dict (verdict, confidence, mitre_technique, summary).
    Raises an Exception with a clear message on failure.
    """
    kind = provider.get("kind", "openai")
    api_key = provider.get("api_key", "")
    model = provider.get("model", "")

    if not api_key:
        raise ValueError("API key is not set for this provider. Open Settings.")
    if not model:
        raise ValueError("Model name is not set for this provider.")

    if kind == "openai":
        return _analyze_openai(compressed_text, api_key, provider.get("base_url"), model)
    elif kind == "anthropic":
        return _analyze_anthropic(compressed_text, api_key, model)
    elif kind == "gemini":
        return _analyze_gemini(compressed_text, api_key, model)
    else:
        raise ValueError(f"Unknown provider kind: {kind}")


def _analyze_openai(compressed_text, api_key, base_url, model):
    from openai import OpenAI

    kwargs = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    client = OpenAI(**kwargs)

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Logs:\n{compressed_text}"},
        ],
        temperature=0.1,
    )
    raw = response.choices[0].message.content
    return _normalize_report(_parse_json_block(raw))


def _analyze_anthropic(compressed_text, api_key, model):
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Logs:\n{compressed_text}"}],
    )
    raw = message.content[0].text
    return _normalize_report(_parse_json_block(raw))


def _analyze_gemini(compressed_text, api_key, model):
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=model,
        contents=f"{SYSTEM_PROMPT}\n\nLogs:\n{compressed_text}",
        config=types.GenerateContentConfig(response_mime_type="application/json"),
    )
    return _normalize_report(_parse_json_block(response.text))

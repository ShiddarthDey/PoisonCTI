"""Thin wrapper around the local Ollama chat model.

Job
---
The single chokepoint for talking to the LLM. Sends chat messages to the Ollama
server and returns text (or a parsed JSON object). EVERY call passes the
deterministic decode options (greedy temperature=0 + the global seed) from
utils.reproducibility.decode_options(cfg), so two runs on the same machine give
identical outputs. Keeping ALL model I/O here means prompts, decoding settings,
and JSON parsing are auditable in one place.

The `ollama` import is lazy so the module imports without a running server
(unit tests monkeypatch chat/chat_json instead of calling Ollama).
"""

from __future__ import annotations

import json
import re


def _content(resp) -> str:
    """Extract the assistant message text from an ollama response (dict or object)."""
    msg = resp["message"] if isinstance(resp, dict) else resp.message
    return msg["content"] if isinstance(msg, dict) else msg.content


def _loads(text: str) -> dict:
    """Parse a JSON object from model output, tolerating stray text around it."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise


def chat(messages: list[dict], model: str, host: str, options: dict) -> str:
    """Send chat messages to Ollama with deterministic `options`; return text."""
    import ollama

    resp = ollama.Client(host=host).chat(model=model, messages=messages, options=options)
    return _content(resp)


def chat_json(messages: list[dict], model: str, host: str, options: dict) -> dict:
    """Chat call requesting a JSON object (format=json); returns the parsed dict."""
    import ollama

    resp = ollama.Client(host=host).chat(
        model=model, messages=messages, options=options, format="json"
    )
    return _loads(_content(resp))

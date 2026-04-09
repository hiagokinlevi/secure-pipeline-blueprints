"""
Minimal YAML compatibility layer for offline automation environments.

This wrapper exposes ``safe_load`` and ``YAMLError`` with a PyYAML-like shape,
but delegates parsing to the system Ruby ``YAML.safe_load`` implementation so
the repository can validate workflows without fetching third-party packages.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any


class YAMLError(Exception):
    """Raised when YAML parsing fails."""


def _normalize(value: Any) -> Any:
    """Normalize parser quirks such as YAML 1.1 ``on`` becoming boolean ``True``."""
    if isinstance(value, dict):
        normalized: dict[Any, Any] = {}
        for key, inner in value.items():
            if key is True or key == "true":
                key = "on"
            normalized[key] = _normalize(inner)
        return normalized
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value


def safe_load(stream: Any) -> Any:
    """Safely parse YAML content into Python primitives."""
    if hasattr(stream, "read"):
        content = stream.read()
    else:
        content = stream
    if not isinstance(content, str):
        raise YAMLError("safe_load() expected a string or readable text stream")

    ruby_script = r"""
require "yaml"
require "json"
begin
  data = YAML.safe_load(ARGF.read, permitted_classes: [], permitted_symbols: [], aliases: false)
  puts JSON.generate(data)
rescue Psych::Exception => e
  warn e.message
  exit 1
end
"""

    try:
        result = subprocess.run(
            ["ruby", "-e", ruby_script],
            input=content,
            capture_output=True,
            check=False,
            text=True,
        )
    except OSError as exc:
        raise YAMLError(f"Unable to execute Ruby YAML parser: {exc}") from exc

    if result.returncode != 0:
        error = result.stderr.strip() or "Unknown YAML parsing error"
        raise YAMLError(error)

    payload = result.stdout.strip()
    if not payload:
        return None

    try:
        return _normalize(json.loads(payload))
    except json.JSONDecodeError as exc:
        raise YAMLError(f"Ruby YAML parser returned invalid JSON: {exc}") from exc

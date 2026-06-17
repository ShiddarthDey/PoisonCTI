"""Consistent logging setup for scripts and library code.

Job
---
Provide a single `get_logger` so every script logs with the same format and level,
and so runs are traceable (which step did what, how long the local LLM took). No
domain logic here.
"""

from __future__ import annotations


def get_logger(name: str):
    """Return a configured logger (consistent format/level) for `name`."""
    raise NotImplementedError

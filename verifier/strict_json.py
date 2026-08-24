"""Strict JSON parsing helpers.

Goals:
- Reject NaN/Infinity and other non-standard constants.
- Reject duplicate keys (ambiguous semantics).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains duplicate keys."""


def _no_duplicates_object_pairs_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    obj: Dict[str, Any] = {}
    for k, v in pairs:
        if k in obj:
            raise DuplicateKeyError(f"duplicate key: {k}")
        obj[k] = v
    return obj


def strict_json_loads(data: str | bytes) -> Any:
    """Parse JSON strictly.

    Raises:
        ValueError: on invalid JSON, duplicate keys, or non-standard constants.
    """
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return json.loads(
        data,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-standard JSON constant")),
        object_pairs_hook=_no_duplicates_object_pairs_hook,
    )

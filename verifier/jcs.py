"""RFC 8785 JSON Canonicalization Scheme (JCS) — minimal implementation.

Reality Layer V1 uses JCS canonical bytes as the only input to hashing/signing.

This implementation is deliberately small:
- supports dict/list/str/int/bool/null
- forbids floats for V1 contract vectors (avoid cross-language formatting pitfalls)

If you need floats, implement full RFC 8785 number formatting rules.
"""

from __future__ import annotations

import json
from typing import Any


def canonicalize(obj: Any) -> bytes:
    """Return canonical UTF-8 JSON bytes for supported types."""

    def dump(o: Any) -> str:
        if o is None:
            return "null"
        if o is True:
            return "true"
        if o is False:
            return "false"
        if isinstance(o, int):
            return str(o)
        if isinstance(o, float):
            raise TypeError("floats are forbidden in V1 canonicalization")
        if isinstance(o, str):
            return json.dumps(o, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
        if isinstance(o, list):
            return "[" + ",".join(dump(x) for x in o) + "]"
        if isinstance(o, dict):
            for k in o.keys():
                if not isinstance(k, str):
                    raise TypeError("JCS requires string keys")
            items = []
            for k in sorted(o.keys()):
                items.append(json.dumps(k, ensure_ascii=False, separators=(",", ":"), sort_keys=False) + ":" + dump(o[k]))
            return "{" + ",".join(items) + "}"
        raise TypeError(f"unsupported type: {type(o)!r}")

    return dump(obj).encode("utf-8")

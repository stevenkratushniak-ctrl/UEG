"""Merkle utilities used by kernel + verifier.

Definition:
- Leaves are 32-byte digests.
- Parent = sha256(left || right)
- If odd number of nodes, last node is duplicated.
- Empty list => sha256(b"")

This is intentionally simple and deterministic.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, List


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_root_hex(digests: Iterable[bytes]) -> str:
    nodes: List[bytes] = list(digests)
    if not nodes:
        return hashlib.sha256(b"").hexdigest()

    level = nodes
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            nxt.append(sha256(level[i] + level[i + 1]))
        level = nxt
    return level[0].hex()

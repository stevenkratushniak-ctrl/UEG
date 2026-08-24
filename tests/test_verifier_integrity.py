from __future__ import annotations

import json
import unittest

from verifier.ed25519 import KeyPair
from verifier.jcs import canonicalize
from verifier.reality_verify import (
    _parse_revocations,
    _safe_member_name,
    _verify_petitions,
    sha256_hex,
)


class VerifierIntegrityTest(unittest.TestCase):
    def test_key_identifier_is_bound_to_canonical_public_key(self) -> None:
        pair = KeyPair.generate()
        key_id = pair.key_id()
        self.assertRegex(key_id, r"^ueg:sha256:[0-9a-f]{64}$")
        pair.validate_key_id(key_id, allow_legacy=False)
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            pair.validate_key_id("ueg:sha256:" + "0" * 64, allow_legacy=False)
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            pair.validate_key_id(pair.legacy_key_id(), allow_legacy=False)
        pair.validate_key_id(pair.legacy_key_id(), allow_legacy=True)

    def test_revocation_formats_are_strict(self) -> None:
        key_id = "ueg:sha256:" + "a" * 64
        valid = [
            b"[]",
            (f'["{key_id}"]').encode(),
            (f'{{"revoked_key_ids":["{key_id}"]}}').encode(),
            (
                f'[{{"key_id":"{key_id}","reason":"compromise",'
                '"revoked_at":"2026-08-18T00:00:00Z"}]'
            ).encode(),
        ]
        for raw in valid:
            _, error = _parse_revocations(raw)
            self.assertIsNone(error, (raw, error))

        invalid = [
            b"null",
            b"[42]",
            b'[{"key_id":42}]',
            b'[{"reason":"missing key"}]',
            b'[{"key_id":"x","unknown":true}]',
            b'{"revoked_key_ids":[42]}',
            b'{"revoked_key_ids":[],"extra":true}',
            b'{"revoked_key_ids":[],"revoked_key_ids":[]}',
        ]
        for raw in invalid:
            _, error = _parse_revocations(raw)
            self.assertIsNotNone(error, raw)

    def test_petition_binding_is_bijective(self) -> None:
        def petition(action: str, receipt_id: str) -> dict:
            body = {"action": action}
            return {
                **body,
                "petition_hash": sha256_hex(canonicalize(body)),
                "receipt_id": receipt_id,
            }

        first = petition("one", "receipt-one")
        second = petition("two", "receipt-two")
        receipts = [
            {"sequence_no": 0, "receipt_id": "receipt-one", "petition_hash": first["petition_hash"]},
            {"sequence_no": 1, "receipt_id": "receipt-two", "petition_hash": second["petition_hash"]},
        ]

        def members(items: list[dict]) -> dict[str, bytes]:
            return {
                "petitions.ndjson": b"\n".join(
                    json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
                    for item in items
                )
            }

        self.assertIsNone(_verify_petitions(members([first, second]), receipts))
        repeated = dict(first, receipt_id=second["receipt_id"])
        repeated_receipts = [
            receipts[0],
            {**receipts[1], "petition_hash": first["petition_hash"]},
        ]
        self.assertIsNone(_verify_petitions(members([first, repeated]), repeated_receipts))
        self.assertIsNotNone(_verify_petitions(members([first, second, first]), receipts))
        self.assertIsNotNone(_verify_petitions(members([first, first]), receipts))

        duplicate_id = dict(second, receipt_id=first["receipt_id"])
        self.assertIsNotNone(_verify_petitions(members([first, duplicate_id]), receipts))

        wrong_id = dict(first, receipt_id=second["receipt_id"])
        self.assertIsNotNone(_verify_petitions(members([wrong_id, second]), receipts))

    def test_archive_member_names_are_portable(self) -> None:
        for name in ("MANIFEST.json", "identity/lifecycle.ndjson", "a-b_c.1"):
            self.assertTrue(_safe_member_name(name), name)
        for name in (
            "",
            "/absolute",
            "\\absolute",
            "../escape",
            "folder/../escape",
            "folder/./file",
            "folder//file",
            "folder\\file",
            "C:/drive",
            "identity/lifecycle?.json",
            "trailing/",
        ):
            self.assertFalse(_safe_member_name(name), name)


if __name__ == "__main__":
    unittest.main()

"""Independent B+ identity/lifecycle verification.

This module intentionally re-derives the Go implementation's canonical
genesis, lifecycle, epoch-window, checkpoint, and anchor rules. It consumes
public bundle and verifier inputs only; it never loads or writes private keys.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .ed25519 import KeyPair
from .jcs import canonicalize
from .strict_json import strict_json_loads
from .reality_verify import (
    BPLUS_IDENTITY_ID,
    BPLUS_VERSION,
    OVERALL_INDETERMINATE,
    OVERALL_INVALID,
    OVERALL_NOT_TRUSTED,
    OVERALL_VERIFIED,
    VerifyResult,
    _canonical_signing_ids,
    _load_trust_roots,
)

# Importing the remaining legacy primitives separately keeps static type tools
# from mistaking them for identity-authority helpers.
from .reality_verify import (  # noqa: E402
    _parse_receipts,
    _parse_revocations,
    _verify_bundle_seal,
    _verify_petitions,
    _verify_receipt_chain,
    _verify_receipt_seal,
)

PASS = "PASS"
FAIL = "FAIL"
INDETERMINATE = "INDETERMINATE"
NOT_CHECKED = "NOT_CHECKED"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^ueg:sha256:[0-9a-f]{64}$")

PROTOCOL = "ueg-bplus/1"
GENESIS_SCHEMA = "ueg.identity-genesis.v1"
LIFECYCLE_SCHEMA = "ueg.identity-lifecycle-record.v1"
CARD_SCHEMA = "ueg.identity-card.v1"
ANCHOR_SCHEMA = "ueg.evidence-anchor.v1"
CHECKPOINT_SCHEMA = "ueg.lifecycle-checkpoint.v1"
GENESIS_DOMAIN = "UEG-BPLUS-GENESIS-v1"
RECORD_DOMAIN = "UEG-BPLUS-LIFECYCLE-v1"
ANCHOR_DOMAIN = "UEG-BPLUS-EVIDENCE-ANCHOR-v1"

ACTIVE = "ACTIVE"
RETIRED = "RETIRED"
SUSPENDED = "SUSPENDED"
REVOKED = "REVOKED"

GENESIS_FIELDS = {
    "schema", "protocol_version", "identity_nonce_b64", "recovery_root_key_id",
    "recovery_root_public_key_pem", "epoch_zero_key_id", "epoch_zero_public_key_pem",
    "canonicalization", "genesis_policy", "advisory_label", "identity_id",
    "recovery_signature_b64", "epoch_zero_proof_b64",
}
RECORD_FIELDS = {
    "schema", "protocol_version", "identity_id", "lifecycle_sequence",
    "previous_record_digest", "action", "epoch_number", "operational_key_id",
    "operational_public_key_pem", "operational_status", "ledger_boundary",
    "previous_epoch", "evidence_anchor_digest", "reason_code", "record_digest",
    "recovery_signature_b64", "retiring_signature_b64", "operational_proof_b64",
}


def _base_result(**updates: Any) -> VerifyResult:
    values: Dict[str, Any] = {
        "ok": False,
        "reason": "",
        "checks": (),
        "bundle_version": BPLUS_VERSION,
        "signature": NOT_CHECKED,
        "bundle_ledger_integrity": NOT_CHECKED,
        "identity_continuity": NOT_CHECKED,
        "lifecycle_chain": NOT_CHECKED,
        "signing_key_status": NOT_CHECKED,
        "epoch_authorization": NOT_CHECKED,
        "evidence_anchor": NOT_CHECKED,
        "checkpoint_authenticity": NOT_CHECKED,
        "checkpoint_source": NOT_CHECKED,
        "checkpoint_sequence": NOT_CHECKED,
        "checkpoint_freshness": NOT_CHECKED,
        "evidence_time_assurance": "HOST_METADATA_ONLY",
        "overall_trust": OVERALL_INVALID,
    }
    values.update(updates)
    return VerifyResult(**values)


def _invalid(code: str, reason: str) -> VerifyResult:
    return _base_result(reason=reason, reason_code=code, overall_trust=OVERALL_INVALID)


def _not_trusted(result: VerifyResult, code: str, reason: str) -> VerifyResult:
    return replace(
        result, ok=False, reason=reason, reason_code=code, overall_trust=OVERALL_NOT_TRUSTED
    )


def _exact_object(value: Any, fields: set[str], label: str) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields are invalid or ambiguous")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def _integer(value: Any, label: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{label} must be an integer")
    return value


def _boundary(value: Any) -> Dict[str, Any]:
    boundary = _exact_object(value, {"sequence_no", "receipt_id"}, "ledger boundary")
    sequence = _integer(boundary["sequence_no"], "ledger boundary sequence")
    receipt_id = boundary["receipt_id"]
    if sequence == -1:
        if receipt_id is not None:
            raise ValueError("empty ledger boundary must have a null receipt_id")
    elif sequence < 0 or not isinstance(receipt_id, str) or HEX64.fullmatch(receipt_id) is None:
        raise ValueError("ledger boundary must name a non-negative sequence and 64-hex receipt id")
    return {"sequence_no": sequence, "receipt_id": receipt_id}


def _same_boundary(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    return left == right


def _domain_payload(domain: str, value: Dict[str, Any]) -> bytes:
    return domain.encode("ascii") + b"\x00" + canonicalize(value)


def _verify_domain(pair: KeyPair, domain: str, value: Dict[str, Any], signature: Any) -> bool:
    return isinstance(signature, str) and pair.verify_b64(_domain_payload(domain, value), signature)


def _genesis_core(genesis: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "advisory_label": genesis["advisory_label"],
        "canonicalization": genesis["canonicalization"],
        "epoch_zero_key_id": genesis["epoch_zero_key_id"],
        "epoch_zero_public_key_pem": genesis["epoch_zero_public_key_pem"],
        "genesis_policy": {
            "concurrent_signing": genesis["genesis_policy"]["concurrent_signing"],
            "one_active_operational_key": genesis["genesis_policy"]["one_active_operational_key"],
            "recovery_root_rotation": genesis["genesis_policy"]["recovery_root_rotation"],
        },
        "identity_nonce_b64": genesis["identity_nonce_b64"],
        "protocol_version": genesis["protocol_version"],
        "recovery_root_key_id": genesis["recovery_root_key_id"],
        "recovery_root_public_key_pem": genesis["recovery_root_public_key_pem"],
        "schema": genesis["schema"],
    }


def _genesis_signed(genesis: Dict[str, Any]) -> Dict[str, Any]:
    value = _genesis_core(genesis)
    value["identity_id"] = genesis["identity_id"]
    return value


def _validate_genesis(genesis: Any) -> Tuple[KeyPair, KeyPair]:
    genesis = _exact_object(genesis, GENESIS_FIELDS, "genesis")
    policy = _exact_object(
        genesis["genesis_policy"],
        {"one_active_operational_key", "concurrent_signing", "recovery_root_rotation"},
        "genesis policy",
    )
    if (
        genesis["schema"] != GENESIS_SCHEMA
        or genesis["protocol_version"] != PROTOCOL
        or genesis["canonicalization"] != "RFC8785-JCS"
        or policy["one_active_operational_key"] is not True
        or policy["concurrent_signing"] is not False
        or policy["recovery_root_rotation"] is not False
        or not isinstance(genesis["advisory_label"], str)
        or len(genesis["advisory_label"]) > 200
        or not isinstance(genesis["identity_id"], str)
        or BPLUS_IDENTITY_ID.fullmatch(genesis["identity_id"]) is None
        or not isinstance(genesis["recovery_root_key_id"], str)
        or KEY_ID.fullmatch(genesis["recovery_root_key_id"]) is None
        or not isinstance(genesis["epoch_zero_key_id"], str)
        or KEY_ID.fullmatch(genesis["epoch_zero_key_id"]) is None
    ):
        raise ValueError("genesis policy or required fields are invalid")
    try:
        nonce = base64.b64decode(_string(genesis["identity_nonce_b64"], "identity nonce"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("genesis nonce is invalid") from exc
    if len(nonce) != 32:
        raise ValueError("genesis nonce must be 32 bytes")
    recovery = KeyPair.load_public_pem_text(_string(genesis["recovery_root_public_key_pem"], "recovery public key"))
    epoch_zero = KeyPair.load_public_pem_text(_string(genesis["epoch_zero_public_key_pem"], "epoch-zero public key"))
    recovery.validate_key_id(genesis["recovery_root_key_id"], allow_legacy=False)
    epoch_zero.validate_key_id(genesis["epoch_zero_key_id"], allow_legacy=False)
    expected_identity = "ueg:identity:sha256:" + hashlib.sha256(canonicalize(_genesis_core(genesis))).hexdigest()
    if expected_identity != genesis["identity_id"]:
        raise ValueError("genesis digest does not match identity_id")
    signed = _genesis_signed(genesis)
    if not _verify_domain(recovery, GENESIS_DOMAIN, signed, genesis["recovery_signature_b64"]):
        raise ValueError("genesis recovery signature is invalid")
    if not _verify_domain(epoch_zero, GENESIS_DOMAIN, signed, genesis["epoch_zero_proof_b64"]):
        raise ValueError("genesis epoch-zero proof is invalid")
    return recovery, epoch_zero


def _previous_epoch(value: Any) -> Dict[str, Any] | None:
    if value is None:
        return None
    previous = _exact_object(
        value,
        {"epoch_number", "operational_key_id", "operational_status", "final_ledger_boundary"},
        "previous epoch",
    )
    return {
        "epoch_number": _integer(previous["epoch_number"], "previous epoch number"),
        "operational_key_id": _string(previous["operational_key_id"], "previous operational key id"),
        "operational_status": _string(previous["operational_status"], "previous operational status"),
        "final_ledger_boundary": _boundary(previous["final_ledger_boundary"]),
    }


def _record_core(record: Dict[str, Any]) -> Dict[str, Any]:
    previous = _previous_epoch(record["previous_epoch"])
    return {
        "action": record["action"],
        "epoch_number": record["epoch_number"],
        "evidence_anchor_digest": record["evidence_anchor_digest"],
        "identity_id": record["identity_id"],
        "ledger_boundary": _boundary(record["ledger_boundary"]),
        "lifecycle_sequence": record["lifecycle_sequence"],
        "operational_key_id": record["operational_key_id"],
        "operational_public_key_pem": record["operational_public_key_pem"],
        "operational_status": record["operational_status"],
        "previous_epoch": previous,
        "previous_record_digest": record["previous_record_digest"],
        "protocol_version": record["protocol_version"],
        "reason_code": record["reason_code"],
        "schema": record["schema"],
    }


def _record_signed(record: Dict[str, Any]) -> Dict[str, Any]:
    value = _record_core(record)
    value["record_digest"] = record["record_digest"]
    return value


def _parse_records(raw: bytes) -> List[Dict[str, Any]]:
    if len(raw) > 10 * 1024 * 1024:
        raise ValueError("lifecycle input exceeds 10 MiB")
    records: List[Dict[str, Any]] = []
    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        if not raw_line.strip():
            continue
        if len(raw_line) > 1024 * 1024:
            raise ValueError(f"lifecycle line {line_number} exceeds 1 MiB")
        record = strict_json_loads(raw_line)
        records.append(_exact_object(record, RECORD_FIELDS, f"lifecycle line {line_number}"))
        if len(records) > 10000:
            raise ValueError("lifecycle contains more than 10000 records")
    if not records:
        raise ValueError("lifecycle contains no records")
    return records


def _derive_state(genesis: Dict[str, Any], records: List[Dict[str, Any]]) -> Dict[str, Any]:
    recovery, epoch_zero = _validate_genesis(genesis)
    if not 1 <= len(records) <= 10000:
        raise ValueError("lifecycle must contain 1 to 10000 records")
    state: Dict[str, Any] = {
        "genesis": genesis,
        "records": records,
        "epochs": {},
        "trust": {},
        "recovery": recovery,
        "active": None,
        "last_sequence": -1,
        "last_digest": "",
    }
    previous_digest: str | None = None
    previous_boundary: Dict[str, Any] | None = None
    for index, record in enumerate(records):
        if (
            _integer(record["lifecycle_sequence"], "lifecycle sequence") != index
            or record["identity_id"] != genesis["identity_id"]
            or record["previous_record_digest"] != previous_digest
        ):
            raise ValueError(f"lifecycle sequence {index} is missing, duplicated, or breaks its chain")
        boundary = _boundary(record["ledger_boundary"])
        if previous_boundary is not None and (
            boundary["sequence_no"] < previous_boundary["sequence_no"]
            or (
                boundary["sequence_no"] == previous_boundary["sequence_no"]
                and not _same_boundary(boundary, previous_boundary)
            )
        ):
            raise ValueError(f"lifecycle sequence {index} moves the ledger boundary backward or conflicts")
        previous_boundary = boundary
        if (
            record["schema"] != LIFECYCLE_SCHEMA
            or record["protocol_version"] != PROTOCOL
            or not isinstance(record["identity_id"], str)
            or BPLUS_IDENTITY_ID.fullmatch(record["identity_id"]) is None
            or _integer(record["epoch_number"], "epoch number") < 0
            or not isinstance(record["operational_key_id"], str)
            or KEY_ID.fullmatch(record["operational_key_id"]) is None
            or not isinstance(record["record_digest"], str)
            or HEX64.fullmatch(record["record_digest"]) is None
            or not isinstance(record["reason_code"], str)
            or not 1 <= len(record["reason_code"].strip()) <= 128
            or (
                record["evidence_anchor_digest"] is not None
                and (
                    not isinstance(record["evidence_anchor_digest"], str)
                    or HEX64.fullmatch(record["evidence_anchor_digest"]) is None
                )
            )
        ):
            raise ValueError(f"lifecycle sequence {index} required fields are invalid")
        operational = KeyPair.load_public_pem_text(
            _string(record["operational_public_key_pem"], "operational public key")
        )
        operational.validate_key_id(record["operational_key_id"], allow_legacy=False)
        prior = _previous_epoch(record["previous_epoch"])
        retiring: KeyPair | None = None
        if prior is not None and prior["epoch_number"] in state["epochs"]:
            retiring = state["trust"][state["epochs"][prior["epoch_number"]]["key_id"]]
        elif state["active"] is not None:
            retiring = state["trust"][state["epochs"][state["active"]]["key_id"]]
        core = _record_core(record)
        if hashlib.sha256(canonicalize(core)).hexdigest() != record["record_digest"]:
            raise ValueError(f"lifecycle sequence {index} digest does not match")
        signed = _record_signed(record)
        if not _verify_domain(recovery, RECORD_DOMAIN, signed, record["recovery_signature_b64"]):
            raise ValueError(f"lifecycle sequence {index} recovery-root signature is invalid")
        needs_retiring = record["action"] in ("ROTATE", "SUSPEND")
        needs_proof = record["action"] in ("GENESIS", "MIGRATION", "ROTATE", "RECOVER", "RESUME")
        if needs_retiring:
            if retiring is None or not _verify_domain(retiring, RECORD_DOMAIN, signed, record["retiring_signature_b64"]):
                raise ValueError(f"lifecycle sequence {index} retiring signature is invalid")
        elif record["retiring_signature_b64"] is not None:
            raise ValueError(f"lifecycle sequence {index} has an unauthorized retiring signature")
        if needs_proof:
            if not _verify_domain(operational, RECORD_DOMAIN, signed, record["operational_proof_b64"]):
                raise ValueError(f"lifecycle sequence {index} operational proof is invalid")
        elif record["operational_proof_b64"] is not None:
            raise ValueError(f"lifecycle sequence {index} has an unauthorized operational proof")

        if index == 0:
            if (
                record["action"] not in ("GENESIS", "MIGRATION")
                or record["previous_record_digest"] is not None
                or record["epoch_number"] != 0
                or record["operational_key_id"] != genesis["epoch_zero_key_id"]
                or record["operational_status"] != ACTIVE
                or prior is not None
                or record["evidence_anchor_digest"] is not None
                or (record["action"] == "GENESIS" and boundary["sequence_no"] != -1)
            ):
                raise ValueError("lifecycle genesis record is inconsistent")
            state["trust"][record["operational_key_id"]] = epoch_zero
            state["epochs"][0] = {
                "number": 0,
                "key_id": record["operational_key_id"],
                "public_pem": record["operational_public_key_pem"],
                "status": ACTIVE,
                "windows": [{"start": {"sequence_no": -1, "receipt_id": None}, "end": None}],
                "known_anchor": None,
            }
            state["active"] = 0
        else:
            _apply_record(state, record, operational, prior, boundary)
        previous_digest = record["record_digest"]
        state["last_sequence"] = index
        state["last_digest"] = previous_digest
    return state


def _close_epoch(
    epoch: Dict[str, Any], status_name: str, boundary: Dict[str, Any], anchor_digest: str | None
) -> None:
    if epoch["windows"] and epoch["windows"][-1]["end"] is None:
        epoch["windows"][-1]["end"] = dict(boundary)
    epoch["status"] = status_name
    epoch["known_anchor"] = anchor_digest


def _apply_record(
    state: Dict[str, Any],
    record: Dict[str, Any],
    operational: KeyPair,
    prior: Dict[str, Any] | None,
    boundary: Dict[str, Any],
) -> None:
    latest_number = max(state["epochs"])
    action = record["action"]
    if action in ("ROTATE", "RECOVER"):
        if prior is None or record["epoch_number"] != latest_number + 1 or record["operational_status"] != ACTIVE:
            raise ValueError("transition must close the latest epoch and activate exactly its successor")
        previous_epoch = state["epochs"].get(prior["epoch_number"])
        if (
            previous_epoch is None
            or previous_epoch["key_id"] != prior["operational_key_id"]
            or previous_epoch["number"] != latest_number
            or prior["final_ledger_boundary"] != boundary
        ):
            raise ValueError("transition does not bind the exact previous epoch and ledger boundary")
        if action == "ROTATE":
            if state["active"] != previous_epoch["number"] or previous_epoch["status"] != ACTIVE or prior["operational_status"] != RETIRED:
                raise ValueError("routine rotation must retire the active epoch")
        else:
            if state["active"] is not None and state["active"] != previous_epoch["number"]:
                raise ValueError("recovery names an epoch that is not current")
            if prior["operational_status"] != REVOKED:
                raise ValueError("lost-key recovery must revoke the prior epoch")
        _close_epoch(
            previous_epoch, prior["operational_status"], boundary, record["evidence_anchor_digest"]
        )
        if record["operational_key_id"] in state["trust"]:
            raise ValueError("new epoch reuses an operational key")
        state["trust"][record["operational_key_id"]] = operational
        state["epochs"][record["epoch_number"]] = {
            "number": record["epoch_number"],
            "key_id": record["operational_key_id"],
            "public_pem": record["operational_public_key_pem"],
            "status": ACTIVE,
            "windows": [{"start": dict(boundary), "end": None}],
            "known_anchor": None,
        }
        state["active"] = record["epoch_number"]
    elif action == "SUSPEND":
        if (
            state["active"] is None
            or record["epoch_number"] != state["active"]
            or record["operational_key_id"] != state["epochs"][state["active"]]["key_id"]
            or record["operational_status"] != SUSPENDED
            or prior is not None
        ):
            raise ValueError("suspension must close the current active epoch")
        _close_epoch(
            state["epochs"][state["active"]],
            SUSPENDED,
            boundary,
            record["evidence_anchor_digest"],
        )
        state["active"] = None
    elif action == "RESUME":
        epoch = state["epochs"].get(record["epoch_number"])
        if (
            state["active"] is not None
            or epoch is None
            or record["epoch_number"] != latest_number
            or epoch["status"] != SUSPENDED
            or record["operational_key_id"] != epoch["key_id"]
            or record["operational_status"] != ACTIVE
            or prior is not None
        ):
            raise ValueError("resumption requires the latest suspended epoch")
        epoch["status"] = ACTIVE
        epoch["windows"].append({"start": dict(boundary), "end": None})
        state["active"] = epoch["number"]
    elif action == "REVOKE":
        epoch = state["epochs"].get(record["epoch_number"])
        if (
            epoch is None
            or record["epoch_number"] != latest_number
            or record["operational_key_id"] != epoch["key_id"]
            or record["operational_status"] != REVOKED
            or prior is not None
            or epoch["status"] in (RETIRED, REVOKED)
        ):
            raise ValueError("revocation must permanently close the latest non-retired epoch")
        if state["active"] == epoch["number"]:
            _close_epoch(epoch, REVOKED, boundary, record["evidence_anchor_digest"])
            state["active"] = None
        else:
            epoch["status"] = REVOKED
            epoch["known_anchor"] = record["evidence_anchor_digest"]
    else:
        raise ValueError(f"unknown lifecycle action {action!r}")


def _parse_checkpoint(raw: bytes) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    if len(raw) > 12 * 1024 * 1024:
        raise ValueError("lifecycle checkpoint exceeds 12 MiB")
    checkpoint = _exact_object(
        strict_json_loads(raw),
        {"schema", "protocol_version", "identity_id", "genesis", "lifecycle_records", "checkpoint_sequence", "checkpoint_digest"},
        "lifecycle checkpoint",
    )
    if (
        checkpoint["schema"] != CHECKPOINT_SCHEMA
        or checkpoint["protocol_version"] != PROTOCOL
        or not isinstance(checkpoint["identity_id"], str)
        or BPLUS_IDENTITY_ID.fullmatch(checkpoint["identity_id"]) is None
        or not isinstance(checkpoint["lifecycle_records"], list)
        or type(checkpoint["checkpoint_sequence"]) is not int
        or checkpoint["checkpoint_sequence"] != len(checkpoint["lifecycle_records"]) - 1
        or not isinstance(checkpoint["checkpoint_digest"], str)
        or HEX64.fullmatch(checkpoint["checkpoint_digest"]) is None
    ):
        raise ValueError("lifecycle checkpoint fields are inconsistent")
    records = [_exact_object(record, RECORD_FIELDS, "checkpoint lifecycle record") for record in checkpoint["lifecycle_records"]]
    state = _derive_state(checkpoint["genesis"], records)
    if (
        checkpoint["identity_id"] != checkpoint["genesis"]["identity_id"]
        or state["last_sequence"] != checkpoint["checkpoint_sequence"]
        or state["last_digest"] != checkpoint["checkpoint_digest"]
    ):
        raise ValueError("lifecycle checkpoint does not name its authenticated chain head")
    return checkpoint, state


def _anchor_core(anchor: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "epoch_number": anchor["epoch_number"],
        "identity_id": anchor["identity_id"],
        "ledger_boundary": _boundary(anchor["ledger_boundary"]),
        "lifecycle_record_digest": anchor["lifecycle_record_digest"],
        "lifecycle_sequence": anchor["lifecycle_sequence"],
        "operational_key_id": anchor["operational_key_id"],
        "protocol_version": anchor["protocol_version"],
        "schema": anchor["schema"],
    }


def _validate_anchor(raw_or_value: bytes | Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    value = strict_json_loads(raw_or_value) if isinstance(raw_or_value, bytes) else raw_or_value
    anchor = _exact_object(
        value,
        {"schema", "protocol_version", "identity_id", "epoch_number", "operational_key_id", "ledger_boundary", "lifecycle_sequence", "lifecycle_record_digest", "anchor_digest", "signature_b64"},
        "evidence anchor",
    )
    sequence = _integer(anchor["lifecycle_sequence"], "anchor lifecycle sequence")
    epoch_number = _integer(anchor["epoch_number"], "anchor epoch number")
    if (
        anchor["schema"] != ANCHOR_SCHEMA
        or anchor["protocol_version"] != PROTOCOL
        or anchor["identity_id"] != state["genesis"]["identity_id"]
        or epoch_number not in state["epochs"]
        or anchor["operational_key_id"] != state["epochs"][epoch_number]["key_id"]
        or sequence < 0
        or sequence >= len(state["records"])
        or anchor["lifecycle_record_digest"] != state["records"][sequence]["record_digest"]
        or not isinstance(anchor["anchor_digest"], str)
        or HEX64.fullmatch(anchor["anchor_digest"]) is None
    ):
        raise ValueError("evidence anchor required fields are invalid")
    _boundary(anchor["ledger_boundary"])
    core = _anchor_core(anchor)
    if hashlib.sha256(canonicalize(core)).hexdigest() != anchor["anchor_digest"]:
        raise ValueError("evidence anchor digest does not match its contents")
    signed = dict(core)
    signed["anchor_digest"] = anchor["anchor_digest"]
    pair = state["trust"][anchor["operational_key_id"]]
    if not _verify_domain(pair, ANCHOR_DOMAIN, signed, anchor["signature_b64"]):
        raise ValueError("evidence anchor signature is invalid")
    return anchor


def _parse_authority(members: Dict[str, bytes]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    card = _exact_object(
        strict_json_loads(members["identity/card.json"]),
        {"schema", "protocol_version", "identity_id", "advisory_label", "genesis"},
        "identity card",
    )
    if card["schema"] != CARD_SCHEMA or card["protocol_version"] != PROTOCOL:
        raise ValueError("identity card fields are invalid")
    checkpoint, checkpoint_state = _parse_checkpoint(members["identity/checkpoint.json"])
    genesis = _exact_object(strict_json_loads(members["identity/genesis.json"]), GENESIS_FIELDS, "genesis")
    records = _parse_records(members["identity/lifecycle.ndjson"])
    state = _derive_state(genesis, records)
    if (
        card["identity_id"] != genesis["identity_id"]
        or card["advisory_label"] != genesis["advisory_label"]
        or card["genesis"] != genesis
        or checkpoint["identity_id"] != genesis["identity_id"]
        or checkpoint["genesis"] != genesis
        or checkpoint["lifecycle_records"] != records
        or checkpoint_state["last_digest"] != state["last_digest"]
    ):
        raise ValueError("B+ identity authority members do not describe one identical genesis and lifecycle")
    anchor = _validate_anchor(members["identity/evidence_anchor.json"], state)
    return state, anchor


def _exact_trust(bundle_trust: Dict[str, KeyPair], state: Dict[str, Any]) -> None:
    if set(bundle_trust) != set(state["trust"]):
        raise ValueError("trust_roots.json does not contain exactly the authenticated lifecycle keys")
    for key_id, expected in state["trust"].items():
        actual = bundle_trust[key_id]
        actual.validate_key_id(key_id, allow_legacy=False)
        if actual.public_pem_bytes() != expected.public_pem_bytes():
            raise ValueError(f"trust root {key_id} differs from lifecycle authority")


def _receipt_authorization(receipts: List[Dict[str, Any]], state: Dict[str, Any]) -> None:
    epochs_by_key = {epoch["key_id"]: epoch for epoch in state["epochs"].values()}
    for receipt in receipts:
        epoch = epochs_by_key.get(receipt["signing_key_id"])
        if epoch is None:
            raise ValueError(f"receipt {receipt['sequence_no']} names no authenticated lifecycle epoch")
        authorized = any(
            receipt["sequence_no"] > window["start"]["sequence_no"]
            and (window["end"] is None or receipt["sequence_no"] <= window["end"]["sequence_no"])
            for window in epoch["windows"]
        )
        if not authorized:
            raise ValueError(f"receipt {receipt['sequence_no']} is outside epoch {epoch['number']}'s authorization windows")


def _checkpoint_receipt_boundaries(receipts: List[Dict[str, Any]], state: Dict[str, Any]) -> None:
    for record in state["records"]:
        boundary = _boundary(record["ledger_boundary"])
        sequence = boundary["sequence_no"]
        if sequence < 0 or sequence >= len(receipts):
            continue
        if boundary["receipt_id"] != receipts[sequence]["receipt_id"]:
            raise ValueError(
                f"lifecycle sequence {record['lifecycle_sequence']} does not bind "
                f"the bundle receipt at sequence {sequence}"
            )


def _embedded_boundaries(receipts: List[Dict[str, Any]], state: Dict[str, Any]) -> None:
    for record in state["records"]:
        boundary = _boundary(record["ledger_boundary"])
        if boundary["sequence_no"] == -1:
            continue
        sequence = boundary["sequence_no"]
        if sequence >= len(receipts) or receipts[sequence]["receipt_id"] != boundary["receipt_id"]:
            raise ValueError(f"lifecycle sequence {record['lifecycle_sequence']} does not bind an exact receipt-chain boundary")


def _read_regular(path: Path, maximum: int) -> bytes:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("external trust input is not a regular file")
    if info.st_size > maximum:
        raise ValueError(f"external trust input exceeds {maximum} bytes")
    return path.read_bytes()


def _select_checkpoint(
    embedded: Dict[str, Any], expected_identity_id: str, checkpoint_path: Path | None, trust_store: Path | None
) -> Tuple[Dict[str, Any], str]:
    if checkpoint_path is not None and trust_store is not None:
        raise ValueError("CHECKPOINT_SOURCE_CONFLICT: choose either a checkpoint file or retained store")
    if checkpoint_path is None and trust_store is None:
        return embedded, "EMBEDDED_ONLY"
    if checkpoint_path is not None:
        raw = _read_regular(checkpoint_path, 12 * 1024 * 1024)
        source = "SUPPLIED_FILE"
    else:
        assert trust_store is not None
        name = expected_identity_id.removeprefix("ueg:identity:sha256:") + ".checkpoint.json"
        raw = _read_regular(trust_store / name, 12 * 1024 * 1024)
        source = "RETAINED_STORE"
    checkpoint, state = _parse_checkpoint(raw)
    if checkpoint["identity_id"] != embedded["genesis"]["identity_id"] or state["last_sequence"] < embedded["last_sequence"]:
        raise ValueError("CHECKPOINT_ROLLBACK: external checkpoint is older than or belongs to another identity")
    if state["records"][embedded["last_sequence"]]["record_digest"] != embedded["last_digest"]:
        raise ValueError("CHECKPOINT_FORK: external checkpoint is not a descendant of the bundle lifecycle")
    return state, source


def _load_external_anchor(path: Path | None, state: Dict[str, Any], receipts: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    if path is None:
        return None
    anchor = _validate_anchor(_read_regular(path, 1024 * 1024), state)
    boundary = _boundary(anchor["ledger_boundary"])
    sequence = boundary["sequence_no"]
    if sequence < 0 or sequence >= len(receipts) or receipts[sequence]["receipt_id"] != boundary["receipt_id"]:
        raise ValueError("external anchor does not match an exact receipt in this bundle")
    return anchor


def _signing_status(
    receipts: List[Dict[str, Any]], state: Dict[str, Any], anchor: Dict[str, Any] | None
) -> Tuple[str, bool]:
    used: Dict[str, int] = {}
    for receipt in receipts:
        used[receipt["signing_key_id"]] = max(used.get(receipt["signing_key_id"], -1), receipt["sequence_no"])
    statuses: set[str] = set()
    indeterminate = False
    for epoch in state["epochs"].values():
        if epoch["key_id"] not in used:
            continue
        statuses.add(epoch["status"])
        if epoch["status"] in (SUSPENDED, REVOKED):
            covered = (
                anchor is not None
                and epoch["known_anchor"] == anchor["anchor_digest"]
                and anchor["epoch_number"] == epoch["number"]
                and anchor["ledger_boundary"]["sequence_no"] >= used[epoch["key_id"]]
            )
            indeterminate = indeterminate or not covered
    joined = "+".join(sorted(statuses))
    if indeterminate:
        return "INDETERMINATE_" + joined, True
    if anchor is not None:
        return "AUTHORIZED_AT_INDEPENDENT_ANCHOR_" + joined, False
    return "AUTHORIZED_" + joined, False


def verify_bplus_bundle(
    members: Dict[str, bytes],
    *,
    expected_key_id: str | None,
    expected_identity_id: str | None,
    checkpoint_path: Path | None,
    anchor_path: Path | None,
    trust_store: Path | None,
    minimum_checkpoint_sequence: int | None,
    minimum_checkpoint_digest: str | None,
    require_current_status: bool,
) -> VerifyResult:
    checks: List[str] = ["B+ manifest matches every declared member byte"]
    result = _base_result(checks=tuple(checks))
    if expected_key_id:
        return _not_trusted(result, "BPLUS_REQUIRES_IDENTITY_PIN", "B+ verification requires an expected identity id")
    try:
        manifest = strict_json_loads(members["MANIFEST.json"])
        embedded, embedded_anchor = _parse_authority(members)
    except Exception as exc:
        return _invalid("LIFECYCLE_INVALID", str(exc))
    identity_id = embedded["genesis"]["identity_id"]
    result = replace(
        result,
        identity_id=identity_id,
        lifecycle_sequence=embedded["last_sequence"],
        lifecycle_digest=embedded["last_digest"],
    )
    if (
        manifest["identity_id"] != identity_id
        or manifest["checkpoint_sequence"] != embedded["last_sequence"]
        or manifest["checkpoint_digest"] != embedded["last_digest"]
        or manifest["evidence_anchor_digest"] != embedded_anchor["anchor_digest"]
    ):
        return _invalid("MANIFEST_AUTHORITY_MISMATCH", "manifest authority fields do not match authenticated B+ members")
    result = replace(result, lifecycle_chain=PASS, checkpoint_authenticity=PASS, checkpoint_sequence=PASS)

    trust, error = _load_trust_roots(members, allow_legacy=False)
    if error:
        return _invalid("TRUST_ROOTS_INVALID", error)
    revoked, error = _parse_revocations(members.get("revocations.json", b""))
    if error or revoked:
        return _invalid("LEGACY_REVOCATION_CONFLICT", "B+ revocations.json must be empty")
    try:
        _exact_trust(trust, embedded)
    except Exception as exc:
        return _invalid("TRUST_ROOT_SUBSTITUTION", str(exc))
    if error := _verify_bundle_seal(members, trust):
        return _invalid("BUNDLE_SEAL_INVALID", error)
    receipts, error = _parse_receipts(members)
    if error:
        return _invalid("RECEIPTS_INVALID", error)
    if error := _verify_receipt_chain(receipts, trust):
        return _invalid("BPLUS_LEDGER_INVALID", error)
    if error := _verify_petitions(members, receipts):
        return _invalid("PETITION_BINDING_INVALID", error)
    if error := _verify_receipt_seal(members, receipts, trust):
        return _invalid("RECEIPT_SEAL_INVALID", error)
    try:
        _embedded_boundaries(receipts, embedded)
        _receipt_authorization(receipts, embedded)
    except Exception as exc:
        return _invalid("BPLUS_LEDGER_INVALID", str(exc))
    bundle_seal = strict_json_loads(members["BUNDLE_SEAL.json"])
    receipt_seal = strict_json_loads(members["seals.json"])[0]
    active = embedded["active"]
    if (
        active is None
        or bundle_seal["signing_key_id"] != embedded["epochs"][active]["key_id"]
        or receipt_seal["signing_key_id"] != embedded["epochs"][active]["key_id"]
    ):
        return _invalid("EXPORT_SIGNER_NOT_ACTIVE", "bundle seals are not signed by the embedded active epoch")
    anchor_boundary = embedded_anchor["ledger_boundary"]
    if (
        anchor_boundary["sequence_no"] != len(receipts) - 1
        or anchor_boundary["receipt_id"] != receipts[-1]["receipt_id"]
    ):
        return _invalid("EMBEDDED_ANCHOR_BOUNDARY_MISMATCH", "embedded anchor does not bind the receipt head")
    signing_ids, error = _canonical_signing_ids(members, receipts, trust)
    if error:
        return _invalid("SIGNING_IDENTITY_INVALID", error)
    result = replace(
        result,
        ok=True,
        signing_key_ids=signing_ids,
        signature=PASS,
        bundle_ledger_integrity=PASS,
        epoch_authorization=PASS,
        evidence_anchor="EMBEDDED_ONLY",
    )
    if not expected_identity_id:
        return replace(
            result,
            reason="the bundle is internally authentic, but B+ identity continuity requires an independently supplied genesis identity pin",
            reason_code="MISSING_EXTERNAL_IDENTITY_PIN",
            identity_continuity=INDETERMINATE,
            checkpoint_source="EMBEDDED_ONLY",
            checkpoint_freshness="UNPROVEN_OFFLINE",
            signing_key_status="AUTHENTIC_EMBEDDED_STATUS_ONLY",
            overall_trust=OVERALL_INDETERMINATE,
        )
    if BPLUS_IDENTITY_ID.fullmatch(expected_identity_id) is None or expected_identity_id != identity_id:
        return _not_trusted(
            replace(result, identity_continuity=FAIL),
            "IDENTITY_PIN_MISMATCH",
            f"expected B+ identity {expected_identity_id}, bundle carries {identity_id}",
        )
    result = replace(result, identity_continuity=PASS)
    try:
        checkpoint_state, source = _select_checkpoint(embedded, expected_identity_id, checkpoint_path, trust_store)
    except Exception as exc:
        message = str(exc)
        code = message.split(":", 1)[0] if message.startswith("CHECKPOINT_") else "CHECKPOINT_INVALID"
        return _not_trusted(result, code, message)
    result = replace(
        result,
        checkpoint_source=source,
        checkpoint_authenticity=PASS,
        checkpoint_sequence=PASS,
        lifecycle_sequence=checkpoint_state["last_sequence"],
        lifecycle_digest=checkpoint_state["last_digest"],
    )
    if minimum_checkpoint_sequence is not None:
        if (
            minimum_checkpoint_sequence < 0
            or checkpoint_state["last_sequence"] < minimum_checkpoint_sequence
            or minimum_checkpoint_sequence >= len(checkpoint_state["records"])
            or checkpoint_state["records"][minimum_checkpoint_sequence]["record_digest"] != minimum_checkpoint_digest
        ):
            return _not_trusted(
                replace(result, checkpoint_sequence=FAIL),
                "MINIMUM_CHECKPOINT_NOT_MET",
                "checkpoint does not contain the required sequence/digest pin",
            )
    elif minimum_checkpoint_digest is not None:
        return _not_trusted(
            replace(result, checkpoint_sequence=FAIL),
            "MINIMUM_CHECKPOINT_NOT_MET",
            "a minimum checkpoint digest requires its sequence",
        )
    try:
        _checkpoint_receipt_boundaries(receipts, checkpoint_state)
    except Exception as exc:
        return _not_trusted(
            replace(result, checkpoint_authenticity=FAIL),
            "CHECKPOINT_RECEIPT_BOUNDARY_MISMATCH",
            str(exc),
        )
    try:
        _receipt_authorization(receipts, checkpoint_state)
    except Exception as exc:
        return _not_trusted(replace(result, epoch_authorization=FAIL), "EPOCH_UNAUTHORIZED", str(exc))
    try:
        external_anchor = _load_external_anchor(anchor_path, checkpoint_state, receipts)
    except Exception as exc:
        return _not_trusted(replace(result, evidence_anchor=FAIL), "EXTERNAL_ANCHOR_INVALID", str(exc))
    if external_anchor is not None:
        result = replace(result, evidence_anchor="INDEPENDENT_MATCH")
    status, status_indeterminate = _signing_status(receipts, checkpoint_state, external_anchor)
    result = replace(
        result,
        ok=True,
        signing_key_status=status,
        checkpoint_freshness="UNPROVEN_OFFLINE",
    )
    if source == "EMBEDDED_ONLY":
        return replace(
            result,
            reason="the identity pin matches, but the only lifecycle status came from inside the bundle",
            reason_code="EMBEDDED_CHECKPOINT_NOT_INDEPENDENT",
            overall_trust=OVERALL_INDETERMINATE,
        )
    if require_current_status:
        return replace(
            result,
            reason="the supplied lifecycle checkpoint is authentic, but an offline verifier cannot prove that no newer revocation exists",
            reason_code="CURRENT_STATUS_FRESHNESS_UNAVAILABLE",
            overall_trust=OVERALL_INDETERMINATE,
        )
    if status_indeterminate:
        return replace(
            result,
            reason="one or more signatures belong to a suspended or revoked epoch and lack an independent known-good anchor",
            reason_code="EPOCH_TRUST_INDETERMINATE",
            overall_trust=OVERALL_INDETERMINATE,
        )
    return replace(
        result,
        reason="B+ evidence verified at the independently supplied lifecycle checkpoint; current-status freshness was not claimed",
        reason_code="BPLUS_VERIFIED_AT_CHECKPOINT",
        trust_verdict=OVERALL_VERIFIED,
        overall_trust=OVERALL_VERIFIED,
    )

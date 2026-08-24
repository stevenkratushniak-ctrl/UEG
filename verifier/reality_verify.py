"""Offline verifier for UEG evidence bundles (Reality Layer V1 layout).

Adapted from the Reality Layer V1 contract pack verifier, with three changes:

1. receipt_id is re-derived from the receipt's contents. The original verifier
   checked the signature over receipt_id but never checked that receipt_id
   described the receipt it sits in, so a receipt's recorded facts could be
   edited while its id and signature stayed valid. This version rejects that.
2. petitions.ndjson, when present, is bound: every receipt's petition_hash must
   match a stored request, and every stored request must hash to the value it
   claims.
3. revocations.json is parsed and revoked key ids are rejected.

What it checks:
  - tar safety (member count, sizes, path traversal, duplicates)
  - MANIFEST integrity, and that the archive holds nothing the manifest omits
  - BUNDLE_SEAL: signed anchor over MANIFEST plus a merkle root of members
  - trust roots and revocations
  - receipt schema, id derivation, signatures, ordering and chain linkage
  - the signed receipt-window seal
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import jsonschema

from .ed25519 import KeyPair
from .jcs import canonicalize
from .merkle import merkle_root_hex
from .strict_json import strict_json_loads

_ROOT = Path(__file__).resolve().parents[1]
_SCHEMAS = _ROOT / "contract" / "schemas"

MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FILES = 200

RECEIPT_CORE_EXCLUDED = ("receipt_id", "signature_b64")
TRUST_NOT_VERIFIED = "NOT_VERIFIED"
TRUST_INTERNALLY_CONSISTENT = "INTERNALLY_CONSISTENT"
TRUST_IDENTITY_TRUSTED = "IDENTITY_TRUSTED"
TRUST_IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
FULL_KEY_ID = re.compile(r"^ueg:sha256:[0-9a-f]{64}$")
BPLUS_IDENTITY_ID = re.compile(r"^ueg:identity:sha256:[0-9a-f]{64}$")
BPLUS_VERSION = "bplus-v1"
OVERALL_VERIFIED = "VERIFIED"
OVERALL_INDETERMINATE = "TRUST_INDETERMINATE"
OVERALL_NOT_TRUSTED = "NOT_TRUSTED"
OVERALL_INVALID = "INVALID"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str
    checks: Tuple[str, ...] = ()
    trust_verdict: str = TRUST_NOT_VERIFIED
    signing_key_ids: Tuple[str, ...] = ()
    expected_key_id: str | None = None
    bundle_version: str | None = None
    reason_code: str | None = None
    signature: str | None = None
    bundle_ledger_integrity: str | None = None
    identity_continuity: str | None = None
    lifecycle_chain: str | None = None
    signing_key_status: str | None = None
    epoch_authorization: str | None = None
    evidence_anchor: str | None = None
    checkpoint_authenticity: str | None = None
    checkpoint_source: str | None = None
    checkpoint_sequence: str | None = None
    checkpoint_freshness: str | None = None
    evidence_time_assurance: str | None = None
    overall_trust: str | None = None
    identity_id: str | None = None
    lifecycle_sequence: int | None = None
    lifecycle_digest: str | None = None


def _invalid_result(reason: str) -> VerifyResult:
    return VerifyResult(
        False,
        reason,
        reason_code="EVIDENCE_INVALID",
        overall_trust=OVERALL_INVALID,
    )


def _load_validator(name: str) -> jsonschema.Draft202012Validator:
    schema = strict_json_loads((_SCHEMAS / name).read_bytes())
    return jsonschema.Draft202012Validator(schema)


_RECEIPT_VALIDATOR = _load_validator("receipt.v1.schema.json")
_SEAL_VALIDATOR = _load_validator("seal.v1.schema.json")
_BUNDLE_SEAL_VALIDATOR = _load_validator("bundle_seal.v1.schema.json")


def _safe_member_name(name: str) -> bool:
    if not name or name.startswith("/") or "\\" in name or ":" in name:
        return False
    for part in name.split("/"):
        if not part or part in (".", "..") or re.fullmatch(r"[A-Za-z0-9._-]+", part) is None:
            return False
    return True


def _read_tar_members(bundle_path: Path) -> Tuple[Dict[str, bytes], Optional[str]]:
    members: Dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(bundle_path, "r:gz") as tf:
            infos = tf.getmembers()
            if len(infos) > MAX_FILES:
                return {}, f"too many files: {len(infos)} > {MAX_FILES}"
            for ti in infos:
                if not ti.isfile():
                    return {}, f"non-regular archive member is not permitted: {ti.name}"
                if not _safe_member_name(ti.name):
                    return {}, f"unsafe member name: {ti.name}"
                if ti.name in members:
                    return {}, f"duplicate member: {ti.name}"
                if ti.size > MAX_FILE_BYTES:
                    return {}, f"member too large: {ti.name} ({ti.size} bytes)"
                total += ti.size
                if total > MAX_TOTAL_BYTES:
                    return {}, f"bundle too large: {total} bytes"
                f = tf.extractfile(ti)
                if f is None:
                    return {}, f"could not extract: {ti.name}"
                members[ti.name] = f.read()
    except tarfile.TarError as exc:
        return {}, f"invalid tar.gz: {exc}"
    return members, None


def _verify_manifest(members: Dict[str, bytes]) -> Tuple[str | None, Optional[str]]:
    if "MANIFEST.json" not in members:
        return None, "missing MANIFEST.json"
    try:
        manifest = strict_json_loads(members["MANIFEST.json"])
    except Exception as exc:
        return None, f"invalid MANIFEST.json: {exc}"

    if not isinstance(manifest, dict):
        return None, "MANIFEST.json must be an object"
    version = manifest.get("version")
    if version not in ("v1", "v2", BPLUS_VERSION):
        return None, "manifest version must be v1, v2, or bplus-v1"
    legacy_fields = {"created_at", "files", "version"}
    bplus_fields = legacy_fields | {
        "identity_id", "checkpoint_sequence", "checkpoint_digest", "evidence_anchor_digest"
    }
    if set(manifest) != (bplus_fields if version == BPLUS_VERSION else legacy_fields):
        return None, "MANIFEST.json fields do not match its declared version"
    if not isinstance(manifest.get("created_at"), str) or not manifest["created_at"]:
        return None, "manifest.created_at must be a non-empty string"

    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        return None, "manifest.files must be a non-empty object"

    required = {"receipts.ndjson", "trust_roots.json", "revocations.json", "seals.json"}
    if version == BPLUS_VERSION:
        required |= {
            "petitions.ndjson",
            "identity/genesis.json",
            "identity/lifecycle.ndjson",
            "identity/card.json",
            "identity/checkpoint.json",
            "identity/evidence_anchor.json",
        }
        if (
            not isinstance(manifest.get("identity_id"), str)
            or BPLUS_IDENTITY_ID.fullmatch(manifest["identity_id"]) is None
            or type(manifest.get("checkpoint_sequence")) is not int
            or manifest["checkpoint_sequence"] < 0
            or not isinstance(manifest.get("checkpoint_digest"), str)
            or re.fullmatch(r"[0-9a-f]{64}", manifest["checkpoint_digest"]) is None
            or not isinstance(manifest.get("evidence_anchor_digest"), str)
            or re.fullmatch(r"[0-9a-f]{64}", manifest["evidence_anchor_digest"]) is None
        ):
            return None, "B+ manifest authority fields are invalid"
    missing = sorted(required - set(files.keys()))
    if missing:
        return None, f"manifest missing required entries: {missing}"

    allowed = set(files.keys()) | {"MANIFEST.json", "BUNDLE_SEAL.json"}
    extras = sorted(set(members.keys()) - allowed)
    if extras:
        return None, f"archive holds files the manifest does not list: {extras}"

    for name, expected in files.items():
        if not isinstance(name, str) or not _safe_member_name(name) or name in {"MANIFEST.json", "BUNDLE_SEAL.json"}:
            return None, f"manifest contains an invalid member name: {name}"
        if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            return None, f"manifest hash for {name} is not 64 lowercase hex characters"
        if name not in members:
            return None, f"manifest references a missing file: {name}"
        if sha256_hex(members[name]) != expected:
            return None, f"hash mismatch: {name}"
    return version, None


def _parse_revocations(raw: bytes) -> Tuple[List[str], Optional[str]]:
    try:
        value = strict_json_loads(raw)
    except Exception as exc:
        return [], str(exc)

    ids: List[str] = []
    if isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, str):
                ids.append(item)
                continue
            if not isinstance(item, dict):
                return [], f"entry {index} must be a key id string or revocation object"
            if not set(item).issubset({"key_id", "reason", "revoked_at"}):
                return [], f"entry {index} contains an unexpected field"
            if not isinstance(item.get("key_id"), str) or not item["key_id"].strip():
                return [], f"entry {index} requires a non-empty key_id"
            for field in ("reason", "revoked_at"):
                if field in item and not isinstance(item[field], str):
                    return [], f"entry {index} field {field} must be a string"
            ids.append(item["key_id"])
    elif isinstance(value, dict):
        if set(value) != {"revoked_key_ids"} or not isinstance(value["revoked_key_ids"], list):
            return [], "object form permits only a revoked_key_ids array"
        for index, item in enumerate(value["revoked_key_ids"]):
            if not isinstance(item, str):
                return [], f"revoked_key_ids[{index}] must be a string"
            ids.append(item)
    else:
        return [], "top level must be an array or revoked_key_ids object"

    if any(not item.strip() for item in ids):
        return [], "revoked key id must not be empty"
    if len(set(ids)) != len(ids):
        return [], "duplicate revoked key id"
    return ids, None


def _load_trust_roots(
    members: Dict[str, bytes], *, allow_legacy: bool
) -> Tuple[Dict[str, KeyPair], Optional[str]]:
    if "trust_roots.json" not in members:
        return {}, "missing trust_roots.json"
    try:
        obj = strict_json_loads(members["trust_roots.json"])
    except Exception as exc:
        return {}, f"invalid trust_roots.json: {exc}"

    if not isinstance(obj, dict) or set(obj) != {"ed25519_public_keys"}:
        return {}, "trust_roots.json must contain exactly ed25519_public_keys"
    keys = obj.get("ed25519_public_keys")
    if not isinstance(keys, dict) or not keys:
        return {}, "trust_roots.ed25519_public_keys must be a non-empty object"

    all_keys: Dict[str, KeyPair] = {}
    canonical_by_claim: Dict[str, str] = {}
    for key_id, pem in keys.items():
        if not isinstance(key_id, str) or not isinstance(pem, str):
            return {}, "trust_roots key map must be string->string"
        try:
            pair = KeyPair.load_public_pem_text(pem)
            pair.validate_key_id(key_id, allow_legacy=allow_legacy)
        except Exception as exc:
            return {}, f"trust root {key_id}: {exc}"
        all_keys[key_id] = pair
        canonical_by_claim[key_id] = pair.key_id()

    revoked, error = _parse_revocations(members.get("revocations.json", b""))
    if error:
        return {}, f"invalid revocations.json: {error}"
    revoked_canonical: set[str] = set()
    for key_id in revoked:
        if key_id not in canonical_by_claim:
            return {}, f"revocation names a key that is not bound in trust_roots.json: {key_id}"
        revoked_canonical.add(canonical_by_claim[key_id])

    out: Dict[str, KeyPair] = {}
    for key_id, pair in all_keys.items():
        if canonical_by_claim[key_id] in revoked_canonical:
            continue
        out[key_id] = pair
    if not out:
        return {}, "every trust root is revoked"
    return out, None


def _verify_bundle_seal(members: Dict[str, bytes], trust: Dict[str, KeyPair]) -> Optional[str]:
    if "BUNDLE_SEAL.json" not in members:
        return "missing BUNDLE_SEAL.json"
    try:
        seal = strict_json_loads(members["BUNDLE_SEAL.json"])
        _BUNDLE_SEAL_VALIDATOR.validate(seal)
    except Exception as exc:
        return f"invalid BUNDLE_SEAL.json: {exc}"

    kp = trust.get(seal["signing_key_id"])
    if kp is None:
        return f"bundle seal signing_key_id is not a trust root: {seal['signing_key_id']}"

    if seal["manifest_sha256"] != sha256_hex(members["MANIFEST.json"]):
        return "bundle seal manifest_sha256 mismatch"

    items = sorted(
        (name, sha256_hex(data)) for name, data in members.items() if name != "BUNDLE_SEAL.json"
    )
    leaves = [hashlib.sha256(f"{n}:{h}".encode("utf-8")).digest() for n, h in items]
    if seal["members_merkle_root"] != merkle_root_hex(leaves):
        return "bundle seal members_merkle_root mismatch"

    seal_base = {k: v for k, v in seal.items() if k not in ("seal_id", "signature_b64")}
    if sha256_hex(canonicalize(seal_base)) != seal["seal_id"]:
        return "bundle seal id does not match its contents"
    body = {k: v for k, v in seal.items() if k != "signature_b64"}
    if not kp.verify_b64(canonicalize(body), seal["signature_b64"]):
        return "bundle seal signature invalid"
    return None


def _parse_receipts(members: Dict[str, bytes]) -> Tuple[List[dict], Optional[str]]:
    if "receipts.ndjson" not in members:
        return [], "missing receipts.ndjson"
    receipts: List[dict] = []
    for raw in members["receipts.ndjson"].splitlines():
        if not raw.strip():
            continue
        try:
            obj = strict_json_loads(raw)
        except Exception as exc:
            return [], f"invalid receipts.ndjson line: {exc}"
        try:
            _RECEIPT_VALIDATOR.validate(obj)
        except Exception as exc:
            return [], f"receipt schema error: {exc}"
        receipts.append(obj)
    if not receipts:
        return [], "no receipts"
    return receipts, None


def _verify_receipt_chain(receipts: List[dict], trust: Dict[str, KeyPair]) -> Optional[str]:
    seen: set[str] = set()
    for i, r in enumerate(receipts):
        rid = r["receipt_id"]
        where = f"sequence_no={r['sequence_no']}"

        if rid in seen:
            return f"duplicate receipt_id: {rid}"
        seen.add(rid)

        if r["sequence_no"] != i:
            return f"sequence gap at {where} (expected {i})"

        # Bind the id to the contents. Without this, a receipt's recorded facts
        # can be edited while its signature still verifies.
        core = {k: v for k, v in r.items() if k not in RECEIPT_CORE_EXCLUDED}
        if sha256_hex(canonicalize(core)) != rid:
            return f"{where}: contents do not match receipt_id (receipt modified after signing)"

        prev = r.get("prev_receipt_id")
        if i == 0:
            if prev not in (None, ""):
                return "genesis prev_receipt_id must be null/empty"
        elif prev != receipts[i - 1]["receipt_id"]:
            return f"{where}: prev_receipt_id mismatch"

        kp = trust.get(r["signing_key_id"])
        if kp is None:
            return f"{where}: signing_key_id is not a trust root: {r['signing_key_id']}"
        if not kp.verify_b64(rid.encode("utf-8"), r["signature_b64"]):
            return f"{where}: invalid signature"
    return None


def _verify_petitions(members: Dict[str, bytes], receipts: List[dict]) -> Optional[str]:
    if "petitions.ndjson" not in members:
        return None
    petitions: List[dict] = []
    for raw in members["petitions.ndjson"].splitlines():
        if not raw.strip():
            continue
        try:
            p = strict_json_loads(raw)
        except Exception as exc:
            return f"invalid petitions.ndjson line: {exc}"
        claimed = p.get("petition_hash")
        body = {k: v for k, v in p.items() if k not in ("petition_hash", "receipt_id")}
        actual = sha256_hex(canonicalize(body))
        if claimed != actual:
            return f"petition contents do not match petition_hash {str(claimed)[:12]}"
        petitions.append(p)
    if len(receipts) != len(petitions):
        return f"receipt/petition count mismatch: {len(receipts)} receipts, {len(petitions)} petitions"
    receipts_by_id = {receipt["receipt_id"]: receipt for receipt in receipts}
    seen_receipt_ids: set[str] = set()
    for petition in petitions:
        petition_hash = petition.get("petition_hash")
        receipt_id = petition.get("receipt_id")
        if not isinstance(petition_hash, str) or not petition_hash:
            return "missing petition_hash"
        if not isinstance(receipt_id, str) or not receipt_id or receipt_id in seen_receipt_ids:
            return f"duplicate or missing petition receipt_id {str(receipt_id)[:12]}"
        seen_receipt_ids.add(receipt_id)
        receipt = receipts_by_id.get(receipt_id)
        if receipt is None:
            return f"orphan petition receipt_id {receipt_id[:12]}"
        if receipt["petition_hash"] != petition_hash:
            return (
                f"petition for receipt {receipt_id[:12]} has hash {petition_hash[:12]}, "
                f"want {receipt['petition_hash'][:12]}"
            )
    return None


def _verify_receipt_seal(
    members: Dict[str, bytes], receipts: List[dict], trust: Dict[str, KeyPair]
) -> Optional[str]:
    if "seals.json" not in members:
        return "missing seals.json"
    try:
        seals = strict_json_loads(members["seals.json"])
    except Exception as exc:
        return f"invalid seals.json: {exc}"
    if not isinstance(seals, list) or len(seals) != 1:
        return "seals.json must contain exactly one receipt-window seal"

    seal = seals[0]
    try:
        _SEAL_VALIDATOR.validate(seal)
    except Exception as exc:
        return f"seal schema error: {exc}"

    kp = trust.get(seal["signing_key_id"])
    if kp is None:
        return f"seal signing_key_id is not a trust root: {seal['signing_key_id']}"

    seal_base = {k: v for k, v in seal.items() if k not in ("seal_id", "signature_b64")}
    if sha256_hex(canonicalize(seal_base)) != seal["seal_id"]:
        return "receipt seal id does not match its contents"
    body = {k: v for k, v in seal.items() if k != "signature_b64"}
    if not kp.verify_b64(canonicalize(body), seal["signature_b64"]):
        return "seal signature invalid"

    if seal["first_receipt_id"] != receipts[0]["receipt_id"]:
        return "seal first_receipt_id mismatch"
    if seal["last_receipt_id"] != receipts[-1]["receipt_id"]:
        return "seal last_receipt_id mismatch"

    ids: Iterable[bytes] = (bytes.fromhex(r["receipt_id"]) for r in receipts)
    if seal["merkle_root"] != merkle_root_hex(ids):
        return "seal merkle_root mismatch"

    policy_hashes = sorted({r["policy_hash"] for r in receipts if isinstance(r.get("policy_hash"), str)})
    if seal["policy_hash_set"] != policy_hashes:
        return "seal policy_hash_set mismatch"
    return None


def _canonical_signing_ids(
    members: Dict[str, bytes], receipts: List[dict], trust: Dict[str, KeyPair]
) -> Tuple[Tuple[str, ...], Optional[str]]:
    bundle_seal = strict_json_loads(members["BUNDLE_SEAL.json"])
    receipt_seals = strict_json_loads(members["seals.json"])
    claimed = [bundle_seal["signing_key_id"], receipt_seals[0]["signing_key_id"]]
    claimed.extend(receipt["signing_key_id"] for receipt in receipts)
    canonical: set[str] = set()
    for key_id in claimed:
        pair = trust.get(key_id)
        if pair is None:
            return (), f"claimed signing key is not an active trust root: {key_id}"
        canonical.add(pair.key_id())
    return tuple(sorted(canonical)), None


def verify_bundle(
    bundle_path: Path,
    *,
    expected_key_id: str | None = None,
    expected_identity_id: str | None = None,
    checkpoint: Path | None = None,
    anchor: Path | None = None,
    trust_store: Path | None = None,
    minimum_checkpoint_sequence: int | None = None,
    minimum_checkpoint_digest: str | None = None,
    require_current_status: bool = False,
) -> VerifyResult:
    checks: List[str] = []

    members, err = _read_tar_members(bundle_path)
    if err:
        return _invalid_result(err)
    checks.append("archive within size and safety limits")

    manifest_version, err = _verify_manifest(members)
    if err:
        return _invalid_result(err)
    checks.append("manifest matches member bytes under strict JSON parsing")

    if manifest_version == BPLUS_VERSION:
        from .bplus_verify import verify_bplus_bundle

        return verify_bplus_bundle(
            members,
            expected_key_id=expected_key_id,
            expected_identity_id=expected_identity_id,
            checkpoint_path=checkpoint,
            anchor_path=anchor,
            trust_store=trust_store,
            minimum_checkpoint_sequence=minimum_checkpoint_sequence,
            minimum_checkpoint_digest=minimum_checkpoint_digest,
            require_current_status=require_current_status,
        )

    trust, err = _load_trust_roots(members, allow_legacy=manifest_version == "v1")
    if err:
        return _invalid_result(err)
    checks.append(f"{len(trust)} active trust-root alias(es), revocations enforced")

    if err := _verify_bundle_seal(members, trust):
        return _invalid_result(err)
    checks.append("bundle seal verified")

    receipts, err = _parse_receipts(members)
    if err:
        return _invalid_result(err)

    if err := _verify_receipt_chain(receipts, trust):
        return _invalid_result(err)
    checks.append(f"{len(receipts)} receipt ids re-derived and signatures verified")

    if err := _verify_petitions(members, receipts):
        return _invalid_result(err)
    checks.append("strictly parsed stored requests bound to their receipts")

    if err := _verify_receipt_seal(members, receipts, trust):
        return _invalid_result(err)
    checks.append("receipt window seal verified")

    signing_key_ids, err = _canonical_signing_ids(members, receipts, trust)
    if err:
        return _invalid_result(err)
    if expected_key_id is None:
        checks.append(
            "self-contained evidence is internally consistent; signer identity was not externally anchored"
        )
        return VerifyResult(
            True,
            TRUST_INTERNALLY_CONSISTENT,
            tuple(checks),
            trust_verdict=TRUST_INTERNALLY_CONSISTENT,
            signing_key_ids=signing_key_ids,
        )
    if (
        FULL_KEY_ID.fullmatch(expected_key_id) is None
        or len(signing_key_ids) != 1
        or signing_key_ids[0] != expected_key_id
    ):
        return VerifyResult(
            False,
            f"expected signing identity {expected_key_id}, bundle was signed by {', '.join(signing_key_ids)}",
            tuple(checks),
            trust_verdict=TRUST_IDENTITY_MISMATCH,
            signing_key_ids=signing_key_ids,
            expected_key_id=expected_key_id,
        )
    checks.append("every signing key matches the externally supplied complete fingerprint")
    return VerifyResult(
        True,
        TRUST_IDENTITY_TRUSTED,
        tuple(checks),
        trust_verdict=TRUST_IDENTITY_TRUSTED,
        signing_key_ids=signing_key_ids,
        expected_key_id=expected_key_id,
    )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Verify a UEG evidence bundle offline.")
    ap.add_argument("bundle", type=Path, help="path to the .tar.gz bundle")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument(
        "--expected-key-id",
        help="externally pinned ueg:sha256:<fingerprint> required for an identity-trusted verdict",
    )
    ap.add_argument("--expected-identity-id", help="independently pinned B+ genesis identity digest")
    ap.add_argument("--checkpoint", type=Path, help="independently supplied B+ lifecycle checkpoint")
    ap.add_argument("--anchor", type=Path, help="independently retained B+ evidence anchor")
    ap.add_argument("--trust-store", type=Path, help="explicit retained B+ checkpoint directory")
    ap.add_argument("--minimum-checkpoint-sequence", type=int)
    ap.add_argument("--minimum-checkpoint-digest")
    ap.add_argument("--require-current-status", action="store_true")
    args = ap.parse_args(argv)

    if args.expected_key_id and args.expected_identity_id:
        ap.error("choose either --expected-key-id or --expected-identity-id")
    if (args.minimum_checkpoint_sequence is None) != (args.minimum_checkpoint_digest is None):
        ap.error("--minimum-checkpoint-sequence and --minimum-checkpoint-digest must be supplied together")

    res = verify_bundle(
        args.bundle,
        expected_key_id=args.expected_key_id,
        expected_identity_id=args.expected_identity_id,
        checkpoint=args.checkpoint,
        anchor=args.anchor,
        trust_store=args.trust_store,
        minimum_checkpoint_sequence=args.minimum_checkpoint_sequence,
        minimum_checkpoint_digest=args.minimum_checkpoint_digest,
        require_current_status=args.require_current_status,
    )
    if args.json:
        print(
            json.dumps(
                {
                    "ok": res.ok,
                    "reason": res.reason,
                    "trust_verdict": res.trust_verdict,
                    "expected_key_id": res.expected_key_id,
                    "signing_key_ids": list(res.signing_key_ids),
                    "checks_passed": list(res.checks),
                    "bundle_version": res.bundle_version,
                    "reason_code": res.reason_code,
                    "SIGNATURE": res.signature,
                    "BUNDLE_LEDGER_INTEGRITY": res.bundle_ledger_integrity,
                    "IDENTITY_CONTINUITY": res.identity_continuity,
                    "LIFECYCLE_CHAIN": res.lifecycle_chain,
                    "SIGNING_KEY_STATUS": res.signing_key_status,
                    "EPOCH_AUTHORIZATION": res.epoch_authorization,
                    "EVIDENCE_ANCHOR": res.evidence_anchor,
                    "CHECKPOINT_AUTHENTICITY": res.checkpoint_authenticity,
                    "CHECKPOINT_SOURCE": res.checkpoint_source,
                    "CHECKPOINT_SEQUENCE": res.checkpoint_sequence,
                    "CHECKPOINT_FRESHNESS": res.checkpoint_freshness,
                    "EVIDENCE_TIME_ASSURANCE": res.evidence_time_assurance,
                    "OVERALL_TRUST": res.overall_trust,
                    "identity_id": res.identity_id,
                    "lifecycle_sequence": res.lifecycle_sequence,
                    "lifecycle_digest": res.lifecycle_digest,
                },
                indent=2,
            )
        )
    elif res.bundle_version == BPLUS_VERSION:
        print(f"{res.overall_trust}: {res.reason}")
    elif res.ok:
        print(res.trust_verdict)
        for check in res.checks:
            print("  +", check)
    else:
        print("INVALID:", res.reason)
    if res.bundle_version == BPLUS_VERSION:
        return 0 if res.overall_trust == OVERALL_VERIFIED else 2
    return 0 if res.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())

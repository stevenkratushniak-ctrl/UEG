#!/usr/bin/env bash
# Benign disposable B+ demo. It never invokes a real destructive utility.
set -uo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ -n ${UEG:-} ]]; then
  :
elif [[ -x "$SCRIPT_DIR/../ueg" ]]; then
  UEG="$SCRIPT_DIR/../ueg"
elif [[ -x "$SCRIPT_DIR/../build/ueg" ]]; then
  UEG="$SCRIPT_DIR/../build/ueg"
else
  printf 'UEG executable not found. Run this script from an extracted UEG package or set UEG=<path>.\n' >&2
  exit 1
fi

WORK=$(mktemp -d)
HOME_DIR="$WORK/evidence"
RECOVERY="$WORK/offline/recovery.json"
PASS="disposable-demo-passphrase"
mkdir -p "$WORK/offline" "$WORK/public"
trap 'rm -rf "$WORK"' EXIT

say() { printf '\n%s\n' "$*"; }
expect() {
  local expected=$1
  shift
  printf '$'; printf ' %q' "$@"; printf '\n'
  "$@"
  local code=$?
  printf '  exit %d\n' "$code"
  if [[ $code -ne $expected ]]; then
    printf '  expected exit %d\n' "$expected" >&2
    exit 1
  fi
}

say "1. Help is inert, then identity creation is explicit."
expect 0 "$UEG" --help
printf '%s\n' "$PASS" | "$UEG" identity init \
  --home "$HOME_DIR" \
  --recovery-package "$RECOVERY" \
  --label "Disposable demo ledger" \
  --passphrase-stdin
INIT_CODE=${PIPESTATUS[1]}
printf '  exit %d\n' "$INIT_CODE"
if [[ $INIT_CODE -ne 0 ]]; then
  exit 1
fi

say "2. A harmless command runs and leaves signed evidence."
expect 0 "$UEG" run --home "$HOME_DIR" -- /usr/bin/printf 'hello from UEG\n'
expect 0 "$UEG" ledger --home "$HOME_DIR"

say "3. A harmless missing executable with a prohibited basename is refused."
expect 77 "$UEG" run --home "$HOME_DIR" -- "$WORK/intentionally-missing/format" synthetic-target

say "4. Replay verifies, re-runs, records, and compares the prior command."
expect 0 "$UEG" replay --home "$HOME_DIR"

say "5. Public trust artifacts and evidence are exported to new files."
expect 0 "$UEG" identity card --home "$HOME_DIR" --output "$WORK/public/identity-card.json"
expect 0 "$UEG" identity anchor --home "$HOME_DIR" --output "$WORK/public/evidence-anchor.json"
expect 0 "$UEG" identity checkpoint export --home "$HOME_DIR" --output "$WORK/public/checkpoint.json"
expect 0 "$UEG" export --home "$HOME_DIR" "$WORK/public/evidence.tar.gz"

IDENTITY_ID=$("$UEG" identity status --home "$HOME_DIR" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["identity_id"])')

say "6. Unpinned verification is indeterminate; independent pin plus checkpoint verifies."
expect 2 "$UEG" verify "$WORK/public/evidence.tar.gz"
expect 0 "$UEG" verify \
  --expected-identity-id "$IDENTITY_ID" \
  --checkpoint "$WORK/public/checkpoint.json" \
  "$WORK/public/evidence.tar.gz"

say "7. The separately packaged Python verifier can independently check the same evidence."
VERIFIER_ROOT=${UEG_PYTHON_VERIFIER_ROOT:-}
if [[ -z $VERIFIER_ROOT && -f "$SCRIPT_DIR/../verifier/reality_verify.py" ]]; then
  VERIFIER_ROOT="$SCRIPT_DIR/.."
fi
if [[ -n $VERIFIER_ROOT && -f "$VERIFIER_ROOT/verifier/reality_verify.py" ]]; then
  expect 0 env PYTHONPATH="$VERIFIER_ROOT${PYTHONPATH:+:$PYTHONPATH}" \
    python3 -m verifier.reality_verify \
    --expected-identity-id "$IDENTITY_ID" \
    --checkpoint "$WORK/public/checkpoint.json" \
    "$WORK/public/evidence.tar.gz"
else
  printf '%s\n' \
    "Not run: the Python verifier is a separate download." \
    "Extract ueg-python-verifier.zip, install its requirements.lock in an isolated environment," \
    "then rerun with UEG_PYTHON_VERIFIER_ROOT set to the extracted directory."
fi

say "8. A changed copy is rejected without touching the evidence home."
python3 - "$WORK/public/evidence.tar.gz" "$WORK/public/tampered.tar.gz" <<'PY'
from pathlib import Path
import sys
data = bytearray(Path(sys.argv[1]).read_bytes())
data[len(data) // 2] ^= 1
Path(sys.argv[2]).write_bytes(data)
PY
expect 2 "$UEG" verify "$WORK/public/tampered.tar.gz"

say "Disposable demo complete. The temporary identity and recovery package are removed by the script."

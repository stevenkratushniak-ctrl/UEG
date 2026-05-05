# Quick Demo

This is the shortest end-to-end demo for UEG from a source checkout.

## Windows PowerShell

Run a command and save a receipt:

```powershell
go run ./cmd/ueg --receipt .\demo-receipt.json cmd /c echo hello-from-ueg
```

Replay the receipt and verify a deterministic match:

```powershell
go run ./cmd/ueg --replay .\demo-receipt.json
```

Tamper with the receipt and prove detection:

```powershell
Copy-Item .\demo-receipt.json .\demo-receipt-tampered.json
$json = Get-Content .\demo-receipt-tampered.json -Raw | ConvertFrom-Json
$json.final_stage = 7
$json | ConvertTo-Json -Depth 100 | Set-Content .\demo-receipt-tampered.json
go run ./cmd/ueg --replay .\demo-receipt-tampered.json
```

Validate the state model:

```powershell
go run ./cmd/ueg --validate
```

Expected signals:

- successful replay prints `REPLAY: DETERMINISTIC - state paths match`
- tampered replay prints `REPLAY: RECEIPT TAMPERED (checksum mismatch)`

## Bash

Run a command and save a receipt:

```bash
go run ./cmd/ueg --receipt ./demo-receipt.json /bin/echo hello-from-ueg
```

Replay the receipt and verify a deterministic match:

```bash
go run ./cmd/ueg --replay ./demo-receipt.json
```

Tamper with the receipt and prove detection:

```bash
cp ./demo-receipt.json ./demo-receipt-tampered.json
python3 - <<'PY'
import json
from pathlib import Path
p = Path("demo-receipt-tampered.json")
data = json.loads(p.read_text())
data["final_stage"] = 7
p.write_text(json.dumps(data, indent=2) + "\n")
PY
go run ./cmd/ueg --replay ./demo-receipt-tampered.json
```

Validate the state model:

```bash
go run ./cmd/ueg --validate
```

Expected signals:

- successful replay prints `REPLAY: DETERMINISTIC - state paths match`
- tampered replay prints `REPLAY: RECEIPT TAMPERED (checksum mismatch)`

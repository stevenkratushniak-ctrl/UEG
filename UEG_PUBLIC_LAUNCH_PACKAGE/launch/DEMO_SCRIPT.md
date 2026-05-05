# Demo Script

These commands assume you are in the UEG repository root on Windows, or inside an extracted release folder on Linux/macOS after downloading the right archive.

## Windows PowerShell

Validate the state model:

```powershell
go run ./cmd/ueg --validate
```

Run a command and save a receipt:

```powershell
go run ./cmd/ueg --receipt .\demo-receipt.json cmd /c echo hello-from-ueg
```

Replay and verify `MATCH`:

```powershell
go run ./cmd/ueg --replay .\demo-receipt.json
```

Tamper with the receipt:

```powershell
Copy-Item .\demo-receipt.json .\demo-receipt-tampered.json
$json = Get-Content .\demo-receipt-tampered.json -Raw | ConvertFrom-Json
$json.final_stage = 7
$json | ConvertTo-Json -Depth 100 | Set-Content .\demo-receipt-tampered.json
```

Replay the tampered receipt and verify detection:

```powershell
go run ./cmd/ueg --replay .\demo-receipt-tampered.json
```

Expected output cues:

- successful replay prints `REPLAY: DETERMINISTIC - state paths match`
- tampered replay prints `REPLAY: RECEIPT TAMPERED (checksum mismatch)`

## Bash

Validate the state model:

```bash
./ueg --validate
```

Run a command and save a receipt:

```bash
./ueg --receipt ./demo-receipt.json /bin/echo hello-from-ueg
```

Replay and verify `MATCH`:

```bash
./ueg --replay ./demo-receipt.json
```

Tamper with the receipt:

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
```

Replay the tampered receipt and verify detection:

```bash
./ueg --replay ./demo-receipt-tampered.json
```

Expected output cues:

- successful replay prints `REPLAY: DETERMINISTIC - state paths match`
- tampered replay prints `REPLAY: RECEIPT TAMPERED (checksum mismatch)`

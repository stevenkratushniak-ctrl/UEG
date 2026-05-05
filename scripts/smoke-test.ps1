[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Push-Location $root
try {
    go test ./...
    go run ./cmd/ueg --validate
}
finally {
    Pop-Location
}

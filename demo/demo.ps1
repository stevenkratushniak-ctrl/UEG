param(
    [string]$Ueg
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Ueg)) {
    $candidates = @(
        (Join-Path $PSScriptRoot '..\ueg.exe'),
        (Join-Path $PSScriptRoot '..\build\ueg.exe'),
        (Join-Path $PSScriptRoot '..\build\ueg')
    )
    $Ueg = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $Ueg) {
        throw 'UEG executable not found. Run this script from an extracted UEG package or pass -Ueg <path>.'
    }
}
$Ueg = (Resolve-Path -LiteralPath $Ueg).Path

$work = Join-Path ([System.IO.Path]::GetTempPath()) ('ueg-bplus-demo-' + [guid]::NewGuid().ToString('N'))
$evidenceHome = Join-Path $work 'evidence'
$offline = Join-Path $work 'offline'
$public = Join-Path $work 'public'
$recovery = Join-Path $offline 'recovery.json'
$passphrase = 'disposable-demo-passphrase'
New-Item -ItemType Directory -Path $offline, $public | Out-Null

function Invoke-Ueg {
    param([int]$Expected, [string[]]$Arguments)
    Write-Host ('> ueg ' + ($Arguments -join ' '))
    & $Ueg @Arguments
    $code = $LASTEXITCODE
    Write-Host "  exit $code"
    if ($code -ne $Expected) {
        throw "Expected exit $Expected, received $code"
    }
}

try {
    Write-Host "`n1. Help is inert, then identity creation is explicit."
    Invoke-Ueg 0 @('--help')
    Write-Host 'The demo supplies a disposable recovery-package passphrase over standard input.'
    Write-Host ('> ueg identity init --home "{0}" --recovery-package "{1}" --label "Disposable demo ledger" --passphrase-stdin' -f $evidenceHome, $recovery)
    $passphrase | & $Ueg @(
        'identity', 'init', '--home', $evidenceHome,
        '--recovery-package', $recovery,
        '--label', 'Disposable demo ledger',
        '--passphrase-stdin'
    )
    $initCode = $LASTEXITCODE
    Write-Host "  exit $initCode"
    if ($initCode -ne 0) {
        throw "Expected exit 0, received $initCode"
    }

    Write-Host "`n2. A harmless command runs and leaves signed evidence."
    Invoke-Ueg 0 @('run', '--home', $evidenceHome, '--', 'whoami.exe')
    Invoke-Ueg 0 @('ledger', '--home', $evidenceHome)

    Write-Host "`n3. A harmless missing executable with a prohibited basename is refused."
    $missingFormat = Join-Path $work 'intentionally-missing\format.exe'
    Invoke-Ueg 77 @('run', '--home', $evidenceHome, '--', $missingFormat, 'synthetic-target')

    Write-Host "`n4. Replay verifies, re-runs, records, and compares the prior command."
    Invoke-Ueg 0 @('replay', '--home', $evidenceHome)

    Write-Host "`n5. Public trust artifacts and evidence are exported to new files."
    $card = Join-Path $public 'identity-card.json'
    $anchor = Join-Path $public 'evidence-anchor.json'
    $checkpoint = Join-Path $public 'checkpoint.json'
    $bundle = Join-Path $public 'evidence.tar.gz'
    Invoke-Ueg 0 @('identity', 'card', '--home', $evidenceHome, '--output', $card)
    Invoke-Ueg 0 @('identity', 'anchor', '--home', $evidenceHome, '--output', $anchor)
    Invoke-Ueg 0 @('identity', 'checkpoint', 'export', '--home', $evidenceHome, '--output', $checkpoint)
    Invoke-Ueg 0 @('export', '--home', $evidenceHome, $bundle)
    $status = (& $Ueg identity status --home $evidenceHome --json | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the initialized identity id' }

    Write-Host "`n6. Unpinned verification is indeterminate; independent pin plus checkpoint verifies."
    Invoke-Ueg 2 @('verify', $bundle)
    Invoke-Ueg 0 @(
        'verify', '--expected-identity-id', $status.identity_id,
        '--checkpoint', $checkpoint, $bundle
    )

    Write-Host "`n7. A changed copy is rejected without touching the evidence home."
    $tampered = Join-Path $public 'tampered.tar.gz'
    $bytes = [System.IO.File]::ReadAllBytes($bundle)
    $bytes[[math]::Floor($bytes.Length / 2)] = $bytes[[math]::Floor($bytes.Length / 2)] -bxor 1
    [System.IO.File]::WriteAllBytes($tampered, $bytes)
    Invoke-Ueg 2 @('verify', $tampered)

    Write-Host "`nDisposable demo complete. Its identity and recovery package will now be removed."
}
finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}

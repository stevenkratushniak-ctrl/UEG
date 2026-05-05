[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputDir) {
    $OutputDir = Join-Path $root "dist"
}
$workDir = Join-Path $root ".release-work"
$mainPath = Join-Path $root "cmd\\ueg\\main.go"
$mainSource = Get-Content $mainPath -Raw

if ($mainSource -notmatch 'const UEGVersion = "([^"]+)"') {
    throw "Unable to determine UEGVersion from $mainPath"
}

$version = $Matches[1]
$targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Ext = ".exe" },
    @{ GOOS = "linux"; GOARCH = "amd64"; Ext = "" },
    @{ GOOS = "darwin"; GOARCH = "amd64"; Ext = "" },
    @{ GOOS = "darwin"; GOARCH = "arm64"; Ext = "" }
)

Remove-Item $OutputDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $OutputDir, $workDir | Out-Null

Push-Location $root
try {
    if (-not $SkipTests) {
        go test ./...
    }

    foreach ($target in $targets) {
        $name = "ueg-v$version-$($target.GOOS)-$($target.GOARCH)"
        $stageDir = Join-Path $workDir $name
        $docsDir = Join-Path $stageDir "docs"
        $taxonomyDir = Join-Path $stageDir "taxonomy"
        New-Item -ItemType Directory -Force -Path $stageDir, $docsDir, $taxonomyDir | Out-Null

        $binaryName = "ueg$($target.Ext)"
        $binaryPath = Join-Path $stageDir $binaryName

        $env:GOOS = $target.GOOS
        $env:GOARCH = $target.GOARCH
        $env:CGO_ENABLED = "0"

        go build -trimpath -ldflags "-s -w" -o $binaryPath ./cmd/ueg

        Copy-Item README.md $stageDir
        Copy-Item docs\*.md $docsDir
        Copy-Item taxonomy\*.json $taxonomyDir

        $archivePath = Join-Path $OutputDir "$name.zip"
        Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $archivePath -Force
    }
}
finally {
    Pop-Location
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

$checksums = foreach ($file in Get-ChildItem $OutputDir -File -Filter *.zip | Sort-Object Name) {
    $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $($file.Name)"
}

Set-Content -Path (Join-Path $OutputDir "checksums.txt") -Value $checksums

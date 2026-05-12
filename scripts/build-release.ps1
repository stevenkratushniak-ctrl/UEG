[CmdletBinding()]
param(
    [string]$OutputDir = "",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputDir) {
    $OutputDir = Join-Path $root "dist"
}
$workDir = Join-Path $root ".release-work"
$mainPath = Join-Path $root "cmd\\ueg\\main.go"
$mainSource = Get-Content $mainPath -Raw
$stableZipTimestamp = [DateTimeOffset]::Parse("2024-01-01T00:00:00+00:00")

function New-DeterministicZip {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDir,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath
    )

    Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue
    $archiveStream = [System.IO.File]::Open($DestinationPath, [System.IO.FileMode]::CreateNew)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new($archiveStream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $files = Get-ChildItem $SourceDir -File -Recurse | ForEach-Object {
                $entryName = $_.FullName.Substring($SourceDir.Length).TrimStart('\').Replace('\', '/')
                [pscustomobject]@{
                    FileInfo = $_
                    EntryName = $entryName
                }
            } | Sort-Object EntryName

            foreach ($item in $files) {
                $entry = $archive.CreateEntry($item.EntryName, [System.IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $stableZipTimestamp
                $entryStream = $entry.Open()
                try {
                    $inputStream = [System.IO.File]::OpenRead($item.FileInfo.FullName)
                    try {
                        $inputStream.CopyTo($entryStream)
                    }
                    finally {
                        $inputStream.Dispose()
                    }
                }
                finally {
                    $entryStream.Dispose()
                }
            }
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $archiveStream.Dispose()
    }
}

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
        New-DeterministicZip -SourceDir $stageDir -DestinationPath $archivePath
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

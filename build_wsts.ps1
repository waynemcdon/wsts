<#
.SYNOPSIS
    Build, (optionally) sign, hash, and package the WSTS executable, then emit
    the release.json manifest consumed by the wsts.spatcyber.com landing page.

.DESCRIPTION
    Reproducible release pipeline for the Windows Security Threat Scanner.
    Steps:
      1. Build WSTS.exe from wsts.spec with PyInstaller.
      2. Authenticode-sign the binary (if a cert thumbprint is supplied).
      3. Compute the SHA-256 hash.
      4. Write release.json (version, filename, size, hash, URLs) for the site.
      5. Copy the artifact + manifest into wsts\downloads\.

.PARAMETER Version
    Release version string, e.g. 1.0.0. Default: 1.0.0

.PARAMETER CertThumbprint
    SHA-1 thumbprint of an installed Authenticode code-signing certificate.
    If omitted, signing is skipped (the binary will be unsigned).

.PARAMETER TimestampUrl
    RFC 3161 timestamp server. Default: http://timestamp.digicert.com

.EXAMPLE
    .\build_wsts.ps1 -Version 1.0.0 -CertThumbprint ABC123...

.NOTES
    Run from the wsts\ folder (the self-contained project root containing
    win_scanner_app.py and wsts.spec). Requires: Python + PyInstaller on PATH.
    signtool.exe (Windows SDK) only needed when -CertThumbprint is supplied.
#>

[CmdletBinding()]
param(
    [string]$Version = "1.0.0",
    [string]$CertThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

# ── Paths ──────────────────────────────────────────────────────────────────
$RepoRoot   = $PSScriptRoot                             # ...\wsts (self-contained)
$SpecFile   = Join-Path $PSScriptRoot "wsts.spec"
$DistDir    = Join-Path $RepoRoot "dist"
$BuiltExe   = Join-Path $DistDir "WSTS.exe"
$OutDir     = Join-Path $PSScriptRoot "downloads"
$FinalName  = "WSTS-Setup-$Version.exe"
$FinalExe   = Join-Path $OutDir $FinalName
$Manifest   = Join-Path $OutDir "release.json"

Write-Host "=== WSTS release build $Version ===" -ForegroundColor Cyan

# ── 1. Build ───────────────────────────────────────────────────────────────
Write-Host "[1/5] Building with PyInstaller..." -ForegroundColor Yellow
Push-Location $RepoRoot
try {
    pyinstaller $SpecFile --clean --noconfirm
} finally {
    Pop-Location
}
if (-not (Test-Path $BuiltExe)) {
    throw "Build failed: $BuiltExe not found."
}

# Stage output folder
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Copy-Item $BuiltExe $FinalExe -Force

# ── 2. Sign (optional but strongly recommended) ────────────────────────────
$signed = $false
if ($CertThumbprint) {
    Write-Host "[2/5] Signing with cert $CertThumbprint..." -ForegroundColor Yellow
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if (-not $signtool) {
        throw "signtool.exe not found on PATH. Install the Windows SDK or omit -CertThumbprint."
    }
    & $signtool.Source sign `
        /sha1 $CertThumbprint `
        /fd SHA256 `
        /tr $TimestampUrl `
        /td SHA256 `
        /d "WSTS - Windows Security Threat Scanner" `
        $FinalExe
    if ($LASTEXITCODE -ne 0) { throw "signtool failed with exit code $LASTEXITCODE" }

    & $signtool.Source verify /pa /v $FinalExe
    if ($LASTEXITCODE -ne 0) { throw "Signature verification failed." }
    $signed = $true
} else {
    Write-Host "[2/5] Skipping signing (no -CertThumbprint). Binary will be UNSIGNED." -ForegroundColor DarkYellow
}

# ── 3. Hash ────────────────────────────────────────────────────────────────
Write-Host "[3/5] Computing SHA-256..." -ForegroundColor Yellow
$hash = (Get-FileHash $FinalExe -Algorithm SHA256).Hash.ToLower()
$size = (Get-Item $FinalExe).Length
$sizeMb = "{0:N1} MB" -f ($size / 1MB)

# Write a sidecar .sha256 file (standard format: "<hash>  <filename>")
"$hash  $FinalName" | Out-File -FilePath "$FinalExe.sha256" -Encoding ascii -NoNewline

# ── 4. Manifest ────────────────────────────────────────────────────────────
Write-Host "[4/5] Writing release.json manifest..." -ForegroundColor Yellow
$manifestObj = [ordered]@{
    product        = "WSTS - Windows Security Threat Scanner"
    version        = $Version
    filename       = $FinalName
    filesize       = $sizeMb
    sha256         = $hash
    signed         = $signed
    download_url   = "/downloads/$FinalName"
    virustotal_url = "https://www.virustotal.com/gui/file/$hash"
    released       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}
$manifestObj | ConvertTo-Json -Depth 4 | Out-File -FilePath $Manifest -Encoding utf8

# ── 5. Summary ─────────────────────────────────────────────────────────────
Write-Host "[5/5] Done." -ForegroundColor Green
Write-Host ""
Write-Host "  Artifact : $FinalExe"
Write-Host "  Size     : $sizeMb"
Write-Host "  SHA-256  : $hash"
Write-Host "  Signed   : $signed"
Write-Host "  Manifest : $Manifest"
Write-Host "  VT link  : https://www.virustotal.com/gui/file/$hash"
Write-Host ""
Write-Host "Next: upload wsts\downloads\* to the server's /downloads/ path and" -ForegroundColor Cyan
Write-Host "      submit the binary to VirusTotal so the report link resolves." -ForegroundColor Cyan

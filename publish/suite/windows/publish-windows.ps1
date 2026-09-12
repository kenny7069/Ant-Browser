param(
  [Parameter(Mandatory = $true)][string]$PayloadRoot,
  [Parameter(Mandatory = $true)][string]$Version,
  [ValidateSet("amd64")][string]$Arch = "amd64",
  [string]$OutputRoot = (Join-Path $PSScriptRoot "dist"),
  [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$SigningCertificateSHA1,
  [Parameter(Mandatory = $true)][string]$ReleaseKeyID,
  [Parameter(Mandatory = $true)][string]$ReleasePublicKey,
  [string]$TimestampURL = "http://timestamp.digicert.com",
  [switch]$KeepStaging
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Fail([string]$Message) { throw "Suite publish preflight: $Message" }
function Require-Leaf([string]$Path, [string]$Label) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "$Label is missing" }
}
function Require-Tool([string]$Name) {
  $tool = Get-Command $Name -ErrorAction SilentlyContinue
  if (-not $tool) { Fail "$Name is required" }
  return $tool.Source
}
function Assert-Authenticode([string]$Path) {
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    Fail "Authenticode signature is not valid: $Path"
  }
}
function Resolve-PayloadPath([string]$RelativePath) {
  if ($RelativePath -notmatch '^[A-Za-z0-9][A-Za-z0-9._+/-]*$' -or $RelativePath.Contains("\") -or $RelativePath.Contains("..")) {
    Fail "manifest contains a non-portable path"
  }
  $candidate = [System.IO.Path]::GetFullPath((Join-Path $PayloadRoot ($RelativePath.Replace('/', [System.IO.Path]::DirectorySeparatorChar))))
  $root = [System.IO.Path]::GetFullPath($PayloadRoot).TrimEnd('\') + '\'
  if (-not $candidate.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { Fail "manifest path escapes payload root" }
  return $candidate
}

if ($Version -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$') { Fail "Version is not release SemVer" }
$PayloadRoot = [System.IO.Path]::GetFullPath($PayloadRoot)
if (-not (Test-Path -LiteralPath $PayloadRoot -PathType Container)) { Fail "payload root is missing" }
$makeNSIS = Require-Tool "makensis.exe"
$signTool = Require-Tool "signtool.exe"

$required = @(
  "Ant Browser.exe",
  "ant-farm-client.exe",
  "runtime/xray.exe",
  "runtime/sing-box.exe",
  "release-manifest.json",
  "release-manifest.envelope.json",
  "LICENSES.json"
)
foreach ($relative in $required) { Require-Leaf (Resolve-PayloadPath $relative) $relative }

$manifestPath = Resolve-PayloadPath "release-manifest.json"
$envelopePath = Resolve-PayloadPath "release-manifest.envelope.json"
$manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$envelope = Get-Content -LiteralPath $envelopePath -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.version -ne $Version -or $manifest.target.os -ne "windows" -or $manifest.target.arch -ne $Arch) { Fail "release manifest identity mismatch" }
$manifestDigest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($envelope.schema_version -ne 1 -or $envelope.algorithm -ne "Ed25519" -or $envelope.manifest_sha256 -cne $manifestDigest -or
    [string]::IsNullOrWhiteSpace($envelope.key_id) -or [string]::IsNullOrWhiteSpace($envelope.signature)) {
  Fail "detached release envelope is missing or does not bind the manifest"
}

$seen = @{}
foreach ($entry in $manifest.entries) {
  $path = Resolve-PayloadPath ([string]$entry.path)
  $key = ([string]$entry.path).ToLowerInvariant()
  if ($seen.ContainsKey($key)) { Fail "manifest contains a case-fold path collision" }
  $seen[$key] = $true
  Require-Leaf $path ([string]$entry.path)
  $item = Get-Item -LiteralPath $path
  if ($item.Length -ne [int64]$entry.size) { Fail "size mismatch: $($entry.path)" }
  $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($digest -cne [string]$entry.sha256) { Fail "SHA256 mismatch: $($entry.path)" }
}
foreach ($relative in @("Ant Browser.exe", "ant-farm-client.exe", "runtime/xray.exe", "runtime/sing-box.exe")) {
  if (-not $seen.ContainsKey($relative.ToLowerInvariant())) { Fail "manifest does not cover $relative" }
  Assert-Authenticode (Resolve-PayloadPath $relative)
}
if (-not $seen.ContainsKey("licenses.json")) { Fail "manifest does not cover LICENSES.json" }
& (Resolve-PayloadPath "ant-farm-client.exe") suite verify-release `
  -manifest $manifestPath -envelope $envelopePath -key-id $ReleaseKeyID -public-key $ReleasePublicKey | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "Ed25519 release envelope verification failed" }

$licenses = Get-Content -LiteralPath (Resolve-PayloadPath "LICENSES.json") -Raw | ConvertFrom-Json
if ($licenses.schema_version -ne 1 -or @($licenses.artifacts).Count -lt 3) { Fail "license manifest is invalid" }
foreach ($license in $licenses.artifacts) {
  if ([string]::IsNullOrWhiteSpace($license.name) -or [string]::IsNullOrWhiteSpace($license.license_expression)) { Fail "license entry is incomplete" }
  Require-Leaf (Resolve-PayloadPath ([string]$license.notice_file)) ([string]$license.notice_file)
  if (-not $seen.ContainsKey(([string]$license.notice_file).ToLowerInvariant())) { Fail "manifest does not cover license notice $($license.notice_file)" }
}
$canonicalLicenses = Join-Path (Split-Path $PSScriptRoot -Parent) "LICENSES.json"
if ((Get-FileHash -LiteralPath $canonicalLicenses -Algorithm SHA256).Hash -cne (Get-FileHash -LiteralPath (Resolve-PayloadPath "LICENSES.json") -Algorithm SHA256).Hash) {
  Fail "payload license manifest differs from the Suite contract"
}
$allowed = @{}
foreach ($key in $seen.Keys) { $allowed[$key] = $true }
foreach ($relative in @("release-manifest.json", "release-manifest.envelope.json")) { $allowed[$relative.ToLowerInvariant()] = $true }
foreach ($file in Get-ChildItem -LiteralPath $PayloadRoot -File -Recurse) {
  $relative = $file.FullName.Substring($PayloadRoot.TrimEnd('\').Length + 1).Replace('\', '/')
  if (-not $allowed.ContainsKey($relative.ToLowerInvariant())) { Fail "payload contains an unexpected or uncovered file: $relative" }
}

$stage = Join-Path $PSScriptRoot ".staging\windows-$Arch-$Version"
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage, $OutputRoot -Force | Out-Null
foreach ($relative in $allowed.Keys) {
  $source = Resolve-PayloadPath $relative
  $destination = Join-Path $stage ($relative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
  New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
  Copy-Item -LiteralPath $source -Destination $destination
}

& $makeNSIS "/DVERSION=$Version" "/DSTAGINGDIR=$stage" "/DOUTPUTDIR=$OutputRoot" (Join-Path $PSScriptRoot "installer.nsi")
if ($LASTEXITCODE -ne 0) { throw "NSIS build failed" }
$installer = Join-Path $OutputRoot "AntBrowserSuite-Setup-$Version-windows-x64.exe"
Require-Leaf $installer "Suite installer"
& $signTool sign /sha1 $SigningCertificateSHA1 /fd SHA256 /tr $TimestampURL /td SHA256 $installer
if ($LASTEXITCODE -ne 0) { throw "Suite installer signing failed" }
Assert-Authenticode $installer
if (-not $KeepStaging) { Remove-Item -LiteralPath $stage -Recurse -Force }
Write-Host "Generated $installer"

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
$versionWithoutBuild = $Version.Split('+')[0]
$prereleaseSeparator = $versionWithoutBuild.IndexOf('-')
if ($prereleaseSeparator -ge 0) {
  foreach ($identifier in $versionWithoutBuild.Substring($prereleaseSeparator + 1).Split('.')) {
    if ($identifier.Length -gt 1 -and $identifier.StartsWith('0') -and $identifier -match '^[0-9]+$') {
      Fail "Version has a numeric prerelease identifier with a leading zero"
    }
  }
}
$PayloadRoot = [System.IO.Path]::GetFullPath($PayloadRoot)
if (-not (Test-Path -LiteralPath $PayloadRoot -PathType Container)) { Fail "payload root is missing" }
$makeNSIS = Require-Tool "makensis.exe"
$signTool = Require-Tool "signtool.exe"

$required = @(
  "AntBrowser.exe",
  "ant-farm-client.exe",
  "runtime/xray.exe",
  "runtime/sing-box.exe",
  "runtime/chrome/chrome.exe",
  "release-manifest.json",
  "release-manifest.envelope.json",
  "LICENSES.json"
)
foreach ($relative in $required) { Require-Leaf (Resolve-PayloadPath $relative) $relative }

$manifestPath = Resolve-PayloadPath "release-manifest.json"
$envelopePath = Resolve-PayloadPath "release-manifest.envelope.json"
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
  $seen[$key] = [string]$entry.path
  Require-Leaf $path ([string]$entry.path)
  $item = Get-Item -LiteralPath $path
  if ($item.Length -ne [int64]$entry.size) { Fail "size mismatch: $($entry.path)" }
  $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($digest -cne [string]$entry.sha256) { Fail "SHA256 mismatch: $($entry.path)" }
  if ([bool]$entry.executable) { Assert-Authenticode $path }
}
foreach ($relative in @("AntBrowser.exe", "ant-farm-client.exe", "runtime/xray.exe", "runtime/sing-box.exe", "runtime/chrome/chrome.exe")) {
  if (-not $seen.ContainsKey($relative.ToLowerInvariant())) { Fail "manifest does not cover $relative" }
}
if (-not $seen.ContainsKey("licenses.json")) { Fail "manifest does not cover LICENSES.json" }
& (Resolve-PayloadPath "ant-farm-client.exe") suite verify-release `
  -manifest $manifestPath -envelope $envelopePath -key-id $ReleaseKeyID -public-key $ReleasePublicKey | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "Ed25519 release envelope verification failed" }
& (Resolve-PayloadPath "ant-farm-client.exe") suite verify-release-embedded `
  -manifest $manifestPath -envelope $envelopePath | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "embedded Farm Client release trust anchor verification failed" }

$licenses = Get-Content -LiteralPath (Resolve-PayloadPath "LICENSES.json") -Raw | ConvertFrom-Json
$dependencies = @($manifest.dependencies)
$artifacts = @($licenses.artifacts)
if ($licenses.schema_version -ne 1 -or $artifacts.Count -eq 0 -or $artifacts.Count -ne $dependencies.Count) { Fail "license manifest is invalid" }
$contractPath = Join-Path (Split-Path $PSScriptRoot -Parent) "LICENSES.json"
$contract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json
$allowedArtifacts = @($contract.allowed_artifacts)
if ($contract.schema_version -ne 1 -or $allowedArtifacts.Count -ne $artifacts.Count) { Fail "license policy contract is invalid" }
$productLicense = $licenses.product_license
$productLicensePolicy = $contract.product_license
if ([string]::IsNullOrWhiteSpace($productLicense.name) -or [string]::IsNullOrWhiteSpace($productLicense.license_expression) -or
    [string]::IsNullOrWhiteSpace($productLicense.notice_file) -or
    ([string]$productLicense.name) -cne ([string]$productLicensePolicy.name) -or
    ([string]$productLicense.license_expression) -cne ([string]$productLicensePolicy.license_expression) -or
    ([string]$productLicense.notice_file) -cne ([string]$productLicensePolicy.notice_file)) {
  Fail "product license does not match the version-agnostic policy contract"
}
Require-Leaf (Resolve-PayloadPath ([string]$productLicense.notice_file)) ([string]$productLicense.notice_file)
if (-not $seen.ContainsKey(([string]$productLicense.notice_file).ToLowerInvariant())) { Fail "manifest does not cover the product license notice" }
$productLegalEntries = @($manifest.entries | Where-Object { ([string]$_.path) -ceq ([string]$productLicense.notice_file) -and ([string]$_.role) -ceq "legal" })
if ($productLegalEntries.Count -ne 1) { Fail "product license notice is not an exact signed legal entry" }
foreach ($license in $licenses.artifacts) {
  if ([string]::IsNullOrWhiteSpace($license.name) -or [string]::IsNullOrWhiteSpace($license.version) -or
      [string]::IsNullOrWhiteSpace($license.license_expression) -or [string]::IsNullOrWhiteSpace($license.notice_file)) {
    Fail "license entry is incomplete"
  }
  Require-Leaf (Resolve-PayloadPath ([string]$license.notice_file)) ([string]$license.notice_file)
  if (-not $seen.ContainsKey(([string]$license.notice_file).ToLowerInvariant())) { Fail "manifest does not cover license notice $($license.notice_file)" }
  $legalEntries = @($manifest.entries | Where-Object { ([string]$_.path) -ceq ([string]$license.notice_file) -and ([string]$_.role) -ceq "legal" })
  if ($legalEntries.Count -ne 1) { Fail "license notice is not an exact signed legal entry" }
  $matchingDependencies = @($dependencies | Where-Object {
    ([string]$_.name) -ceq ([string]$license.name) -and ([string]$_.version) -ceq ([string]$license.version) -and
    ([string]$_.license_ref) -ceq ([string]$license.notice_file)
  })
  if ($matchingDependencies.Count -ne 1) { Fail "license artifact does not exactly match a signed dependency" }
  $matchingPolicy = @($allowedArtifacts | Where-Object {
    ([string]$_.name) -ceq ([string]$license.name) -and
    ([string]$_.license_expression) -ceq ([string]$license.license_expression) -and
    ([string]$_.notice_file) -ceq ([string]$license.notice_file)
  })
  if ($matchingPolicy.Count -ne 1) { Fail "license artifact is outside the version-agnostic policy contract" }
}
foreach ($dependency in $dependencies) {
  $matchingArtifacts = @($artifacts | Where-Object {
    ([string]$_.name) -ceq ([string]$dependency.name) -and ([string]$_.version) -ceq ([string]$dependency.version) -and
    ([string]$_.notice_file) -ceq ([string]$dependency.license_ref)
  })
  if ($matchingArtifacts.Count -ne 1) { Fail "signed dependency does not have one exact license artifact" }
}
foreach ($allowedArtifact in $allowedArtifacts) {
  $matchingArtifacts = @($artifacts | Where-Object {
    ([string]$_.name) -ceq ([string]$allowedArtifact.name) -and
    ([string]$_.license_expression) -ceq ([string]$allowedArtifact.license_expression) -and
    ([string]$_.notice_file) -ceq ([string]$allowedArtifact.notice_file)
  })
  if ($matchingArtifacts.Count -ne 1) { Fail "license policy artifact is missing from the payload" }
}
$allowed = @{}
foreach ($key in $seen.Keys) { $allowed[$key] = [string]$seen[$key] }
foreach ($relative in @("release-manifest.json", "release-manifest.envelope.json")) { $allowed[$relative.ToLowerInvariant()] = $relative }
foreach ($file in Get-ChildItem -LiteralPath $PayloadRoot -File -Recurse) {
  $relative = $file.FullName.Substring($PayloadRoot.TrimEnd('\').Length + 1).Replace('\', '/')
  $key = $relative.ToLowerInvariant()
  if (-not $allowed.ContainsKey($key)) { Fail "payload contains an unexpected or uncovered file: $relative" }
  if ($relative -cne [string]$allowed[$key]) { Fail "payload path casing differs from its signed canonical path: $relative" }
}

$stage = Join-Path $PSScriptRoot ".staging\windows-$Arch-$Version"
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage, $OutputRoot -Force | Out-Null
foreach ($key in $allowed.Keys) {
  $relative = [string]$allowed[$key]
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

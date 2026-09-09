param(
  [Parameter(Mandatory = $true)][ValidateSet("amd64")][string]$Arch,
  [string]$Version = "1.5.0",
  [switch]$SkipBuild,
  [switch]$SkipRuntimeVerify,
  [switch]$KeepStaging
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$Output = Join-Path $PSScriptRoot "dist"
$Stage = Join-Path $PSScriptRoot ".staging\windows-$Arch"
$Binary = Join-Path $Stage "ant-farm-client.exe"

if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$') { throw "Invalid package version" }
if (-not $SkipRuntimeVerify) {
  & bash (Join-Path $Root "tools/runtime/verify-runtime.sh") "windows-$Arch"
  if ($LASTEXITCODE -ne 0) { throw "Runtime verification failed" }
}
if (Test-Path $Stage) { Remove-Item -LiteralPath $Stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $Stage "bin"), $Output | Out-Null

if (-not $SkipBuild) {
  Push-Location $Root
  try {
    $env:GOOS = "windows"; $env:GOARCH = $Arch; $env:CGO_ENABLED = "0"
    & go build -trimpath -ldflags "-s -w -X ant-chrome/backend.FarmClientVersion=$Version" -o $Binary ./backend/cmd/ant-farm-client
    if ($LASTEXITCODE -ne 0) { throw "Go build failed" }
  } finally { Pop-Location }
}
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { throw "Farm Client binary missing" }
Copy-Item -LiteralPath (Join-Path $Root "bin\xray.exe") -Destination (Join-Path $Stage "bin\xray.exe")
Copy-Item -LiteralPath (Join-Path $Root "bin\sing-box.exe") -Destination (Join-Path $Stage "bin\sing-box.exe")
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "config.example.yaml") -Destination (Join-Path $Stage "config.example.yaml")
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "README.md") -Destination (Join-Path $Stage "README.md")

$Zip = Join-Path $Output "AntFarmClient-$Version-windows-x64.zip"
if (Test-Path $Zip) { Remove-Item -LiteralPath $Zip -Force }
Compress-Archive -Path (Join-Path $Stage "*") -DestinationPath $Zip -CompressionLevel Optimal

$MakeNSIS = (Get-Command makensis.exe -ErrorAction SilentlyContinue)
if (-not $MakeNSIS) { throw "makensis.exe is required" }
& $MakeNSIS.Source "/DVERSION=$Version" "/DSTAGINGDIR=$Stage" "/DOUTPUTDIR=$Output" (Join-Path $PSScriptRoot "installer.nsi")
if ($LASTEXITCODE -ne 0) { throw "NSIS build failed" }
if (-not $KeepStaging) { Remove-Item -LiteralPath $Stage -Recurse -Force }
Write-Host "Generated $Zip and AntFarmClient-Setup-$Version-x64.exe"

param(
    [Parameter(Mandatory = $true)]
    [string]$AlternateUsername,

    [string]$AlternateDomain = ".",

    [switch]$SkipRace
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "This acceptance runner requires a real Windows host."
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go is not available on PATH."
}

$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$SharedParent = Join-Path ([IO.Path]::GetTempPath()) ("bf-p1-dacl-shared-" + [guid]::NewGuid().ToString("N"))
$ProbePath = Join-Path $SharedParent "bf-p1-public-probe.txt"
$OwnerPrincipal = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$AlternatePrincipal = if ($AlternateDomain -eq ".") {
    "$env:COMPUTERNAME\$AlternateUsername"
} else {
    "$AlternateDomain\$AlternateUsername"
}

$PasswordBSTR = [IntPtr]::Zero
$PasswordWasProvided = -not [string]::IsNullOrEmpty($env:BF_P1_WINDOWS_DACL_ALT_PASSWORD)

try {
    New-Item -ItemType Directory -Path $SharedParent | Out-Null
    & icacls.exe $SharedParent /inheritance:r /grant:r "${OwnerPrincipal}:(OI)(CI)F" "${AlternatePrincipal}:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to configure the shared-parent DACL."
    }

    [IO.File]::WriteAllText($ProbePath, "BF-P1-WINDOWS-DACL-PUBLIC-PROBE`n", [Text.UTF8Encoding]::new($false))
    & icacls.exe $ProbePath /inheritance:r /grant:r "${OwnerPrincipal}:F" "${AlternatePrincipal}:R" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to configure the positive-control probe DACL."
    }

    if (-not $PasswordWasProvided) {
        $SecurePassword = Read-Host "Password for $AlternatePrincipal" -AsSecureString
        $PasswordBSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $env:BF_P1_WINDOWS_DACL_ALT_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($PasswordBSTR)
    }
    $env:BF_P1_WINDOWS_DACL_E2E = "1"
    $env:BF_P1_WINDOWS_DACL_SHARED_PARENT = $SharedParent
    $env:BF_P1_WINDOWS_DACL_ALT_USERNAME = $AlternateUsername
    $env:BF_P1_WINDOWS_DACL_ALT_DOMAIN = $AlternateDomain

    Push-Location $RepositoryRoot
    try {
        & go test ./backend/internal/proxy -run '^TestSecureRuntimeWindowsDACLE2E$' -count=1 -v
        if ($LASTEXITCODE -ne 0) {
            throw "Windows DACL acceptance test failed."
        }
        if (-not $SkipRace) {
            & go test -race ./backend/internal/proxy -run '^TestSecureRuntimeWindowsDACLE2E$' -count=1 -v
            if ($LASTEXITCODE -ne 0) {
                throw "Windows DACL race acceptance test failed."
            }
        }
    } finally {
        Pop-Location
    }
} finally {
    Remove-Item Env:BF_P1_WINDOWS_DACL_E2E -ErrorAction SilentlyContinue
    Remove-Item Env:BF_P1_WINDOWS_DACL_SHARED_PARENT -ErrorAction SilentlyContinue
    Remove-Item Env:BF_P1_WINDOWS_DACL_ALT_USERNAME -ErrorAction SilentlyContinue
    Remove-Item Env:BF_P1_WINDOWS_DACL_ALT_DOMAIN -ErrorAction SilentlyContinue
    Remove-Item Env:BF_P1_WINDOWS_DACL_ALT_PASSWORD -ErrorAction SilentlyContinue
    if ($PasswordBSTR -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordBSTR)
    }
    if (Test-Path -LiteralPath $SharedParent) {
        Remove-Item -LiteralPath $SharedParent -Recurse -Force
    }
}

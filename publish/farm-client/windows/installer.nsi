Unicode True

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef STAGINGDIR
  !error "STAGINGDIR is required"
!endif
!ifndef OUTPUTDIR
  !error "OUTPUTDIR is required"
!endif

!define PRODUCT_NAME "Ant Farm Client"
!define PRODUCT_EXE "ant-farm-client.exe"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntFarmClient"
!define INSTALL_DIR "$PROGRAMFILES64\Ant Farm Client"
!define STATE_DIR "$LOCALAPPDATA\AntFarmClient"
!define POWERSHELL_EXE "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"

!include "MUI2.nsh"
!include "LogicLib.nsh"

!macro WriteOwnedProcessScript HANDLE
  FileWrite ${HANDLE} "param([string]$$ExactExecutable)$\r$\n"
  FileWrite ${HANDLE} "$$ErrorActionPreference = 'Stop'$\r$\n"
  FileWrite ${HANDLE} "if ([string]::IsNullOrWhiteSpace($$ExactExecutable)) { exit 2 }$\r$\n"
  FileWrite ${HANDLE} "$$target = [System.IO.Path]::GetFullPath($$ExactExecutable)$\r$\n"
  FileWrite ${HANDLE} "$$deadline = (Get-Date).AddSeconds(30)$\r$\n"
  FileWrite ${HANDLE} "do {$\r$\n"
  FileWrite ${HANDLE} "  $$owned = @(Get-CimInstance Win32_Process | Where-Object { $$_.ExecutablePath -and [System.IO.Path]::GetFullPath($$_.ExecutablePath).Equals($$target, [System.StringComparison]::OrdinalIgnoreCase) })$\r$\n"
  FileWrite ${HANDLE} "  if ($$owned.Count -eq 0) { exit 0 }$\r$\n"
  FileWrite ${HANDLE} "  foreach ($$process in $$owned) { try { Stop-Process -Id $$process.ProcessId -ErrorAction Stop } catch {} }$\r$\n"
  FileWrite ${HANDLE} "  Start-Sleep -Milliseconds 500$\r$\n"
  FileWrite ${HANDLE} "} while ((Get-Date) -lt $$deadline)$\r$\n"
  FileWrite ${HANDLE} "exit 1$\r$\n"
!macroend

Function CloseOwnedClient
  IfFileExists "$INSTDIR\${PRODUCT_EXE}" 0 done
  IfFileExists "${POWERSHELL_EXE}" 0 unavailable
  GetTempFileName $0
  Delete $0
  StrCpy $0 "$0.ps1"
  FileOpen $1 $0 w
  !insertmacro WriteOwnedProcessScript $1
  FileClose $1
  ExecWait '"${POWERSHELL_EXE}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$0" -ExactExecutable "$INSTDIR\${PRODUCT_EXE}"' $2
  Delete $0
  ${If} $2 != 0
    Abort "Ant Farm Client did not exit cleanly; installation was not changed."
  ${EndIf}
  Goto done
unavailable:
  Abort "PowerShell is required for ownership-scoped shutdown; global taskkill fallback is prohibited."
done:
FunctionEnd

Function un.CloseOwnedClient
  IfFileExists "$INSTDIR\${PRODUCT_EXE}" 0 done
  IfFileExists "${POWERSHELL_EXE}" 0 unavailable
  IfFileExists "${STATE_DIR}\client.yaml" 0 +2
    ExecWait '"$INSTDIR\${PRODUCT_EXE}" -config "${STATE_DIR}\client.yaml" autostart remove'
  GetTempFileName $0
  Delete $0
  StrCpy $0 "$0.ps1"
  FileOpen $1 $0 w
  !insertmacro WriteOwnedProcessScript $1
  FileClose $1
  ExecWait '"${POWERSHELL_EXE}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$0" -ExactExecutable "$INSTDIR\${PRODUCT_EXE}"' $2
  Delete $0
  ${If} $2 != 0
    Abort "Ant Farm Client did not exit cleanly; uninstall was cancelled."
  ${EndIf}
  Goto done
unavailable:
  Abort "PowerShell is required for ownership-scoped shutdown; global taskkill fallback is prohibited."
done:
FunctionEnd

Name "${PRODUCT_NAME} ${VERSION}"
OutFile "${OUTPUTDIR}\AntFarmClient-Setup-${VERSION}-x64.exe"
InstallDir "${INSTALL_DIR}"
InstallDirRegKey HKLM "${UNINSTALL_KEY}" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Ant Farm Client" SecMain
  SectionIn RO
  Call CloseOwnedClient
  SetOutPath "$INSTDIR"
  File "${STAGINGDIR}\${PRODUCT_EXE}"
  File "${STAGINGDIR}\config.example.yaml"
  File "${STAGINGDIR}\README.md"
  SetOutPath "$INSTDIR\bin"
  File "${STAGINGDIR}\bin\xray.exe"
  File "${STAGINGDIR}\bin\sing-box.exe"
  SetOutPath "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "Ant Chrome Team"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
  WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
  Call un.CloseOwnedClient
  Delete /REBOOTOK "$INSTDIR\${PRODUCT_EXE}"
  Delete /REBOOTOK "$INSTDIR\config.example.yaml"
  Delete /REBOOTOK "$INSTDIR\README.md"
  Delete /REBOOTOK "$INSTDIR\bin\xray.exe"
  Delete /REBOOTOK "$INSTDIR\bin\sing-box.exe"
  RMDir "$INSTDIR\bin"
  Delete /REBOOTOK "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  ; Per-user state and Ant browser profiles are intentionally preserved.
SectionEnd

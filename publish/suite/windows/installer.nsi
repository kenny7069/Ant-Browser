Unicode True

!ifndef VERSION
  !error "VERSION is required"
!endif
!ifndef STAGINGDIR
  !error "STAGINGDIR is required"
!endif
!ifndef OUTPUTDIR
  !error "OUTPUTDIR is required"
!endif

!define PRODUCT_NAME "Ant Browser Suite"
!define INSTALL_BASE "$PROGRAMFILES64\Ant Browser Suite"
!define VERSION_DIR "${INSTALL_BASE}\versions\${VERSION}"
!define USER_ROOT "$LOCALAPPDATA\AntSuite"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\AntBrowserSuite"

!include "MUI2.nsh"
!include "LogicLib.nsh"

Name "${PRODUCT_NAME} ${VERSION}"
OutFile "${OUTPUTDIR}\AntBrowserSuite-Setup-${VERSION}-windows-x64.exe"
InstallDir "${INSTALL_BASE}"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Ant Browser Suite" SecMain
  SectionIn RO
  SetOutPath "${VERSION_DIR}"
  File /r "${STAGINGDIR}\*"

  ; Mutable roots are created once and are never populated or overwritten by
  ; an upgrade. Setup/finalize applies the current-user-only ACL before use.
  CreateDirectory "${USER_ROOT}\config"
  CreateDirectory "${USER_ROOT}\browser-data"
  CreateDirectory "${USER_ROOT}\agent-state"
  CreateDirectory "${USER_ROOT}\logs"

  ; The launcher reads durable ownership-handoff.json and always supplies the
  ; absolute --farm-client-config argument. No socket/env discovery is used.
  CreateShortcut "$DESKTOP\Ant Browser Suite.lnk" "${VERSION_DIR}\ant-farm-client.exe" "suite launch-gui"

  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "${VERSION_DIR}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" "${VERSION_DIR}\Uninstall.exe"
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteUninstaller "${VERSION_DIR}\Uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$DESKTOP\Ant Browser Suite.lnk"
  ; Only this immutable version is removed. Per-user config, identity, setup,
  ; browser profiles and handoff state are deliberately retained for repair.
  RMDir /r "${VERSION_DIR}"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
SectionEnd

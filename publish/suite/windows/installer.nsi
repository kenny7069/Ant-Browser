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
!insertmacro MUI_LANGUAGE "English"

Section "Ant Browser Suite" SecMain
  SectionIn RO
  IfFileExists "${VERSION_DIR}\*.*" 0 install_new_version
    Abort "This immutable Suite version is already installed"
  install_new_version:
  SetOutPath "${VERSION_DIR}"
  File /r "${STAGINGDIR}\*"
SectionEnd

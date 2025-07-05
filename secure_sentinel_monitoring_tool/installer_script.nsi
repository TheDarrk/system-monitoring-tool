; Secure Sentinel Installer
!include "MUI2.nsh"

; --- Basic Settings ---
Name "Secure Sentinel"
OutFile "SecureSentinel_Setup.exe"
InstallDir "$PROGRAMFILES\Secure Sentinel"
RequestExecutionLevel admin

; --- Modern UI Configuration ---
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

; --- Installation Section ---
Section "Main Application"
  ; Set output path
  SetOutPath "$INSTDIR"
  
  ; Include all files from build directory
  File /r "..\build\exe.win-amd64-3.10\*.*"
  
  ; Create shortcuts
  CreateShortcut "$DESKTOP\Secure Sentinel.lnk" "$INSTDIR\SecureSentinel.exe"
  CreateShortcut "$SMPROGRAMS\Secure Sentinel.lnk" "$INSTDIR\SecureSentinel.exe"
  
  ; Add uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

; --- Uninstaller Section ---
Section "Uninstall"
  ; Remove files
  Delete "$INSTDIR\*.*"
  RMDir /r "$INSTDIR"
  
  ; Remove shortcuts
  Delete "$DESKTOP\Secure Sentinel.lnk"
  Delete "$SMPROGRAMS\Secure Sentinel.lnk"
  
  ; Remove uninstaller
  Delete "$INSTDIR\Uninstall.exe"
SectionEnd
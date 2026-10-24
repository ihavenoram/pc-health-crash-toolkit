@echo off
rem PC Health and Crash Toolkit - launcher for System_Health_Extras_Check.ps1
rem Asks for administrator rights (UAC) unless already elevated or SYSTEM. /noelevate skips the prompt.
rem Waits for a key at the end so the output stays on screen. /nopause skips that.
setlocal
set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "L_ARGS= %* "
set "L_PAUSE=1"
set "L_ASK=1"
echo.%L_ARGS%| find /i " /nopause " >nul && set "L_PAUSE="
echo.%L_ARGS%| find /i " /noelevate " >nul && set "L_ASK="
echo.%L_ARGS%| find /i " /elevated " >nul && set "L_ASK="
set "L_ARGS=%L_ARGS: /noelevate=%"
set "L_ARGS=%L_ARGS: /elevated=%"
set "L_ARGS=%L_ARGS: /nopause=%"
if not defined L_ASK goto run
net session >nul 2>&1
if not errorlevel 1 goto run
set "L_SELF=%~f0"
set "L_FWD=%L_ARGS%"
if not defined L_PAUSE set "L_FWD=%L_ARGS%/nopause "
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath $env:L_SELF -ArgumentList ('/elevated' + $env:L_FWD) -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"
if not errorlevel 1 exit /b 0
echo Elevation was declined or failed - running without administrator rights, so some checks will be limited.
:run
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0System_Health_Extras_Check.ps1"%L_ARGS%
set "L_RC=%errorlevel%"
if defined L_PAUSE (echo. & pause)
endlocal & exit /b %L_RC%

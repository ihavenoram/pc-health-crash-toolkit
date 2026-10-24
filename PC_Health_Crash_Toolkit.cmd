@echo off
rem PC Health and Crash Toolkit - opens the GUI without a console window.
rem The script stages itself to C:\ProgramData\PCHealthToolkit and asks for elevation (UAC).
start "" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0PC_Health_Crash_Toolkit.ps1"

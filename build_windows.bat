@echo off
rem Double-click to build the Windows app.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_windows.ps1"
pause

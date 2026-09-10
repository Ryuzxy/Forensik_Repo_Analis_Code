@echo off
title Forensik Repo Analyzer
cd /d "%~dp0"

set "GOCACHE=%~dp0.gocache"

if not exist "%~dp0forensic_analyzer.exe" (
    echo [*] Mengompilasi forensic_analyzer.exe...
    go build -o "%~dp0forensic_analyzer.exe" "%~dp0main.go"
)

if "%~1"=="" (
    echo [*] Memindai seluruh artefak di folder Bin/, File_ISO/, dan MemDump/...
    "%~dp0forensic_analyzer.exe" -all -out reports
) else (
    echo [*] Menganalisis target: %1
    "%~dp0forensic_analyzer.exe" -file "%~1" -out reports
)

echo.
echo [✓] Pemindaian selesai. Laporan tersimpan di folder 'reports/'.
pause

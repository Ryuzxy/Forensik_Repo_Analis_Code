<#
.SYNOPSIS
    Forensic Repo Analyzer Launcher
.DESCRIPTION
    Script praktis untuk menjalankan analisis forensik pada folder Bin, File_ISO, MemDump, Hex, dan Heap.
#>

param (
    [string]$Mode = "all",      # "all", "bin", "iso", "mem", "hex", "heap", atau file path
    [string]$File = "",
    [string]$Hex = "",          # string kode hex mentah
    [string]$OutputDir = "reports"
)

$Host.UI.RawUI.WindowTitle = "Forensik Repo Analyzer"
$ErrorActionPreference = "Stop"

# Set GOCACHE lokal agar terhindar dari conflict cache sistem
$env:GOCACHE = "$PSScriptRoot\.gocache"

$exePath = "$PSScriptRoot\forensic_analyzer.exe"

# Recompile jika exe belum ada
if (-not (Test-Path $exePath)) {
    Write-Host "[*] Mengompilasi forensic_analyzer.exe..." -ForegroundColor Cyan
    go build -o $exePath "$PSScriptRoot\main.go"
}

if ($Hex -ne "") {
    Write-Host "[*] Menganalisis string kode hex..." -ForegroundColor Green
    & $exePath -hex $Hex -out $OutputDir
} elseif ($File -ne "") {
    Write-Host "[*] Menganalisis file spesifik: $File" -ForegroundColor Green
    & $exePath -file $File -out $OutputDir
} elseif ($Mode -eq "all") {
    Write-Host "[*] Memindai seluruh artefak di folder Bin/, File_ISO/, MemDump/, Hex/, dan Heap/..." -ForegroundColor Green
    & $exePath -all -out $OutputDir
} else {
    Write-Host "[*] Menganalisis dengan tipe $Mode..." -ForegroundColor Green
    & $exePath -type $Mode -out $OutputDir
}

Write-Host "`n[✓] Selesai. Tekan ENTER untuk keluar..." -ForegroundColor Yellow
$null = Read-Host

# Forensik_Repo_Analis_Code

Advanced Digital Forensics Analyzer Toolkit dibuat untuk menganalisis artefak digital (Binary/Executable, ISO Disk Image, dan Memory Dump) berbasis **Go** dengan performa tinggi dan konsumsi memori yang efisien (streaming I/O).

---

## 📂 Struktur Folder Repositori

```text
Forensik_Repo_Analis_Code/
├── Bin/                  # Modul & tempat file artefak binary / executable (.exe, .dll, ELF)
│   ├── analyzer.go       # Logika analisis PE Header, Sections, Entropy, Imports, IOCs
│   └── analyzer_test.go  # Unit test modul binary
├── File_ISO/             # Modul & tempat file disk image (.iso, .img)
│   ├── analyzer.go       # Parser ISO 9660 PVD, tree walker, phishing MOTW detector
│   └── analyzer_test.go  # Unit test modul ISO
├── MemDump/              # Modul & tempat file memory dump (.raw, .dmp, .vmem, .dd)
│   ├── analyzer.go       # Streaming memory scanner, dual string extraction, PE hunter
│   └── analyzer_test.go  # Unit test modul memory dump
├── pkg/
│   ├── common/           # Shared models, Shannon Entropy, multi-hash, IOC patterns
│   └── reporter/         # Generator laporan Console, Markdown, dan JSON
├── reports/              # Direktori output otomatis untuk laporan investigasi (.json & .md)
├── main.go               # CLI Orchestrator utama
├── forensic_analyzer.exe # Executable portable mandiri (siap pakai)
├── run_analysis.ps1      # Launcher praktis PowerShell
└── run_analysis.bat      # Launcher Batch (Double-click di Windows)
```

---

## 🚀 Fitur Utama

### 1. `Bin/` (Binary / Executable Analyzer)
- **Kalkulasi Hash Kriptografis**: MD5, SHA-1, dan SHA-256 dalam single-pass streaming.
- **Deteksi Magic Bytes / File Format**: Mengenali Windows PE, Linux ELF, macOS Mach-O, ZIP, dsb.
- **Deep PE Header Inspection**:
  - Arsitektur target (`x86`, `x64`, `ARM`, `ARM64`).
  - Analisis Compile Timestamp & deteksi anomali **Timestomping**.
  - Entry Point & Subsystem (GUI, Console, Driver).
- **Shannon Entropy Profiling**:
  - Menghitung entropi per section PE (`.text`, `.data`, `.rdata`, dll).
  - Deteksi **Packing / Enkripsi / Obfuscation** jika entropi > 7.1.
  - Deteksi section dengan izin **Writable & Executable (W+X)** (potensi *self-modifying code* / shellcode runner).
  - Mengenali signature packer populer (UPX, VMProtect, Themida, ASPack, dsb).
- **Dangerous API Import Detection**:
  - Process Injection (`CreateRemoteThread`, `WriteProcessMemory`, `QueueUserAPC`, `NtMapViewOfSection`).
  - Keylogging & Hooking (`SetWindowsHookEx`, `GetAsyncKeyState`).
  - Evasion & Anti-Debug (`IsDebuggerPresent`, `NtQueryInformationProcess`).
  - Dropper / Network C2 (`URLDownloadToFile`, `HttpSendRequest`, `InternetOpen`).
- **Pencarian IOC Strings**:
  - Deteksi IPv4, URL, Domain, Email, dan Registry Persistence Keys (`CurrentVersion\Run`, `schtasks`).

---

### 2. `File_ISO/` (Disk Image Analyzer)
- **Parsing Standar ISO 9660**:
  - Membaca Primary Volume Descriptor (Volume ID, System ID, Publisher ID, Timestamps).
- **Directory Hierarchy Walking**:
  - Merekam seluruh struktur folder, file, atribut, dan ukuran file.
- **Deteksi Teknik Serangan Phishing / MOTW Bypass**:
  - Menandai ekstensi berbahaya yang sering diselundupkan penyerang di dalam file ISO: `.exe`, `.lnk`, `.bat`, `.cmd`, `.vbs`, `.js`, `.hta`, `.scr`, `.dll`, `.ps1`.
  - Deteksi teknik **Double Extension** (contoh: `invoice.pdf.exe`).
  - Deteksi kombinasi **Shortcut (.lnk) + Binary/DLL** untuk *DLL Sideloading*.
  - Deteksi file dengan atribut tersembunyi (*Hidden File Flag*).

---

### 3. `MemDump/` (Memory Dump Analyzer)
- **High-Performance Chunk Streaming**:
  - Menggunakan buffer streaming 4MB dengan overlap 8KB, aman untuk memory dump berukuran multi-gigabyte tanpa overload RAM.
- **Dual-Encoding String Extraction**:
  - Ekstraksi simultan untuk teks **ASCII** dan **UTF-16LE / Unicode** (banyak artefak Windows NT tersimpan dalam UTF-16LE).
- **Embedded PE Header Hunter**:
  - Melacak header executable PE (`MZ` & `PE\0\0`) di unallocated/raw memory (indikasi *Process Hollowing* atau *Reflective DLL Injection*).
- **Memory Artifact & Command-Line Hunting**:
  - Melacak sisa jejak eksekusi perintah berbahaya sebelum memori didump (`cmd.exe /c`, `powershell -enc`, `vssadmin delete shadows`, `whoami /all`, `mimikatz`, `procdump`, `net user /add`).
- **Ekstraksi IOC & Kredensial**:
  - IPv4, IPv6, URL C2, email, domain, JWT token, AWS Access Keys, dan header private key.

---

## 🛠️ Cara Penggunaan

### Cara 1: Menggunakan Executable / Launcher (Paling Mudah)
Cukup letakkan file artefak Anda ke dalam folder `Bin/`, `File_ISO/`, atau `MemDump/`, lalu:
- **Klik dua kali** pada `run_analysis.bat` (atau jalankan `.\run_analysis.ps1` di PowerShell).

### Cara 2: Menjalankan via Command Line (CLI)

1. **Scan Seluruh Folder Repositori (`Bin/`, `File_ISO/`, `MemDump/`)**:
   ```powershell
   .\forensic_analyzer.exe -all
   # atau via Go:
   go run main.go -all
   ```

2. **Analisis Berkas Spesifik**:
   ```powershell
   .\forensic_analyzer.exe -file "C:\path\to\suspicious.exe"
   .\forensic_analyzer.exe -file "C:\path\to\sample.iso"
   .\forensic_analyzer.exe -file "C:\path\to\memory.raw"
   ```

3. **Analisis Direktori Khusus**:
   ```powershell
   .\forensic_analyzer.exe -dir "C:\cases\incident_01\evidence"
   ```

4. **Menentukan Output Folder Laporan**:
   ```powershell
   .\forensic_analyzer.exe -all -out "hasil_analisis"
   ```

---

## 📊 Hasil Laporan (Reports)

Setiap pemindaian menghasilkan:
1. **Tampilan Terminal Berwarna**: Rangkuman temuan ancaman, skor risiko (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), dan IOC.
2. **File JSON (`reports/forensic_report_<timestamp>.json`)**: Data terstruktur lengkap siap diintegrasikan dengan SIEM / SOAR / pipeline otomatis.
3. **File Markdown (`reports/forensic_report_<timestamp>.md`)**: Laporan investigasi bergaya GitHub Markdown dengan tabel terstruktur untuk dokumentasi insiden.

---

## 🧪 Menjalankan Pengujian (Unit Tests)

```powershell
$env:GOCACHE = "$PWD\.gocache"; go test -v ./...
```

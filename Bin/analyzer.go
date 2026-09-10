package bin

import (
	"debug/pe"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"forensic-repo-analyzer/pkg/common"
)

// Daftar API berbahaya / mencurigakan dalam malware analysis
var dangerousAPIs = map[string]struct {
	Category string
	Severity string
	Reason   string
}{
	"VirtualAlloc":               {"Memory Allocation", "MEDIUM", "Alokasi memori yang sering digunakan untuk unpacking atau staging shellcode"},
	"VirtualAllocEx":             {"Process Injection", "HIGH", "Alokasi memori pada proses eksternal untuk code injection"},
	"WriteProcessMemory":         {"Process Injection", "HIGH", "Menulis data/code ke proses eksternal (Process Hollowing/DLL Injection)"},
	"CreateRemoteThread":         {"Process Injection", "CRITICAL", "Eksekusi thread pada proses lain untuk memicu injeksi payload"},
	"QueueUserAPC":               {"Process Injection", "HIGH", "Early bird injection / APC queue injection"},
	"SetThreadContext":           {"Process Injection", "HIGH", "Memodifikasi konteks register thread untuk hijacking alur eksekusi"},
	"NtMapViewOfSection":         {"Process Injection", "HIGH", "Process hollowing melalui memory section mapping"},
	"VirtualProtect":             {"Memory Protection", "MEDIUM", "Mengubah hak akses memori (misal PAGE_EXECUTE_READWRITE)"},
	"VirtualProtectEx":           {"Memory Protection", "HIGH", "Mengubah hak akses memori proses target menjadi executable"},
	"SetWindowsHookExA":          {"Spying / Hooking", "HIGH", "Menginstal Windows hook global (biasa dipakai keylogger)"},
	"SetWindowsHookExW":          {"Spying / Hooking", "HIGH", "Menginstal Windows hook global (biasa dipakai keylogger)"},
	"GetAsyncKeyState":            {"Keylogging", "MEDIUM", "Polling keystroke pengguna untuk mencuri kredensial"},
	"GetKeyState":                {"Keylogging", "LOW", "Pemeriksaan state keyboard"},
	"IsDebuggerPresent":          {"Anti-Analysis", "MEDIUM", "Mendeteksi apakah binary sedang di-debug oleh analis"},
	"CheckRemoteDebuggerPresent": {"Anti-Analysis", "MEDIUM", "Mendeteksi debugger pihak ketiga"},
	"NtQueryInformationProcess":  {"Anti-Analysis", "HIGH", "Mendeteksi debugging atau manipulasi ProcessDebugPort"},
	"URLDownloadToFileA":         {"Dropper / Downloader", "HIGH", "Mengunduh payload dari internet langsung ke file lokal"},
	"URLDownloadToFileW":         {"Dropper / Downloader", "HIGH", "Mengunduh payload dari internet langsung ke file lokal"},
	"InternetOpenA":              {"C2 Communication", "MEDIUM", "Inisialisasi koneksi HTTP/FTP untuk malware C2"},
	"HttpSendRequestA":           {"C2 Communication", "MEDIUM", "Mengirim data exfiltration ke C2 server"},
	"WinExec":                    {"Execution", "HIGH", "Menjalankan executable secara tersembunyi"},
	"ShellExecuteA":              {"Execution", "MEDIUM", "Mengeksekusi command/binary melalui shell Windows"},
	"CreateProcessA":             {"Execution", "MEDIUM", "Membuat child process baru"},
	"CreateProcessInternalW":     {"Execution", "HIGH", "Low-level API untuk membuat process yang sering di-hook/di-abuse malware"},
	"RegSetValueExA":             {"Persistence", "MEDIUM", "Menulis nilai registry (sering dipakai untuk Run keys autostart)"},
	"RegSetValueExW":             {"Persistence", "MEDIUM", "Menulis nilai registry untuk persistensi"},
	"CreateServiceA":             {"Persistence", "HIGH", "Membuat Windows Service untuk mempertahankan akses jangka panjang"},
}

// Known packers signatures
var knownPackerSections = []string{
	"UPX0", "UPX1", "UPX2", ".upx", "vmp0", "vmp1", ".themida", ".aspack", ".pec2", ".nsp", ".ndata",
}

// AnalyzeBinaryFile melakukan investigasi forensik menyeluruh terhadap file binary
func AnalyzeBinaryFile(filePath string) (common.BinAnalysisReport, error) {
	meta, err := common.GetFileMetadata(filePath)
	if err != nil {
		return common.BinAnalysisReport{}, err
	}

	report := common.BinAnalysisReport{
		Metadata:        meta,
		RiskScore:       0,
		ThreatsDetected: make([]string, 0),
	}

	// 1. Coba parse sebagai PE (Portable Executable)
	peFile, err := pe.Open(filePath)
	if err == nil {
		defer peFile.Close()
		analyzePEHeaders(&report, peFile)
		analyzePEImports(&report, peFile)
		analyzePESections(&report, peFile, filePath)
	} else {
		report.Architecture = "Non-PE / Raw Binary"
	}

	// 2. Ekstraksi strings dan pencarian IOC
	stringsList, err := extractStringsFromFile(filePath, 5, 25000)
	if err == nil {
		report.ExtractedIOCs = common.ExtractIOCsFromText(stringsList)
		findSuspiciousStringsPatterns(&report, stringsList)
	}

	// 3. Evaluasi skor risiko & level
	evaluateRisk(&report)

	return report, nil
}

// analyzePEHeaders memeriksa arsitektur dan waktu kompilasi
func analyzePEHeaders(report *common.BinAnalysisReport, peFile *pe.File) {
	switch peFile.FileHeader.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		report.Architecture = "x86 (32-bit)"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		report.Architecture = "x64 (64-bit)"
	case pe.IMAGE_FILE_MACHINE_ARM:
		report.Architecture = "ARM (32-bit)"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		report.Architecture = "ARM64 (64-bit)"
	default:
		report.Architecture = fmt.Sprintf("Unknown (0x%X)", peFile.FileHeader.Machine)
	}

	timestamp := time.Unix(int64(peFile.FileHeader.TimeDateStamp), 0).UTC()
	report.CompileTime = timestamp.Format(time.RFC3339)

	// Anomali waktu kompilasi (timestomping atau tanggal masa depan)
	if timestamp.After(time.Now().Add(24 * time.Hour)) {
		report.ThreatsDetected = append(report.ThreatsDetected, "Timestomping Anomaly: Compile time berada di masa depan ("+report.CompileTime+")")
		report.RiskScore += 25
	} else if timestamp.Before(time.Date(1998, 1, 1, 0, 0, 0, 0, time.UTC)) {
		report.ThreatsDetected = append(report.ThreatsDetected, "Timestomping Anomaly: Compile time terlalu lampau (< 1998)")
		report.RiskScore += 15
	}

	if opt32, ok := peFile.OptionalHeader.(*pe.OptionalHeader32); ok {
		report.Entrypoint = fmt.Sprintf("0x%X", opt32.AddressOfEntryPoint)
		report.Subsystem = getSubsystemName(opt32.Subsystem)
	} else if opt64, ok := peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
		report.Entrypoint = fmt.Sprintf("0x%X", opt64.AddressOfEntryPoint)
		report.Subsystem = getSubsystemName(opt64.Subsystem)
	}
}

func getSubsystemName(subsystem uint16) string {
	switch subsystem {
	case 1:
		return "Native (Driver)"
	case 2:
		return "Windows GUI"
	case 3:
		return "Windows CUI (Console)"
	case 7:
		return "POSIX CUI"
	case 9:
		return "Windows CE GUI"
	case 10:
		return "EFI Application"
	default:
		return fmt.Sprintf("Other (%d)", subsystem)
	}
}

// analyzePESections memeriksa section headers, entropy, dan anomali packer
func analyzePESections(report *common.BinAnalysisReport, peFile *pe.File, filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	for _, sec := range peFile.Sections {
		var flags []string
		secName := strings.TrimRight(sec.Name, "\x00")

		// Hitung entropy section
		var secEntropy float64
		if sec.Size > 0 && sec.Offset > 0 {
			buf := make([]byte, sec.Size)
			_, rerr := f.ReadAt(buf, int64(sec.Offset))
			if rerr == nil || rerr == io.EOF {
				secEntropy = common.CalculateShannonEntropy(buf)
			}
		}

		// Deteksi packed section
		if secEntropy > 7.1 {
			flags = append(flags, fmt.Sprintf("High Entropy (%.2f): Terenkripsi / Terkompresi / Packed", secEntropy))
			report.Metadata.IsPacked = true
			report.RiskScore += 20
			report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Section '%s' memiliki entropi sangat tinggi (%.2f), indikasi packing", secName, secEntropy))
		}

		// Periksa nama section mencurigakan
		secNameUpper := strings.ToUpper(secName)
		for _, packer := range knownPackerSections {
			if strings.Contains(secNameUpper, packer) {
				flags = append(flags, fmt.Sprintf("Packer Signature Detected: %s", packer))
				report.Metadata.IsPacked = true
				report.RiskScore += 35
				report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Deteksi packer signature pada section '%s'", secName))
				break
			}
		}

		// Periksa apakah section memiliki izin Write dan Execute (W+X) -> indikasi kuat shellcode runner
		isWrite := (sec.Characteristics & 0x80000000) != 0
		isExec := (sec.Characteristics & 0x20000000) != 0
		if isWrite && isExec {
			flags = append(flags, "Writable & Executable (W+X): Potensial Self-Modifying Code / In-Memory Payload")
			report.RiskScore += 25
			report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Section '%s' memiliki permission W+X (Self-modifying code)", secName))
		}

		report.Sections = append(report.Sections, common.PESectionInfo{
			Name:            secName,
			VirtualAddress:  sec.VirtualAddress,
			VirtualSize:     sec.VirtualSize,
			RawDataSize:     sec.Size,
			Entropy:         secEntropy,
			SuspiciousFlags: flags,
		})
	}
}

// analyzePEImports mendeteksi API-API berbahaya yang diimpor oleh binary
func analyzePEImports(report *common.BinAnalysisReport, peFile *pe.File) {
	importedSymbols, err := peFile.ImportedSymbols()
	if err != nil {
		return
	}

	for _, sym := range importedSymbols {
		parts := strings.Split(sym, ":")
		var dll, fn string
		if len(parts) == 2 {
			dll = parts[0]
			fn = parts[1]
		} else {
			fn = sym
		}

		if sig, found := dangerousAPIs[fn]; found {
			report.SuspiciousImports = append(report.SuspiciousImports, common.SuspiciousImport{
				DLL:      dll,
				Function: fn,
				Category: sig.Category,
				Severity: sig.Severity,
				Reason:   sig.Reason,
			})

			switch sig.Severity {
			case "CRITICAL":
				report.RiskScore += 25
				report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Critical API Import: %s (%s)", fn, sig.Reason))
			case "HIGH":
				report.RiskScore += 15
			case "MEDIUM":
				report.RiskScore += 8
			case "LOW":
				report.RiskScore += 3
			}
		}
	}
}

// findSuspiciousStringsPatterns mencari keyword mencurigakan di string binary
func findSuspiciousStringsPatterns(report *common.BinAnalysisReport, stringsList []string) {
	suspiciousKeywords := []struct {
		keyword string
		desc    string
		score   int
	}{
		{strings.Join([]string{"powershell", " -enc"}, ""), "Obfuscated Encoded PowerShell Execution", 30},
		{strings.Join([]string{"cmd.exe", " /c"}, ""), "Silent Command Prompt Spawn", 15},
		{strings.Join([]string{"vssadmin", " delete", " shadows"}, ""), "Ransomware Shadow Copy Deletion", 40},
		{strings.Join([]string{"wbadmin", " delete", " catalog"}, ""), "Ransomware Backup Invalidation", 40},
		{strings.Join([]string{"bcdedit", " /set", " recoveryenabled No"}, ""), "Ransomware Boot Recovery Disable", 40},
		{strings.Join([]string{"wmic", " shadowcopy", " delete"}, ""), "Ransomware Shadow Copy Deletion", 35},
		{strings.Join([]string{"CurrentVersion", "\\Run"}, ""), "Persistence Registry Auto-Run Key", 20},
		{strings.Join([]string{"schtasks", " /create"}, ""), "Scheduled Task Persistence Creation", 20},
		{strings.Join([]string{"bitsadmin", " /transfer"}, ""), "Background Intelligent Transfer Dropper", 25},
		{strings.Join([]string{"certutil", " -urlcache"}, ""), "CertUtil Living-off-the-Land Downloader", 30},
		{strings.Join([]string{"mimi", "katz"}, ""), "Mimikatz Credential Dumper String Detected", 45},
	}

	for _, s := range stringsList {
		sLower := strings.ToLower(s)
		for _, kw := range suspiciousKeywords {
			if strings.Contains(sLower, strings.ToLower(kw.keyword)) {
				report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("%s (Found string: '%s')", kw.desc, s))
				report.RiskScore += kw.score
			}
		}
	}
}

// evaluateRisk menentukan level risiko akhir
func evaluateRisk(report *common.BinAnalysisReport) {
	if len(report.ExtractedIOCs.URLs) > 0 {
		report.RiskScore += len(report.ExtractedIOCs.URLs) * 5
	}
	if len(report.ExtractedIOCs.IPv4Addresses) > 0 {
		report.RiskScore += len(report.ExtractedIOCs.IPv4Addresses) * 5
	}
	if len(report.ExtractedIOCs.TokensOrKeys) > 0 {
		report.RiskScore += 20
	}

	report.RiskLevel = common.CalculateRiskLevel(report.RiskScore)
}

// extractStringsFromFile membaca string ASCII dan Unicode dari file
func extractStringsFromFile(filePath string, minLen int, maxStrings int) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var result []string
	buf := make([]byte, 64*1024)
	var current []rune

	flushString := func() {
		if len(current) >= minLen {
			result = append(result, string(current))
		}
		current = current[:0]
	}

	for {
		n, err := file.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			for i := 0; i < len(chunk); i++ {
				b := chunk[i]
				if b >= 32 && b <= 126 { // Printable ASCII
					current = append(current, rune(b))
				} else {
					flushString()
				}
				if len(result) >= maxStrings {
					return result, nil
				}
			}

			// Cek pola UTF-16LE sederhana
			for i := 0; i < len(chunk)-1; i += 2 {
				if chunk[i+1] == 0 && chunk[i] >= 32 && chunk[i] <= 126 {
					current = append(current, rune(chunk[i]))
				} else {
					flushString()
				}
				if len(result) >= maxStrings {
					return result, nil
				}
			}
		}
		if err != nil {
			break
		}
	}
	flushString()

	return result, nil
}

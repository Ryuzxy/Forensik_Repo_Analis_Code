package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"forensic-repo-analyzer/pkg/common"
)

// PrintConsoleReport menampilkan hasil investigasi forensik ke terminal
func PrintConsoleReport(report common.OverallForensicReport) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("             FORENSIK REPO ANALYZER - SUMMARY REPORT")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Waktu Analisis : %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Total Berkas   : %d (Bin: %d | ISO: %d | MemDump: %d | Hex: %d | Heap: %d)\n",
		report.Summary.TotalFilesScanned,
		report.Summary.BinFilesCount,
		report.Summary.ISOFilesCount,
		report.Summary.MemFilesCount,
		report.Summary.HexFilesCount,
		report.Summary.HeapFilesCount,
	)
	fmt.Printf("Total Ancaman  : %d Terdeteksi\n", report.Summary.TotalThreatsFound)
	fmt.Println(strings.Repeat("-", 80))

	// Print Bin Reports
	if len(report.BinReports) > 0 {
		fmt.Println("\n[*] HASIL ANALISIS BINARY (Folder: Bin/)")
		for _, b := range report.BinReports {
			printBinReportConsole(b)
		}
	}

	// Print ISO Reports
	if len(report.ISOReports) > 0 {
		fmt.Println("\n[*] HASIL ANALISIS DISK IMAGE (Folder: File_ISO/)")
		for _, iso := range report.ISOReports {
			printISOReportConsole(iso)
		}
	}

	// Print MemDump Reports
	if len(report.MemReports) > 0 {
		fmt.Println("\n[*] HASIL ANALISIS MEMORY DUMP (Folder: MemDump/)")
		for _, m := range report.MemReports {
			printMemReportConsole(m)
		}
	}

	// Print Hex Reports
	if len(report.HexReports) > 0 {
		fmt.Println("\n[*] HASIL ANALISIS KODE HEX & SHELLCODE (Folder: Hex/)")
		for _, h := range report.HexReports {
			printHexReportConsole(h)
		}
	}

	// Print Heap Reports
	if len(report.HeapReports) > 0 {
		fmt.Println("\n[*] HASIL ANALISIS HEAP MEMORY (Folder: Heap/)")
		for _, hp := range report.HeapReports {
			printHeapReportConsole(hp)
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
}

func printBinReportConsole(b common.BinAnalysisReport) {
	badge := formatRiskBadge(b.RiskLevel)
	fmt.Printf("\n  File         : %s\n", b.Metadata.FileName)
	fmt.Printf("  Tipe/Arch    : %s (%s)\n", b.Metadata.FileType, b.Architecture)
	fmt.Printf("  Ukuran       : %d bytes | Entropi: %.2f (Packed: %v)\n", b.Metadata.FileSize, b.Metadata.Entropy, b.Metadata.IsPacked)
	fmt.Printf("  SHA-256      : %s\n", b.Metadata.Hashes.SHA256)
	fmt.Printf("  Status Risk  : %s (Skor: %d)\n", badge, b.RiskScore)

	if len(b.Sections) > 0 {
		fmt.Println("  Sections PE  :")
		for _, s := range b.Sections {
			flagStr := ""
			if len(s.SuspiciousFlags) > 0 {
				flagStr = fmt.Sprintf(" [!] %s", strings.Join(s.SuspiciousFlags, "; "))
			}
			fmt.Printf("    - %-10s | VirtSize: 0x%-6X | RawSize: 0x%-6X | Entropi: %.2f%s\n",
				s.Name, s.VirtualSize, s.RawDataSize, s.Entropy, flagStr)
		}
	}

	if len(b.SuspiciousImports) > 0 {
		fmt.Printf("  API Mencurigakan (%d):\n", len(b.SuspiciousImports))
		for _, imp := range b.SuspiciousImports {
			fmt.Printf("    - [%s] %s!%s (%s)\n", imp.Severity, imp.DLL, imp.Function, imp.Reason)
		}
	}

	if len(b.ThreatsDetected) > 0 {
		fmt.Println("  Temuan Ancaman:")
		for _, t := range b.ThreatsDetected {
			fmt.Printf("    [!] %s\n", t)
		}
	}

	printIOCSummary(b.ExtractedIOCs)
}

func printISOReportConsole(iso common.ISOAnalysisReport) {
	badge := formatRiskBadge(iso.RiskLevel)
	fmt.Printf("\n  File         : %s\n", iso.Metadata.FileName)
	fmt.Printf("  Volume ID    : %s\n", iso.VolumeInfo.VolumeID)
	fmt.Printf("  Publisher    : %s | System ID: %s\n", iso.VolumeInfo.PublisherID, iso.VolumeInfo.SystemID)
	fmt.Printf("  Total File   : %d (Folder: %d)\n", iso.TotalFiles, iso.TotalDirs)
	fmt.Printf("  Status Risk  : %s (Skor: %d)\n", badge, iso.RiskScore)

	if len(iso.SuspiciousFiles) > 0 {
		fmt.Printf("  Berkas Berbahaya/Mencurigakan Dalam ISO (%d):\n", len(iso.SuspiciousFiles))
		for _, sf := range iso.SuspiciousFiles {
			fmt.Printf("    [!] %s (%d bytes) - %s\n", sf.Path, sf.Size, sf.Reason)
		}
	}

	if len(iso.ThreatsDetected) > 0 {
		fmt.Println("  Temuan Ancaman:")
		for _, t := range iso.ThreatsDetected {
			fmt.Printf("    [!] %s\n", t)
		}
	}
}

func printMemReportConsole(m common.MemAnalysisReport) {
	badge := formatRiskBadge(m.RiskLevel)
	fmt.Printf("\n  File         : %s\n", m.Metadata.FileName)
	fmt.Printf("  Ukuran       : %d bytes | Durasi Scan: %.2f detik\n", m.Metadata.FileSize, m.ScanDurationSec)
	fmt.Printf("  Total String : %d diekstrak\n", m.TotalStrings)
	fmt.Printf("  Status Risk  : %s (Skor: %d)\n", badge, m.RiskScore)

	if len(m.Artifacts) > 0 {
		fmt.Printf("  Artefak Memori Ditemukan (%d):\n", len(m.Artifacts))
		for _, a := range m.Artifacts {
			fmt.Printf("    - [%s] %s: %s\n", a.Type, a.Description, a.Snippet)
		}
	}

	if len(m.ThreatsDetected) > 0 {
		fmt.Println("  Temuan Ancaman:")
		for _, t := range m.ThreatsDetected {
			fmt.Printf("    [!] %s\n", t)
		}
	}

	printIOCSummary(m.IOCs)
}

func printHexReportConsole(h common.HexAnalysisReport) {
	badge := formatRiskBadge(h.RiskLevel)
	fmt.Printf("\n  Sumber       : %s\n", h.InputSource)
	fmt.Printf("  Ukuran Byte  : %d bytes | Entropi: %.2f\n", h.ByteLength, h.Entropy)
	fmt.Printf("  SHA-256      : %s\n", h.Hashes.SHA256)
	fmt.Printf("  Status Risk  : %s (Skor: %d)\n", badge, h.RiskScore)

	if len(h.ShellcodeFindings) > 0 {
		fmt.Printf("  Pola Shellcode Terdeteksi (%d):\n", len(h.ShellcodeFindings))
		for _, sf := range h.ShellcodeFindings {
			fmt.Printf("    - [%s] 0x%X: %s\n", sf.Type, sf.Offset, sf.Description)
		}
	}

	if len(h.XORDeobfuscation) > 0 {
		fmt.Printf("  Kandidat Deobfuscasi XOR (%d):\n", len(h.XORDeobfuscation))
		for _, x := range h.XORDeobfuscation {
			fmt.Printf("    - Key %s (Byte: 0x%02X) | Cocok: '%s' | Cuplikan: \"%s\"\n", x.KeyHex, x.KeyByte, x.MatchedWord, x.SampleText)
		}
	}

	if h.HexDumpPreview != "" {
		fmt.Println("  Preview Hexdump (Kanonikal):")
		lines := strings.Split(strings.TrimRight(h.HexDumpPreview, "\n"), "\n")
		for _, l := range takeFirst(lines, 6) {
			fmt.Printf("    %s\n", l)
		}
	}

	if len(h.ThreatsDetected) > 0 {
		fmt.Println("  Temuan Ancaman:")
		for _, t := range h.ThreatsDetected {
			fmt.Printf("    [!] %s\n", t)
		}
	}

	printIOCSummary(h.IOCs)
}

func printHeapReportConsole(hp common.HeapAnalysisReport) {
	badge := formatRiskBadge(hp.RiskLevel)
	fmt.Printf("\n  File         : %s\n", hp.Metadata.FileName)
	fmt.Printf("  Ukuran       : %d bytes | Entropi: %.2f\n", hp.Metadata.FileSize, hp.Metadata.Entropy)
	fmt.Printf("  Status Risk  : %s (Skor: %d)\n", badge, hp.RiskScore)

	if len(hp.HeapPatterns) > 0 {
		fmt.Printf("  Pola Marker Heap Ditemukan (%d):\n", len(hp.HeapPatterns))
		for _, p := range hp.HeapPatterns {
			fmt.Printf("    - [%s] %s (%s): %d kali (Offset awal: 0x%X)\n", p.Severity, p.HexValue, p.PatternName, p.Count, p.FirstOffset)
		}
	}

	if hp.HeapSprayDetected {
		fmt.Printf("  [!] HEAP SPRAY ALERT: %s\n", hp.HeapSprayDetails)
	}

	if len(hp.CarvedHTTP) > 0 {
		fmt.Printf("  Carved HTTP Headers (%d):\n", len(hp.CarvedHTTP))
		for _, h := range takeFirst(hp.CarvedHTTP, 4) {
			fmt.Printf("    - %s\n", h)
		}
	}

	if len(hp.CarvedJSON) > 0 {
		fmt.Printf("  Carved JSON Objects (%d):\n", len(hp.CarvedJSON))
		for _, j := range takeFirst(hp.CarvedJSON, 3) {
			fmt.Printf("    - %s\n", j)
		}
	}

	if len(hp.ThreatsDetected) > 0 {
		fmt.Println("  Temuan Ancaman:")
		for _, t := range hp.ThreatsDetected {
			fmt.Printf("    [!] %s\n", t)
		}
	}

	printIOCSummary(hp.IOCs)
}

func printIOCSummary(ioc common.IOCReport) {
	hasIOC := len(ioc.IPv4Addresses) > 0 || len(ioc.URLs) > 0 || len(ioc.Emails) > 0 || len(ioc.TokensOrKeys) > 0
	if !hasIOC {
		return
	}

	fmt.Println("  Indikator Kompromi (IOC):")
	if len(ioc.IPv4Addresses) > 0 {
		fmt.Printf("    - IPv4 (%d): %s\n", len(ioc.IPv4Addresses), strings.Join(takeFirst(ioc.IPv4Addresses, 5), ", "))
	}
	if len(ioc.URLs) > 0 {
		fmt.Printf("    - URLs (%d): %s\n", len(ioc.URLs), strings.Join(takeFirst(ioc.URLs, 3), ", "))
	}
	if len(ioc.Emails) > 0 {
		fmt.Printf("    - Emails (%d): %s\n", len(ioc.Emails), strings.Join(takeFirst(ioc.Emails, 3), ", "))
	}
	if len(ioc.TokensOrKeys) > 0 {
		fmt.Printf("    - Kredensial/Keys (%d): %s\n", len(ioc.TokensOrKeys), strings.Join(takeFirst(ioc.TokensOrKeys, 3), ", "))
	}
}

func takeFirst(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	res := append([]string{}, list[:n]...)
	res = append(res, fmt.Sprintf("...+%d lainnya", len(list)-n))
	return res
}

func formatRiskBadge(level string) string {
	switch level {
	case "CRITICAL":
		return "[CRITICAL 🚨]"
	case "HIGH":
		return "[HIGH ⚠️]"
	case "MEDIUM":
		return "[MEDIUM ⚡]"
	default:
		return "[LOW/CLEAN ✅]"
	}
}

// SaveReports menyimpan laporan dalam format JSON dan Markdown ke folder target
func SaveReports(report common.OverallForensicReport, outputDir string) (jsonPath, mdPath string, err error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", "", err
	}

	timestamp := report.GeneratedAt.Format("20060102_150405")
	jsonPath = filepath.Join(outputDir, fmt.Sprintf("forensic_report_%s.json", timestamp))
	mdPath = filepath.Join(outputDir, fmt.Sprintf("forensic_report_%s.md", timestamp))

	// 1. Simpan JSON
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err == nil {
		_ = os.WriteFile(jsonPath, jsonData, 0644)
	}

	// 2. Simpan Markdown
	mdContent := generateMarkdownReport(report)
	_ = os.WriteFile(mdPath, []byte(mdContent), 0644)

	return jsonPath, mdPath, nil
}

// generateMarkdownReport menyusun laporan bergaya GitHub Markdown
func generateMarkdownReport(report common.OverallForensicReport) string {
	var sb strings.Builder

	sb.WriteString("# Laporan Investigasi Forensik Digital\n\n")
	sb.WriteString(fmt.Sprintf("**Waktu Pembuatan:** `%s`  \n", report.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Total File Dianalisis:** `%d`  \n", report.Summary.TotalFilesScanned))
	sb.WriteString(fmt.Sprintf("**Total Ancaman Terdeteksi:** `%d`  \n\n", report.Summary.TotalThreatsFound))

	sb.WriteString("## Ringkasan Eksekutif\n\n")
	sb.WriteString("| Kategori | Jumlah Berkas | Keterangan |\n")
	sb.WriteString("|---|---|---|\n")
	sb.WriteString(fmt.Sprintf("| **Bin (Executable/PE/ELF)** | %d | Analisis arsitektur, section entropy, import API, dan packer signature |\n", report.Summary.BinFilesCount))
	sb.WriteString(fmt.Sprintf("| **File_ISO (Disk Image)** | %d | Metadata ISO 9660, hirarki direktori, dan deteksi MOTW bypass malware |\n", report.Summary.ISOFilesCount))
	sb.WriteString(fmt.Sprintf("| **MemDump (Memory Dump)** | %d | Streaming scanner, artefak command-line, embedded PE, dan IOC hunting |\n", report.Summary.MemFilesCount))
	sb.WriteString(fmt.Sprintf("| **Hex (Raw Hex & Shellcode)** | %d | Normalisasi hex, deteksi pola shellcode (NOP sled, GetPC), XOR brute-force |\n", report.Summary.HexFilesCount))
	sb.WriteString(fmt.Sprintf("| **Heap (Heap Structure & Spray)** | %d | Windows Heap debug markers, heap spray heuristics, in-heap HTTP/JSON carving |\n\n", report.Summary.HeapFilesCount))

	// Detail Bin
	if len(report.BinReports) > 0 {
		sb.WriteString("## 1. Analisis Berkas Binary (`Bin/`)\n\n")
		for _, b := range report.BinReports {
			sb.WriteString(fmt.Sprintf("### Berkas: `%s`\n\n", b.Metadata.FileName))
			sb.WriteString(fmt.Sprintf("- **Tipe**: %s (%s)\n", b.Metadata.FileType, b.Architecture))
			sb.WriteString(fmt.Sprintf("- **Ukuran**: %d bytes\n", b.Metadata.FileSize))
			sb.WriteString(fmt.Sprintf("- **Entropi Keseluruhan**: `%.3f` (Packed: `%v`)\n", b.Metadata.Entropy, b.Metadata.IsPacked))
			sb.WriteString(fmt.Sprintf("- **SHA-256**: `%s`\n", b.Metadata.Hashes.SHA256))
			sb.WriteString(fmt.Sprintf("- **Tingkat Risiko**: **%s** (Skor: %d)\n\n", b.RiskLevel, b.RiskScore))

			if len(b.ThreatsDetected) > 0 {
				sb.WriteString("#### Temuan Ancaman:\n")
				for _, t := range b.ThreatsDetected {
					sb.WriteString(fmt.Sprintf("- ⚠️ %s\n", t))
				}
				sb.WriteString("\n")
			}

			if len(b.Sections) > 0 {
				sb.WriteString("#### Struktur Section PE:\n\n")
				sb.WriteString("| Nama | Virtual Size | Raw Size | Entropi | Catatan |\n")
				sb.WriteString("|---|---|---|---|---|\n")
				for _, s := range b.Sections {
					notes := strings.Join(s.SuspiciousFlags, ", ")
					if notes == "" {
						notes = "-"
					}
					sb.WriteString(fmt.Sprintf("| `%s` | `0x%X` | `0x%X` | `%.2f` | %s |\n", s.Name, s.VirtualSize, s.RawDataSize, s.Entropy, notes))
				}
				sb.WriteString("\n")
			}
		}
	}

	// Detail ISO
	if len(report.ISOReports) > 0 {
		sb.WriteString("## 2. Analisis Berkas ISO (`File_ISO/`)\n\n")
		for _, iso := range report.ISOReports {
			sb.WriteString(fmt.Sprintf("### Berkas: `%s`\n\n", iso.Metadata.FileName))
			sb.WriteString(fmt.Sprintf("- **Volume ID**: `%s`\n", iso.VolumeInfo.VolumeID))
			sb.WriteString(fmt.Sprintf("- **Total Berkas Dalam ISO**: %d file, %d folder\n", iso.TotalFiles, iso.TotalDirs))
			sb.WriteString(fmt.Sprintf("- **Tingkat Risiko**: **%s** (Skor: %d)\n\n", iso.RiskLevel, iso.RiskScore))

			if len(iso.SuspiciousFiles) > 0 {
				sb.WriteString("#### Berkas Berisiko Tinggi Ditemukan Di Dalam ISO:\n\n")
				sb.WriteString("| Lokasi Berkas | Ukuran (bytes) | Indikasi Bahaya |\n")
				sb.WriteString("|---|---|---|\n")
				for _, sf := range iso.SuspiciousFiles {
					sb.WriteString(fmt.Sprintf("| `%s` | %d | %s |\n", sf.Path, sf.Size, sf.Reason))
				}
				sb.WriteString("\n")
			}
		}
	}

	// Detail MemDump
	if len(report.MemReports) > 0 {
		sb.WriteString("## 3. Analisis Memory Dump (`MemDump/`)\n\n")
		for _, m := range report.MemReports {
			sb.WriteString(fmt.Sprintf("### Berkas: `%s`\n\n", m.Metadata.FileName))
			sb.WriteString(fmt.Sprintf("- **Ukuran**: %d bytes\n", m.Metadata.FileSize))
			sb.WriteString(fmt.Sprintf("- **Durasi Scan**: %.2f detik\n", m.ScanDurationSec))
			sb.WriteString(fmt.Sprintf("- **Total String Diekstrak**: %d\n", m.TotalStrings))
			sb.WriteString(fmt.Sprintf("- **Tingkat Risiko**: **%s** (Skor: %d)\n\n", m.RiskLevel, m.RiskScore))

			if len(m.Artifacts) > 0 {
				sb.WriteString("#### Artefak Memori Relevan:\n")
				for _, a := range m.Artifacts {
					sb.WriteString(fmt.Sprintf("- **[%s]** %s: `%s`\n", a.Type, a.Description, a.Snippet))
				}
				sb.WriteString("\n")
			}

			if len(m.IOCs.IPv4Addresses) > 0 || len(m.IOCs.URLs) > 0 || len(m.IOCs.TokensOrKeys) > 0 {
				sb.WriteString("#### Indikator Kompromi (IOC):\n")
				for _, ip := range m.IOCs.IPv4Addresses {
					sb.WriteString(fmt.Sprintf("- IPv4: `%s`\n", ip))
				}
				for _, u := range m.IOCs.URLs {
					sb.WriteString(fmt.Sprintf("- URL: `%s`\n", u))
				}
				for _, tok := range m.IOCs.TokensOrKeys {
					sb.WriteString(fmt.Sprintf("- Kredensial: `%s`\n", tok))
				}
				sb.WriteString("\n")
			}
		}
	}

	// Detail Hex
	if len(report.HexReports) > 0 {
		sb.WriteString("## 4. Analisis Kode Hex & Shellcode (`Hex/`)\n\n")
		for _, h := range report.HexReports {
			sb.WriteString(fmt.Sprintf("### Target: `%s`\n\n", h.InputSource))
			sb.WriteString(fmt.Sprintf("- **Panjang Byte**: %d bytes\n", h.ByteLength))
			sb.WriteString(fmt.Sprintf("- **Entropi**: `%.3f`\n", h.Entropy))
			sb.WriteString(fmt.Sprintf("- **SHA-256**: `%s`\n", h.Hashes.SHA256))
			sb.WriteString(fmt.Sprintf("- **Tingkat Risiko**: **%s** (Skor: %d)\n\n", h.RiskLevel, h.RiskScore))

			if len(h.ShellcodeFindings) > 0 {
				sb.WriteString("#### Pola Shellcode Terdeteksi:\n")
				for _, sf := range h.ShellcodeFindings {
					sb.WriteString(fmt.Sprintf("- ⚠️ **[%s]** (Offset `0x%X`): %s\n", sf.Type, sf.Offset, sf.Description))
				}
				sb.WriteString("\n")
			}

			if len(h.XORDeobfuscation) > 0 {
				sb.WriteString("#### Hasil Deobfuscasi XOR:\n")
				for _, x := range h.XORDeobfuscation {
					sb.WriteString(fmt.Sprintf("- 🔓 **Key `%s`**: Menemukan `%s` (Cuplikan: `%s`)\n", x.KeyHex, x.MatchedWord, x.SampleText))
				}
				sb.WriteString("\n")
			}
		}
	}

	// Detail Heap
	if len(report.HeapReports) > 0 {
		sb.WriteString("## 5. Analisis Struktur Heap Memory (`Heap/`)\n\n")
		for _, hp := range report.HeapReports {
			sb.WriteString(fmt.Sprintf("### Berkas: `%s`\n\n", hp.Metadata.FileName))
			sb.WriteString(fmt.Sprintf("- **Ukuran**: %d bytes\n", hp.Metadata.FileSize))
			sb.WriteString(fmt.Sprintf("- **Entropi**: `%.3f`\n", hp.Metadata.Entropy))
			sb.WriteString(fmt.Sprintf("- **Tingkat Risiko**: **%s** (Skor: %d)\n\n", hp.RiskLevel, hp.RiskScore))

			if len(hp.HeapPatterns) > 0 {
				sb.WriteString("#### Marker Heap & Pola Korupsi Terdeteksi:\n\n")
				sb.WriteString("| Marker Hex | Nama Pola | Jumlah | Offset Awal | Keterangan |\n")
				sb.WriteString("|---|---|---|---|---|\n")
				for _, p := range hp.HeapPatterns {
					sb.WriteString(fmt.Sprintf("| `%s` | %s | %d | `0x%X` | %s |\n", p.HexValue, p.PatternName, p.Count, p.FirstOffset, p.Description))
				}
				sb.WriteString("\n")
			}

			if hp.HeapSprayDetected {
				sb.WriteString(fmt.Sprintf("#### ⚠️ Peringatan Heap Spraying:\n%s\n\n", hp.HeapSprayDetails))
			}

			if len(hp.CarvedHTTP) > 0 {
				sb.WriteString("#### In-Heap Carved HTTP Headers:\n")
				for _, hdr := range hp.CarvedHTTP {
					sb.WriteString(fmt.Sprintf("- `%s`\n", hdr))
				}
				sb.WriteString("\n")
			}
		}
	}

	return sb.String()
}

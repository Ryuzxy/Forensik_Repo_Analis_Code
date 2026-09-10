package hexanalyzer

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"

	"forensic-repo-analyzer/pkg/common"
)

var (
	// Regex untuk membersihkan representasi hexdump standar (misal "00000000: 4d 5a ... |MZ..|")
	hexdumpLineRegex = regexp.MustCompile(`^(?:[0-9a-fA-F]{4,16}[:\s]+)?((?:[0-9a-fA-F]{2}[\s\-,]+){1,32})`)
	// Kata kunci untuk deteksi hasil deobfuscasi XOR yang valid
	xorTargets = []string{
		"http://", "https://", "powershell", "cmd.exe", "This program",
		"LoadLibrary", "GetProcAddress", "VirtualAlloc", "kernel32", "user32",
		"WSAStartup", "socket", "connect", "mimikatz", "beacon",
	}
)

// NormalizeAndDecodeHex memproses berbagai format teks hex menjadi slice bytes
func NormalizeAndDecodeHex(raw string) ([]byte, error) {
	// Coba proses format baris demi baris (jika input merupakan output hexdump terformat)
	lines := strings.Split(raw, "\n")
	var hexBytes strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Jika baris memiliki pemisah ASCII '|' di ujung (format canonical xxd), ambil bagian sebelum '|'
		if idx := strings.Index(trimmed, "|"); idx != -1 {
			trimmed = trimmed[:idx]
		}

		// Hapus offset di awal jika ada (misal: "00000000: " atau "0x0000: ")
		if colonIdx := strings.Index(trimmed, ":"); colonIdx != -1 && colonIdx < 18 {
			trimmed = trimmed[colonIdx+1:]
		}

		// Hapus prefix umum format hex: '0x', '\x', spasi, koma, kutip, dash
		trimmed = strings.ReplaceAll(trimmed, "0x", "")
		trimmed = strings.ReplaceAll(trimmed, "0X", "")
		trimmed = strings.ReplaceAll(trimmed, "\\x", "")
		trimmed = strings.ReplaceAll(trimmed, "\\X", "")
		trimmed = strings.ReplaceAll(trimmed, " ", "")
		trimmed = strings.ReplaceAll(trimmed, "\t", "")
		trimmed = strings.ReplaceAll(trimmed, ",", "")
		trimmed = strings.ReplaceAll(trimmed, "-", "")
		trimmed = strings.ReplaceAll(trimmed, ";", "")
		trimmed = strings.ReplaceAll(trimmed, "\"", "")
		trimmed = strings.ReplaceAll(trimmed, "'", "")

		// Validasi karakter hanya hex
		for _, r := range trimmed {
			if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
				hexBytes.WriteRune(r)
			}
		}
	}

	cleanedHex := hexBytes.String()
	if len(cleanedHex) == 0 {
		return nil, fmt.Errorf("tidak ditemukan karakter heksadesimal yang valid")
	}

	// Jika panjang ganjil, tambahkan 0 di depan byte terakhir
	if len(cleanedHex)%2 != 0 {
		cleanedHex = cleanedHex[:len(cleanedHex)-1] + "0" + cleanedHex[len(cleanedHex)-1:]
	}

	decoded, err := hex.DecodeString(cleanedHex)
	if err != nil {
		return nil, fmt.Errorf("gagal men-decode hex: %w", err)
	}

	return decoded, nil
}

// GenerateHexDump menyusun tampilan hexdump 16-byte kanonikal
func GenerateHexDump(data []byte, maxBytes int) string {
	if len(data) == 0 {
		return ""
	}
	limit := len(data)
	if maxBytes > 0 && limit > maxBytes {
		limit = maxBytes
	}

	var sb strings.Builder
	for offset := 0; offset < limit; offset += 16 {
		chunkEnd := offset + 16
		if chunkEnd > limit {
			chunkEnd = limit
		}
		chunk := data[offset:chunkEnd]

		// Format Offset
		sb.WriteString(fmt.Sprintf("%08X  ", offset))

		// Format Hex Bytes (16 kolom dengan pemisah di tengah)
		for i := 0; i < 16; i++ {
			if i == 8 {
				sb.WriteString(" ")
			}
			if i < len(chunk) {
				sb.WriteString(fmt.Sprintf("%02X ", chunk[i]))
			} else {
				sb.WriteString("   ")
			}
		}

		// Format ASCII Printable
		sb.WriteString(" |")
		for _, b := range chunk {
			if b >= 32 && b <= 126 {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}

	if limit < len(data) {
		sb.WriteString(fmt.Sprintf("... (%d bytes berikutnya tidak ditampilkan)\n", len(data)-limit))
	}

	return sb.String()
}

// DetectShellcodePatterns mencari pola shellcode, NOP sleds, dan call/pop GetPC
func DetectShellcodePatterns(data []byte) []common.ShellcodeFinding {
	var findings []common.ShellcodeFinding

	// 1. NOP Sled Detection (0x90 berurutan >= 8 byte)
	nopCount := 0
	nopStart := -1
	for i, b := range data {
		if b == 0x90 {
			if nopCount == 0 {
				nopStart = i
			}
			nopCount++
		} else {
			if nopCount >= 8 {
				findings = append(findings, common.ShellcodeFinding{
					Offset:      int64(nopStart),
					Type:        "NOP_Sled",
					Description: fmt.Sprintf("Deteksi NOP sled (0x90) berurutan sepanjang %d bytes (indikasi shellcode landing pad)", nopCount),
					Snippet:     fmt.Sprintf("0x90 repeated %d times at offset 0x%X", nopCount, nopStart),
				})
			}
			nopCount = 0
		}
	}
	if nopCount >= 8 {
		findings = append(findings, common.ShellcodeFinding{
			Offset:      int64(nopStart),
			Type:        "NOP_Sled",
			Description: fmt.Sprintf("Deteksi NOP sled (0x90) berurutan sepanjang %d bytes di akhir buffer", nopCount),
			Snippet:     fmt.Sprintf("0x90 repeated %d times at offset 0x%X", nopCount, nopStart),
		})
	}

	// 2. GetPC Technique (call $+5; pop reg)
	// x86 call next instruction (E8 00 00 00 00) diikuti oleh pop reg (58-5F)
	for i := 0; i < len(data)-5; i++ {
		if data[i] == 0xE8 && data[i+1] == 0x00 && data[i+2] == 0x00 && data[i+3] == 0x00 && data[i+4] == 0x00 {
			nextByte := data[i+5]
			if nextByte >= 0x58 && nextByte <= 0x5F { // pop eax ... pop edi
				findings = append(findings, common.ShellcodeFinding{
					Offset:      int64(i),
					Type:        "GetPC_CallPop",
					Description: "Deteksi teknik GetPC (call $+5; pop register) untuk kalkulasi runtime relative address pada position-independent shellcode",
					Snippet:     fmt.Sprintf("Opcode: E8 00 00 00 00 %02X at offset 0x%X", nextByte, i),
				})
			}
		}
	}

	// 3. PEB Traversal Patterns (Mencari basis kernel32 via Process Environment Block)
	// x86: mov eax, fs:[0x30] -> 64 A1 30 00 00 00
	pebX86 := []byte{0x64, 0xA1, 0x30, 0x00, 0x00, 0x00}
	if idx := bytes.Index(data, pebX86); idx != -1 {
		findings = append(findings, common.ShellcodeFinding{
			Offset:      int64(idx),
			Type:        "PEB_Traversal",
			Description: "Deteksi instruksi x86 PEB lookup (mov eax, fs:[0x30]) untuk resolusi fungsi API dynamically tanpa import table",
			Snippet:     fmt.Sprintf("fs:[0x30] lookup at offset 0x%X", idx),
		})
	}

	// x64: mov rax, gs:[0x60] -> 65 48 8B 04 25 60 00 00 00 atau 65 48 8B
	pebX64 := []byte{0x65, 0x48, 0x8B}
	for i := 0; i < len(data)-8; i++ {
		if bytes.Equal(data[i:i+3], pebX64) && data[i+3] == 0x04 && data[i+4] == 0x25 && data[i+5] == 0x60 {
			findings = append(findings, common.ShellcodeFinding{
				Offset:      int64(i),
				Type:        "PEB_Traversal",
				Description: "Deteksi instruksi x64 PEB lookup (mov rax, gs:[0x60]) untuk locating InLoadOrderModuleList",
				Snippet:     fmt.Sprintf("gs:[0x60] lookup at offset 0x%X", i),
			})
			break
		}
	}

	// 4. Direct Syscall Sequences (0x0F 0x05)
	syscallSig := []byte{0x0F, 0x05}
	idx := 0
	foundSyscalls := 0
	for {
		pos := bytes.Index(data[idx:], syscallSig)
		if pos == -1 || foundSyscalls >= 3 {
			break
		}
		findings = append(findings, common.ShellcodeFinding{
			Offset:      int64(idx + pos),
			Type:        "Syscall_Sequence",
			Description: "Deteksi instruksi direct syscall (0x0F 0x05) yang biasa dipakai malware untuk mem-bypass EDR/AV user-mode hooks",
			Snippet:     fmt.Sprintf("Direct syscall at offset 0x%X", idx+pos),
		})
		foundSyscalls++
		idx += pos + 2
	}

	return findings
}

// BruteForceXOR melakukan deobfuscasi XOR 1-byte (0x01-0xFF) dan mencari string target
func BruteForceXOR(data []byte) []common.XORCandidate {
	var candidates []common.XORCandidate
	if len(data) == 0 {
		return candidates
	}

	buf := make([]byte, len(data))
	for key := 1; key <= 255; key++ {
		k := byte(key)
		for i, b := range data {
			buf[i] = b ^ k
		}

		decodedStr := string(buf)
		decodedLower := strings.ToLower(decodedStr)

		for _, target := range xorTargets {
			if strings.Contains(decodedLower, strings.ToLower(target)) {
				// Ambil sampel potongan teks sekitar string yang cocok
				idx := strings.Index(decodedLower, strings.ToLower(target))
				start := idx - 10
				if start < 0 {
					start = 0
				}
				end := idx + len(target) + 30
				if end > len(decodedStr) {
					end = len(decodedStr)
				}
				sample := sanitizePrintable(decodedStr[start:end])

				candidates = append(candidates, common.XORCandidate{
					KeyHex:      fmt.Sprintf("0x%02X", k),
					KeyByte:     k,
					MatchedWord: target,
					SampleText:  sample,
				})
				break
			}
		}
	}

	return candidates
}

func sanitizePrintable(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('.')
		}
	}
	return sb.String()
}

// AnalyzeHexData melakukan analisis mendalam terhadap input string kode hex
func AnalyzeHexData(sourceName string, hexInput string) (common.HexAnalysisReport, error) {
	decoded, err := NormalizeAndDecodeHex(hexInput)
	if err != nil {
		return common.HexAnalysisReport{}, err
	}

	report := common.HexAnalysisReport{
		InputSource:       sourceName,
		ByteLength:        len(decoded),
		Entropy:           common.CalculateShannonEntropy(decoded),
		Hashes:            common.ComputeBufferHashes(decoded),
		HexDumpPreview:    GenerateHexDump(decoded, 160), // 10 baris pertama
		ShellcodeFindings: DetectShellcodePatterns(decoded),
		XORDeobfuscation:  BruteForceXOR(decoded),
		ThreatsDetected:   make([]string, 0),
	}

	// Ekstraksi string dari decoded byte
	var strList []string
	var cur []rune
	for _, b := range decoded {
		if b >= 32 && b <= 126 {
			cur = append(cur, rune(b))
		} else {
			if len(cur) >= 4 {
				strList = append(strList, string(cur))
			}
			cur = cur[:0]
		}
	}
	if len(cur) >= 4 {
		strList = append(strList, string(cur))
	}

	report.IOCs = common.ExtractIOCsFromText(strList)

	// Hitung skor risiko
	score := 0
	if len(report.ShellcodeFindings) > 0 {
		score += len(report.ShellcodeFindings) * 25
		for _, f := range report.ShellcodeFindings {
			report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Shellcode Signature: %s (%s)", f.Type, f.Description))
		}
	}

	if len(report.XORDeobfuscation) > 0 {
		score += 30
		report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("XOR Obfuscation Terdeteksi: Payload didecode dengan key %s (Keyword: '%s')",
			report.XORDeobfuscation[0].KeyHex, report.XORDeobfuscation[0].MatchedWord))
	}

	if report.Entropy > 7.1 {
		score += 20
		report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Entropi Tinggi (%.2f): Payload kemungkinan terenkripsi atau terkompresi", report.Entropy))
	}

	if len(report.IOCs.URLs) > 0 || len(report.IOCs.IPv4Addresses) > 0 {
		score += 20
	}

	report.RiskScore = score
	report.RiskLevel = common.CalculateRiskLevel(score)

	return report, nil
}

// AnalyzeHexFile membaca file (bisa file .hex, .txt, atau binary raw) dan menganalisisnya
func AnalyzeHexFile(filePath string) (common.HexAnalysisReport, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return common.HexAnalysisReport{}, err
	}

	// Cek apakah isi file merupakan teks hex atau raw binary bytes
	isAsciiHex := true
	for _, b := range content[:min(len(content), 1024)] {
		if b != '\r' && b != '\n' && b != '\t' && b != ' ' && b != ',' && b != 'x' && b != 'X' &&
			!((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			isAsciiHex = false
			break
		}
	}

	if isAsciiHex {
		return AnalyzeHexData(filePath, string(content))
	}

	// Jika file raw bytes, langsung encode ke hex string lalu analisis
	hexStr := hex.EncodeToString(content)
	return AnalyzeHexData(filePath, hexStr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

package memdump

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"forensic-repo-analyzer/pkg/common"
)

const (
	ChunkSize   = 4 * 1024 * 1024 // 4MB buffer untuk streaming cepat tanpa boros RAM
	OverlapSize = 8 * 1024        // 8KB overlap untuk mencegah string terpotong di perbatasan chunk
	MaxStrings  = 100000          // Batas maksimum string untuk ekstraksi IOC
)

// SuspiciousCmdPatterns command line mencurigakan yang sering tertinggal di RAM
var SuspiciousCmdPatterns = []struct {
	Pattern string
	Desc    string
	Risk    int
}{
	{strings.Join([]string{"powershell", ".exe -enc"}, ""), "Encoded PowerShell Execution", 35},
	{strings.Join([]string{"powershell", " -w hidden"}, ""), "Hidden PowerShell Window Spawn", 30},
	{strings.Join([]string{"cmd.exe", " /c start /min"}, ""), "Hidden Minimized Command Prompt", 20},
	{strings.Join([]string{"vssadmin", " delete", " shadows"}, ""), "Ransomware Shadow Copy Deletion", 45},
	{strings.Join([]string{"wbadmin", " delete", " catalog"}, ""), "Ransomware Backup Wipe", 40},
	{strings.Join([]string{"bcdedit", " /set", " bootstatuspolicy"}, ""), "Ransomware Boot Policy Tampering", 40},
	{strings.Join([]string{"whoami", " /all"}, ""), "Privilege Reconnaissance Command", 20},
	{strings.Join([]string{"net", " user", " /add"}, ""), "Unauthorized Account Creation", 35},
	{strings.Join([]string{"net", " localgroup", " administrators"}, ""), "Privilege Escalation to Admin", 40},
	{strings.Join([]string{"nltest", " /dclist:"}, ""), "Domain Controller Reconnaissance", 25},
	{strings.Join([]string{"mimi", "katz"}, ""), "Mimikatz In-Memory Credential Dump", 45},
	{strings.Join([]string{"sekurlsa", "::logonpasswords"}, ""), "LSASS Password Dump Command", 50},
	{strings.Join([]string{"procdump", " lsass"}, ""), "LSASS Memory Dump Attempt", 50},
}

// AnalyzeMemoryDump melakukan investigasi streaming terhadap file dump memori
func AnalyzeMemoryDump(filePath string) (common.MemAnalysisReport, error) {
	startTime := time.Now()

	meta, err := common.GetFileMetadata(filePath)
	if err != nil {
		return common.MemAnalysisReport{}, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return common.MemAnalysisReport{}, err
	}
	defer file.Close()

	report := common.MemAnalysisReport{
		Metadata:        meta,
		RiskScore:       0,
		ThreatsDetected: make([]string, 0),
		Artifacts:       make([]common.MemoryArtifact, 0),
	}

	// Buffer streaming
	buf := make([]byte, ChunkSize)
	var fileOffset int64 = 0
	var allExtractedStrings []string
	foundPEHeaders := 0

	for {
		n, err := file.Read(buf)
		if n == 0 {
			break
		}

		chunk := buf[:n]

		// 1. Scan Embedded PE Header (In-memory payload / injected DLL)
		peOffsets := findEmbeddedPEHeaders(chunk)
		for _, relOff := range peOffsets {
			absOff := fileOffset + int64(relOff)
			foundPEHeaders++
			if foundPEHeaders <= 10 {
				report.Artifacts = append(report.Artifacts, common.MemoryArtifact{
					Type:        "Embedded_PE_Header",
					Offset:      absOff,
					Description: "Ditemukan header executable PE (MZ) dalam memory dump (indikasi Process Hollowing / DLL Injection)",
					Snippet:     fmt.Sprintf("MZ Header at physical memory offset: 0x%X", absOff),
				})
			}
		}

		// 2. Ekstrak string ASCII dan UTF-16LE dari chunk
		if len(allExtractedStrings) < MaxStrings {
			extracted := extractChunkStrings(chunk, 5)
			allExtractedStrings = append(allExtractedStrings, extracted...)
		}

		// Mundur sedikit untuk chunk overlap (jika bukan akhir file)
		if n == ChunkSize {
			fileOffset += int64(n - OverlapSize)
			file.Seek(fileOffset, io.SeekStart)
		} else {
			fileOffset += int64(n)
		}

		if err != nil {
			break
		}
	}

	if foundPEHeaders > 0 {
		report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Ditemukan %d embedded PE executable signatures dalam memory dump", foundPEHeaders))
		report.RiskScore += 35
	}

	report.TotalStrings = len(allExtractedStrings)

	// 3. Scan command line dan pattern mencurigakan dari strings yang diekstrak
	scanSuspiciousMemoryStrings(&report, allExtractedStrings)

	// 4. Ekstrak IOC (IP, URL, Email, Domain, Credentials)
	report.IOCs = common.ExtractIOCsFromText(allExtractedStrings)
	if len(report.IOCs.IPv4Addresses) > 0 {
		report.RiskScore += len(report.IOCs.IPv4Addresses) * 3
	}
	if len(report.IOCs.URLs) > 0 {
		report.RiskScore += len(report.IOCs.URLs) * 4
	}
	if len(report.IOCs.TokensOrKeys) > 0 {
		report.RiskScore += 25
		report.ThreatsDetected = append(report.ThreatsDetected, "Ditemukan kredensial / private key / token dalam memory dump")
	}

	report.ScanDurationSec = time.Since(startTime).Seconds()
	report.RiskLevel = common.CalculateRiskLevel(report.RiskScore)

	return report, nil
}

// findEmbeddedPEHeaders mencari signature 'MZ' yang valid dengan PE signature di e_lfanew
func findEmbeddedPEHeaders(chunk []byte) []int {
	var offsets []int
	mzSig := []byte{'M', 'Z'}

	idx := 0
	for {
		pos := bytes.Index(chunk[idx:], mzSig)
		if pos == -1 {
			break
		}

		actualPos := idx + pos
		if actualPos+64 < len(chunk) {
			eLfanew := int(chunk[actualPos+0x3C]) |
				int(chunk[actualPos+0x3D])<<8 |
				int(chunk[actualPos+0x3E])<<16 |
				int(chunk[actualPos+0x3F])<<24

			if eLfanew >= 64 && eLfanew < 1024 && actualPos+eLfanew+4 < len(chunk) {
				peSig := chunk[actualPos+eLfanew : actualPos+eLfanew+4]
				if bytes.Equal(peSig, []byte{'P', 'E', 0x00, 0x00}) {
					offsets = append(offsets, actualPos)
				}
			}
		}

		idx = actualPos + 2
		if idx >= len(chunk) {
			break
		}
	}

	return offsets
}

// extractChunkStrings mengekstrak printable ASCII dan UTF-16LE dari chunk byte
func extractChunkStrings(chunk []byte, minLen int) []string {
	var results []string
	var current []byte

	flush := func() {
		if len(current) >= minLen {
			results = append(results, string(current))
		}
		current = current[:0]
	}

	// 1. ASCII Scan
	for i := 0; i < len(chunk); i++ {
		b := chunk[i]
		if b >= 32 && b <= 126 {
			current = append(current, b)
		} else {
			flush()
		}
	}
	flush()

	// 2. UTF-16LE Scan
	for i := 0; i < len(chunk)-1; i += 2 {
		if chunk[i+1] == 0x00 && chunk[i] >= 32 && chunk[i] <= 126 {
			current = append(current, chunk[i])
		} else {
			flush()
		}
	}
	flush()

	return results
}

// scanSuspiciousMemoryStrings mendeteksi command line atau malware strings di RAM
func scanSuspiciousMemoryStrings(report *common.MemAnalysisReport, stringsList []string) {
	seenArtifact := make(map[string]bool)

	for _, s := range stringsList {
		sLower := strings.ToLower(s)
		for _, pat := range SuspiciousCmdPatterns {
			if strings.Contains(sLower, strings.ToLower(pat.Pattern)) {
				if !seenArtifact[pat.Pattern] {
					seenArtifact[pat.Pattern] = true
					report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Memory Artifact: %s (Matched: '%s')", pat.Desc, s))
					report.RiskScore += pat.Risk
					report.Artifacts = append(report.Artifacts, common.MemoryArtifact{
						Type:        "Suspicious_Execution",
						Description: pat.Desc,
						Snippet:     s,
					})
				}
			}
		}
	}
}

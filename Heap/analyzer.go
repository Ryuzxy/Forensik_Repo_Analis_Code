package heapanalyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"

	"forensic-repo-analyzer/pkg/common"
)

// Magic signatures Windows Heap & Debugging
var heapSignatures = []struct {
	Name        string
	PatternLE   []byte
	PatternBE   []byte
	HexStr      string
	Severity    string
	Description string
}{
	{
		Name:        "Uninitialized Heap Memory",
		PatternLE:   []byte{0x0D, 0xF0, 0xAD, 0xBA},
		PatternBE:   []byte{0xBA, 0xAD, 0xF0, 0x0D},
		HexStr:      "0xBAADF00D",
		Severity:    "MEDIUM",
		Description: "Blok memori heap Windows yang dialokasikan oleh LocalAlloc/HeapAlloc namun belum diinisialisasi",
	},
	{
		Name:        "Freed Heap Memory",
		PatternLE:   []byte{0xEE, 0xFE, 0xEE, 0xFE},
		PatternBE:   []byte{0xFE, 0xEE, 0xFE, 0xEE},
		HexStr:      "0xFEEEFEEE",
		Severity:    "HIGH",
		Description: "Blok heap yang telah di-free (indikasi analisis Use-After-Free / Double Free)",
	},
	{
		Name:        "Heap Guard Boundary",
		PatternLE:   []byte{0xAB, 0xAB, 0xAB, 0xAB},
		PatternBE:   []byte{0xAB, 0xAB, 0xAB, 0xAB},
		HexStr:      "0xABABABAB",
		Severity:    "LOW",
		Description: "Guard byte penanda batas akhir alokasi heap CRT/Windows",
	},
	{
		Name:        "Uninitialized Stack/CRT Debug",
		PatternLE:   []byte{0xCC, 0xCC, 0xCC, 0xCC},
		PatternBE:   []byte{0xCC, 0xCC, 0xCC, 0xCC},
		HexStr:      "0xCCCCCCCC",
		Severity:    "LOW",
		Description: "Buffer filler debug Microsoft Visual C++ untuk mendeteksi uninitialized memory",
	},
	{
		Name:        "NoMansLand Heap Buffer",
		PatternLE:   []byte{0xFD, 0xFD, 0xFD, 0xFD},
		PatternBE:   []byte{0xFD, 0xFD, 0xFD, 0xFD},
		HexStr:      "0xFDFDFDFD",
		Severity:    "MEDIUM",
		Description: "Guard page pembatas sebelum dan sesudah alokasi memori heap",
	},
	{
		Name:        "Poisoned / Crash Marker",
		PatternLE:   []byte{0xEF, 0xBE, 0xAD, 0xDE},
		PatternBE:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
		HexStr:      "0xDEADBEEF",
		Severity:    "HIGH",
		Description: "Nilai penanda crash, invalid pointer, atau memory poisoning",
	},
}

var (
	httpHeaderRegex = regexp.MustCompile(`(?i)(?:GET|POST|PUT|DELETE|HEAD)\s+[^\r\n]+\s+HTTP/[0-9\.]+|Authorization:\s*Bearer\s+[A-Za-z0-9_\-\.]+|Set-Cookie:\s*[^\r\n]+|Cookie:\s*[^\r\n]+`)
	jsonBlockRegex  = regexp.MustCompile(`\{[^{}]{10,500}\}`)
)

// AnalyzeHeapFile melakukan analisis mendalam terhadap file dump heap memori
func AnalyzeHeapFile(filePath string) (common.HeapAnalysisReport, error) {
	meta, err := common.GetFileMetadata(filePath)
	if err != nil {
		return common.HeapAnalysisReport{}, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return common.HeapAnalysisReport{}, err
	}
	defer file.Close()

	report := common.HeapAnalysisReport{
		Metadata:        meta,
		HeapPatterns:    make([]common.HeapPatternFinding, 0),
		CarvedHTTP:      make([]string, 0),
		CarvedJSON:      make([]string, 0),
		ThreatsDetected: make([]string, 0),
	}

	// Buffer streaming
	buf := make([]byte, 1024*1024) // 1MB buffer
	var fileOffset int64 = 0
	var allExtractedStrings []string

	// Counters untuk heap signatures
	sigCounts := make(map[string]int)
	sigFirstOffset := make(map[string]int64)

	// Heap spray detector trackers
	var sprayRepeats int
	var sprayValue byte
	var maxSprayLen int

	for {
		n, err := file.Read(buf)
		if n == 0 {
			break
		}
		chunk := buf[:n]

		// 1. Scan Windows Heap Magic Signatures
		for _, sig := range heapSignatures {
			idx := 0
			for {
				pLE := bytes.Index(chunk[idx:], sig.PatternLE)
				pBE := bytes.Index(chunk[idx:], sig.PatternBE)
				pos := -1
				if pLE != -1 && pBE != -1 {
					if pLE < pBE {
						pos = pLE
					} else {
						pos = pBE
					}
				} else if pLE != -1 {
					pos = pLE
				} else if pBE != -1 {
					pos = pBE
				}

				if pos == -1 {
					break
				}

				absPos := fileOffset + int64(idx+pos)
				sigCounts[sig.HexStr]++
				if _, exists := sigFirstOffset[sig.HexStr]; !exists {
					sigFirstOffset[sig.HexStr] = absPos
				}

				idx += pos + 4
				if idx >= len(chunk) {
					break
				}
			}
		}

		// 2. Scan Heap Spraying Heuristics (blok berulang panjang dengan pola pointer umum exploit, misal 0x0C, 0x0D, 0x90)
		for _, b := range chunk {
			if b == sprayValue && (b == 0x0C || b == 0x0D || b == 0x90 || b == 0x08) {
				sprayRepeats++
				if sprayRepeats > maxSprayLen {
					maxSprayLen = sprayRepeats
				}
			} else {
				sprayValue = b
				sprayRepeats = 1
			}
		}

		// 3. Ekstrak string & carve data terstruktur
		extracted := extractStrings(chunk, 6)
		if len(allExtractedStrings) < 20000 {
			allExtractedStrings = append(allExtractedStrings, extracted...)
		}

		// Carve HTTP headers
		httpMatches := httpHeaderRegex.FindAllString(string(chunk), -1)
		for _, m := range httpMatches {
			if len(report.CarvedHTTP) < 25 && !contains(report.CarvedHTTP, m) {
				report.CarvedHTTP = append(report.CarvedHTTP, m)
			}
		}

		// Carve JSON fragments
		jsonMatches := jsonBlockRegex.FindAllString(string(chunk), -1)
		for _, j := range jsonMatches {
			if len(report.CarvedJSON) < 15 && isValidJSON(j) && !contains(report.CarvedJSON, j) {
				report.CarvedJSON = append(report.CarvedJSON, j)
			}
		}

		fileOffset += int64(n)
		if err != nil && err == io.EOF {
			break
		}
	}

	// Ringkas temuan heap patterns
	for _, sig := range heapSignatures {
		if count := sigCounts[sig.HexStr]; count > 0 {
			report.HeapPatterns = append(report.HeapPatterns, common.HeapPatternFinding{
				PatternName: sig.Name,
				HexValue:    sig.HexStr,
				Count:       count,
				FirstOffset: sigFirstOffset[sig.HexStr],
				Description: sig.Description,
				Severity:    sig.Severity,
			})

			if sig.Severity == "HIGH" {
				report.ThreatsDetected = append(report.ThreatsDetected,
					fmt.Sprintf("Ditemukan %d instance marker '%s' (%s) pada offset awal 0x%X", count, sig.HexStr, sig.Name, sigFirstOffset[sig.HexStr]))
				report.RiskScore += 25
			} else if sig.Severity == "MEDIUM" {
				report.RiskScore += 10
			}
		}
	}

	// Deteksi Heap Spray
	if maxSprayLen >= 4096 {
		report.HeapSprayDetected = true
		report.HeapSprayDetails = fmt.Sprintf("Ditemukan perulangan byte 0x%02X sepanjang %d bytes secara kontinu (indikasi Heap Spraying Exploit)", sprayValue, maxSprayLen)
		report.ThreatsDetected = append(report.ThreatsDetected, report.HeapSprayDetails)
		report.RiskScore += 40
	}

	if len(report.CarvedHTTP) > 0 {
		report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Ditemukan %d potongan HTTP Header/Authorization token dalam heap", len(report.CarvedHTTP)))
		report.RiskScore += 15
	}

	// Ekstrak IOC
	report.IOCs = common.ExtractIOCsFromText(allExtractedStrings)
	if len(report.IOCs.IPv4Addresses) > 0 {
		report.RiskScore += len(report.IOCs.IPv4Addresses) * 3
	}
	if len(report.IOCs.URLs) > 0 {
		report.RiskScore += len(report.IOCs.URLs) * 4
	}

	report.RiskLevel = common.CalculateRiskLevel(report.RiskScore)

	return report, nil
}

func extractStrings(data []byte, minLen int) []string {
	var result []string
	var cur []byte

	flush := func() {
		if len(cur) >= minLen {
			result = append(result, string(cur))
		}
		cur = cur[:0]
	}

	for _, b := range data {
		if b >= 32 && b <= 126 {
			cur = append(cur, b)
		} else {
			flush()
		}
	}
	flush()
	return result
}

func isValidJSON(s string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(s), &js) == nil
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

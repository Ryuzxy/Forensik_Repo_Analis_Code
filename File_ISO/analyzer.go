package fileiso

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"forensic-repo-analyzer/pkg/common"
)

const (
	SectorSize     = 2048
	PVDOffset      = 16 * SectorSize // Sektor 16
	ISOStandardID  = "CD001"
)

// Suspicious extensions sering dikemas dalam ISO untuk bypass Mark-of-the-Web (MOTW)
var dangerousExtensions = map[string]struct {
	Category string
	Risk     int
	Reason   string
}{
	".exe": {"Executable", 40, "Direct Windows executable file"},
	".lnk": {"Shortcut", 35, "Windows Shortcut, sering memicu eksekusi payload tersembunyi"},
	".bat": {"Script", 35, "Windows Batch script"},
	".cmd": {"Script", 35, "Windows Command script"},
	".vbs": {"Script", 40, "VBScript, sering dipakai malware dropper"},
	".js":  {"Script", 35, "JavaScript file runnable by WScript/CScript"},
	".hta": {"Script", 45, "HTML Application executed via mshta.exe"},
	".scr": {"Executable", 40, "Screensaver binary (ekivalen dengan .exe)"},
	".dll": {"Library", 30, "Dynamic Link Library yang potensial di-load via DLL side-loading"},
	".ps1": {"Script", 40, "PowerShell script"},
	".iso": {"Archive", 20, "Nested ISO inside ISO"},
}

// AnalyzeISOFile melakukan investigasi forensik file ISO Disk Image
func AnalyzeISOFile(filePath string) (common.ISOAnalysisReport, error) {
	meta, err := common.GetFileMetadata(filePath)
	if err != nil {
		return common.ISOAnalysisReport{}, err
	}

	file, err := os.Open(filePath)
	if err != nil {
		return common.ISOAnalysisReport{}, err
	}
	defer file.Close()

	report := common.ISOAnalysisReport{
		Metadata:        meta,
		RiskScore:       0,
		ThreatsDetected: make([]string, 0),
		Files:           make([]common.ISOEntry, 0),
		SuspiciousFiles: make([]common.ISOEntry, 0),
	}

	// 1. Baca Primary Volume Descriptor (PVD)
	pvdBuf := make([]byte, SectorSize)
	_, err = file.ReadAt(pvdBuf, PVDOffset)
	if err != nil {
		return report, fmt.Errorf("gagal membaca sektor PVD ISO: %w", err)
	}

	if string(pvdBuf[1:6]) != ISOStandardID {
		report.Metadata.FileType = "Raw Disk Image (Non-ISO 9660)"
		report.ThreatsDetected = append(report.ThreatsDetected, "File bukan standar ISO 9660 CD001 (mungkin format UDF/Raw)")
		evaluateISORisk(&report)
		return report, nil
	}

	report.Metadata.FileType = "ISO 9660 Disk Image"
	parsePVD(&report, pvdBuf)

	// 2. Baca Root Directory Record (dimulai di offset 156 di PVD)
	rootDirRecord := pvdBuf[156:190]
	rootExtent := binary.LittleEndian.Uint32(rootDirRecord[2:6])
	rootSize := binary.LittleEndian.Uint32(rootDirRecord[10:14])

	// 3. Jelajahi direktori dan file dalam ISO
	readDirectory(file, rootExtent, rootSize, "/", &report)

	// 4. Deteksi anomali umum serangan phishing MOTW bypass
	inspectSuspiciousDeliveryTechniques(&report)

	// 5. Evaluasi skor risiko
	evaluateISORisk(&report)

	return report, nil
}

// parsePVD mengekstrak metadata dari Primary Volume Descriptor
func parsePVD(report *common.ISOAnalysisReport, pvd []byte) {
	cleanString := func(b []byte) string {
		return strings.TrimSpace(string(bytes.Trim(b, "\x00 ")))
	}

	vol := &report.VolumeInfo
	vol.SystemID = cleanString(pvd[8:40])
	vol.VolumeID = cleanString(pvd[40:72])
	vol.VolumeSpaceSize = binary.LittleEndian.Uint32(pvd[80:84])
	vol.LogicalBlockSize = binary.LittleEndian.Uint16(pvd[128:130])
	vol.VolumeSetID = cleanString(pvd[190:318])
	vol.PublisherID = cleanString(pvd[318:446])
	vol.DataPreparerID = cleanString(pvd[446:574])
	vol.ApplicationID = cleanString(pvd[574:702])

	vol.CreationTime = parseISODateTime(string(pvd[813:830]))
	vol.ModificationTime = parseISODateTime(string(pvd[830:847]))
}

// parseISODateTime mengubah format string ISO 9660 'YYYYMMDDHHMMSScc' ke time.Time
func parseISODateTime(s string) time.Time {
	if len(s) < 14 {
		return time.Time{}
	}
	year, _ := strconv.Atoi(s[0:4])
	month, _ := strconv.Atoi(s[4:6])
	day, _ := strconv.Atoi(s[6:8])
	hour, _ := strconv.Atoi(s[8:10])
	min, _ := strconv.Atoi(s[10:12])
	sec, _ := strconv.Atoi(s[12:14])

	return time.Date(year, time.Month(month), day, hour, min, sec, 0, time.UTC)
}

// parseDirectoryRecordDate membaca 7-byte tanggal pada directory record
func parseDirectoryRecordDate(d []byte) time.Time {
	if len(d) < 7 {
		return time.Time{}
	}
	year := int(d[0]) + 1900
	month := int(d[1])
	day := int(d[2])
	hour := int(d[3])
	min := int(d[4])
	sec := int(d[5])

	return time.Date(year, time.Month(month), day, hour, min, sec, 0, time.UTC)
}

// readDirectory membaca dan mengurai entri direktori ISO secara rekursif
func readDirectory(file *os.File, extentBlock uint32, sizeBytes uint32, currentPath string, report *common.ISOAnalysisReport) {
	if extentBlock == 0 || sizeBytes == 0 {
		return
	}

	buf := make([]byte, sizeBytes)
	_, err := file.ReadAt(buf, int64(extentBlock)*int64(SectorSize))
	if err != nil && err != io.EOF {
		return
	}

	var offset uint32
	for offset < sizeBytes {
		sectorRemaining := SectorSize - (offset % SectorSize)
		if sectorRemaining < 34 {
			offset += sectorRemaining
			continue
		}

		recordLen := uint32(buf[offset])
		if recordLen == 0 {
			offset += sectorRemaining
			continue
		}

		if offset+recordLen > sizeBytes {
			break
		}

		record := buf[offset : offset+recordLen]
		fileExtent := binary.LittleEndian.Uint32(record[2:6])
		fileDataLen := binary.LittleEndian.Uint32(record[10:14])
		fileDate := parseDirectoryRecordDate(record[18:25])
		fileFlags := record[25]
		isDir := (fileFlags & 0x02) != 0
		isHidden := (fileFlags & 0x01) != 0

		nameLen := int(record[32])
		if 33+nameLen <= int(recordLen) {
			rawName := record[33 : 33+nameLen]
			var entryName string

			if len(rawName) == 1 && rawName[0] == 0x00 {
				entryName = "."
			} else if len(rawName) == 1 && rawName[0] == 0x01 {
				entryName = ".."
			} else {
				entryName = string(rawName)
				if idx := strings.Index(entryName, ";"); idx != -1 {
					entryName = entryName[:idx]
				}
			}

			if entryName != "." && entryName != ".." {
				fullPath := filepath.ToSlash(filepath.Join(currentPath, entryName))
				ext := strings.ToLower(filepath.Ext(entryName))

				isSuspicious := false
				var reason string

				if !isDir {
					report.TotalFiles++
					if sig, dangerous := dangerousExtensions[ext]; dangerous {
						isSuspicious = true
						reason = fmt.Sprintf("High Risk Extension: %s (%s)", ext, sig.Reason)
						report.RiskScore += sig.Risk
						report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Suspicious file in ISO: '%s' (%s)", fullPath, reason))
					}

					parts := strings.Split(entryName, ".")
					if len(parts) > 2 {
						isSuspicious = true
						reason += " [Double Extension Detected]"
						report.RiskScore += 25
						report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Double extension trick detected: '%s'", entryName))
					}

					if isHidden {
						isSuspicious = true
						reason += " [Hidden File Flag Set]"
						report.RiskScore += 15
						report.ThreatsDetected = append(report.ThreatsDetected, fmt.Sprintf("Hidden file flag in ISO: '%s'", fullPath))
					}
				} else {
					report.TotalDirs++
				}

				entry := common.ISOEntry{
					Path:         fullPath,
					Name:         entryName,
					IsDir:        isDir,
					Size:         int64(fileDataLen),
					ModTime:      fileDate,
					IsSuspicious: isSuspicious,
					Reason:       reason,
				}

				report.Files = append(report.Files, entry)
				if isSuspicious {
					report.SuspiciousFiles = append(report.SuspiciousFiles, entry)
				}

				if isDir && fileExtent != extentBlock && strings.Count(fullPath, "/") < 8 {
					readDirectory(file, fileExtent, fileDataLen, fullPath, report)
				}
			}
		}

		offset += recordLen
	}
}

// inspectSuspiciousDeliveryTechniques mencari karakteristik ISO malware delivery (MOTW bypass)
func inspectSuspiciousDeliveryTechniques(report *common.ISOAnalysisReport) {
	var hasLNK bool
	var hasEXE bool
	var hasDLL bool

	for _, f := range report.SuspiciousFiles {
		ext := strings.ToLower(filepath.Ext(f.Name))
		if ext == ".lnk" {
			hasLNK = true
		}
		if ext == ".exe" || ext == ".scr" {
			hasEXE = true
		}
		if ext == ".dll" {
			hasDLL = true
		}
	}

	if hasLNK && (hasDLL || hasEXE) {
		report.ThreatsDetected = append(report.ThreatsDetected, "CRITICAL: Pola Phishing Terdeteksi (ISO berisi Shortcut .LNK + Binary/DLL untuk DLL Sideloading/MOTW Bypass)")
		report.RiskScore += 40
	}
}

// evaluateISORisk menghitung kategori risiko ISO
func evaluateISORisk(report *common.ISOAnalysisReport) {
	report.RiskLevel = common.CalculateRiskLevel(report.RiskScore)
}

package common

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	ipv4Regex       = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	urlRegex        = regexp.MustCompile(`https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'\(\)\*\+,;=%]+`)
	emailRegex      = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	domainRegex     = regexp.MustCompile(`\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|xyz|ru|cn|top|cc|info|biz|co|gov|edu)\b`)
	jwtRegex        = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	privKeyRegex    = regexp.MustCompile(`-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP)? ?PRIVATE KEY-----`)
	awsKeyRegex     = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	genericKeyRegex = regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|password|bearer|auth|token)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{8,64})`)
)

// ComputeFileHashes menghitung hash MD5, SHA1, SHA256 sekaligus dalam single pass streaming
func ComputeFileHashes(filePath string) (HashInfo, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return HashInfo{}, err
	}
	defer file.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()

	multi := io.MultiWriter(hMD5, hSHA1, hSHA256)
	buf := make([]byte, 64*1024)
	if _, err := io.CopyBuffer(multi, file, buf); err != nil {
		return HashInfo{}, err
	}

	return HashInfo{
		MD5:    hex.EncodeToString(hMD5.Sum(nil)),
		SHA1:   hex.EncodeToString(hSHA1.Sum(nil)),
		SHA256: hex.EncodeToString(hSHA256.Sum(nil)),
	}, nil
}

// ComputeBufferHashes menghitung hash MD5, SHA1, SHA256 dari byte slice
func ComputeBufferHashes(data []byte) HashInfo {
	hMD5 := md5.Sum(data)
	hSHA1 := sha1.Sum(data)
	hSHA256 := sha256.Sum256(data)

	return HashInfo{
		MD5:    hex.EncodeToString(hMD5[:]),
		SHA1:   hex.EncodeToString(hSHA1[:]),
		SHA256: hex.EncodeToString(hSHA256[:]),
	}
}

// DetectFileType mendeteksi jenis file berdasarkan magic bytes di header
func DetectFileType(header []byte) (fileType, mimeType string) {
	if len(header) >= 2 && header[0] == 'M' && header[1] == 'Z' {
		return "Windows Executable/DLL (PE)", "application/x-dosexec"
	}
	if len(header) >= 4 && bytes.Equal(header[:4], []byte{0x7F, 'E', 'L', 'F'}) {
		return "Linux Executable (ELF)", "application/x-elf"
	}
	if len(header) >= 4 && (bytes.Equal(header[:4], []byte{0xFE, 0xED, 0xFA, 0xCE}) ||
		bytes.Equal(header[:4], []byte{0xFE, 0xED, 0xFA, 0xCF}) ||
		bytes.Equal(header[:4], []byte{0xCE, 0xFA, 0xED, 0xFE}) ||
		bytes.Equal(header[:4], []byte{0xCF, 0xFA, 0xED, 0xFE})) {
		return "Mach-O Binary (macOS)", "application/x-mach-binary"
	}
	if len(header) >= 4 && bytes.Equal(header[:4], []byte{0x50, 0x4B, 0x03, 0x04}) {
		return "ZIP Archive", "application/zip"
	}
	if len(header) >= 4 && bytes.Equal(header[:4], []byte{0x52, 0x61, 0x72, 0x21}) {
		return "RAR Archive", "application/x-rar"
	}
	if len(header) >= 4 && bytes.Equal(header[:4], []byte{0x25, 0x50, 0x44, 0x46}) {
		return "PDF Document", "application/pdf"
	}
	if len(header) >= 4 && bytes.Equal(header[:4], []byte{0x4D, 0x44, 0x4D, 0x50}) {
		return "Windows Minidump (MDMP)", "application/x-dmp"
	}
	if len(header) >= 7 && bytes.Equal(header[:7], []byte{0x50, 0x41, 0x47, 0x45, 0x44, 0x55, 0x4D}) {
		return "Windows Full Memory Dump (PAGEDUMP)", "application/x-raw-memory"
	}

	return "Raw Binary / Data", "application/octet-stream"
}

// GetFileMetadata mengumpulkan informasi lengkap file
func GetFileMetadata(filePath string) (FileMetadata, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		return FileMetadata{}, err
	}

	hashes, err := ComputeFileHashes(filePath)
	if err != nil {
		return FileMetadata{}, err
	}

	entropy, _ := CalculateFileEntropy(filePath)

	header := make([]byte, 512)
	file, err := os.Open(filePath)
	if err == nil {
		file.Read(header)
		file.Close()
	}

	fileType, mimeType := DetectFileType(header)

	isPacked := entropy > 7.1

	return FileMetadata{
		FilePath: filePath,
		FileName: filepath.Base(filePath),
		FileSize: fi.Size(),
		ModTime:  fi.ModTime(),
		FileType: fileType,
		MimeType: mimeType,
		Hashes:   hashes,
		Entropy:  entropy,
		IsPacked: isPacked,
	}, nil
}

// ExtractIOCsFromText mengekstrak IP, URL, email, domain, and tokens dari kumpulan teks
func ExtractIOCsFromText(lines []string) IOCReport {
	var report IOCReport
	seenIP := make(map[string]bool)
	seenURL := make(map[string]bool)
	seenEmail := make(map[string]bool)
	seenDomain := make(map[string]bool)
	seenToken := make(map[string]bool)

	for _, line := range lines {
		if len(line) < 4 {
			continue
		}

		// IPv4
		ips := ipv4Regex.FindAllString(line, -1)
		for _, ip := range ips {
			// filter bogon / loopback / local zeros
			if strings.HasPrefix(ip, "0.") || ip == "255.255.255.255" {
				continue
			}
			parsed := net.ParseIP(ip)
			if parsed != nil && !seenIP[ip] {
				seenIP[ip] = true
				report.IPv4Addresses = append(report.IPv4Addresses, ip)
			}
		}

		// URLs
		urls := urlRegex.FindAllString(line, -1)
		for _, u := range urls {
			if !seenURL[u] && len(u) > 10 {
				seenURL[u] = true
				report.URLs = append(report.URLs, u)
			}
		}

		// Emails
		emails := emailRegex.FindAllString(line, -1)
		for _, em := range emails {
			emLower := strings.ToLower(em)
			if !seenEmail[emLower] {
				seenEmail[emLower] = true
				report.Emails = append(report.Emails, emLower)
			}
		}

		// Domains
		domains := domainRegex.FindAllString(line, -1)
		for _, d := range domains {
			dLower := strings.ToLower(d)
			if !seenDomain[dLower] && !strings.Contains(dLower, "microsoft.com") && !strings.Contains(dLower, "w3.org") {
				seenDomain[dLower] = true
				report.Domains = append(report.Domains, dLower)
			}
		}

		// Tokens
		jwts := jwtRegex.FindAllString(line, -1)
		for _, j := range jwts {
			if !seenToken[j] {
				seenToken[j] = true
				report.TokensOrKeys = append(report.TokensOrKeys, "JWT: "+j[:15]+"...")
			}
		}

		if privKeyRegex.MatchString(line) {
			keySig := "Private Key Header Detected"
			if !seenToken[keySig] {
				seenToken[keySig] = true
				report.TokensOrKeys = append(report.TokensOrKeys, keySig)
			}
		}

		awsKeys := awsKeyRegex.FindAllString(line, -1)
		for _, a := range awsKeys {
			if !seenToken[a] {
				seenToken[a] = true
				report.TokensOrKeys = append(report.TokensOrKeys, "AWS Key: "+a)
			}
		}

		genMatches := genericKeyRegex.FindStringSubmatch(line)
		if len(genMatches) > 1 {
			val := genMatches[1]
			if !seenToken[val] && len(val) > 12 {
				seenToken[val] = true
				report.TokensOrKeys = append(report.TokensOrKeys, "Secret Candidate: "+val)
			}
		}
	}

	// Limit list lengths so reports don't get bloated
	if len(report.IPv4Addresses) > 100 {
		report.IPv4Addresses = report.IPv4Addresses[:100]
	}
	if len(report.URLs) > 100 {
		report.URLs = report.URLs[:100]
	}
	if len(report.Domains) > 100 {
		report.Domains = report.Domains[:100]
	}
	if len(report.Emails) > 100 {
		report.Emails = report.Emails[:100]
	}
	if len(report.TokensOrKeys) > 50 {
		report.TokensOrKeys = report.TokensOrKeys[:50]
	}

	return report
}

// CalculateRiskLevel mengonversi risk score menjadi kategori status
func CalculateRiskLevel(score int) string {
	switch {
	case score >= 70:
		return "CRITICAL"
	case score >= 45:
		return "HIGH"
	case score >= 20:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

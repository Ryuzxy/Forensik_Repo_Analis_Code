package common

import (
	"math"
	"testing"
)

func TestCalculateShannonEntropy(t *testing.T) {
	// 1. Data seragam 1 karakter -> entropy 0
	uniform := []byte("AAAAAAAAAA")
	entUniform := CalculateShannonEntropy(uniform)
	if entUniform != 0.0 {
		t.Errorf("Expected entropy 0.0 for uniform data, got %.3f", entUniform)
	}

	// 2. Data acak 256 nilai byte berbeda -> entropy mendekati 8.0
	allBytes := make([]byte, 256)
	for i := 0; i < 256; i++ {
		allBytes[i] = byte(i)
	}
	entMax := CalculateShannonEntropy(allBytes)
	if math.Abs(entMax-8.0) > 0.01 {
		t.Errorf("Expected entropy close to 8.0, got %.3f", entMax)
	}

	// 3. Teks normal bahasa inggris -> entropy 3.0 - 5.0
	text := []byte("The quick brown fox jumps over the lazy dog.")
	entText := CalculateShannonEntropy(text)
	if entText < 3.0 || entText > 5.0 {
		t.Errorf("Expected text entropy between 3.0 and 5.0, got %.3f", entText)
	}
}

func TestExtractIOCsFromText(t *testing.T) {
	sampleLines := []string{
		"Connect to C2 at http://evil-malware-domain.xyz/payload.exe now",
		"Infiltrating host 192.168.1.105 and exfiltrating data to 45.33.32.156",
		"Contact attacker at hacker@darknet-group.org",
		"Found secret key: api_key = AKIA1234567890ABCDEF",
		"Private key start: -----BEGIN RSA PRIVATE KEY-----",
	}

	iocs := ExtractIOCsFromText(sampleLines)

	if len(iocs.IPv4Addresses) == 0 {
		t.Errorf("Expected IPv4 addresses to be detected")
	}
	if len(iocs.URLs) == 0 {
		t.Errorf("Expected URLs to be detected")
	}
	if len(iocs.Emails) == 0 {
		t.Errorf("Expected email to be detected")
	}
	if len(iocs.TokensOrKeys) == 0 {
		t.Errorf("Expected credentials/keys to be detected")
	}
}

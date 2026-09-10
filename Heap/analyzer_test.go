package heapanalyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeHeapFileWithMock(t *testing.T) {
	tempDir := t.TempDir()
	heapFilePath := filepath.Join(tempDir, "test_heap.dmp")

	var mockData []byte

	// 1. Tambahkan marker 0xBAADF00D (Uninitialized heap)
	mockData = append(mockData, []byte{0xBA, 0xAD, 0xF0, 0x0D, 0x00, 0x00}...)

	// 2. Tambahkan marker 0xFEEEFEEE (Freed heap)
	mockData = append(mockData, []byte{0xFE, 0xEE, 0xFE, 0xEE, 0x00, 0x00}...)

	// 3. Tambahkan pola heap spraying (0x0C berulang 5000 kali)
	sprayBytes := make([]byte, 5000)
	for i := range sprayBytes {
		sprayBytes[i] = 0x0C
	}
	mockData = append(mockData, sprayBytes...)

	// 4. Tambahkan carved HTTP header
	mockData = append(mockData, []byte("POST /api/v1/auth HTTP/1.1\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.test\r\n\r\n")...)

	// 5. Tambahkan carved JSON
	mockData = append(mockData, []byte("{\"user\":\"admin\",\"session_token\":\"9a8b7c6d5e4f\",\"ip\":\"192.168.1.50\"}")...)

	err := os.WriteFile(heapFilePath, mockData, 0644)
	if err != nil {
		t.Fatalf("Failed to write mock heap file: %v", err)
	}

	report, err := AnalyzeHeapFile(heapFilePath)
	if err != nil {
		t.Fatalf("AnalyzeHeapFile returned error: %v", err)
	}

	if len(report.HeapPatterns) < 2 {
		t.Errorf("Expected at least 2 heap patterns, got %d", len(report.HeapPatterns))
	}

	if !report.HeapSprayDetected {
		t.Errorf("Expected heap spray detection to be true")
	}

	if len(report.CarvedHTTP) == 0 {
		t.Errorf("Expected HTTP header to be carved from heap")
	}

	if len(report.CarvedJSON) == 0 {
		t.Errorf("Expected JSON block to be carved from heap")
	}
}

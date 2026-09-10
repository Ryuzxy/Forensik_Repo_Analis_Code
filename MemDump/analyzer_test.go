package memdump

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeMemoryDumpWithMock(t *testing.T) {
	tempDir := t.TempDir()
	mockDumpPath := filepath.Join(tempDir, "test_memory.raw")

	c2Url := strings.Join([]string{"http://", "198.51.100.23", "/beacon.php"}, "")
	vssCmd := strings.Join([]string{"cmd.exe /c ", "vssadmin ", "delete ", "shadows"}, "")
	awsKey := strings.Join([]string{"AKIA", "IOSFODNN7EXAMPLE"}, "")

	var mockData []byte
	mockData = append(mockData, []byte("Windows kernel memory unallocated chunk test...\n")...)

	peChunk := make([]byte, 256)
	peChunk[0] = 'M'
	peChunk[1] = 'Z'
	peChunk[0x3C] = 0x80
	peChunk[0x80] = 'P'
	peChunk[0x81] = 'E'
	peChunk[0x82] = 0x00
	peChunk[0x83] = 0x00
	mockData = append(mockData, peChunk...)

	mockData = append(mockData, []byte(vssCmd+"\n")...)
	mockData = append(mockData, []byte("Attacker endpoint: "+c2Url+"\n")...)
	mockData = append(mockData, []byte("Credential token: "+awsKey+"\n")...)

	err := os.WriteFile(mockDumpPath, mockData, 0644)
	if err != nil {
		t.Fatalf("Failed to create mock memory file: %v", err)
	}

	report, err := AnalyzeMemoryDump(mockDumpPath)
	if err != nil {
		t.Fatalf("AnalyzeMemoryDump returned error: %v", err)
	}

	if len(report.Artifacts) == 0 {
		t.Errorf("Expected memory artifacts to be detected")
	}

	if len(report.IOCs.IPv4Addresses) == 0 {
		t.Errorf("Expected IPv4 to be detected from memory dump")
	}

	if len(report.IOCs.URLs) == 0 {
		t.Errorf("Expected URL to be detected from memory dump")
	}

	if report.RiskScore == 0 {
		t.Errorf("Expected non-zero risk score for malicious memory sample")
	}
}

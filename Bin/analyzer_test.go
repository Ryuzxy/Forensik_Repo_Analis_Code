package bin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeBinaryFileWithRawSample(t *testing.T) {
	tempDir := t.TempDir()
	sampleBinPath := filepath.Join(tempDir, "sample_suspicious.bin")

	// Hindari deteksi static AV pada string test dengan string joining
	c2Domain := strings.Join([]string{"http://", "suspicious-c2-sample", ".xyz/beacon"}, "")
	psCmd := strings.Join([]string{"powershell", " -enc", " dGVzdA=="}, "")
	regKey := strings.Join([]string{"CurrentVersion", "\\Run\\AutoStartSample"}, "")

	var data []byte
	data = append(data, []byte("Test raw mock payload for forensic test\n")...)
	data = append(data, []byte("C2 URL: "+c2Domain+"\n")...)
	data = append(data, []byte("Execution: "+psCmd+"\n")...)
	data = append(data, []byte("Persistence: "+regKey+"\n")...)

	err := os.WriteFile(sampleBinPath, data, 0644)
	if err != nil {
		t.Fatalf("Failed to create sample file: %v", err)
	}

	report, err := AnalyzeBinaryFile(sampleBinPath)
	if err != nil {
		t.Fatalf("AnalyzeBinaryFile returned error: %v", err)
	}

	if report.Metadata.FileName != "sample_suspicious.bin" {
		t.Errorf("Expected file name 'sample_suspicious.bin', got %s", report.Metadata.FileName)
	}

	if len(report.ThreatsDetected) == 0 {
		t.Errorf("Expected threats to be detected from suspicious strings")
	}

	if report.RiskScore == 0 {
		t.Errorf("Expected risk score to be greater than 0")
	}
}

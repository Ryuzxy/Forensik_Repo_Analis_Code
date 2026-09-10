package fileiso

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeISOFileWithMock(t *testing.T) {
	tempDir := t.TempDir()
	isoPath := filepath.Join(tempDir, "mock_image.iso")

	totalSize := 18 * SectorSize
	isoData := make([]byte, totalSize)

	// PVD di sector 16
	pvd := isoData[PVDOffset : PVDOffset+SectorSize]
	pvd[0] = 0x01
	copy(pvd[1:6], []byte("CD001"))
	pvd[6] = 0x01

	copy(pvd[8:40], []byte("FORENSIC_OS"))
	copy(pvd[40:72], []byte("SUSPICIOUS_DISK"))

	binary.LittleEndian.PutUint32(pvd[80:84], 18)
	binary.LittleEndian.PutUint16(pvd[128:130], SectorSize)

	rootRec := pvd[156:190]
	rootRec[0] = 34
	binary.LittleEndian.PutUint32(rootRec[2:6], 17)
	binary.LittleEndian.PutUint32(rootRec[10:14], SectorSize)
	rootRec[25] = 0x02

	dirOffset := 17 * SectorSize
	dirBlock := isoData[dirOffset : dirOffset+SectorSize]

	dirBlock[0] = 34
	binary.LittleEndian.PutUint32(dirBlock[2:6], 17)
	binary.LittleEndian.PutUint32(dirBlock[10:14], SectorSize)
	dirBlock[25] = 0x02
	dirBlock[32] = 1
	dirBlock[33] = 0x00

	entry2Offset := 34
	fileName := "INVOICE.PDF.EXE;1"
	recLen := 33 + len(fileName)
	if recLen%2 != 0 {
		recLen++
	}
	dirBlock[entry2Offset] = byte(recLen)
	binary.LittleEndian.PutUint32(dirBlock[entry2Offset+2:entry2Offset+6], 18)
	binary.LittleEndian.PutUint32(dirBlock[entry2Offset+10:entry2Offset+14], 1024)
	dirBlock[entry2Offset+25] = 0x00
	dirBlock[entry2Offset+32] = byte(len(fileName))
	copy(dirBlock[entry2Offset+33:], []byte(fileName))

	err := os.WriteFile(isoPath, isoData, 0644)
	if err != nil {
		t.Fatalf("Failed to create mock ISO: %v", err)
	}

	report, err := AnalyzeISOFile(isoPath)
	if err != nil {
		t.Fatalf("AnalyzeISOFile returned error: %v", err)
	}

	if report.VolumeInfo.VolumeID != "SUSPICIOUS_DISK" {
		t.Errorf("Expected Volume ID 'SUSPICIOUS_DISK', got '%s'", report.VolumeInfo.VolumeID)
	}

	if report.TotalFiles == 0 {
		t.Errorf("Expected files inside ISO to be enumerated")
	}

	if len(report.SuspiciousFiles) == 0 {
		t.Errorf("Expected INVOICE.PDF.EXE to be marked suspicious")
	}
}

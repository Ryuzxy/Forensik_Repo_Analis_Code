package common

import (
	"io"
	"math"
	"os"
)

// CalculateShannonEntropy menghitung nilai entropi Shannon dari slice bytes (0.0 - 8.0)
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	dataLen := float64(len(data))
	var entropy float64

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / dataLen
			entropy -= p * math.Log2(p)
		}
	}

	return math.Round(entropy*1000) / 1000
}

// CalculateFileEntropy menghitung nilai entropi dari seluruh isi file secara streaming
func CalculateFileEntropy(filePath string) (float64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var freq [256]int64
	var totalBytes int64

	buf := make([]byte, 64*1024)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			totalBytes += int64(n)
			for i := 0; i < n; i++ {
				freq[buf[i]]++
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, err
		}
	}

	if totalBytes == 0 {
		return 0.0, nil
	}

	var entropy float64
	totalFloat := float64(totalBytes)

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / totalFloat
			entropy -= p * math.Log2(p)
		}
	}

	return math.Round(entropy*1000) / 1000, nil
}

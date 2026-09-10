package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	bin "forensic-repo-analyzer/Bin"
	fileiso "forensic-repo-analyzer/File_ISO"
	heapanalyzer "forensic-repo-analyzer/Heap"
	hexanalyzer "forensic-repo-analyzer/Hex"
	memdump "forensic-repo-analyzer/MemDump"
	"forensic-repo-analyzer/pkg/common"
	"forensic-repo-analyzer/pkg/reporter"
)

func main() {
	var (
		scanAll    = flag.Bool("all", false, "Scan seluruh folder repositori (Bin, File_ISO, MemDump, Hex, Heap)")
		targetFile = flag.String("file", "", "Path ke file spesifik yang ingin dianalisis")
		targetDir  = flag.String("dir", "", "Path ke direktori tertentu yang ingin dianalisis")
		fileType   = flag.String("type", "auto", "Tipe analisis: 'bin', 'iso', 'mem', 'hex', 'heap', atau 'auto'")
		hexInput   = flag.String("hex", "", "String kode hex langsung atau path file hex")
		heapInput  = flag.String("heap", "", "Path ke file dump heap memori")
		outputDir  = flag.String("out", "reports", "Direktori tujuan penyimpanan laporan")
	)
	flag.Parse()

	// Default behavior jika tidak ada argumen spesifik: scan seluruh folder
	if *targetFile == "" && *targetDir == "" && *hexInput == "" && *heapInput == "" {
		*scanAll = true
	}

	fmt.Println(`
  ╔═══════════════════════════════════════════════════════════════╗
  ║                FORENSIK REPO ANALYZER                         ║
  ║      Advanced Forensic Toolkit for Bin, ISO, Mem, Hex & Heap  ║
  ╚═══════════════════════════════════════════════════════════════╝`)

	overallReport := common.OverallForensicReport{
		GeneratedAt: time.Now(),
		Summary:     common.ScanSummary{},
		BinReports:  make([]common.BinAnalysisReport, 0),
		ISOReports:  make([]common.ISOAnalysisReport, 0),
		MemReports:  make([]common.MemAnalysisReport, 0),
		HexReports:  make([]common.HexAnalysisReport, 0),
		HeapReports: make([]common.HeapAnalysisReport, 0),
	}

	if *hexInput != "" {
		// Analisis kode hex (bisa file atau string hex mentah)
		analyzeHexInput(*hexInput, &overallReport)
	} else if *heapInput != "" {
		// Analisis heap dump
		analyzeSingleFile(*heapInput, "heap", &overallReport)
	} else if *targetFile != "" {
		// Analisis single file
		analyzeSingleFile(*targetFile, *fileType, &overallReport)
	} else if *targetDir != "" {
		// Analisis directory kustom
		analyzeDirectory(*targetDir, *fileType, &overallReport)
	} else if *scanAll {
		// Analisis seluruh folder repositori
		runRepositoryScan(&overallReport)
	}

	// Hitung ringkasan
	overallReport.Summary.BinFilesCount = len(overallReport.BinReports)
	overallReport.Summary.ISOFilesCount = len(overallReport.ISOReports)
	overallReport.Summary.MemFilesCount = len(overallReport.MemReports)
	overallReport.Summary.HexFilesCount = len(overallReport.HexReports)
	overallReport.Summary.HeapFilesCount = len(overallReport.HeapReports)
	overallReport.Summary.TotalFilesScanned = overallReport.Summary.BinFilesCount +
		overallReport.Summary.ISOFilesCount +
		overallReport.Summary.MemFilesCount +
		overallReport.Summary.HexFilesCount +
		overallReport.Summary.HeapFilesCount

	for _, b := range overallReport.BinReports {
		overallReport.Summary.TotalThreatsFound += len(b.ThreatsDetected)
	}
	for _, i := range overallReport.ISOReports {
		overallReport.Summary.TotalThreatsFound += len(i.ThreatsDetected)
	}
	for _, m := range overallReport.MemReports {
		overallReport.Summary.TotalThreatsFound += len(m.ThreatsDetected)
	}
	for _, h := range overallReport.HexReports {
		overallReport.Summary.TotalThreatsFound += len(h.ThreatsDetected)
	}
	for _, hp := range overallReport.HeapReports {
		overallReport.Summary.TotalThreatsFound += len(hp.ThreatsDetected)
	}

	if overallReport.Summary.TotalFilesScanned == 0 {
		fmt.Println("\n[i] Tidak ada berkas target yang ditemukan untuk dianalisis.")
		fmt.Println("    Silakan letakkan file artefak pada folder terkait:")
		fmt.Println("    - Folder 'Bin/'      : Untuk file executable/binary (.exe, .dll, .bin, ELF)")
		fmt.Println("    - Folder 'File_ISO/' : Untuk file disk image (.iso, .img)")
		fmt.Println("    - Folder 'MemDump/'  : Untuk file memory dump (.raw, .dmp, .vmem, .dd)")
		fmt.Println("    - Folder 'Hex/'      : Untuk file kode hex/shellcode (.hex, .raw, .txt)")
		fmt.Println("    - Folder 'Heap/'     : Untuk file heap memory dump (.dmp, .raw)")
		fmt.Println("\n    Atau jalankan analisis secara instan via CLI:")
		fmt.Println("    forensic_analyzer.exe -hex \"909090905589e5\"")
		fmt.Println("    forensic_analyzer.exe -file <path_ke_file>")
		return
	}

	// Cetak laporan ke terminal
	reporter.PrintConsoleReport(overallReport)

	// Simpan laporan ke folder output
	jsonPath, mdPath, err := reporter.SaveReports(overallReport, *outputDir)
	if err != nil {
		fmt.Printf("[!] Gagal menyimpan laporan: %v\n", err)
	} else {
		fmt.Println("\n[+] Laporan investigasi forensik berhasil disimpan:")
		fmt.Printf("    - JSON     : %s\n", jsonPath)
		fmt.Printf("    - Markdown : %s\n", mdPath)
	}
}

func runRepositoryScan(report *common.OverallForensicReport) {
	fmt.Println("\n[+] Memulai pemindaian otomatis seluruh repositori...")

	// 1. Folder Bin
	binFiles := findFiles("Bin")
	if len(binFiles) > 0 {
		fmt.Printf("    -> Ditemukan %d file di folder 'Bin/'\n", len(binFiles))
		for _, f := range binFiles {
			fmt.Printf("       [Analisis Bin] Memproses: %s ...\n", filepath.Base(f))
			res, err := bin.AnalyzeBinaryFile(f)
			if err != nil {
				fmt.Printf("       [!] Error menganalisis %s: %v\n", f, err)
				continue
			}
			report.BinReports = append(report.BinReports, res)
		}
	} else {
		fmt.Println("    [-] Folder 'Bin/' kosong.")
	}

	// 2. Folder File_ISO
	isoFiles := findFiles("File_ISO")
	if len(isoFiles) > 0 {
		fmt.Printf("    -> Ditemukan %d file di folder 'File_ISO/'\n", len(isoFiles))
		for _, f := range isoFiles {
			fmt.Printf("       [Analisis ISO] Memproses: %s ...\n", filepath.Base(f))
			res, err := fileiso.AnalyzeISOFile(f)
			if err != nil {
				fmt.Printf("       [!] Error menganalisis %s: %v\n", f, err)
				continue
			}
			report.ISOReports = append(report.ISOReports, res)
		}
	} else {
		fmt.Println("    [-] Folder 'File_ISO/' kosong.")
	}

	// 3. Folder MemDump
	memFiles := findFiles("MemDump")
	if len(memFiles) > 0 {
		fmt.Printf("    -> Ditemukan %d file di folder 'MemDump/'\n", len(memFiles))
		for _, f := range memFiles {
			fmt.Printf("       [Analisis Memory] Memproses: %s ...\n", filepath.Base(f))
			res, err := memdump.AnalyzeMemoryDump(f)
			if err != nil {
				fmt.Printf("       [!] Error menganalisis %s: %v\n", f, err)
				continue
			}
			report.MemReports = append(report.MemReports, res)
		}
	} else {
		fmt.Println("    [-] Folder 'MemDump/' kosong.")
	}

	// 4. Folder Hex
	hexFiles := findFiles("Hex")
	if len(hexFiles) > 0 {
		fmt.Printf("    -> Ditemukan %d file di folder 'Hex/'\n", len(hexFiles))
		for _, f := range hexFiles {
			fmt.Printf("       [Analisis Hex] Memproses: %s ...\n", filepath.Base(f))
			res, err := hexanalyzer.AnalyzeHexFile(f)
			if err != nil {
				fmt.Printf("       [!] Error menganalisis %s: %v\n", f, err)
				continue
			}
			report.HexReports = append(report.HexReports, res)
		}
	} else {
		fmt.Println("    [-] Folder 'Hex/' kosong.")
	}

	// 5. Folder Heap
	heapFiles := findFiles("Heap")
	if len(heapFiles) > 0 {
		fmt.Printf("    -> Ditemukan %d file di folder 'Heap/'\n", len(heapFiles))
		for _, f := range heapFiles {
			fmt.Printf("       [Analisis Heap] Memproses: %s ...\n", filepath.Base(f))
			res, err := heapanalyzer.AnalyzeHeapFile(f)
			if err != nil {
				fmt.Printf("       [!] Error menganalisis %s: %v\n", f, err)
				continue
			}
			report.HeapReports = append(report.HeapReports, res)
		}
	} else {
		fmt.Println("    [-] Folder 'Heap/' kosong.")
	}
}

func analyzeHexInput(input string, report *common.OverallForensicReport) {
	// Cek apakah input adalah file yang ada
	if fi, err := os.Stat(input); err == nil && !fi.IsDir() {
		fmt.Printf("[+] Menganalisis file kode hex: %s ...\n", input)
		res, err := hexanalyzer.AnalyzeHexFile(input)
		if err != nil {
			fmt.Printf("[!] Error menganalisis hex file: %v\n", err)
			return
		}
		report.HexReports = append(report.HexReports, res)
		return
	}

	// Jika bukan file, analisis sebagai string hex mentah
	fmt.Printf("[+] Menganalisis raw hex input (%d karakter) ...\n", len(input))
	res, err := hexanalyzer.AnalyzeHexData("Raw Hex Input", input)
	if err != nil {
		fmt.Printf("[!] Error memproses raw hex: %v\n", err)
		return
	}
	report.HexReports = append(report.HexReports, res)
}

func analyzeSingleFile(filePath string, fType string, report *common.OverallForensicReport) {
	fi, err := os.Stat(filePath)
	if err != nil {
		fmt.Printf("[!] File tidak ditemukan: %s\n", filePath)
		return
	}
	if fi.IsDir() {
		analyzeDirectory(filePath, fType, report)
		return
	}

	fmt.Printf("[+] Menganalisis file: %s ...\n", filePath)
	selectedType := determineType(filePath, fType)

	switch selectedType {
	case "iso":
		res, err := fileiso.AnalyzeISOFile(filePath)
		if err != nil {
			fmt.Printf("[!] Error menganalisis ISO: %v\n", err)
			return
		}
		report.ISOReports = append(report.ISOReports, res)

	case "mem":
		res, err := memdump.AnalyzeMemoryDump(filePath)
		if err != nil {
			fmt.Printf("[!] Error menganalisis Memory Dump: %v\n", err)
			return
		}
		report.MemReports = append(report.MemReports, res)

	case "hex":
		res, err := hexanalyzer.AnalyzeHexFile(filePath)
		if err != nil {
			fmt.Printf("[!] Error menganalisis Hex: %v\n", err)
			return
		}
		report.HexReports = append(report.HexReports, res)

	case "heap":
		res, err := heapanalyzer.AnalyzeHeapFile(filePath)
		if err != nil {
			fmt.Printf("[!] Error menganalisis Heap: %v\n", err)
			return
		}
		report.HeapReports = append(report.HeapReports, res)

	default: // bin
		res, err := bin.AnalyzeBinaryFile(filePath)
		if err != nil {
			fmt.Printf("[!] Error menganalisis Binary: %v\n", err)
			return
		}
		report.BinReports = append(report.BinReports, res)
	}
}

func analyzeDirectory(dirPath string, fType string, report *common.OverallForensicReport) {
	files := findFiles(dirPath)
	fmt.Printf("[+] Menganalisis %d file di direktori: %s\n", len(files), dirPath)
	for _, f := range files {
		analyzeSingleFile(f, fType, report)
	}
}

func determineType(filePath string, explicitType string) string {
	if explicitType != "" && explicitType != "auto" {
		return strings.ToLower(explicitType)
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	cleanPath := filepath.ToSlash(filePath)

	switch {
	case ext == ".iso" || ext == ".img" || strings.Contains(cleanPath, "/File_ISO/"):
		return "iso"
	case strings.Contains(cleanPath, "/Heap/"):
		return "heap"
	case strings.Contains(cleanPath, "/Hex/"):
		return "hex"
	case strings.Contains(cleanPath, "/MemDump/"):
		return "mem"
	case ext == ".hex":
		return "hex"
	case ext == ".dmp" || ext == ".raw" || ext == ".vmem" || ext == ".dd" || ext == ".mem":
		return "mem"
	default:
		return "bin"
	}
}

func findFiles(dir string) []string {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return files
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))

		// Abaikan file metadata, source code analyzer, script, dan git files
		if strings.HasPrefix(name, ".") ||
			ext == ".go" ||
			ext == ".md" ||
			ext == ".bat" ||
			ext == ".ps1" ||
			strings.EqualFold(name, "license") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	return files
}

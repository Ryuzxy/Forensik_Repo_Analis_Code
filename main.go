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
	memdump "forensic-repo-analyzer/MemDump"
	"forensic-repo-analyzer/pkg/common"
	"forensic-repo-analyzer/pkg/reporter"
)

func main() {
	var (
		scanAll    = flag.Bool("all", false, "Scan seluruh folder repositori (Bin, File_ISO, MemDump)")
		targetFile = flag.String("file", "", "Path ke file spesifik yang ingin dianalisis")
		targetDir  = flag.String("dir", "", "Path ke direktori tertentu yang ingin dianalisis")
		fileType   = flag.String("type", "auto", "Tipe analisis: 'bin', 'iso', 'mem', atau 'auto'")
		outputDir  = flag.String("out", "reports", "Direktori tujuan penyimpanan laporan")
	)
	flag.Parse()

	// Default behavior jika tidak ada argumen: scan seluruh folder
	if *targetFile == "" && *targetDir == "" {
		*scanAll = true
	}

	fmt.Println(`
  ╔═══════════════════════════════════════════════════════════════╗
  ║                FORENSIK REPO ANALYZER                         ║
  ║      Advanced Forensic Toolkit for Bin, ISO & MemDump         ║
  ╚═══════════════════════════════════════════════════════════════╝`)

	overallReport := common.OverallForensicReport{
		GeneratedAt: time.Now(),
		Summary:     common.ScanSummary{},
		BinReports:  make([]common.BinAnalysisReport, 0),
		ISOReports:  make([]common.ISOAnalysisReport, 0),
		MemReports:  make([]common.MemAnalysisReport, 0),
	}

	if *targetFile != "" {
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
	overallReport.Summary.TotalFilesScanned = overallReport.Summary.BinFilesCount +
		overallReport.Summary.ISOFilesCount +
		overallReport.Summary.MemFilesCount

	for _, b := range overallReport.BinReports {
		overallReport.Summary.TotalThreatsFound += len(b.ThreatsDetected)
	}
	for _, i := range overallReport.ISOReports {
		overallReport.Summary.TotalThreatsFound += len(i.ThreatsDetected)
	}
	for _, m := range overallReport.MemReports {
		overallReport.Summary.TotalThreatsFound += len(m.ThreatsDetected)
	}

	if overallReport.Summary.TotalFilesScanned == 0 {
		fmt.Println("\n[i] Tidak ada berkas target yang ditemukan untuk dianalisis.")
		fmt.Println("    Silakan letakkan file artefak pada folder terkait:")
		fmt.Println("    - Folder 'Bin/'      : Untuk file executable/binary (.exe, .dll, .bin, ELF)")
		fmt.Println("    - Folder 'File_ISO/' : Untuk file disk image (.iso, .img)")
		fmt.Println("    - Folder 'MemDump/'  : Untuk file memory dump (.raw, .dmp, .vmem, .dd)")
		fmt.Println("\n    Atau jalankan analisis file spesifik dengan perintah:")
		fmt.Println("    go run main.go -file <path_ke_file>")
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
	switch ext {
	case ".iso", ".img":
		return "iso"
	case ".dmp", ".raw", ".vmem", ".dd", ".mem":
		return "mem"
	default:
		// Deteksi berdasarkan folder induk jika berada di dalam repo
		cleanPath := filepath.ToSlash(filePath)
		if strings.Contains(cleanPath, "/File_ISO/") {
			return "iso"
		}
		if strings.Contains(cleanPath, "/MemDump/") {
			return "mem"
		}
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
			ext == ".txt" ||
			strings.EqualFold(name, "license") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	return files
}

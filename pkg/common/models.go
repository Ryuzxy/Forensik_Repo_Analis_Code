package common

import "time"

// HashInfo menyimpan hash kriptografi file
type HashInfo struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
}

// FileMetadata menyimpan metadata dasar file
type FileMetadata struct {
	FilePath  string    `json:"file_path"`
	FileName  string    `json:"file_name"`
	FileSize  int64     `json:"file_size"`
	ModTime   time.Time `json:"mod_time"`
	FileType  string    `json:"file_type"`
	MimeType  string    `json:"mime_type"`
	Hashes    HashInfo  `json:"hashes"`
	Entropy   float64   `json:"entropy"`
	IsPacked  bool      `json:"is_packed"`
}

// PESectionInfo menyimpan informasi section PE (Windows Binary)
type PESectionInfo struct {
	Name            string  `json:"name"`
	VirtualAddress  uint32  `json:"virtual_address"`
	VirtualSize     uint32  `json:"virtual_size"`
	RawDataSize     uint32  `json:"raw_data_size"`
	Entropy         float64 `json:"entropy"`
	SuspiciousFlags []string `json:"suspicious_flags,omitempty"`
}

// SuspiciousImport menyimpan informasi API berbahaya/mencurigakan
type SuspiciousImport struct {
	DLL      string `json:"dll"`
	Function string `json:"function"`
	Category string `json:"category"`
	Severity string `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Reason   string `json:"reason"`
}

// BinAnalysisReport menyimpan hasil analisis modul Bin
type BinAnalysisReport struct {
	Metadata          FileMetadata       `json:"metadata"`
	Architecture      string             `json:"architecture"`
	CompileTime       string             `json:"compile_time,omitempty"`
	Subsystem         string             `json:"subsystem,omitempty"`
	Entrypoint        string             `json:"entrypoint,omitempty"`
	Sections          []PESectionInfo    `json:"sections,omitempty"`
	SuspiciousImports []SuspiciousImport `json:"suspicious_imports,omitempty"`
	ExtractedIOCs     IOCReport          `json:"extracted_iocs"`
	RiskScore         int                `json:"risk_score"`
	RiskLevel         string             `json:"risk_level"`
	ThreatsDetected   []string           `json:"threats_detected"`
}

// ISOEntry menyimpan informasi item file/folder di dalam file ISO
type ISOEntry struct {
	Path         string    `json:"path"`
	Name         string    `json:"name"`
	IsDir        bool      `json:"is_dir"`
	Size         int64     `json:"size"`
	ModTime      time.Time `json:"mod_time"`
	IsSuspicious bool      `json:"is_suspicious"`
	Reason       string    `json:"reason,omitempty"`
	MD5          string    `json:"md5,omitempty"`
	SHA256       string    `json:"sha256,omitempty"`
}

// ISOVolumeInfo menyimpan metadata volume ISO 9660
type ISOVolumeInfo struct {
	SystemID         string    `json:"system_id"`
	VolumeID         string    `json:"volume_id"`
	VolumeSpaceSize  uint32    `json:"volume_space_size"`
	LogicalBlockSize uint16    `json:"logical_block_size"`
	VolumeSetID      string    `json:"volume_set_id"`
	PublisherID      string    `json:"publisher_id"`
	DataPreparerID   string    `json:"data_preparer_id"`
	ApplicationID    string    `json:"application_id"`
	CreationTime     time.Time `json:"creation_time"`
	ModificationTime time.Time `json:"modification_time"`
}

// ISOAnalysisReport menyimpan hasil analisis modul File_ISO
type ISOAnalysisReport struct {
	Metadata        FileMetadata   `json:"metadata"`
	VolumeInfo      ISOVolumeInfo  `json:"volume_info"`
	TotalFiles      int            `json:"total_files"`
	TotalDirs       int            `json:"total_dirs"`
	Files           []ISOEntry     `json:"files"`
	SuspiciousFiles []ISOEntry     `json:"suspicious_files"`
	RiskScore       int            `json:"risk_score"`
	RiskLevel       string         `json:"risk_level"`
	ThreatsDetected []string       `json:"threats_detected"`
}

// MemoryArtifact menyimpan artefak yang ditemukan di memory dump
type MemoryArtifact struct {
	Type        string `json:"type"`        // "Embedded_PE", "Sensitive_Token", "Command_Line", etc.
	Offset      int64  `json:"offset"`
	Description string `json:"description"`
	Snippet     string `json:"snippet"`
}

// IOCReport menyimpan Indicators of Compromise
type IOCReport struct {
	IPv4Addresses []string `json:"ipv4_addresses"`
	IPv6Addresses []string `json:"ipv6_addresses"`
	URLs          []string `json:"urls"`
	Domains       []string `json:"domains"`
	Emails        []string `json:"emails"`
	CryptoWallets []string `json:"crypto_wallets,omitempty"`
	TokensOrKeys  []string `json:"tokens_or_keys,omitempty"`
}

// MemAnalysisReport menyimpan hasil analisis modul MemDump
type MemAnalysisReport struct {
	Metadata        FileMetadata     `json:"metadata"`
	ScanDurationSec float64          `json:"scan_duration_sec"`
	TotalStrings    int              `json:"total_strings_extracted"`
	IOCs            IOCReport        `json:"iocs"`
	Artifacts       []MemoryArtifact `json:"artifacts"`
	RiskScore       int              `json:"risk_score"`
	RiskLevel       string           `json:"risk_level"`
	ThreatsDetected []string         `json:"threats_detected"`
}

// OverallForensicReport menampung seluruh hasil analisis
type OverallForensicReport struct {
	GeneratedAt time.Time           `json:"generated_at"`
	Summary     ScanSummary         `json:"summary"`
	BinReports  []BinAnalysisReport `json:"bin_reports"`
	ISOReports  []ISOAnalysisReport `json:"iso_reports"`
	MemReports  []MemAnalysisReport `json:"mem_reports"`
}

// ScanSummary ringkasan eksekutif
type ScanSummary struct {
	TotalFilesScanned int `json:"total_files_scanned"`
	TotalThreatsFound int `json:"total_threats_found"`
	BinFilesCount     int `json:"bin_files_count"`
	ISOFilesCount     int `json:"iso_files_count"`
	MemFilesCount     int `json:"mem_files_count"`
}

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;
use zip::read::ZipArchive;

/// Comprehensive archive analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveAnalysis {
    pub archive_type: ArchiveType,
    pub metadata: ArchiveMetadata,
    pub entries: Vec<ArchiveEntry>,
    pub security_analysis: ArchiveSecurityAnalysis,
    pub suspicious_indicators: SuspiciousArchiveIndicators,
    pub nested_archives: Vec<NestedArchiveInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArchiveType {
    Zip,
    ZipEncrypted,
    ZipSelfExtracting,
    Rar,
    SevenZip,
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveMetadata {
    pub total_entries: usize,
    pub total_size_compressed: u64,
    pub total_size_uncompressed: u64,
    pub compression_ratio: f64,
    pub has_encryption: bool,
    pub has_password: bool,
    pub comment: Option<String>,
    pub created_by: Option<String>,
    pub creation_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    pub file_name: String,
    pub is_directory: bool,
    pub size_compressed: u64,
    pub size_uncompressed: u64,
    pub compression_method: String,
    pub compression_ratio: f64,
    pub last_modified: Option<String>,
    pub crc32: Option<u32>,
    pub is_encrypted: bool,
    pub is_text: bool,
    pub permissions: Option<u32>,
    pub comment: Option<String>,
    pub file_type: FileType,
    pub risk_indicators: Vec<RiskIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileType {
    Executable,
    Script,
    Document,
    Archive,
    Image,
    Text,
    Data,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskIndicator {
    pub indicator_type: String,
    pub description: String,
    pub severity: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveSecurityAnalysis {
    pub overall_risk: RiskLevel,
    pub malicious_patterns: Vec<MaliciousPattern>,
    pub suspicious_files: Vec<SuspiciousFile>,
    pub path_traversal_risks: Vec<PathTraversalRisk>,
    pub zip_bomb_indicators: ZipBombIndicators,
    pub hidden_content: Vec<HiddenContent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousPattern {
    pub pattern_type: String,
    pub description: String,
    pub matched_files: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousFile {
    pub path: String,
    pub reason: String,
    pub risk_level: RiskLevel,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathTraversalRisk {
    pub entry_path: String,
    pub resolved_path: String,
    pub risk_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ZipBombIndicators {
    pub is_potential_bomb: bool,
    pub compression_ratio: f64,
    pub nesting_level: u32,
    pub recursive_entries: Vec<String>,
    pub quine_detection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HiddenContent {
    pub content_type: String,
    pub location: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuspiciousArchiveIndicators {
    pub has_executable: bool,
    pub has_script: bool,
    pub has_double_extension: bool,
    pub has_path_traversal: bool,
    pub has_hidden_files: bool,
    pub has_suspicious_names: bool,
    pub executable_count: u32,
    pub script_count: u32,
    pub suspicious_patterns: Vec<String>,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestedArchiveInfo {
    pub path: String,
    pub archive_type: ArchiveType,
    pub size: u64,
    pub depth: u32,
}

/// Main entry point for ZIP analysis
pub fn analyze_zip<P: AsRef<Path>>(path: P) -> Result<ArchiveAnalysis> {
    let path = path.as_ref();
    let file = File::open(path).context("Failed to open ZIP file")?;

    let mut archive = ZipArchive::new(file).context("Failed to read ZIP archive")?;

    let metadata = extract_zip_metadata(&mut archive)?;
    let mut entries = Vec::new();
    let mut suspicious_indicators = SuspiciousArchiveIndicators::default();
    let mut nested_archives = Vec::new();

    // Analyze each entry
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let entry_info = analyze_zip_entry(&mut entry, &mut suspicious_indicators)?;

        // Check for nested archives
        if matches!(entry_info.file_type, FileType::Archive) {
            nested_archives.push(NestedArchiveInfo {
                path: entry_info.path.clone(),
                archive_type: detect_archive_type(&entry_info.file_name),
                size: entry_info.size_uncompressed,
                depth: 1,
            });
        }

        entries.push(entry_info);
    }

    // Perform security analysis
    let security_analysis = perform_security_analysis(&entries, &metadata)?;

    // Calculate risk score
    suspicious_indicators.risk_score =
        calculate_risk_score(&suspicious_indicators, &security_analysis);

    Ok(ArchiveAnalysis {
        archive_type: ArchiveType::Zip,
        metadata,
        entries,
        security_analysis,
        suspicious_indicators,
        nested_archives,
    })
}

fn extract_zip_metadata<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<ArchiveMetadata> {
    let mut total_compressed = 0u64;
    let mut total_uncompressed = 0u64;

    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index_raw(i) {
            total_compressed += entry.compressed_size();
            total_uncompressed += entry.size();
        }
    }

    let compression_ratio = if total_uncompressed > 0 {
        1.0 - (total_compressed as f64 / total_uncompressed as f64)
    } else {
        0.0
    };

    Ok(ArchiveMetadata {
        total_entries: archive.len(),
        total_size_compressed: total_compressed,
        total_size_uncompressed: total_uncompressed,
        compression_ratio,
        has_encryption: false, // Check entries for encryption
        has_password: false,
        comment: if archive.comment().is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(archive.comment()).to_string())
        },
        created_by: None, // Would need to parse ZIP extra fields
        creation_date: None,
    })
}

fn analyze_zip_entry<R: std::io::Read>(
    entry: &mut zip::read::ZipFile<'_, R>,
    indicators: &mut SuspiciousArchiveIndicators,
) -> Result<ArchiveEntry> {
    let path = entry.name()?.into_owned();
    let file_name = Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let is_directory = entry.is_dir();
    let size_compressed = entry.compressed_size();
    let size_uncompressed = entry.size();
    let compression_ratio = if size_uncompressed > 0 {
        1.0 - (size_compressed as f64 / size_uncompressed as f64)
    } else {
        0.0
    };

    let compression_method = format!("{:?}", entry.compression());
    let last_modified = entry.last_modified().map(|dt| {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        )
    });

    let crc32 = Some(entry.crc32());
    let is_encrypted = entry.encrypted();
    let permissions = entry.unix_mode();
    let comment = if entry.comment().is_empty() {
        None
    } else {
        Some(entry.comment().to_string())
    };

    // Determine file type and check for suspicious patterns
    let file_type = determine_file_type(&file_name, &path);
    let mut risk_indicators = Vec::new();

    // Check for suspicious patterns
    if matches!(file_type, FileType::Executable) {
        indicators.has_executable = true;
        indicators.executable_count += 1;
        risk_indicators.push(RiskIndicator {
            indicator_type: "Executable".to_string(),
            description: "Archive contains executable file".to_string(),
            severity: RiskLevel::Medium,
        });
    }

    if matches!(file_type, FileType::Script) {
        indicators.has_script = true;
        indicators.script_count += 1;
        risk_indicators.push(RiskIndicator {
            indicator_type: "Script".to_string(),
            description: "Archive contains script file".to_string(),
            severity: RiskLevel::Medium,
        });
    }

    // Check for double extensions
    if has_double_extension(&file_name) {
        indicators.has_double_extension = true;
        risk_indicators.push(RiskIndicator {
            indicator_type: "DoubleExtension".to_string(),
            description: "File has double extension (possible masquerading)".to_string(),
            severity: RiskLevel::High,
        });
    }

    // Check for path traversal
    if path.contains("..") || path.starts_with('/') || path.contains("\\..") {
        indicators.has_path_traversal = true;
        risk_indicators.push(RiskIndicator {
            indicator_type: "PathTraversal".to_string(),
            description: "Path contains directory traversal sequences".to_string(),
            severity: RiskLevel::Critical,
        });
    }

    // Check for hidden files
    if file_name.starts_with('.') || path.contains("/.") {
        indicators.has_hidden_files = true;
        risk_indicators.push(RiskIndicator {
            indicator_type: "HiddenFile".to_string(),
            description: "Hidden file detected".to_string(),
            severity: RiskLevel::Low,
        });
    }

    // Check for suspicious names
    if is_suspicious_filename(&file_name) {
        indicators.has_suspicious_names = true;
        indicators.suspicious_patterns.push(file_name.clone());
    }

    Ok(ArchiveEntry {
        path,
        file_name,
        is_directory,
        size_compressed,
        size_uncompressed,
        compression_method,
        compression_ratio,
        last_modified,
        crc32,
        is_encrypted,
        is_text: false, // Would need content analysis
        permissions,
        comment,
        file_type,
        risk_indicators,
    })
}

fn determine_file_type(file_name: &str, _path: &str) -> FileType {
    let lower_name = file_name.to_lowercase();

    // Check extensions
    if lower_name.ends_with(".exe")
        || lower_name.ends_with(".dll")
        || lower_name.ends_with(".so")
        || lower_name.ends_with(".dylib")
        || lower_name.ends_with(".com")
        || lower_name.ends_with(".scr")
    {
        FileType::Executable
    } else if lower_name.ends_with(".ps1")
        || lower_name.ends_with(".py")
        || lower_name.ends_with(".js")
        || lower_name.ends_with(".vbs")
        || lower_name.ends_with(".bat")
        || lower_name.ends_with(".cmd")
        || lower_name.ends_with(".sh")
        || lower_name.ends_with(".pl")
    {
        FileType::Script
    } else if lower_name.ends_with(".doc")
        || lower_name.ends_with(".docx")
        || lower_name.ends_with(".xls")
        || lower_name.ends_with(".xlsx")
        || lower_name.ends_with(".ppt")
        || lower_name.ends_with(".pptx")
        || lower_name.ends_with(".pdf")
    {
        FileType::Document
    } else if lower_name.ends_with(".zip")
        || lower_name.ends_with(".rar")
        || lower_name.ends_with(".7z")
        || lower_name.ends_with(".tar")
        || lower_name.ends_with(".gz")
        || lower_name.ends_with(".bz2")
    {
        FileType::Archive
    } else if lower_name.ends_with(".jpg")
        || lower_name.ends_with(".jpeg")
        || lower_name.ends_with(".png")
        || lower_name.ends_with(".gif")
        || lower_name.ends_with(".bmp")
        || lower_name.ends_with(".ico")
    {
        FileType::Image
    } else if lower_name.ends_with(".txt")
        || lower_name.ends_with(".log")
        || lower_name.ends_with(".ini")
        || lower_name.ends_with(".cfg")
        || lower_name.ends_with(".conf")
        || lower_name.ends_with(".json")
    {
        FileType::Text
    } else {
        FileType::Unknown
    }
}

fn has_double_extension(file_name: &str) -> bool {
    let lower_name = file_name.to_lowercase();

    // Common double extension patterns
    let suspicious_patterns = [
        ".pdf.exe", ".doc.exe", ".jpg.exe", ".png.exe", ".txt.exe", ".mp3.exe", ".mp4.exe",
        ".avi.exe", ".pdf.scr", ".doc.scr", ".jpg.scr", ".png.scr", ".pdf.com", ".doc.com",
        ".jpg.com", ".png.com", ".txt.com", ".mp3.com", ".mp4.com", ".avi.com",
    ];

    suspicious_patterns
        .iter()
        .any(|pattern| lower_name.ends_with(pattern))
}

fn is_suspicious_filename(file_name: &str) -> bool {
    let lower_name = file_name.to_lowercase();

    // Suspicious keywords
    let suspicious_keywords = [
        "crack",
        "keygen",
        "patch",
        "loader",
        "activator",
        "hack",
        "cheat",
        "exploit",
        "payload",
        "backdoor",
        "trojan",
        "virus",
        "malware",
        "ransom",
        "cryptor",
        "stealer",
        "keylog",
        "bot",
        "rat",
        "rootkit",
    ];

    suspicious_keywords
        .iter()
        .any(|keyword| lower_name.contains(keyword))
}

fn detect_archive_type(file_name: &str) -> ArchiveType {
    let lower_name = file_name.to_lowercase();

    if lower_name.ends_with(".zip") {
        ArchiveType::Zip
    } else if lower_name.ends_with(".rar") {
        ArchiveType::Rar
    } else if lower_name.ends_with(".7z") {
        ArchiveType::SevenZip
    } else if lower_name.ends_with(".tar") {
        ArchiveType::Tar
    } else if lower_name.ends_with(".tar.gz") || lower_name.ends_with(".tgz") {
        ArchiveType::TarGz
    } else if lower_name.ends_with(".tar.bz2") || lower_name.ends_with(".tbz2") {
        ArchiveType::TarBz2
    } else if lower_name.ends_with(".tar.xz") || lower_name.ends_with(".txz") {
        ArchiveType::TarXz
    } else {
        ArchiveType::Unknown
    }
}

fn perform_security_analysis(
    entries: &[ArchiveEntry],
    metadata: &ArchiveMetadata,
) -> Result<ArchiveSecurityAnalysis> {
    let malicious_patterns = Vec::new();
    let mut suspicious_files = Vec::new();
    let mut path_traversal_risks = Vec::new();
    let mut hidden_content = Vec::new();

    // Check for malicious patterns
    for entry in entries {
        // Check for path traversal
        if entry.path.contains("..") || entry.path.starts_with('/') {
            path_traversal_risks.push(PathTraversalRisk {
                entry_path: entry.path.clone(),
                resolved_path: "Outside archive root".to_string(),
                risk_type: "Directory Traversal".to_string(),
            });
        }

        // Check for suspicious files
        if !entry.risk_indicators.is_empty() {
            let max_risk = entry
                .risk_indicators
                .iter()
                .map(|r| &r.severity)
                .max_by_key(|s| match s {
                    RiskLevel::Low => 1,
                    RiskLevel::Medium => 2,
                    RiskLevel::High => 3,
                    RiskLevel::Critical => 4,
                })
                .unwrap_or(&RiskLevel::Low);

            suspicious_files.push(SuspiciousFile {
                path: entry.path.clone(),
                reason: entry.risk_indicators[0].description.clone(),
                risk_level: max_risk.clone(),
                indicators: entry
                    .risk_indicators
                    .iter()
                    .map(|r| r.indicator_type.clone())
                    .collect(),
            });
        }

        // Check for hidden content
        if entry.file_name.starts_with('.') {
            hidden_content.push(HiddenContent {
                content_type: "Hidden File".to_string(),
                location: entry.path.clone(),
                description: "File name starts with dot".to_string(),
            });
        }
    }

    // Check for zip bomb indicators
    let zip_bomb_indicators = check_zip_bomb(entries, metadata);

    // Determine overall risk
    let overall_risk = determine_overall_risk(
        &suspicious_files,
        &path_traversal_risks,
        &zip_bomb_indicators,
    );

    Ok(ArchiveSecurityAnalysis {
        overall_risk,
        malicious_patterns,
        suspicious_files,
        path_traversal_risks,
        zip_bomb_indicators,
        hidden_content,
    })
}

fn check_zip_bomb(entries: &[ArchiveEntry], metadata: &ArchiveMetadata) -> ZipBombIndicators {
    let mut indicators = ZipBombIndicators {
        is_potential_bomb: false,
        compression_ratio: metadata.compression_ratio,
        nesting_level: 0,
        recursive_entries: Vec::new(),
        quine_detection: false,
    };

    // Check for extreme compression ratio
    if metadata.compression_ratio > 0.99 {
        indicators.is_potential_bomb = true;
    }

    // Check for suspicious file sizes
    for entry in entries {
        if entry.size_compressed < 1000 && entry.size_uncompressed > 1_000_000_000 {
            indicators.is_potential_bomb = true;
            indicators.recursive_entries.push(entry.path.clone());
        }

        // Check for nested archives
        if matches!(entry.file_type, FileType::Archive) {
            indicators.nesting_level += 1;
        }
    }

    // Check for quine patterns (archive containing itself)
    for entry in entries {
        if entry.file_name.ends_with(".zip")
            && entry.size_uncompressed == metadata.total_size_uncompressed
        {
            indicators.quine_detection = true;
            indicators.is_potential_bomb = true;
        }
    }

    indicators
}

fn determine_overall_risk(
    suspicious_files: &[SuspiciousFile],
    path_traversal_risks: &[PathTraversalRisk],
    zip_bomb_indicators: &ZipBombIndicators,
) -> RiskLevel {
    let critical_count = suspicious_files
        .iter()
        .filter(|f| matches!(f.risk_level, RiskLevel::Critical))
        .count();
    let high_count = suspicious_files
        .iter()
        .filter(|f| matches!(f.risk_level, RiskLevel::High))
        .count();

    if critical_count > 0
        || !path_traversal_risks.is_empty()
        || zip_bomb_indicators.is_potential_bomb
    {
        RiskLevel::Critical
    } else if high_count > 0 {
        RiskLevel::High
    } else if !suspicious_files.is_empty() {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn calculate_risk_score(
    indicators: &SuspiciousArchiveIndicators,
    security: &ArchiveSecurityAnalysis,
) -> u8 {
    let mut score = 0u8;

    if indicators.has_executable {
        score += 20;
    }
    if indicators.has_script {
        score += 15;
    }
    if indicators.has_double_extension {
        score += 30;
    }
    if indicators.has_path_traversal {
        score += 40;
    }
    if indicators.has_hidden_files {
        score += 5;
    }
    if indicators.has_suspicious_names {
        score += 10;
    }

    // Add score based on counts
    score += (indicators.executable_count * 5).min(20) as u8;
    score += (indicators.script_count * 3).min(15) as u8;

    // Add score based on security analysis
    match security.overall_risk {
        RiskLevel::Critical => score += 30,
        RiskLevel::High => score += 20,
        RiskLevel::Medium => score += 10,
        RiskLevel::Low => score += 0,
    }

    score.min(100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_archive_type_detection() {
        assert!(matches!(detect_archive_type("test.zip"), ArchiveType::Zip));
        assert!(matches!(detect_archive_type("test.rar"), ArchiveType::Rar));
        assert!(matches!(
            detect_archive_type("test.7z"),
            ArchiveType::SevenZip
        ));
        assert!(matches!(
            detect_archive_type("test.tar.gz"),
            ArchiveType::TarGz
        ));
        assert!(matches!(
            detect_archive_type("test.tgz"),
            ArchiveType::TarGz
        ));
    }

    #[test]
    fn test_file_type_detection() {
        assert!(matches!(
            determine_file_type("test.exe", "test.exe"),
            FileType::Executable
        ));
        assert!(matches!(
            determine_file_type("script.ps1", "script.ps1"),
            FileType::Script
        ));
        assert!(matches!(
            determine_file_type("doc.pdf", "doc.pdf"),
            FileType::Document
        ));
        assert!(matches!(
            determine_file_type("image.jpg", "image.jpg"),
            FileType::Image
        ));
        assert!(matches!(
            determine_file_type("config.ini", "config.ini"),
            FileType::Text
        ));
    }

    #[test]
    fn test_double_extension_detection() {
        assert!(has_double_extension("document.pdf.exe"));
        assert!(has_double_extension("image.jpg.scr"));
        assert!(has_double_extension("file.txt.com"));
        assert!(!has_double_extension("normal.exe"));
        assert!(!has_double_extension("document.pdf"));
    }

    #[test]
    fn test_suspicious_filename_detection() {
        assert!(is_suspicious_filename("crack.exe"));
        assert!(is_suspicious_filename("keygen_2024.exe"));
        assert!(is_suspicious_filename("game_hack.dll"));
        assert!(is_suspicious_filename("trojan_loader.bat"));
        assert!(!is_suspicious_filename("notepad.exe"));
        assert!(!is_suspicious_filename("document.pdf"));
    }

    #[test]
    fn test_empty_zip_analysis() {
        use zip::write::ZipWriter;

        let temp_file = NamedTempFile::new().unwrap();
        {
            let file = temp_file.reopen().unwrap();
            let zip = ZipWriter::new(file);
            zip.finish().unwrap();
        }

        let result = analyze_zip(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert_eq!(analysis.metadata.total_entries, 0);
        assert!(matches!(analysis.archive_type, ArchiveType::Zip));
        assert!(matches!(
            analysis.security_analysis.overall_risk,
            RiskLevel::Low
        ));
    }

    #[test]
    fn test_zip_with_files() {
        use zip::write::{SimpleFileOptions, ZipWriter};

        let temp_file = NamedTempFile::new().unwrap();
        {
            let file = temp_file.reopen().unwrap();
            let mut zip = ZipWriter::new(file);

            // Add a text file
            zip.start_file("readme.txt", SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"This is a test file").unwrap();

            // Add a suspicious file
            zip.start_file("crack.exe", SimpleFileOptions::default())
                .unwrap();
            zip.write_all(b"MZ\x90\x00").unwrap(); // PE header

            zip.finish().unwrap();
        }

        let result = analyze_zip(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert_eq!(analysis.metadata.total_entries, 2);
        assert!(analysis.suspicious_indicators.has_executable);
        assert!(analysis.suspicious_indicators.has_suspicious_names);
        assert!(analysis.suspicious_indicators.risk_score > 0);
    }
}

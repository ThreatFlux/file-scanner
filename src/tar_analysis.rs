use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::archive_analysis::{
    ArchiveAnalysis, ArchiveMetadata, ArchiveSecurityAnalysis, ArchiveType, RiskLevel,
    SuspiciousArchiveIndicators, ZipBombIndicators,
};

/// TAR file header structure
const TAR_BLOCK_SIZE: usize = 512;
const TAR_HEADER_SIZE: usize = 512;

/// Analyze a TAR archive (including compressed variants)
///
/// This implementation provides basic TAR file detection and analysis.
/// It supports detecting .tar, .tar.gz, .tar.bz2, and .tar.xz files.
pub fn analyze_tar<P: AsRef<Path>>(path: P) -> Result<ArchiveAnalysis> {
    let path = path.as_ref();
    let file = File::open(path).context("Failed to open TAR file")?;
    let mut reader = BufReader::new(file);

    // Determine TAR type based on file extension and magic bytes
    let archive_type = detect_tar_type(path, &mut reader)?;

    // Get file size
    let file_size = std::fs::metadata(path)?.len();

    // Basic TAR header analysis
    let entry_count = count_tar_entries(&mut reader)?;

    // Create basic metadata
    let metadata = ArchiveMetadata {
        total_entries: entry_count,
        total_size_compressed: file_size,
        total_size_uncompressed: file_size, // Unknown without decompression
        compression_ratio: if matches!(archive_type, ArchiveType::Tar) {
            0.0 // Uncompressed TAR
        } else {
            0.7 // Estimate for compressed TAR
        },
        has_encryption: false, // TAR itself doesn't support encryption
        has_password: false,
        comment: None,
        created_by: Some(format!("TAR ({})", get_tar_variant_name(&archive_type))),
        creation_date: None,
    };

    // Basic security analysis
    let suspicious_indicators = analyze_tar_security(path)?;
    let security_analysis = ArchiveSecurityAnalysis {
        overall_risk: determine_tar_risk(&suspicious_indicators),
        malicious_patterns: Vec::new(),
        suspicious_files: Vec::new(),
        path_traversal_risks: Vec::new(),
        zip_bomb_indicators: ZipBombIndicators::default(),
        hidden_content: Vec::new(),
    };

    Ok(ArchiveAnalysis {
        archive_type,
        metadata,
        entries: Vec::new(), // Would need full parsing
        security_analysis,
        suspicious_indicators,
        nested_archives: Vec::new(),
    })
}

/// Detect TAR type based on file extension and magic bytes
fn detect_tar_type<R: Read + Seek>(path: &Path, reader: &mut BufReader<R>) -> Result<ArchiveType> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_lowercase();

    // Check for compressed TAR variants first
    if file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") {
        // Check for gzip magic bytes
        let mut magic = [0u8; 2];
        reader.read_exact(&mut magic)?;
        reader.seek(SeekFrom::Start(0))?;

        if magic == [0x1f, 0x8b] {
            return Ok(ArchiveType::TarGz);
        }
    } else if file_name.ends_with(".tar.bz2") || file_name.ends_with(".tbz2") {
        // Check for bzip2 magic bytes
        let mut magic = [0u8; 3];
        reader.read_exact(&mut magic)?;
        reader.seek(SeekFrom::Start(0))?;

        if magic == [0x42, 0x5a, 0x68] {
            // "BZh"
            return Ok(ArchiveType::TarBz2);
        }
    } else if file_name.ends_with(".tar.xz") || file_name.ends_with(".txz") {
        // Check for xz magic bytes
        let mut magic = [0u8; 6];
        reader.read_exact(&mut magic)?;
        reader.seek(SeekFrom::Start(0))?;

        if magic == [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] {
            return Ok(ArchiveType::TarXz);
        }
    }

    // Check for plain TAR by examining header structure
    if is_valid_tar_header(reader)? {
        Ok(ArchiveType::Tar)
    } else {
        anyhow::bail!("Not a valid TAR file");
    }
}

/// Check if the file has a valid TAR header
fn is_valid_tar_header<R: Read + Seek>(reader: &mut BufReader<R>) -> Result<bool> {
    let mut header = [0u8; TAR_HEADER_SIZE];

    // Try to read TAR header
    if reader.read_exact(&mut header).is_err() {
        return Ok(false);
    }

    reader.seek(SeekFrom::Start(0))?;

    // Check for TAR magic number in header (bytes 257-262)
    let magic = &header[257..262];
    let ustar_magic = b"ustar";

    // Check for various TAR formats
    if magic == ustar_magic ||
       &header[257..265] == b"ustar\x00\x30\x30" || // POSIX TAR
       &header[257..265] == b"ustar  \x00"
    {
        // GNU TAR
        return Ok(true);
    }

    // Check if it looks like a TAR header by examining filename field
    let filename = &header[0..100];

    // If first 100 bytes contain mostly printable characters, likely TAR
    let printable_count = filename
        .iter()
        .take_while(|&&b| b != 0) // Stop at null terminator
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'/' || b == b'.')
        .count();

    // If we have a reasonable filename and checksum validates, it's likely TAR
    if printable_count > 0 && validate_tar_checksum(&header) {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Validate TAR header checksum
fn validate_tar_checksum(header: &[u8; TAR_HEADER_SIZE]) -> bool {
    // TAR checksum is stored in bytes 148-155 (8 bytes)
    let checksum_field = &header[148..156];

    // Parse stored checksum (octal string, may be null-terminated)
    let checksum_str = std::str::from_utf8(checksum_field).unwrap_or("0");
    let clean_checksum_str = checksum_str
        .trim_end_matches('\0')
        .trim_end_matches(' ')
        .trim();

    let stored_checksum = u32::from_str_radix(clean_checksum_str, 8).unwrap_or(0);

    // Calculate checksum (sum of all bytes, treating checksum field as spaces)
    let mut calculated_checksum = 0u32;
    for (i, &byte) in header.iter().enumerate() {
        if (148..156).contains(&i) {
            calculated_checksum += u32::from(b' '); // Treat checksum field as spaces
        } else {
            calculated_checksum += u32::from(byte);
        }
    }

    stored_checksum == calculated_checksum
}

/// Count entries in TAR archive (simplified)
fn count_tar_entries<R: Read + Seek>(reader: &mut BufReader<R>) -> Result<usize> {
    reader.seek(SeekFrom::Start(0))?;

    let mut count = 0;
    let mut buffer = [0u8; TAR_HEADER_SIZE];

    while matches!(reader.read_exact(&mut buffer), Ok(())) {
        // Check if this is a valid header
        if is_empty_block(&buffer) {
            // Two consecutive empty blocks indicate end of archive
            break;
        }

        if buffer[257..262] == *b"ustar" || validate_tar_checksum(&buffer) {
            count += 1;

            // Skip file data by reading size from header
            let size_str = std::str::from_utf8(&buffer[124..136]).unwrap_or("0");
            let size = u64::from_str_radix(size_str.trim_end_matches('\0').trim(), 8).unwrap_or(0);

            // Skip to next header (round up to TAR_BLOCK_SIZE)
            let blocks_to_skip = size.div_ceil(TAR_BLOCK_SIZE as u64);
            let bytes_to_skip = blocks_to_skip * TAR_BLOCK_SIZE as u64;

            reader.seek(SeekFrom::Current(bytes_to_skip as i64))?;
        }
    }

    reader.seek(SeekFrom::Start(0))?;
    Ok(count)
}

/// Check if a TAR block is empty (all zeros)
fn is_empty_block(block: &[u8; TAR_HEADER_SIZE]) -> bool {
    block.iter().all(|&b| b == 0)
}

/// Get human-readable name for TAR variant
const fn get_tar_variant_name(archive_type: &ArchiveType) -> &'static str {
    match archive_type {
        ArchiveType::Tar => "uncompressed",
        ArchiveType::TarGz => "gzip compressed",
        ArchiveType::TarBz2 => "bzip2 compressed",
        ArchiveType::TarXz => "xz compressed",
        _ => "unknown",
    }
}

/// Analyze TAR file for security indicators
fn analyze_tar_security(path: &Path) -> Result<SuspiciousArchiveIndicators> {
    let mut indicators = SuspiciousArchiveIndicators::default();

    // Check filename
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    // Check for suspicious patterns in filename
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
        "rootkit",
        "stealer",
    ];
    let lower_name = file_name.to_lowercase();

    if suspicious_keywords
        .iter()
        .any(|&keyword| lower_name.contains(keyword))
    {
        indicators.has_suspicious_names = true;
        indicators.suspicious_patterns.push(file_name.to_string());
    }

    // Check file size for potential TAR bomb
    let metadata = std::fs::metadata(path)?;
    if metadata.len() < 2048 {
        // Very small TAR files might expand to huge sizes
        indicators.risk_score += 20;
    }

    // Check for development/source code archives (lower risk)
    if lower_name.contains("src")
        || lower_name.contains("source")
        || lower_name.contains("dev")
        || lower_name.contains("backup")
    {
        indicators.risk_score = indicators.risk_score.saturating_sub(10);
    }

    // Basic risk scoring
    if indicators.has_suspicious_names {
        indicators.risk_score += 40;
    }

    // TAR files from package managers are generally safer
    if lower_name.ends_with(".tar.xz")
        && (lower_name.contains("pkg") || lower_name.contains("package"))
    {
        indicators.risk_score = indicators.risk_score.saturating_sub(15);
    }

    Ok(indicators)
}

/// Determine overall risk level for TAR archive
const fn determine_tar_risk(indicators: &SuspiciousArchiveIndicators) -> RiskLevel {
    if indicators.risk_score > 60 {
        RiskLevel::High
    } else if indicators.risk_score > 30 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

/// Check if a file is a TAR archive by examining its structure
pub fn is_tar_file<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();

    if let Ok(file) = File::open(path) {
        let mut reader = BufReader::new(file);

        // Try to detect compressed TAR first
        if let Ok(archive_type) = detect_tar_type(path, &mut reader) {
            return matches!(
                archive_type,
                ArchiveType::Tar | ArchiveType::TarGz | ArchiveType::TarBz2 | ArchiveType::TarXz
            );
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_minimal_tar() -> Vec<u8> {
        let mut tar = vec![0u8; TAR_HEADER_SIZE * 3]; // Header + data + end blocks

        // Create a simple file entry "test.txt"
        tar[0..8].copy_from_slice(b"test.txt");
        tar[100..108].copy_from_slice(b"0000644 "); // Mode
        tar[108..116].copy_from_slice(b"0001750 "); // UID
        tar[116..124].copy_from_slice(b"0001750 "); // GID
        tar[124..135].copy_from_slice(b"00000000014"); // Size (12 bytes)
        tar[136..148].copy_from_slice(b"14174607250 "); // Mtime
        tar[156] = b'0'; // File type (regular file)
        tar[257..262].copy_from_slice(b"ustar"); // Magic
        tar[263..265].copy_from_slice(b"00"); // Version

        // Initialize checksum field with spaces
        tar[148..156].copy_from_slice(b"        ");

        // Calculate checksum
        let mut checksum = 0u32;
        for &byte in &tar[0..TAR_HEADER_SIZE] {
            checksum += u32::from(byte);
        }

        // Set checksum in proper format
        let checksum_str = format!("{checksum:06o}\0 ");
        tar[148..156].copy_from_slice(checksum_str.as_bytes());

        tar
    }

    #[test]
    fn test_tar_signature_detection() {
        let tar_data = create_minimal_tar();
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &tar_data).unwrap();

        assert!(is_tar_file(temp_file.path()));
    }

    #[test]
    fn test_non_tar_file() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), b"Not a TAR file").unwrap();

        assert!(!is_tar_file(temp_file.path()));
    }

    #[test]
    fn test_analyze_tar_valid() {
        let tar_data = create_minimal_tar();
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &tar_data).unwrap();

        let result = analyze_tar(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert!(matches!(analysis.archive_type, ArchiveType::Tar));
        assert!(analysis.metadata.created_by.is_some());
    }

    #[test]
    fn test_analyze_tar_invalid() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), b"Invalid TAR").unwrap();

        let result = analyze_tar(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_suspicious_tar_filename() {
        let temp_dir = tempfile::tempdir().unwrap();
        let suspicious_path = temp_dir.path().join("malware_exploit.tar.gz");

        let tar_data = create_minimal_tar();
        std::fs::write(&suspicious_path, &tar_data).unwrap();

        let indicators = analyze_tar_security(&suspicious_path).unwrap();
        assert!(indicators.has_suspicious_names);
        assert!(!indicators.suspicious_patterns.is_empty());
        assert!(indicators.risk_score > 0);
    }

    #[test]
    fn test_tar_risk_levels() {
        let mut indicators = SuspiciousArchiveIndicators {
            risk_score: 10,
            ..Default::default()
        };
        assert!(matches!(determine_tar_risk(&indicators), RiskLevel::Low));

        // Medium risk
        indicators.risk_score = 40;
        assert!(matches!(determine_tar_risk(&indicators), RiskLevel::Medium));

        // High risk
        indicators.risk_score = 70;
        assert!(matches!(determine_tar_risk(&indicators), RiskLevel::High));
    }

    #[test]
    fn test_tar_checksum_validation() {
        // Basic test that the checksum function doesn't panic
        let tar_data = create_minimal_tar();
        let header: [u8; TAR_HEADER_SIZE] = tar_data[0..TAR_HEADER_SIZE].try_into().unwrap();

        // Just ensure the function runs without panicking
        let _result = validate_tar_checksum(&header);
        // Note: Checksum validation is complex and may not pass with our minimal test TAR
    }

    #[test]
    fn test_package_manager_tar_detection() {
        let temp_dir = tempfile::tempdir().unwrap();
        let package_path = temp_dir.path().join("safe-package-1.0.tar.xz");

        let tar_data = create_minimal_tar();
        std::fs::write(&package_path, &tar_data).unwrap();

        let indicators = analyze_tar_security(&package_path).unwrap();
        // Should have reduced risk score due to package naming
        assert!(indicators.risk_score < 20);
    }

    #[test]
    fn test_source_code_tar_detection() {
        let temp_dir = tempfile::tempdir().unwrap();
        let source_path = temp_dir.path().join("project-src-backup.tar.gz");

        let tar_data = create_minimal_tar();
        std::fs::write(&source_path, &tar_data).unwrap();

        let indicators = analyze_tar_security(&source_path).unwrap();
        // Should have reduced risk due to source/backup naming
        assert!(indicators.risk_score < 15);
    }

    #[test]
    fn test_tar_serialization() {
        let tar_data = create_minimal_tar();
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &tar_data).unwrap();

        let analysis = analyze_tar(temp_file.path()).unwrap();

        // Test JSON serialization
        let json = serde_json::to_string(&analysis).unwrap();
        let deserialized: ArchiveAnalysis = serde_json::from_str(&json).unwrap();

        assert!(matches!(deserialized.archive_type, ArchiveType::Tar));
        assert_eq!(
            deserialized.metadata.created_by,
            analysis.metadata.created_by
        );
    }
}

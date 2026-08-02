use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::archive_analysis::{
    ArchiveAnalysis, ArchiveMetadata, ArchiveSecurityAnalysis, ArchiveType, RiskLevel,
    SuspiciousArchiveIndicators, ZipBombIndicators,
};

/// RAR file header signatures
const RAR_SIGNATURE_V4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR_SIGNATURE_V5: &[u8] = b"Rar!\x1a\x07\x01\x00";

/// Analyze a RAR archive
///
/// Note: This is a basic implementation that detects RAR files and provides
/// metadata based on file inspection. Full RAR parsing would require a
/// dedicated RAR library.
pub fn analyze_rar<P: AsRef<Path>>(path: P) -> Result<ArchiveAnalysis> {
    let path = path.as_ref();
    let file = File::open(path).context("Failed to open RAR file")?;
    let mut reader = BufReader::new(file);

    // Read header
    let mut header = [0u8; 8];
    reader
        .read_exact(&mut header)
        .context("Failed to read RAR header")?;

    // Determine RAR version
    let (archive_type, version) = if &header[0..7] == RAR_SIGNATURE_V4 {
        (ArchiveType::Rar, "4.x")
    } else if header == RAR_SIGNATURE_V5 {
        (ArchiveType::Rar, "5.x")
    } else {
        anyhow::bail!("Not a valid RAR file");
    };

    // Get file size
    let file_size = std::fs::metadata(path)?.len();

    // Create basic metadata
    let metadata = ArchiveMetadata {
        total_entries: 0, // Would need full parsing
        total_size_compressed: file_size,
        total_size_uncompressed: file_size, // Unknown without parsing
        compression_ratio: 0.0,             // Unknown
        has_encryption: detect_encryption(&mut reader)?,
        has_password: false, // Would need to check
        comment: None,
        created_by: Some(format!("RAR {version}")),
        creation_date: None,
    };

    // Basic security analysis
    let suspicious_indicators = analyze_rar_security(path)?;
    let security_analysis = ArchiveSecurityAnalysis {
        overall_risk: determine_rar_risk(&suspicious_indicators),
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

/// Detect if RAR archive is encrypted
fn detect_encryption(reader: &mut BufReader<File>) -> Result<bool> {
    // Save current position
    let current_pos = reader.stream_position()?;

    // In RAR format, encryption is indicated in the file headers
    // This is a simplified check - full implementation would parse headers
    let mut buffer = [0u8; 1024];
    let bytes_read = reader.read(&mut buffer)?;

    // Restore position
    reader.seek(SeekFrom::Start(current_pos))?;

    // Look for encryption indicators in the header
    // RAR uses specific flags in the header to indicate encryption
    for &byte in buffer.iter().take(bytes_read.saturating_sub(2)) {
        // Check for common encryption flag patterns
        if byte == 0x80 || (byte & 0x04) != 0 {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Analyze RAR file for security indicators
fn analyze_rar_security(path: &Path) -> Result<SuspiciousArchiveIndicators> {
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
    ];
    let lower_name = file_name.to_lowercase();

    if suspicious_keywords
        .iter()
        .any(|&keyword| lower_name.contains(keyword))
    {
        indicators.has_suspicious_names = true;
        indicators.suspicious_patterns.push(file_name.to_string());
    }

    // Check file size for potential RAR bomb
    let metadata = std::fs::metadata(path)?;
    if metadata.len() < 1000 {
        // Very small RAR files might expand to huge sizes
        indicators.risk_score += 20;
    }

    // Basic risk scoring
    if indicators.has_suspicious_names {
        indicators.risk_score += 30;
    }

    Ok(indicators)
}

/// Determine overall risk level for RAR archive
const fn determine_rar_risk(indicators: &SuspiciousArchiveIndicators) -> RiskLevel {
    if indicators.risk_score > 60 {
        RiskLevel::High
    } else if indicators.risk_score > 30 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

/// Check if a file is a RAR archive by examining its header
pub fn is_rar_file<P: AsRef<Path>>(path: P) -> bool {
    if let Ok(mut file) = File::open(path.as_ref()) {
        let mut header = [0u8; 8];
        // Try to read 8 bytes (for v5), but also handle v4 which is only 7 bytes
        match file.read(&mut header) {
            Ok(7) => &header[0..7] == RAR_SIGNATURE_V4,
            Ok(8..) => &header[0..7] == RAR_SIGNATURE_V4 || header == RAR_SIGNATURE_V5,
            _ => false,
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_rar_signature_detection() {
        // Test RAR v4 signature
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), RAR_SIGNATURE_V4).unwrap();
        assert!(is_rar_file(temp_file.path()));

        // Test RAR v5 signature
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), RAR_SIGNATURE_V5).unwrap();
        assert!(is_rar_file(temp_file.path()));
    }

    #[test]
    fn test_non_rar_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Not a RAR file").unwrap();
        temp_file.flush().unwrap();

        assert!(!is_rar_file(temp_file.path()));
    }

    #[test]
    fn test_analyze_rar_invalid_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(b"Invalid RAR").unwrap();
        temp_file.flush().unwrap();

        let result = analyze_rar(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_rar_v4() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(RAR_SIGNATURE_V4).unwrap();
        // Add some dummy data
        temp_file.write_all(&[0u8; 100]).unwrap();
        temp_file.flush().unwrap();

        let result = analyze_rar(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert!(matches!(analysis.archive_type, ArchiveType::Rar));
        assert_eq!(analysis.metadata.created_by, Some("RAR 4.x".to_string()));
    }

    #[test]
    fn test_analyze_rar_v5() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(RAR_SIGNATURE_V5).unwrap();
        // Add some dummy data
        temp_file.write_all(&[0u8; 100]).unwrap();
        temp_file.flush().unwrap();

        let result = analyze_rar(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert!(matches!(analysis.archive_type, ArchiveType::Rar));
        assert_eq!(analysis.metadata.created_by, Some("RAR 5.x".to_string()));
    }

    #[test]
    fn test_suspicious_rar_filename() {
        let temp_dir = tempfile::tempdir().unwrap();
        let suspicious_path = temp_dir.path().join("crack_v2.rar");

        let mut file = File::create(&suspicious_path).unwrap();
        file.write_all(RAR_SIGNATURE_V4).unwrap();
        file.write_all(&[0u8; 100]).unwrap();

        let indicators = analyze_rar_security(&suspicious_path).unwrap();
        assert!(indicators.has_suspicious_names);
        assert!(!indicators.suspicious_patterns.is_empty());
        assert!(indicators.risk_score > 0);
    }

    #[test]
    fn test_small_rar_bomb_detection() {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(RAR_SIGNATURE_V4).unwrap();
        // Very small file - potential bomb
        temp_file.write_all(&[0u8; 10]).unwrap();
        temp_file.flush().unwrap();

        let indicators = analyze_rar_security(temp_file.path()).unwrap();
        assert!(indicators.risk_score >= 20);
    }

    #[test]
    fn test_rar_risk_levels() {
        let mut indicators = SuspiciousArchiveIndicators {
            risk_score: 10,
            ..Default::default()
        };
        assert!(matches!(determine_rar_risk(&indicators), RiskLevel::Low));

        // Medium risk
        indicators.risk_score = 40;
        assert!(matches!(determine_rar_risk(&indicators), RiskLevel::Medium));

        // High risk
        indicators.risk_score = 70;
        assert!(matches!(determine_rar_risk(&indicators), RiskLevel::High));
    }

    #[test]
    fn test_encryption_detection() {
        // Create a file with encryption indicators
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(RAR_SIGNATURE_V4).unwrap();
        // Add some data with encryption flag
        temp_file.write_all(&[0x00, 0x80, 0x00]).unwrap(); // Encryption flag
        temp_file.write_all(&[0u8; 100]).unwrap();
        temp_file.flush().unwrap();

        let file = File::open(temp_file.path()).unwrap();
        let mut reader = BufReader::new(file);

        // Skip header
        let mut header = [0u8; 8];
        reader.read_exact(&mut header).unwrap();

        let encrypted = detect_encryption(&mut reader).unwrap();
        assert!(encrypted);
    }
}

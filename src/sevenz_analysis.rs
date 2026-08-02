use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::archive_analysis::{
    ArchiveAnalysis, ArchiveMetadata, ArchiveSecurityAnalysis, ArchiveType, RiskLevel,
    SuspiciousArchiveIndicators, ZipBombIndicators,
};

/// 7-Zip file header signatures
const SEVENZ_SIGNATURE: &[u8] = b"7z\xBC\xAF\x27\x1C";

/// Analyze a 7-Zip archive
///
/// Note: This is a basic implementation that detects 7z files and provides
/// metadata based on file inspection. Full 7z parsing would require a
/// dedicated 7z library.
pub fn analyze_7z<P: AsRef<Path>>(path: P) -> Result<ArchiveAnalysis> {
    let path = path.as_ref();
    let file = File::open(path).context("Failed to open 7z file")?;
    let mut reader = BufReader::new(file);

    // Read header
    let mut header = [0u8; 6];
    reader
        .read_exact(&mut header)
        .context("Failed to read 7z header")?;

    // Check signature
    if header != SEVENZ_SIGNATURE {
        anyhow::bail!("Not a valid 7z file");
    }

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
        created_by: Some("7-Zip".to_string()),
        creation_date: None,
    };

    // Basic security analysis
    let suspicious_indicators = analyze_7z_security(path)?;
    let security_analysis = ArchiveSecurityAnalysis {
        overall_risk: determine_7z_risk(&suspicious_indicators),
        malicious_patterns: Vec::new(),
        suspicious_files: Vec::new(),
        path_traversal_risks: Vec::new(),
        zip_bomb_indicators: ZipBombIndicators::default(),
        hidden_content: Vec::new(),
    };

    Ok(ArchiveAnalysis {
        archive_type: ArchiveType::SevenZip,
        metadata,
        entries: Vec::new(), // Would need full parsing
        security_analysis,
        suspicious_indicators,
        nested_archives: Vec::new(),
    })
}

/// Detect if 7z archive is encrypted
fn detect_encryption(reader: &mut BufReader<File>) -> Result<bool> {
    // Save current position
    let current_pos = reader.stream_position()?;

    // In 7z format, encryption is indicated in the header
    // This is a simplified check - full implementation would parse headers
    let mut buffer = [0u8; 32];
    let bytes_read = reader.read(&mut buffer)?;

    // Restore position
    reader.seek(SeekFrom::Start(current_pos))?;

    // Look for encryption indicators in the 7z header
    // 7z uses specific bytes to indicate encryption
    for &byte in buffer.iter().take(bytes_read) {
        // Check for AES encryption indicator
        if byte == 0x06 || byte == 0x01 {
            // Common encryption method IDs
            return Ok(true);
        }
    }

    Ok(false)
}

/// Analyze 7z file for security indicators
fn analyze_7z_security(path: &Path) -> Result<SuspiciousArchiveIndicators> {
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
    ];
    let lower_name = file_name.to_lowercase();

    if suspicious_keywords
        .iter()
        .any(|&keyword| lower_name.contains(keyword))
    {
        indicators.has_suspicious_names = true;
        indicators.suspicious_patterns.push(file_name.to_string());
    }

    // Check file size for potential 7z bomb
    let metadata = std::fs::metadata(path)?;
    if metadata.len() < 1000 {
        // Very small 7z files might expand to huge sizes
        indicators.risk_score += 25;
    }

    // Check for password-protected indicators (simplified)
    if lower_name.contains("password") || lower_name.contains("encrypted") {
        indicators.risk_score += 15;
    }

    // Basic risk scoring
    if indicators.has_suspicious_names {
        indicators.risk_score += 35;
    }

    Ok(indicators)
}

/// Determine overall risk level for 7z archive
const fn determine_7z_risk(indicators: &SuspiciousArchiveIndicators) -> RiskLevel {
    if indicators.risk_score > 70 {
        RiskLevel::Critical
    } else if indicators.risk_score > 50 {
        RiskLevel::High
    } else if indicators.risk_score > 25 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

/// Check if a file is a 7z archive by examining its header
pub fn is_7z_file<P: AsRef<Path>>(path: P) -> bool {
    if let Ok(mut file) = File::open(path.as_ref()) {
        let mut header = [0u8; 6];
        if file.read_exact(&mut header).is_ok() {
            return header == SEVENZ_SIGNATURE;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_7z_signature_detection() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), SEVENZ_SIGNATURE).unwrap();
        assert!(is_7z_file(temp_file.path()));
    }

    #[test]
    fn test_non_7z_file() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), b"Not a 7z file").unwrap();
        assert!(!is_7z_file(temp_file.path()));
    }

    #[test]
    fn test_analyze_7z_invalid_file() {
        let temp_file = NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), b"Invalid 7z").unwrap();

        let result = analyze_7z(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_7z_valid() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut content = Vec::from(SEVENZ_SIGNATURE);
        content.extend_from_slice(&[0u8; 100]); // Add some dummy data
        std::fs::write(temp_file.path(), &content).unwrap();

        let result = analyze_7z(temp_file.path());
        assert!(result.is_ok());

        let analysis = result.unwrap();
        assert!(matches!(analysis.archive_type, ArchiveType::SevenZip));
        assert_eq!(analysis.metadata.created_by, Some("7-Zip".to_string()));
    }

    #[test]
    fn test_suspicious_7z_filename() {
        let temp_dir = tempfile::tempdir().unwrap();
        let suspicious_path = temp_dir.path().join("malware_crack.7z");

        let mut content = Vec::from(SEVENZ_SIGNATURE);
        content.extend_from_slice(&[0u8; 100]);
        std::fs::write(&suspicious_path, &content).unwrap();

        let indicators = analyze_7z_security(&suspicious_path).unwrap();
        assert!(indicators.has_suspicious_names);
        assert!(!indicators.suspicious_patterns.is_empty());
        assert!(indicators.risk_score > 0);
    }

    #[test]
    fn test_small_7z_bomb_detection() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut content = Vec::from(SEVENZ_SIGNATURE);
        content.extend_from_slice(&[0u8; 10]); // Very small file - potential bomb
        std::fs::write(temp_file.path(), &content).unwrap();

        let indicators = analyze_7z_security(temp_file.path()).unwrap();
        assert!(indicators.risk_score >= 25);
    }

    #[test]
    fn test_7z_risk_levels() {
        let mut indicators = SuspiciousArchiveIndicators {
            risk_score: 10,
            ..Default::default()
        };
        assert!(matches!(determine_7z_risk(&indicators), RiskLevel::Low));

        // Medium risk
        indicators.risk_score = 30;
        assert!(matches!(determine_7z_risk(&indicators), RiskLevel::Medium));

        // High risk
        indicators.risk_score = 60;
        assert!(matches!(determine_7z_risk(&indicators), RiskLevel::High));

        // Critical risk
        indicators.risk_score = 80;
        assert!(matches!(
            determine_7z_risk(&indicators),
            RiskLevel::Critical
        ));
    }

    #[test]
    fn test_encryption_detection() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut content = Vec::from(SEVENZ_SIGNATURE);
        // Add header with encryption indicator
        content.extend_from_slice(&[0x06, 0x01, 0x00]); // Encryption method indicators
        content.extend_from_slice(&[0u8; 100]);
        std::fs::write(temp_file.path(), &content).unwrap();

        let file = File::open(temp_file.path()).unwrap();
        let mut reader = BufReader::new(file);

        // Skip signature
        let mut header = [0u8; 6];
        reader.read_exact(&mut header).unwrap();

        let encrypted = detect_encryption(&mut reader).unwrap();
        assert!(encrypted);
    }

    #[test]
    fn test_password_protected_filename() {
        let temp_dir = tempfile::tempdir().unwrap();
        let password_path = temp_dir.path().join("encrypted_data.7z");

        let mut content = Vec::from(SEVENZ_SIGNATURE);
        content.extend_from_slice(&[0u8; 100]);
        std::fs::write(&password_path, &content).unwrap();

        let indicators = analyze_7z_security(&password_path).unwrap();
        assert!(indicators.risk_score >= 15); // Password indicator bonus
    }

    #[test]
    fn test_7z_serialization() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut content = Vec::from(SEVENZ_SIGNATURE);
        content.extend_from_slice(&[0u8; 1024]);
        std::fs::write(temp_file.path(), &content).unwrap();

        let analysis = analyze_7z(temp_file.path()).unwrap();

        // Test JSON serialization
        let json = serde_json::to_string(&analysis).unwrap();
        let deserialized: ArchiveAnalysis = serde_json::from_str(&json).unwrap();

        assert!(matches!(deserialized.archive_type, ArchiveType::SevenZip));
        assert_eq!(
            deserialized.metadata.created_by,
            analysis.metadata.created_by
        );
    }
}

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub is_signed: bool,
    pub signature_type: Option<String>,
    pub signer: Option<String>,
    pub timestamp: Option<String>,
    pub certificate_chain: Vec<CertificateInfo>,
    pub verification_status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
}

pub fn verify_signature(path: &Path) -> Result<SignatureInfo> {
    // Try different signature verification methods based on the platform and file type

    // First, check if it's a PE file with Authenticode signature
    if let Ok(authenticode_info) = check_authenticode_signature(path) {
        return Ok(authenticode_info);
    }

    // Check for GPG signatures
    if let Ok(gpg_info) = check_gpg_signature(path) {
        return Ok(gpg_info);
    }

    // Check for macOS code signatures
    if cfg!(target_os = "macos") {
        if let Ok(codesign_info) = check_macos_codesign(path) {
            return Ok(codesign_info);
        }
    }

    // No signature found
    Ok(SignatureInfo {
        is_signed: false,
        signature_type: None,
        signer: None,
        timestamp: None,
        certificate_chain: Vec::new(),
        verification_status: "No signature found".to_string(),
    })
}

fn check_authenticode_signature(path: &Path) -> Result<SignatureInfo> {
    // This is a simplified version. In production, you'd use Windows APIs
    // or a library like authenticode-parser

    let buffer = std::fs::read(path)?;

    // Check for PE signature
    if buffer.len() < 64 || &buffer[0..2] != b"MZ" {
        anyhow::bail!("Not a PE file");
    }

    // In a real implementation, you would:
    // 1. Parse the PE headers
    // 2. Find the security directory
    // 3. Parse the PKCS#7 signature
    // 4. Verify the certificate chain

    // For now, we'll use osslsigncode if available
    if let Ok(output) = Command::new("osslsigncode")
        .arg("verify")
        .arg(path)
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let _stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() && stdout.contains("Signature verification: ok") {
            return Ok(SignatureInfo {
                is_signed: true,
                signature_type: Some("Authenticode".to_string()),
                signer: extract_signer_from_output(&stdout),
                timestamp: extract_timestamp_from_output(&stdout),
                certificate_chain: Vec::new(), // Would parse from output
                verification_status: "Valid".to_string(),
            });
        }
    }

    anyhow::bail!("No Authenticode signature found")
}

fn check_gpg_signature(path: &Path) -> Result<SignatureInfo> {
    // Check for detached GPG signature
    let sig_path = path.with_extension(format!(
        "{}.sig",
        path.extension().unwrap_or_default().to_str().unwrap_or("")
    ));
    let asc_path = path.with_extension(format!(
        "{}.asc",
        path.extension().unwrap_or_default().to_str().unwrap_or("")
    ));

    let sig_file = if sig_path.exists() {
        Some(sig_path)
    } else if asc_path.exists() {
        Some(asc_path)
    } else {
        None
    };

    if let Some(sig_file) = sig_file {
        if let Ok(output) = Command::new("gpg")
            .arg("--verify")
            .arg(sig_file)
            .arg(path)
            .output()
        {
            let stderr = String::from_utf8_lossy(&output.stderr);

            if stderr.contains("Good signature") {
                return Ok(SignatureInfo {
                    is_signed: true,
                    signature_type: Some("GPG".to_string()),
                    signer: extract_gpg_signer(&stderr),
                    timestamp: extract_gpg_timestamp(&stderr),
                    certificate_chain: Vec::new(),
                    verification_status: "Valid".to_string(),
                });
            }
        }
    }

    anyhow::bail!("No GPG signature found")
}

fn check_macos_codesign(path: &Path) -> Result<SignatureInfo> {
    if let Ok(output) = Command::new("codesign")
        .arg("-dv")
        .arg("--verbose=4")
        .arg(path)
        .output()
    {
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            let mut info = SignatureInfo {
                is_signed: true,
                signature_type: Some("Apple Code Signature".to_string()),
                signer: None,
                timestamp: None,
                certificate_chain: Vec::new(),
                verification_status: "Unknown".to_string(),
            };

            // Parse authority
            if let Some(auth_line) = stderr.lines().find(|l| l.starts_with("Authority=")) {
                info.signer = Some(auth_line.replace("Authority=", "").to_string());
            }

            // Parse timestamp
            if let Some(ts_line) = stderr.lines().find(|l| l.starts_with("Timestamp=")) {
                info.timestamp = Some(ts_line.replace("Timestamp=", "").to_string());
            }

            // Verify signature
            if let Ok(verify_output) = Command::new("codesign")
                .arg("--verify")
                .arg("--deep")
                .arg("--strict")
                .arg(path)
                .output()
            {
                info.verification_status = if verify_output.status.success() {
                    "Valid".to_string()
                } else {
                    "Invalid".to_string()
                };
            }

            return Ok(info);
        }
    }

    anyhow::bail!("No macOS code signature found")
}

fn extract_signer_from_output(output: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.contains("Subject:"))
        .map(|l| l.split("Subject:").nth(1).unwrap_or("").trim().to_string())
}

fn extract_timestamp_from_output(output: &str) -> Option<String> {
    output.lines().find(|l| l.contains("Timestamp:")).map(|l| {
        l.split("Timestamp:")
            .nth(1)
            .unwrap_or("")
            .trim()
            .to_string()
    })
}

fn extract_gpg_signer(output: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.contains("Good signature from"))
        .map(|l| {
            l.split("Good signature from")
                .nth(1)
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .to_string()
        })
}

fn extract_gpg_timestamp(output: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.contains("Signature made"))
        .map(|l| {
            l.split("Signature made")
                .nth(1)
                .unwrap_or("")
                .trim()
                .to_string()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_file(content: &[u8]) -> Result<(TempDir, std::path::PathBuf)> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_file");
        let mut file = fs::File::create(&file_path)?;
        file.write_all(content)?;
        Ok((temp_dir, file_path))
    }

    fn create_pe_file() -> Vec<u8> {
        let mut pe = vec![
            // DOS header
            0x4d, 0x5a, // "MZ"
        ];

        // Pad DOS header to 64 bytes
        while pe.len() < 64 {
            pe.push(0);
        }

        pe
    }

    #[test]
    fn test_signature_info_creation() {
        let info = SignatureInfo {
            is_signed: true,
            signature_type: Some("Test".to_string()),
            signer: Some("Test Signer".to_string()),
            timestamp: Some("2024-01-01".to_string()),
            certificate_chain: vec![CertificateInfo {
                subject: "CN=Test".to_string(),
                issuer: "CN=Test CA".to_string(),
                serial_number: "123456".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2025-01-01".to_string(),
            }],
            verification_status: "Valid".to_string(),
        };

        assert!(info.is_signed);
        assert_eq!(info.signature_type, Some("Test".to_string()));
        assert_eq!(info.signer, Some("Test Signer".to_string()));
        assert_eq!(info.certificate_chain.len(), 1);
    }

    #[test]
    fn test_certificate_info_creation() {
        let cert = CertificateInfo {
            subject: "CN=Test Certificate".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "ABCDEF123456".to_string(),
            not_before: "2024-01-01T00:00:00Z".to_string(),
            not_after: "2025-01-01T00:00:00Z".to_string(),
        };

        assert_eq!(cert.subject, "CN=Test Certificate");
        assert_eq!(cert.issuer, "CN=Test CA");
        assert_eq!(cert.serial_number, "ABCDEF123456");
    }

    #[test]
    fn test_verify_signature_no_signature() {
        let content = b"Just plain text file";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let result = verify_signature(&file_path).unwrap();

        assert!(!result.is_signed);
        assert_eq!(result.signature_type, None);
        assert_eq!(result.signer, None);
        assert_eq!(result.timestamp, None);
        assert!(result.certificate_chain.is_empty());
        assert_eq!(result.verification_status, "No signature found");
    }

    #[test]
    fn test_check_authenticode_signature_not_pe() {
        let content = b"Not a PE file";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let result = check_authenticode_signature(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_authenticode_signature_pe_no_sig() {
        let pe_content = create_pe_file();
        let (_temp_dir, file_path) = create_test_file(&pe_content).unwrap();

        let result = check_authenticode_signature(&file_path);
        // Should fail because osslsigncode is likely not available or PE has no signature
        assert!(result.is_err());
    }

    #[test]
    fn test_check_gpg_signature_no_sig_file() {
        let content = b"Test file content";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let result = check_gpg_signature(&file_path);
        assert!(result.is_err()); // No .sig or .asc file exists
    }

    #[test]
    fn test_check_gpg_signature_with_sig_file() {
        let content = b"Test file content";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        // Create a dummy .sig file
        let sig_path = file_path.with_extension("sig");
        fs::write(&sig_path, b"dummy signature").unwrap();

        let result = check_gpg_signature(&file_path);
        // Should fail because gpg command will fail on dummy signature
        assert!(result.is_err());
    }

    #[test]
    fn test_check_gpg_signature_with_asc_file() {
        let content = b"Test file content";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        // Create a dummy .asc file
        let asc_path = file_path.with_extension("asc");
        fs::write(&asc_path, b"dummy ascii signature").unwrap();

        let result = check_gpg_signature(&file_path);
        // Should fail because gpg command will fail on dummy signature
        assert!(result.is_err());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_check_macos_codesign() {
        let content = b"Test binary content";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        let result = check_macos_codesign(&file_path);
        // Should fail because test file is not a proper macOS binary
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_signer_from_output() {
        let output = "Some other line\nSubject: CN=Test Signer, O=Test Org\nAnother line";
        let signer = extract_signer_from_output(output);
        assert_eq!(signer, Some("CN=Test Signer, O=Test Org".to_string()));
    }

    #[test]
    fn test_extract_signer_from_output_no_subject() {
        let output = "Some line\nAnother line\nNo subject here";
        let signer = extract_signer_from_output(output);
        assert_eq!(signer, None);
    }

    #[test]
    fn test_extract_timestamp_from_output() {
        let output = "Line 1\nTimestamp: 2024-01-01 12:00:00\nLine 3";
        let timestamp = extract_timestamp_from_output(output);
        assert_eq!(timestamp, Some("2024-01-01 12:00:00".to_string()));
    }

    #[test]
    fn test_extract_timestamp_from_output_no_timestamp() {
        let output = "Line 1\nLine 2\nNo timestamp here";
        let timestamp = extract_timestamp_from_output(output);
        assert_eq!(timestamp, None);
    }

    #[test]
    fn test_extract_gpg_signer() {
        let output = "gpg: Signature made Mon 01 Jan 2024\ngpg: Good signature from \"Test User <test@example.com>\"\ngpg: checking";
        let signer = extract_gpg_signer(output);
        assert_eq!(signer, Some("Test User <test@example.com>".to_string()));
    }

    #[test]
    fn test_extract_gpg_signer_no_good_signature() {
        let output =
            "gpg: Signature made Mon 01 Jan 2024\ngpg: BAD signature from someone\ngpg: checking";
        let signer = extract_gpg_signer(output);
        assert_eq!(signer, None);
    }

    #[test]
    fn test_extract_gpg_timestamp() {
        let output =
            "gpg: Signature made Mon 01 Jan 2024 12:00:00 UTC\ngpg: Good signature\ngpg: checking";
        let timestamp = extract_gpg_timestamp(output);
        assert_eq!(timestamp, Some("Mon 01 Jan 2024 12:00:00 UTC".to_string()));
    }

    #[test]
    fn test_extract_gpg_timestamp_no_signature_made() {
        let output = "gpg: Some other output\ngpg: Good signature\ngpg: checking";
        let timestamp = extract_gpg_timestamp(output);
        assert_eq!(timestamp, None);
    }

    #[test]
    fn test_signature_info_serialization() {
        let info = SignatureInfo {
            is_signed: true,
            signature_type: Some("GPG".to_string()),
            signer: Some("Test User".to_string()),
            timestamp: Some("2024-01-01".to_string()),
            certificate_chain: vec![CertificateInfo {
                subject: "CN=Test".to_string(),
                issuer: "CN=CA".to_string(),
                serial_number: "123".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2025-01-01".to_string(),
            }],
            verification_status: "Valid".to_string(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: SignatureInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.is_signed, info.is_signed);
        assert_eq!(deserialized.signature_type, info.signature_type);
        assert_eq!(deserialized.signer, info.signer);
        assert_eq!(deserialized.certificate_chain.len(), 1);
    }

    #[test]
    fn test_certificate_info_serialization() {
        let cert = CertificateInfo {
            subject: "CN=Test Certificate".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "ABCDEF123456".to_string(),
            not_before: "2024-01-01T00:00:00Z".to_string(),
            not_after: "2025-01-01T00:00:00Z".to_string(),
        };

        // Test JSON serialization
        let json = serde_json::to_string(&cert).unwrap();
        let deserialized: CertificateInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.subject, cert.subject);
        assert_eq!(deserialized.issuer, cert.issuer);
        assert_eq!(deserialized.serial_number, cert.serial_number);
        assert_eq!(deserialized.not_before, cert.not_before);
        assert_eq!(deserialized.not_after, cert.not_after);
    }

    #[test]
    fn test_verify_signature_nonexistent_file() {
        let path = std::path::Path::new("/nonexistent/file");
        let result = verify_signature(path);

        // The function returns Ok with "No signature found" for nonexistent files
        // because the signature verification functions handle file errors internally
        if result.is_ok() {
            let info = result.unwrap();
            assert!(!info.is_signed);
            assert_eq!(info.verification_status, "No signature found");
        } else {
            // It's also acceptable if it returns an error
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_empty_file_signature() {
        let (_temp_dir, file_path) = create_test_file(b"").unwrap();

        let result = verify_signature(&file_path).unwrap();

        assert!(!result.is_signed);
        assert_eq!(result.verification_status, "No signature found");
    }

    #[test]
    fn test_signature_info_defaults() {
        let info = SignatureInfo {
            is_signed: false,
            signature_type: None,
            signer: None,
            timestamp: None,
            certificate_chain: Vec::new(),
            verification_status: "Unknown".to_string(),
        };

        assert!(!info.is_signed);
        assert!(info.signature_type.is_none());
        assert!(info.signer.is_none());
        assert!(info.timestamp.is_none());
        assert!(info.certificate_chain.is_empty());
        assert_eq!(info.verification_status, "Unknown");
    }

    #[test]
    fn test_extract_functions_with_empty_input() {
        assert_eq!(extract_signer_from_output(""), None);
        assert_eq!(extract_timestamp_from_output(""), None);
        assert_eq!(extract_gpg_signer(""), None);
        assert_eq!(extract_gpg_timestamp(""), None);
    }

    #[test]
    fn test_extract_functions_with_partial_matches() {
        // Test partial matches that shouldn't trigger
        assert_eq!(extract_signer_from_output("Subject is missing colon"), None);
        assert_eq!(
            extract_timestamp_from_output("Timestamp is missing colon"),
            None
        );
        assert_eq!(extract_gpg_signer("Good signature is incomplete"), None);
        assert_eq!(extract_gpg_timestamp("Signature is incomplete"), None);
    }

    #[test]
    fn test_complex_gpg_output_parsing() {
        let complex_output = r#"
gpg: Signature made Fri 15 Dec 2023 10:30:45 AM UTC
gpg:                using RSA key 1234567890ABCDEF
gpg: Can't check signature: No public key
gpg: Signature made Fri 15 Dec 2023 10:30:45 AM UTC  
gpg:                using RSA key FEDCBA0987654321
gpg: Good signature from "John Doe <john@example.com>"
gpg: WARNING: This key is not certified with a trusted signature!
"#;

        let signer = extract_gpg_signer(complex_output);
        assert_eq!(signer, Some("John Doe <john@example.com>".to_string()));

        let timestamp = extract_gpg_timestamp(complex_output);
        assert_eq!(
            timestamp,
            Some("Fri 15 Dec 2023 10:30:45 AM UTC".to_string())
        );
    }

    #[test]
    fn test_pe_file_too_small() {
        let small_content = b"MZ"; // Too small to be valid PE
        let (_temp_dir, file_path) = create_test_file(small_content).unwrap();

        let result = check_authenticode_signature(&file_path);
        assert!(result.is_err());
    }

    // Additional comprehensive tests for better coverage

    #[test]
    fn test_pe_file_exact_64_bytes() {
        let mut content = b"MZ".to_vec();
        while content.len() < 64 {
            content.push(0);
        }
        let (_temp_dir, file_path) = create_test_file(&content).unwrap();

        let result = check_authenticode_signature(&file_path);
        assert!(result.is_err()); // No signature in minimal PE
    }

    #[test]
    fn test_verify_signature_with_all_file_types() {
        // Test various file types
        let test_files = vec![
            (b"#!/bin/bash\necho test".to_vec(), "script.sh"),
            (b"<?xml version=\"1.0\"?>".to_vec(), "data.xml"),
            (b"{\"test\": \"json\"}".to_vec(), "data.json"),
            (vec![0xFF, 0xD8, 0xFF, 0xE0], "image.jpg"), // JPEG header
            (vec![0x89, 0x50, 0x4E, 0x47], "image.png"), // PNG header
        ];

        for (content, name) in test_files {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join(name);
            fs::write(&file_path, content).unwrap();

            let result = verify_signature(&file_path).unwrap();
            assert!(!result.is_signed);
            assert_eq!(result.verification_status, "No signature found");
        }
    }

    #[test]
    fn test_gpg_signature_extensions() {
        let content = b"Test content";
        let temp_dir = TempDir::new().unwrap();

        // Test with different base extensions
        let extensions = vec!["txt", "bin", "exe", "tar.gz", ""];

        for ext in extensions {
            let filename = if ext.is_empty() {
                "file"
            } else {
                &format!("file.{}", ext)
            };

            let file_path = temp_dir.path().join(filename);
            fs::write(&file_path, content).unwrap();

            // Create corresponding .sig file
            let sig_extension = if ext.is_empty() {
                "sig".to_string()
            } else {
                format!("{}.sig", ext)
            };

            let sig_path = file_path.with_extension(&sig_extension);
            fs::write(&sig_path, b"dummy sig").unwrap();

            let result = check_gpg_signature(&file_path);
            assert!(result.is_err()); // GPG will fail on dummy signature
        }
    }

    #[test]
    fn test_extract_signer_various_formats() {
        let test_cases = vec![
            ("Subject: CN=Test", "CN=Test"),
            ("Subject:CN=Test", "CN=Test"), // No space after colon
            ("Subject:    CN=Test    ", "CN=Test"), // Extra spaces
            ("Subject: CN=Test, O=Org, C=US", "CN=Test, O=Org, C=US"),
            ("Subject: ", ""), // Empty subject
        ];

        for (input, expected) in test_cases {
            let result = extract_signer_from_output(input);
            assert_eq!(result, Some(expected.to_string()));
        }
    }

    #[test]
    fn test_extract_timestamp_various_formats() {
        let test_cases = vec![
            ("Timestamp: 2024-01-01", "2024-01-01"),
            ("Timestamp:2024-01-01", "2024-01-01"), // No space
            ("Timestamp:    2024-01-01    ", "2024-01-01"), // Extra spaces
            ("Timestamp: ", ""),                    // Empty timestamp
            (
                "Timestamp: 2024-01-01T10:30:45.123Z",
                "2024-01-01T10:30:45.123Z",
            ), // ISO format
        ];

        for (input, expected) in test_cases {
            let result = extract_timestamp_from_output(input);
            assert_eq!(result, Some(expected.to_string()));
        }
    }

    #[test]
    fn test_extract_gpg_signer_edge_cases() {
        let test_cases = vec![
            (
                "gpg: Good signature from \"Test \\\"Quoted\\\" User\"",
                "Test \\\"Quoted\\\" User",
            ),
            (
                "gpg: Good signature from \"\"", // Empty quotes
                "",
            ),
        ];

        for (input, expected) in test_cases {
            let result = extract_gpg_signer(input);
            assert_eq!(result, Some(expected.to_string()));
        }

        // Test newline case separately - extract_gpg_signer works line by line
        let input_with_newline = "gpg: Good signature from \"User with\nnewline\"";
        let result = extract_gpg_signer(input_with_newline);
        // The function splits by lines and only gets first part before newline
        assert_eq!(result, Some("User with".to_string()));
    }

    #[test]
    fn test_certificate_chain_operations() {
        let mut info = SignatureInfo {
            is_signed: true,
            signature_type: Some("Test".to_string()),
            signer: Some("Test Signer".to_string()),
            timestamp: None,
            certificate_chain: Vec::new(),
            verification_status: "Unknown".to_string(),
        };

        // Test adding certificates
        for i in 0..5 {
            info.certificate_chain.push(CertificateInfo {
                subject: format!("CN=Cert{}", i),
                issuer: format!("CN=Issuer{}", i),
                serial_number: format!("{:X}", i),
                not_before: "2024-01-01".to_string(),
                not_after: "2025-01-01".to_string(),
            });
        }

        assert_eq!(info.certificate_chain.len(), 5);
        assert_eq!(info.certificate_chain[0].subject, "CN=Cert0");
        assert_eq!(info.certificate_chain[4].subject, "CN=Cert4");
    }

    #[test]
    fn test_complex_certificate_chain() {
        let chain = vec![
            CertificateInfo {
                subject: "CN=End Entity, O=Company".to_string(),
                issuer: "CN=Intermediate CA, O=CA Company".to_string(),
                serial_number: "01".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2025-01-01".to_string(),
            },
            CertificateInfo {
                subject: "CN=Intermediate CA, O=CA Company".to_string(),
                issuer: "CN=Root CA, O=Root CA Company".to_string(),
                serial_number: "02".to_string(),
                not_before: "2020-01-01".to_string(),
                not_after: "2030-01-01".to_string(),
            },
            CertificateInfo {
                subject: "CN=Root CA, O=Root CA Company".to_string(),
                issuer: "CN=Root CA, O=Root CA Company".to_string(), // Self-signed
                serial_number: "03".to_string(),
                not_before: "2010-01-01".to_string(),
                not_after: "2040-01-01".to_string(),
            },
        ];

        let info = SignatureInfo {
            is_signed: true,
            signature_type: Some("Authenticode".to_string()),
            signer: Some("CN=End Entity, O=Company".to_string()),
            timestamp: Some("2024-06-01".to_string()),
            certificate_chain: chain,
            verification_status: "Valid".to_string(),
        };

        // Verify chain structure
        assert_eq!(info.certificate_chain.len(), 3);
        assert_eq!(info.certificate_chain[0].subject, info.signer.unwrap());
        assert_eq!(
            info.certificate_chain[2].subject,
            info.certificate_chain[2].issuer
        ); // Root is self-signed
    }

    #[test]
    fn test_signature_verification_error_handling() {
        // Test with directory instead of file
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path().join("testdir");
        fs::create_dir(&dir_path).unwrap();

        let result = verify_signature(&dir_path);
        assert!(result.is_ok()); // Should handle gracefully
        let info = result.unwrap();
        assert!(!info.is_signed);
        assert_eq!(info.verification_status, "No signature found");
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let content = b"Test file";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        // Make file unreadable
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o000)).unwrap();

        let result = verify_signature(&file_path);

        // Restore permissions for cleanup
        fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();

        // Should handle permission errors gracefully
        assert!(result.is_ok());
        let info = result.unwrap();
        assert!(!info.is_signed);
    }

    #[test]
    fn test_yaml_serialization_all_fields() {
        let info = SignatureInfo {
            is_signed: true,
            signature_type: Some("GPG".to_string()),
            signer: Some("Test User <test@example.com>".to_string()),
            timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            certificate_chain: vec![CertificateInfo {
                subject: "CN=Test".to_string(),
                issuer: "CN=CA".to_string(),
                serial_number: "123456".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2025-01-01".to_string(),
            }],
            verification_status: "Valid".to_string(),
        };

        let yaml = serde_yaml::to_string(&info).unwrap();
        assert!(yaml.contains("is_signed: true"));
        assert!(yaml.contains("signature_type: GPG"));
        assert!(yaml.contains("signer: Test User"));

        let deserialized: SignatureInfo = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.is_signed, info.is_signed);
        assert_eq!(deserialized.signature_type, info.signature_type);
    }

    #[test]
    fn test_parse_osslsigncode_complex_output() {
        let output = r#"
Current PE checksum   : 00012345
Calculated PE checksum: 00012345

Signature Index: 0  (Primary Signature)

Message digest algorithm  : SHA256
Current message digest    : 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
Calculated message digest : 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF

Signer's certificate:
    Signer #0:
        Subject: /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Corporation
        Issuer : /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Code Signing PCA 2011
        Serial : 33000002EC630E593A91424F37000000000EC
        Certificate expiration date:
            notBefore : Jul 29 20:47:31 2021 GMT
            notAfter  : Jul 27 20:47:31 2022 GMT

Timestamp: Jul 30 21:15:45 2021 GMT

Number of certificates: 3
    Signer #0:
        Subject: /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Corporation
        Issuer : /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Code Signing PCA 2011
        Serial : 33000002EC630E593A91424F37000000000EC
    Signer #1:
        Subject: /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Code Signing PCA 2011
        Issuer : /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Root Certificate Authority 2011
        Serial : 61077656000000000008
    Signer #2:
        Subject: /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Root Certificate Authority 2011
        Issuer : /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Root Certificate Authority 2011
        Serial : 3F8BC8B5FC9FB29643B569D66C42E144

Signature verification: ok

Number of signatures  : 1
"#;

        let signer = extract_signer_from_output(output);
        assert_eq!(
            signer,
            Some(
                "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Corporation"
                    .to_string()
            )
        );

        let timestamp = extract_timestamp_from_output(output);
        assert_eq!(timestamp, Some("Jul 30 21:15:45 2021 GMT".to_string()));
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let content = b"Test file";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();
        let path = Arc::new(file_path);

        let mut handles = vec![];

        // Spawn multiple threads to verify signature concurrently
        for i in 0..10 {
            let path_clone = Arc::clone(&path);
            let handle = thread::spawn(move || {
                let result = verify_signature(&path_clone).unwrap();
                assert!(!result.is_signed);
                assert_eq!(result.verification_status, "No signature found");
                i
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            let thread_id = handle.join().unwrap();
            assert!(thread_id < 10);
        }
    }

    #[test]
    fn test_special_characters_in_output() {
        // Test with various special characters
        let outputs = vec![
            "Subject: CN=Test\x00User", // Null byte
            "Subject: CN=Test\tUser",   // Tab
            "Subject: CN=Test\rUser",   // Carriage return
            "Subject: CN=Test\\User",   // Backslash
            "Subject: CN=Test$User",    // Dollar sign
        ];

        for output in outputs {
            let result = extract_signer_from_output(output);
            assert!(result.is_some());
            assert!(result.unwrap().contains("Test"));
        }
    }

    #[test]
    fn test_large_certificate_info() {
        let mut large_subject = String::from("CN=");
        for _ in 0..1000 {
            large_subject.push_str("VeryLongCertificateName");
        }

        let cert = CertificateInfo {
            subject: large_subject.clone(),
            issuer: large_subject.clone(),
            serial_number: "A".repeat(256),
            not_before: "2024-01-01T00:00:00Z".to_string(),
            not_after: "2025-01-01T00:00:00Z".to_string(),
        };

        // Should handle large data without panic
        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.len() > 40000); // Verify it's actually large

        let deserialized: CertificateInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.subject.len(), cert.subject.len());
    }

    #[test]
    fn test_signature_info_partial_data() {
        // Test with various combinations of missing data
        let test_cases = vec![
            (false, None, None, None, "No signature found"),
            (true, Some("GPG"), None, None, "Unknown"),
            (false, None, Some("User"), None, "Invalid"),
            (true, Some("Test"), Some("User"), Some("2024"), "Valid"),
        ];

        for (is_signed, sig_type, signer, timestamp, status) in test_cases {
            let info = SignatureInfo {
                is_signed,
                signature_type: sig_type.map(String::from),
                signer: signer.map(String::from),
                timestamp: timestamp.map(String::from),
                certificate_chain: vec![],
                verification_status: status.to_string(),
            };

            // Verify the structure is valid
            if is_signed {
                // If it's signed, at least one of these should be present
                assert!(info.signature_type.is_some() || info.signer.is_some() || info.timestamp.is_some(),
                    "If is_signed=true, at least one of signature_type, signer, or timestamp should be Some");
            }
        }
    }

    #[test]
    fn test_binary_file_signatures() {
        // Create various binary file headers
        let binary_headers = vec![
            vec![0x7F, 0x45, 0x4C, 0x46], // ELF
            vec![0xCA, 0xFE, 0xBA, 0xBE], // Mach-O
            vec![0xFE, 0xED, 0xFA, 0xCE], // Mach-O
            vec![0xCE, 0xFA, 0xED, 0xFE], // Mach-O
            vec![0x50, 0x4B, 0x03, 0x04], // ZIP/JAR
        ];

        for header in binary_headers {
            let mut content = header.clone();
            content.extend_from_slice(&vec![0; 100]); // Pad with zeros

            let (_temp_dir, file_path) = create_test_file(&content).unwrap();
            let result = verify_signature(&file_path).unwrap();

            assert!(!result.is_signed);
            assert_eq!(result.verification_status, "No signature found");
        }
    }
}

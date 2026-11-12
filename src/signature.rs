use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;

/// Most bytes read for any one header region. Signature detection looks only
/// at headers, load commands and the certificate-table entry (never the whole
/// file, so a 300 MiB binary costs a few KiB). A Mach-O whose load commands
/// exceed this is reported as not inspected, not as unsigned.
const HEADER_READ_CAP: u64 = 8 << 20;
/// Bytes of a universal header: 8 + 64 entries of 32 bytes.
const FAT_HEADER_LEN: usize = 8 + 64 * 32;

/// Random-access reader over the file that keeps the length at hand.
struct FileReader {
    file: File,
    len: u64,
    /// Bytes handed out so far (tests assert that detection stays small).
    bytes_read: u64,
}

impl FileReader {
    fn open(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            file,
            len,
            bytes_read: 0,
        })
    }

    /// Up to `n` bytes at `offset` (fewer at the end of the file); `None`
    /// past the end, when `n` exceeds the read cap, or on an I/O error.
    fn read_at(&mut self, offset: u64, n: u64) -> Option<Vec<u8>> {
        if offset >= self.len || n > HEADER_READ_CAP {
            return None;
        }
        let n = n.min(self.len - offset);
        self.file.seek(SeekFrom::Start(offset)).ok()?;
        let mut out = Vec::new();
        self.file.by_ref().take(n).read_to_end(&mut out).ok()?;
        self.bytes_read += out.len() as u64;
        Some(out)
    }
}

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
    // Checks that could not run (missing external tool) are remembered so the
    // final answer can say "not checked" instead of "no signature found".
    let mut not_checked: Vec<String> = Vec::new();

    // First, check if it's a PE file with Authenticode signature
    if let Ok(authenticode_info) = check_authenticode_signature(path) {
        return Ok(authenticode_info);
    }

    // Check for GPG signatures
    if let Ok(gpg_info) = check_gpg_signature(path) {
        return Ok(gpg_info);
    }
    if detached_signature_candidates(path)
        .iter()
        .any(|p| p.exists())
        && !tool_available("gpg")
    {
        not_checked.push("a detached .sig/.asc file exists but gpg is not installed".to_string());
    }

    // Check for macOS code signatures (only for Mach-O binaries)
    if let Ok(mut reader) = FileReader::open(path) {
        if let Some(found) = macho_code_signature(&mut reader) {
            if cfg!(target_os = "macos") && tool_available("codesign") {
                if let Ok(codesign_info) = check_macos_codesign(path) {
                    return Ok(codesign_info);
                }
                if !found.present {
                    // The load commands were never inspected: say so instead of
                    // claiming a command exists.
                    if let Some(problem) = found.problem {
                        not_checked.push(problem);
                    }
                } else {
                    return Ok(SignatureInfo {
                        is_signed: false,
                        signature_type: Some("Mach-O code signature".to_string()),
                        signer: None,
                        timestamp: None,
                        certificate_chain: Vec::new(),
                        verification_status: format!(
                            "Code signature load command present but codesign could not read it (damaged or stripped signature){}",
                            found.problem.map_or(String::new(), |p| format!(": {p}"))
                        ),
                    });
                }
            } else if found.present {
                // The load commands prove a signature blob exists even when we
                // cannot run the verifier.
                return Ok(SignatureInfo {
                    is_signed: true,
                    signature_type: Some("Mach-O code signature".to_string()),
                    signer: None,
                    timestamp: None,
                    certificate_chain: Vec::new(),
                    verification_status: "Present, not verified (codesign is not available)"
                        .to_string(),
                });
            } else if let Some(problem) = found.problem {
                not_checked.push(problem);
            }
        }
    }

    if !not_checked.is_empty() {
        return Ok(SignatureInfo {
            is_signed: false,
            signature_type: None,
            signer: None,
            timestamp: None,
            certificate_chain: Vec::new(),
            verification_status: format!("Not checked: {}", not_checked.join("; ")),
        });
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

/// True when `name` can be started (found on PATH and runnable).
fn tool_available(name: &str) -> bool {
    // Spawning is the only portable test; a missing program fails with NotFound.
    match Command::new(name)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(_) => true,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Location of the PE security (certificate table) data directory, read from
/// the headers: `Some(Some((file_offset, size)))` when the entry is populated,
/// `Some(None)` for a PE with an empty entry, `None` when the bytes are not a PE.
fn pe_certificate_table(reader: &mut FileReader) -> Option<Option<(u64, u64)>> {
    fn u16_at(b: &[u8], o: usize) -> Option<u16> {
        Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
    }
    fn u32_at(b: &[u8], o: usize) -> Option<u32> {
        Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
    }
    let dos = reader.read_at(0, 64)?;
    if dos.len() < 64 || &dos[0..2] != b"MZ" {
        return None;
    }
    let pe_off = u64::from(u32_at(&dos, 0x3c)?);
    // PE signature, COFF header, optional header and the first data directories
    let b = reader.read_at(pe_off, 24 + 112 + 8 * 5)?;
    if b.get(0..4)? != b"PE\0\0" {
        return None;
    }
    let opt = 24;
    let dd = match u16_at(&b, opt)? {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return None,
    };
    let count = u32_at(&b, dd - 4)?;
    if count <= 4 {
        return Some(None);
    }
    let offset = u64::from(u32_at(&b, dd + 32)?);
    let size = u64::from(u32_at(&b, dd + 36)?);
    if offset == 0 && size == 0 {
        return Some(None);
    }
    Some(Some((offset, size)))
}

/// What the load commands of a Mach-O say about its signature.
#[derive(Debug, Default, PartialEq, Eq)]
struct CodeSignatureScan {
    /// An `LC_CODE_SIGNATURE` load command exists.
    present: bool,
    /// Something that stopped a full check (blob outside its slice, load
    /// commands too large to read).
    problem: Option<String>,
}

/// Load commands of the thin Mach-O at `base` (inside a slice of `slice_len`
/// bytes), looking for `LC_CODE_SIGNATURE`. Only the header and the load
/// commands are read. `None` when the bytes are not a Mach-O header.
fn thin_code_signature(
    reader: &mut FileReader,
    base: u64,
    slice_len: u64,
) -> Option<CodeSignatureScan> {
    const LC_CODE_SIGNATURE: u32 = 0x1d;
    let head = reader.read_at(base, 32)?;
    if head.len() < 28 {
        return None;
    }
    let magic = [head[0], head[1], head[2], head[3]];
    let (little, header_len) = match magic {
        [0xcf, 0xfa, 0xed, 0xfe] => (true, 32u64),
        [0xce, 0xfa, 0xed, 0xfe] => (true, 28),
        [0xfe, 0xed, 0xfa, 0xcf] => (false, 32),
        [0xfe, 0xed, 0xfa, 0xce] => (false, 28),
        _ => return None,
    };
    let rd = |b: &[u8], o: usize| -> Option<u32> {
        let v: [u8; 4] = b.get(o..o + 4)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(v)
        } else {
            u32::from_be_bytes(v)
        })
    };
    let ncmds = u64::from(rd(&head, 16)?);
    let sizeofcmds = u64::from(rd(&head, 20)?);
    let mut scan = CodeSignatureScan::default();
    if sizeofcmds > HEADER_READ_CAP {
        scan.problem = Some(format!(
            "the load commands ({sizeofcmds} bytes) exceed the {} MiB read cap and were not inspected",
            HEADER_READ_CAP >> 20
        ));
        return Some(scan);
    }
    let cmds = reader.read_at(base + header_len, sizeofcmds)?;
    let mut pos = 0usize;
    for _ in 0..ncmds {
        let (Some(cmd), Some(cmdsize)) = (rd(&cmds, pos), rd(&cmds, pos + 4)) else {
            break;
        };
        let cmdsize = cmdsize as usize;
        if cmdsize < 8 || pos.saturating_add(cmdsize) > cmds.len() {
            break;
        }
        if cmd == LC_CODE_SIGNATURE {
            scan.present = true;
            if let (Some(off), Some(size)) = (rd(&cmds, pos + 8), rd(&cmds, pos + 12)) {
                if u64::from(off) + u64::from(size) > slice_len {
                    scan.problem = Some(format!(
                        "the signature blob (offset {off}, size {size}) lies outside the file"
                    ));
                }
            }
        }
        pos += cmdsize;
    }
    Some(scan)
}

/// For Mach-O (thin or universal) files: what the load commands say about the
/// code signature; `None` when the file is not a Mach-O. Universal files are
/// walked through the bounded slice reader, so a file-controlled
/// architecture count is never trusted.
fn macho_code_signature(reader: &mut FileReader) -> Option<CodeSignatureScan> {
    let head = reader.read_at(0, FAT_HEADER_LEN as u64)?;
    if crate::binary_parser::is_fat_macho(&head) {
        let len = reader.len;
        // `fat_slice_table` asks whether a universal header starts at a slice
        // offset; the answer comes from an 8-byte read there.
        let table = {
            let cell = std::cell::RefCell::new(&mut *reader);
            crate::binary_parser::fat_slice_table(&head, len, |offset| {
                cell.borrow_mut()
                    .read_at(offset, 8)
                    .is_some_and(|b| crate::binary_parser::is_fat_macho(&b))
            })?
        };
        let mut total = CodeSignatureScan::default();
        let mut parsed_any = false;
        for slice in &table {
            if let Some(scan) = thin_code_signature(reader, slice.offset, slice.size) {
                parsed_any = true;
                total.present |= scan.present;
                if total.problem.is_none() {
                    total.problem = scan.problem;
                }
            }
        }
        return parsed_any.then_some(total);
    }
    if head.len() >= 4 && head[0..3] == [0xCA, 0xFE, 0xBA] {
        // Java class file or damaged universal header: not a Mach-O to inspect
        return None;
    }
    let len = reader.len;
    thin_code_signature(reader, 0, len)
}

fn check_authenticode_signature(path: &Path) -> Result<SignatureInfo> {
    let mut reader = FileReader::open(path)?;
    let file_len = reader.len;

    // Check for PE signature
    let Some(table) = pe_certificate_table(&mut reader) else {
        anyhow::bail!("Not a PE file");
    };
    let Some((offset, size)) = table else {
        anyhow::bail!("No Authenticode signature found");
    };

    if size < 8 || offset.checked_add(size).is_none_or(|end| end > file_len) {
        return Ok(SignatureInfo {
            is_signed: false,
            signature_type: Some("Authenticode".to_string()),
            signer: None,
            timestamp: None,
            certificate_chain: Vec::new(),
            verification_status: format!(
                "Malformed: the PE security directory (offset {offset}, size {size}) {}",
                if size < 8 {
                    "is too small to hold a certificate entry"
                } else {
                    "lies outside the file"
                }
            ),
        });
    }

    // The headers show a populated certificate table. Ask an external verifier
    // when one is installed; otherwise report presence only.
    match Command::new("osslsigncode")
        .arg("verify")
        .arg(path)
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let valid = output.status.success() && stdout.contains("Signature verification: ok");
            Ok(SignatureInfo {
                is_signed: true,
                signature_type: Some("Authenticode".to_string()),
                signer: if valid {
                    extract_signer_from_output(&stdout)
                } else {
                    None
                },
                timestamp: if valid {
                    extract_timestamp_from_output(&stdout)
                } else {
                    None
                },
                certificate_chain: Vec::new(),
                verification_status: if valid {
                    "Valid".to_string()
                } else {
                    "Present, verification failed (osslsigncode did not report a valid signature)"
                        .to_string()
                },
            })
        }
        Err(_) => Ok(SignatureInfo {
            is_signed: true,
            signature_type: Some("Authenticode".to_string()),
            signer: None,
            timestamp: None,
            certificate_chain: Vec::new(),
            verification_status: format!(
                "Present, not verified (certificate table of {size} bytes found in the PE headers; osslsigncode is not installed, so the signature was not checked)"
            ),
        }),
    }
}

/// Candidate detached-signature paths: the full file name plus `.sig` / `.asc`
/// (`app` -> `app.sig`, `app.bin` -> `app.bin.sig`).
fn detached_signature_candidates(path: &Path) -> Vec<std::path::PathBuf> {
    ["sig", "asc"]
        .iter()
        .map(|suffix| {
            let mut name = path.as_os_str().to_os_string();
            name.push(".");
            name.push(suffix);
            std::path::PathBuf::from(name)
        })
        .collect()
}

fn check_gpg_signature(path: &Path) -> Result<SignatureInfo> {
    check_gpg_signature_with(path, "gpg")
}

fn check_gpg_signature_with(path: &Path, program: &str) -> Result<SignatureInfo> {
    // Check for detached GPG signature
    let sig_file = detached_signature_candidates(path)
        .into_iter()
        .find(|p| p.exists());

    if let Some(sig_file) = sig_file {
        if let Ok(output) = Command::new(program)
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
            let first = stderr.lines().next().unwrap_or("no output").trim();
            return Ok(SignatureInfo {
                is_signed: false,
                signature_type: Some("GPG".to_string()),
                signer: None,
                timestamp: None,
                certificate_chain: Vec::new(),
                verification_status: format!("Detached signature present, not verified ({first})"),
            });
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

            // Parse authorities: the first is the leaf signer, the rest the chain
            let authorities: Vec<&str> = stderr
                .lines()
                .filter_map(|l| l.strip_prefix("Authority="))
                .collect();
            info.signer = authorities.first().map(|a| (*a).to_string());
            // codesign prints only subject names, so the other fields stay empty
            info.certificate_chain = authorities
                .iter()
                .map(|a| CertificateInfo {
                    subject: (*a).to_string(),
                    issuer: String::new(),
                    serial_number: String::new(),
                    not_before: String::new(),
                    not_after: String::new(),
                })
                .collect();

            // Ad-hoc signatures carry no identity: they prove integrity only
            let adhoc = stderr.lines().any(|l| l.trim() == "Signature=adhoc");
            if adhoc {
                info.signature_type = Some("Apple ad-hoc signature".to_string());
            }

            // Parse timestamp
            if let Some(ts_line) = stderr.lines().find(|l| l.starts_with("Timestamp=")) {
                info.timestamp = Some(ts_line.replace("Timestamp=", ""));
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
                    if adhoc {
                        "Valid (ad-hoc: no signing identity, not a trusted publisher)".to_string()
                    } else {
                        "Valid".to_string()
                    }
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

    #[test]
    fn macho_signature_scan_reads_only_headers_of_a_huge_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("big");
        let mut head = vec![0xcf, 0xfa, 0xed, 0xfe];
        head.extend_from_slice(&0x0100_000cu32.to_le_bytes());
        head.extend_from_slice(&[0u8; 24]); // no load commands
        let f = fs::File::create(&path).unwrap();
        (&f).write_all(&head).unwrap();
        f.set_len(1 << 30).unwrap();
        let mut reader = FileReader::open(&path).unwrap();
        let scan = macho_code_signature(&mut reader);
        assert!(scan.is_some_and(|s| !s.present));
        assert!(
            reader.bytes_read < 64 * 1024,
            "read {} bytes of a 1 GiB file",
            reader.bytes_read
        );
    }

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
    #[cfg(unix)]
    fn test_check_gpg_signature_with_sig_file() {
        let content = b"Test file content";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        // Create a dummy .sig file
        let sig_path = file_path.with_extension("sig");
        fs::write(&sig_path, b"dummy signature").unwrap();

        // A stub gpg that rejects the signature: always the same outcome
        let stub = stub_gpg(sig_path.parent().unwrap(), "gpg: BAD signature");
        let info = check_gpg_signature_with(&file_path, stub.to_str().unwrap()).unwrap();
        assert!(!info.is_signed);
        assert!(info
            .verification_status
            .starts_with("Detached signature present, not verified"));
    }

    #[test]
    #[cfg(unix)]
    fn test_check_gpg_signature_with_asc_file() {
        let content = b"Test file content";
        let (_temp_dir, file_path) = create_test_file(content).unwrap();

        // Create a dummy .asc file
        let asc_path = file_path.with_extension("asc");
        fs::write(&asc_path, b"dummy ascii signature").unwrap();

        let stub = stub_gpg(asc_path.parent().unwrap(), "gpg: BAD signature");
        let info = check_gpg_signature_with(&file_path, stub.to_str().unwrap()).unwrap();
        assert!(!info.is_signed);
        assert!(info
            .verification_status
            .starts_with("Detached signature present, not verified"));
    }

    #[cfg(unix)]
    fn stub_gpg(dir: &Path, stderr_line: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let stub = dir.join("stub-gpg.sh");
        fs::write(
            &stub,
            format!("#!/bin/sh\necho '{stderr_line}' >&2\nexit 0\n"),
        )
        .unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
        stub
    }

    #[test]
    #[cfg(unix)]
    fn detached_sig_next_to_extensionless_file_is_verified() {
        let (temp_dir, file_path) = create_test_file(b"payload").unwrap();
        let bare = temp_dir.path().join("sample");
        fs::write(&bare, b"payload").unwrap();
        fs::write(temp_dir.path().join("sample.sig"), b"sig").unwrap();
        let stub = stub_gpg(temp_dir.path(), "gpg: Good signature from \"A <a@b.c>\"");
        let info = check_gpg_signature_with(&bare, stub.to_str().unwrap()).unwrap();
        assert!(info.is_signed);
        assert_eq!(info.signature_type.as_deref(), Some("GPG"));
        assert_eq!(info.verification_status, "Valid");
        drop(file_path);
    }

    #[test]
    #[cfg(unix)]
    fn rejected_detached_sig_is_reported_as_present_not_verified() {
        let (temp_dir, _f) = create_test_file(b"x").unwrap();
        let bare = temp_dir.path().join("sample.bin");
        fs::write(&bare, b"payload").unwrap();
        fs::write(temp_dir.path().join("sample.bin.asc"), b"sig").unwrap();
        let stub = stub_gpg(temp_dir.path(), "gpg: BAD signature");
        let info = check_gpg_signature_with(&bare, stub.to_str().unwrap()).unwrap();
        assert!(!info.is_signed);
        assert!(info
            .verification_status
            .starts_with("Detached signature present, not verified (gpg: BAD"));
    }

    #[test]
    fn fat_header_with_huge_count_is_not_walked() {
        let mut buf = vec![0xCA, 0xFE, 0xBA, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF];
        buf.resize(4096, 0);
        let (_dir, path) = create_test_file(&buf).unwrap();
        let start = std::time::Instant::now();
        let mut reader = FileReader::open(&path).unwrap();
        assert_eq!(macho_code_signature(&mut reader), None);
        assert!(start.elapsed().as_secs() < 60);
    }

    /// Thin 64-bit little-endian Mach-O with the given load commands.
    fn thin_macho(commands: &[Vec<u8>], tail: &[u8]) -> Vec<u8> {
        let mut b = vec![0xcf, 0xfa, 0xed, 0xfe];
        b.extend_from_slice(&0x0100_000cu32.to_le_bytes()); // arm64
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        b.extend_from_slice(&(commands.len() as u32).to_le_bytes());
        let total: usize = commands.iter().map(Vec::len).sum();
        b.extend_from_slice(&(total as u32).to_le_bytes());
        b.extend_from_slice(&[0u8; 8]);
        for c in commands {
            b.extend_from_slice(c);
        }
        b.extend_from_slice(tail);
        b
    }

    fn code_signature_command(dataoff: u32, datasize: u32) -> Vec<u8> {
        let mut c = 0x1du32.to_le_bytes().to_vec();
        c.extend_from_slice(&16u32.to_le_bytes());
        c.extend_from_slice(&dataoff.to_le_bytes());
        c.extend_from_slice(&datasize.to_le_bytes());
        c
    }

    #[test]
    fn code_signature_command_is_found_from_the_headers_only() {
        let bytes = thin_macho(&[code_signature_command(64, 16)], &[0u8; 128]);
        let (_dir, path) = create_test_file(&bytes).unwrap();
        let mut reader = FileReader::open(&path).unwrap();
        let scan = macho_code_signature(&mut reader).unwrap();
        assert!(scan.present);
        assert_eq!(scan.problem, None);
    }

    #[test]
    fn signature_blob_outside_the_file_is_a_problem() {
        let bytes = thin_macho(&[code_signature_command(1 << 20, 4096)], &[0u8; 16]);
        let (_dir, path) = create_test_file(&bytes).unwrap();
        let mut reader = FileReader::open(&path).unwrap();
        let scan = macho_code_signature(&mut reader).unwrap();
        assert!(scan.present);
        assert!(scan.problem.unwrap().contains("outside the file"));
    }

    #[test]
    fn huge_load_command_area_is_reported_not_read() {
        let mut bytes = thin_macho(&[], &[0u8; 64]);
        bytes[16..20].copy_from_slice(&u32::MAX.to_le_bytes()); // ncmds
        bytes[20..24].copy_from_slice(&u32::MAX.to_le_bytes()); // sizeofcmds
        let (_dir, path) = create_test_file(&bytes).unwrap();
        let mut reader = FileReader::open(&path).unwrap();
        let scan = macho_code_signature(&mut reader).unwrap();
        assert!(!scan.present);
        assert!(scan.problem.unwrap().contains("read cap"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn damaged_signature_is_not_reported_as_no_signature() {
        // Load command present, blob zeroed: codesign cannot read it
        let bytes = thin_macho(&[code_signature_command(64, 16)], &[0u8; 128]);
        let (_dir, path) = create_test_file(&bytes).unwrap();
        let info = verify_signature(&path).unwrap();
        assert!(!info.is_signed);
        assert_ne!(info.verification_status, "No signature found");
        assert!(info.verification_status.contains("codesign"));
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
        if let Ok(info) = result {
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
    #[cfg(unix)]
    fn test_gpg_signature_extensions() {
        let content = b"Test content";
        let temp_dir = TempDir::new().unwrap();

        // Test with different base extensions
        let extensions = vec!["txt", "bin", "exe", "tar.gz", ""];

        for ext in extensions {
            let filename = if ext.is_empty() {
                "file"
            } else {
                &format!("file.{ext}")
            };

            let file_path = temp_dir.path().join(filename);
            fs::write(&file_path, content).unwrap();

            // The detached signature is the full file name plus `.sig`
            let mut sig_name = file_path.as_os_str().to_os_string();
            sig_name.push(".sig");
            let sig_path = std::path::PathBuf::from(sig_name);
            fs::write(&sig_path, b"dummy sig").unwrap();

            let stub = stub_gpg(temp_dir.path(), "gpg: BAD signature");
            let info = check_gpg_signature_with(&file_path, stub.to_str().unwrap()).unwrap();
            assert!(!info.is_signed);
            assert!(info
                .verification_status
                .starts_with("Detached signature present, not verified"));
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
                subject: format!("CN=Cert{i}"),
                issuer: format!("CN=Issuer{i}"),
                serial_number: format!("{i:X}"),
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
        let output = r"
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
";

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
            content.extend_from_slice(&[0; 100]); // Pad with zeros

            let (_temp_dir, file_path) = create_test_file(&content).unwrap();
            let result = verify_signature(&file_path).unwrap();

            assert!(!result.is_signed);
            assert_eq!(result.verification_status, "No signature found");
        }
    }

    #[test]
    fn detached_signature_names_append_to_the_full_file_name() {
        let names: Vec<String> = detached_signature_candidates(Path::new("/x/sample"))
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["/x/sample.sig", "/x/sample.asc"]);
        let names: Vec<String> = detached_signature_candidates(Path::new("/x/sample.bin"))
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["/x/sample.bin.sig", "/x/sample.bin.asc"]);
    }
}

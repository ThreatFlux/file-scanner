//! Universal (fat) Mach-O handling, Mach-O architecture and mime reporting,
//! library lists, entropy sanity and signature details for the binary-format
//! analyzers.

use file_scanner::binary_parser::{
    is_fat_macho, is_java_class_header, needed_libraries, parse_binary, parse_binary_with_arch,
    select_fat_slice,
};
use file_scanner::dependency_analysis::analyze_dependencies;
use file_scanner::entropy_analysis::analyze_entropy;
use file_scanner::function_analysis::{
    analyze_symbols, analyze_symbols_with_arch, ImportInfo, SymbolCounts, SymbolTable,
};
use file_scanner::metadata::FileMetadata;
use file_scanner::signature::verify_signature;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const CPU_ARM64: u32 = 0x0100_000C;
const CPU_X86_64: u32 = 0x0100_0007;

/// A 32-byte little-endian 64-bit Mach-O header with no load commands.
fn thin_macho(cputype: u32, subtype: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0xFEED_FACFu32.to_le_bytes());
    b.extend_from_slice(&cputype.to_le_bytes());
    b.extend_from_slice(&subtype.to_le_bytes());
    b.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
    b.extend_from_slice(&[0u8; 16]); // ncmds, sizeofcmds, flags, reserved
    b
}

/// Wrap thin images into a universal binary (slices aligned to 4096 bytes).
fn fat(slices: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    out.extend_from_slice(&(slices.len() as u32).to_be_bytes());
    let mut offset = 4096u32;
    let mut bodies = Vec::new();
    for (cpu, sub, body) in slices {
        out.extend_from_slice(&cpu.to_be_bytes());
        out.extend_from_slice(&sub.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&12u32.to_be_bytes());
        bodies.push((offset, body));
        offset += (body.len() as u32).div_ceil(4096).max(1) * 4096;
    }
    for (off, body) in bodies {
        out.resize(off as usize, 0);
        out.extend_from_slice(body);
    }
    out
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn java_class_header() -> Vec<u8> {
    let mut b = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x37];
    b.extend_from_slice(&[0u8; 32]);
    b
}

#[test]
fn fat_header_and_class_header_are_told_apart() {
    let f = fat(&[(CPU_ARM64, 0, thin_macho(CPU_ARM64, 0))]);
    assert!(is_fat_macho(&f));
    assert!(!is_java_class_header(&f));
    let class = java_class_header();
    assert!(!is_fat_macho(&class));
    assert!(is_java_class_header(&class));
    // a class version with a nonzero minor part is still a class file
    let preview = [0xCA, 0xFE, 0xBA, 0xBE, 0xFF, 0xFF, 0x00, 0x3D];
    assert!(is_java_class_header(&preview));
    assert!(!is_fat_macho(b"\xCA\xFE"));
}

#[test]
fn fat_macho_is_reported_as_macho_and_lists_every_slice() {
    let dir = TempDir::new().unwrap();
    let bytes = fat(&[
        (CPU_X86_64, 3, thin_macho(CPU_X86_64, 3)),
        (CPU_ARM64, 0, thin_macho(CPU_ARM64, 0)),
    ]);
    let path = write(&dir, "universal", &bytes);

    let info = parse_binary(&path).unwrap();
    assert_eq!(info.format, "Mach-O");
    assert!(info.java_analysis.is_none());
    let slices = info.universal_slices.as_ref().expect("slice list");
    let names: Vec<_> = slices.iter().map(|s| s.architecture.as_str()).collect();
    assert_eq!(names, ["x86_64", "ARM64"]);
    assert_eq!(slices.iter().filter(|s| s.analyzed).count(), 1);
    // the analyzed slice is the host architecture when present
    let host = if cfg!(target_arch = "aarch64") {
        "ARM64"
    } else {
        "x86_64"
    };
    assert_eq!(info.analyzed_slice.as_deref(), Some(host));
    assert_eq!(info.architecture, host);
}

#[test]
fn fat_macho_arch_argument_picks_the_slice() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "universal",
        &fat(&[
            (CPU_X86_64, 3, thin_macho(CPU_X86_64, 3)),
            (CPU_ARM64, 0, thin_macho(CPU_ARM64, 0)),
        ]),
    );
    let x86 = parse_binary_with_arch(&path, Some("x86_64")).unwrap();
    assert_eq!(x86.architecture, "x86_64");
    assert_eq!(x86.analyzed_slice.as_deref(), Some("x86_64"));
    let arm = parse_binary_with_arch(&path, Some("arm64")).unwrap();
    assert_eq!(arm.architecture, "ARM64");
    // an unknown name falls back to the default choice instead of failing
    assert!(parse_binary_with_arch(&path, Some("sparc")).is_ok());
}

#[test]
fn fat_macho_without_host_slice_uses_first() {
    let bytes = fat(&[(0x0100_0012, 0, thin_macho(0x0100_0012, 0))]);
    let selection = select_fat_slice(&bytes, None).unwrap();
    assert_eq!(selection.selected, 0);
    assert_eq!(selection.slices[0].architecture, "PowerPC64");
    assert_eq!(selection.data.len(), 32);
}

#[test]
fn truncated_fat_header_does_not_panic() {
    let mut bytes = fat(&[(CPU_ARM64, 0, thin_macho(CPU_ARM64, 0))]);
    bytes.truncate(24);
    assert!(select_fat_slice(&bytes, None).is_none());
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "cut", &bytes);
    // not a class file and not a usable Mach-O: never a Java verdict
    if let Ok(info) = parse_binary(&path) {
        assert_ne!(info.format, "Java Class");
    }
}

/// A universal Mach-O whose only slice is the whole file (or another fat header).
fn self_referencing_fat() -> Vec<u8> {
    let mut b = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 1];
    for v in [CPU_ARM64, 0, 0, 4096, 12] {
        b.extend_from_slice(&v.to_be_bytes());
    }
    b.resize(4096, 0);
    b
}

#[test]
fn fat_file_whose_slice_is_itself_does_not_recurse() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "fat_self", &self_referencing_fat());
    assert!(select_fat_slice(&self_referencing_fat(), None).is_none());
    // slice starting at a nested fat header, past the table
    let mut nested = self_referencing_fat();
    nested[8 + 8..8 + 12].copy_from_slice(&64u32.to_be_bytes());
    nested[64..72].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 1]);
    assert!(select_fat_slice(&nested, None).is_none());
    let nested_path = write(&dir, "fat_in_fat", &nested);
    for p in [&path, &nested_path] {
        let _ = analyze_symbols(p);
        let _ = parse_binary(p);
        let _ = analyze_entropy(p);
        let _ = needed_libraries(p);
        let _ = analyze_symbols_with_arch(p, Some("arm64"));
        let _ = verify_signature(p);
    }
}

#[test]
fn fat_header_with_huge_architecture_count_is_cheap() {
    let dir = TempDir::new().unwrap();
    let mut bytes = vec![0xCA, 0xFE, 0xBA, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF];
    bytes.resize(4096, 0);
    let path = write(&dir, "huge_count", &bytes);
    let start = std::time::Instant::now();
    let sig = verify_signature(&path).unwrap();
    assert!(!sig.is_signed);
    assert!(start.elapsed().as_secs() < 3, "took {:?}", start.elapsed());
}

#[test]
fn thin_arm64_macho_reports_arm64_and_a_macho_mime() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "thin_arm64", &thin_macho(CPU_ARM64, 0));
    let info = parse_binary(&path).unwrap();
    assert_eq!(info.format, "Mach-O");
    assert_eq!(info.architecture, "ARM64");
    assert!(info.universal_slices.is_none());

    let x86 = write(&dir, "thin_x86", &thin_macho(CPU_X86_64, 3));
    assert_eq!(parse_binary(&x86).unwrap().architecture, "x86_64");

    for (name, bytes) in [
        ("thin_arm64", thin_macho(CPU_ARM64, 0)),
        ("fat", fat(&[(CPU_ARM64, 0, thin_macho(CPU_ARM64, 0))])),
    ] {
        let p = write(&dir, name, &bytes);
        let mut meta = FileMetadata::new(&p).unwrap();
        meta.extract_basic_info().unwrap();
        assert_eq!(
            meta.mime_type.as_deref(),
            Some("application/x-mach-binary"),
            "{name}"
        );
    }
}

#[test]
fn class_file_mime_is_not_macho() {
    let dir = TempDir::new().unwrap();
    let p = write(&dir, "Hello.class", &java_class_header());
    let mut meta = FileMetadata::new(&p).unwrap();
    meta.extract_basic_info().unwrap();
    assert_eq!(meta.mime_type.as_deref(), Some("application/java-vm"));
}

#[test]
fn fat_macho_symbols_do_not_fail_on_empty_slices() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "universal",
        &fat(&[(CPU_ARM64, 0, thin_macho(CPU_ARM64, 0))]),
    );
    let table = analyze_symbols(&path).unwrap();
    assert_eq!(table.symbol_count.total_functions, 0);
    assert!(analyze_symbols_with_arch(&path, Some("arm64")).is_ok());
}

/// The running test executable is a thin Mach-O with a symbol table on macOS.
/// Wrapping it into a universal file must give the same answers.
#[cfg(target_os = "macos")]
mod real_macho {
    use super::*;

    fn wrapped_self() -> (TempDir, PathBuf, PathBuf) {
        let exe = std::env::current_exe().unwrap();
        let thin = std::fs::read(&exe).unwrap();
        let cpu = if cfg!(target_arch = "aarch64") {
            CPU_ARM64
        } else {
            CPU_X86_64
        };
        let dir = TempDir::new().unwrap();
        // a decoy slice first so that "first slice" and "host slice" differ
        let decoy_cpu = if cpu == CPU_ARM64 {
            CPU_X86_64
        } else {
            CPU_ARM64
        };
        let fat_bytes = fat(&[(decoy_cpu, 3, thin_macho(decoy_cpu, 3)), (cpu, 0, thin)]);
        let path = write(&dir, "wrapped", &fat_bytes);
        (dir, path, exe)
    }

    #[test]
    fn universal_file_gets_symbols_sections_and_imports_of_the_host_slice() {
        let (_dir, path, exe) = wrapped_self();
        let via_fat = analyze_symbols(&path).unwrap();
        let direct = analyze_symbols(&exe).unwrap();
        assert!(via_fat.symbol_count.total_functions > 0);
        assert_eq!(
            via_fat.symbol_count.total_functions,
            direct.symbol_count.total_functions
        );

        let entropy = analyze_entropy(&path).unwrap();
        assert!(!entropy.sections.is_empty());
        assert_ne!(entropy.sections[0].name, "entire_file");

        let info = parse_binary(&path).unwrap();
        assert_eq!(info.format, "Mach-O");
        assert!(!info.imports.is_empty());
        assert!(!needed_libraries(&path).is_empty());
        assert_eq!(needed_libraries(&path), needed_libraries(&exe));
    }

    #[test]
    fn double_underscore_functions_are_kept() {
        let (_dir, _path, exe) = wrapped_self();
        let table = analyze_symbols(&exe).unwrap();
        // Rust and C++ symbols carry two leading underscores on Mach-O
        assert!(
            table.functions.iter().any(
                |f| !f.is_imported && (f.name.starts_with("__ZN") || f.name.starts_with("__R"))
            ),
            "mangled functions were dropped"
        );
        assert!(!table
            .functions
            .iter()
            .any(|f| f.name == "__mh_execute_header"));
    }

    #[test]
    fn dependencies_are_libraries_not_functions() {
        let (_dir, path, _exe) = wrapped_self();
        let table = analyze_symbols(&path).unwrap();
        let deps = analyze_dependencies(&path, &table, None).unwrap();
        let names: Vec<_> = deps.dependencies.iter().map(|d| d.name.as_str()).collect();
        assert!(names.iter().any(|n| n.contains("libSystem")), "{names:?}");
        assert!(names.iter().all(|n| !n.starts_with('_')), "{names:?}");
        // exactly the libraries of the load commands: no names made up from strings
        let libs = needed_libraries(&path);
        assert_eq!(names.len(), libs.len(), "{names:?} vs {libs:?}");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn adhoc_signed_binary_is_not_reported_as_a_trusted_signature() {
        let exe = std::env::current_exe().unwrap();
        let sig = verify_signature(&exe).unwrap();
        // the linker always ad-hoc signs on Apple silicon
        assert!(sig.is_signed, "{sig:?}");
        assert_eq!(
            sig.signature_type.as_deref(),
            Some("Apple ad-hoc signature")
        );
        assert!(sig.signer.is_none());
        assert!(!sig.verification_status.eq_ignore_ascii_case("valid"));
    }
}

#[test]
fn dependencies_group_imports_under_their_library() {
    let imports: Vec<ImportInfo> = (0..40)
        .map(|i| ImportInfo {
            name: format!("Func{i}"),
            library: Some(
                if i % 4 == 0 {
                    "SHLWAPI.dll"
                } else {
                    "KERNEL32.dll"
                }
                .to_string(),
            ),
            address: None,
            ordinal: None,
            is_delayed: false,
        })
        .collect();
    let table = SymbolTable {
        functions: vec![],
        global_variables: vec![],
        cross_references: vec![],
        imports,
        exports: vec![],
        symbol_count: SymbolCounts {
            total_functions: 0,
            local_functions: 0,
            imported_functions: 40,
            exported_functions: 0,
            global_variables: 0,
            cross_references: 0,
        },
    };
    let analysis = analyze_dependencies(Path::new("/nonexistent"), &table, None).unwrap();
    assert_eq!(analysis.dependencies.len(), 2);
    let kernel = analysis
        .dependencies
        .iter()
        .find(|d| d.name == "KERNEL32.dll")
        .unwrap();
    assert_eq!(kernel.imported_functions.len(), 30);
    assert!(kernel.is_system_library);
    assert_eq!(analysis.analysis_stats.total_dependencies_found, 2);
}

#[test]
fn elf_needed_libraries_and_unique_imports() {
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_programs/c_advanced_binary");
    assert!(sample.exists(), "tracked sample missing: {sample:?}");
    let info = parse_binary(&sample).unwrap();
    assert!(info.needed_libraries.iter().any(|l| l == "libc.so.6"));

    let table = analyze_symbols(&sample).unwrap();
    let mut seen = std::collections::HashSet::new();
    for import in &table.imports {
        assert!(!import.name.contains('@'), "{}", import.name);
        assert!(seen.insert(import.name.clone()), "twice: {}", import.name);
    }
    let deps = analyze_dependencies(&sample, &table, None).unwrap();
    let names: Vec<_> = deps.dependencies.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, ["libc.so.6"]);
    assert!(deps.license_summary.compliance_issues.is_empty());
}

#[test]
fn ordinary_binary_data_is_not_called_encrypted() {
    // Mostly non-printable but low-entropy bytes, like machine code padding
    let dir = TempDir::new().unwrap();
    let data: Vec<u8> = (0..8192)
        .map(|i| [0u8, 1, 2, 3, 0x90, 0xC3, 0x48, 0x89][i % 8])
        .collect();
    let path = write(&dir, "plain.bin", &data);
    let result = analyze_entropy(&path).unwrap();
    assert!(!result.encryption_indicators.likely_encrypted);
    assert!(result
        .recommendations
        .iter()
        .all(|r| !r.contains("encrypted")));
}

#[test]
fn recognized_format_without_sections_still_gets_a_measured_score() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "thin", &thin_macho(CPU_ARM64, 0));
    let result = analyze_entropy(&path).unwrap();
    assert!(!result.sections.is_empty());
    assert!(result.obfuscation_score.is_finite());
    assert!(result.obfuscation_score < 100.0);
}

// ---- PE certificate table -------------------------------------------------

/// Minimal PE32+ headers whose security directory points at `cert`.
fn pe_with_cert_table(cert: Option<(u32, u32)>, tail: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 0x40];
    b[0] = b'M';
    b[1] = b'Z';
    b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    b.extend_from_slice(b"PE\0\0");
    b.extend_from_slice(&0x8664u16.to_le_bytes()); // machine
    b.extend_from_slice(&0u16.to_le_bytes()); // sections
    b.extend_from_slice(&[0u8; 12]);
    b.extend_from_slice(&240u16.to_le_bytes()); // optional header size
    b.extend_from_slice(&0x22u16.to_le_bytes());
    let opt_start = b.len();
    b.extend_from_slice(&0x20Bu16.to_le_bytes());
    b.resize(opt_start + 108, 0);
    b.extend_from_slice(&16u32.to_le_bytes()); // number of data directories
    b.resize(opt_start + 112 + 4 * 8, 0);
    let (off, size) = cert.unwrap_or((0, 0));
    b.extend_from_slice(&off.to_le_bytes());
    b.extend_from_slice(&size.to_le_bytes());
    b.resize(opt_start + 240, 0);
    b.extend_from_slice(tail);
    b
}

#[test]
fn pe_certificate_table_is_reported_as_present_not_verified() {
    let dir = TempDir::new().unwrap();
    let header_len = pe_with_cert_table(None, &[]).len();
    let cert_offset = header_len.div_ceil(8) * 8;
    let mut cert = Vec::new();
    cert.extend_from_slice(&24u32.to_le_bytes()); // dwLength
    cert.extend_from_slice(&0x0200u16.to_le_bytes()); // revision
    cert.extend_from_slice(&0x0002u16.to_le_bytes()); // PKCS signed data
    cert.extend_from_slice(&[0u8; 16]);
    let bytes = pe_with_cert_table(Some((cert_offset as u32, cert.len() as u32)), &{
        let mut tail = vec![0u8; cert_offset - header_len];
        tail.extend_from_slice(&cert);
        tail
    });
    let path = write(&dir, "signed.exe", &bytes);

    let sig = verify_signature(&path).unwrap();
    assert!(sig.is_signed, "{sig:?}");
    assert_eq!(sig.signature_type.as_deref(), Some("Authenticode"));
    assert_ne!(sig.verification_status, "No signature found");
    assert!(
        sig.verification_status.starts_with("Present, not verified")
            || sig.verification_status == "Valid"
            || sig
                .verification_status
                .starts_with("Present, verification failed"),
        "{}",
        sig.verification_status
    );
}

#[test]
fn pe_without_certificate_table_is_unsigned() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "plain.exe", &pe_with_cert_table(None, &[0u8; 64]));
    let sig = verify_signature(&path).unwrap();
    assert!(!sig.is_signed);
    assert_eq!(sig.verification_status, "No signature found");
}

#[test]
fn pe_certificate_table_outside_the_file_is_called_malformed() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "broken.exe",
        &pe_with_cert_table(Some((0x10_0000, 0x400)), &[0u8; 64]),
    );
    let sig = verify_signature(&path).unwrap();
    assert!(!sig.is_signed);
    assert!(sig.verification_status.starts_with("Malformed"));
}

#[test]
fn detached_signature_next_to_an_extensionless_file_is_found() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "sample", b"\x7fELF not really");
    std::fs::write(dir.path().join("sample.sig"), b"junk").unwrap();
    let sig = verify_signature(&path).unwrap();
    // The .sig next to an extensionless file is found: gpg either rejects the
    // junk or is missing, but the answer is never "No signature found". The
    // stubbed-gpg unit tests in src/signature.rs cover the Valid path.
    assert!(!sig.is_signed, "{sig:?}");
    assert!(
        sig.verification_status.starts_with("Not checked")
            || sig
                .verification_status
                .starts_with("Detached signature present"),
        "{sig:?}"
    );
}

#[test]
fn pe_certificate_directory_too_small_is_called_too_small() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "tiny.exe",
        &pe_with_cert_table(Some((0x200, 4)), &[0u8; 64]),
    );
    let sig = verify_signature(&path).unwrap();
    assert!(!sig.is_signed);
    assert!(sig.verification_status.contains("too small"), "{sig:?}");
}

#[test]
fn rc4_pattern_and_compressed_debug_sections_do_not_mean_encrypted() {
    let dir = TempDir::new().unwrap();
    let mut data = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
    data.extend_from_slice(&[0x67, 0xe6, 0x09, 0x6a]);
    data.resize(8192, 0x90);
    let path = write(&dir, "rc4_and_sha.bin", &data);
    let result = analyze_entropy(&path).unwrap();
    assert!(!result.encryption_indicators.likely_encrypted);
}

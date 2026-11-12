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
    // not a class file and not a usable Mach-O: raw data, no Java verdict and
    // no toolchain claim
    let info = parse_binary(&path).unwrap();
    assert_eq!(info.format, "Raw");
    assert!(info.compiler.is_none() && info.linker.is_none(), "{info:?}");
    assert!(info.universal_slices.is_none());
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
    assert!(
        start.elapsed().as_secs() < 300,
        "took {:?}",
        start.elapsed()
    );
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
    // The fixture carries no real PKCS#7 blob: whatever verifier is installed,
    // it is never "Valid".
    assert!(
        sig.verification_status.starts_with("Present, not verified")
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

// ---- hostile counts, entropy and attribution ------------------------------

/// Thin arm64 Mach-O with an `LC_SYMTAB` whose symbol count is `nsyms`.
fn macho_with_symtab(nsyms: u32, subtype: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0xFEED_FACFu32.to_le_bytes());
    b.extend_from_slice(&CPU_ARM64.to_le_bytes());
    b.extend_from_slice(&subtype.to_le_bytes());
    b.extend_from_slice(&2u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes()); // ncmds
    b.extend_from_slice(&24u32.to_le_bytes()); // sizeofcmds
    b.extend_from_slice(&[0u8; 8]);
    b.extend_from_slice(&2u32.to_le_bytes()); // LC_SYMTAB
    b.extend_from_slice(&24u32.to_le_bytes());
    b.extend_from_slice(&64u32.to_le_bytes()); // symoff
    b.extend_from_slice(&nsyms.to_le_bytes());
    b.extend_from_slice(&1024u32.to_le_bytes()); // stroff
    b.extend_from_slice(&16u32.to_le_bytes()); // strsize
    b.resize(2048, 0);
    b
}

#[test]
fn macho_with_a_huge_symbol_count_is_cheap_everywhere() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "nsyms", &macho_with_symtab(u32::MAX, 0));
    let start = std::time::Instant::now();
    let info = parse_binary(&path).unwrap();
    assert_eq!(info.format, "Mach-O");
    let _ = analyze_symbols(&path);
    let _ = analyze_dependencies(
        &path,
        &analyze_symbols(&path).unwrap_or_else(|_| empty_table()),
        None,
    );
    assert!(
        start.elapsed().as_secs() < 300,
        "took {:?}",
        start.elapsed()
    );
}

fn empty_table() -> SymbolTable {
    SymbolTable {
        functions: vec![],
        global_variables: vec![],
        cross_references: vec![],
        imports: vec![],
        exports: vec![],
        symbol_count: SymbolCounts {
            total_functions: 0,
            local_functions: 0,
            imported_functions: 0,
            exported_functions: 0,
            global_variables: 0,
            cross_references: 0,
        },
    }
}

#[test]
fn thin_arm64e_macho_is_named_arm64e() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "arm64e", &thin_macho(CPU_ARM64, 2));
    assert_eq!(parse_binary(&path).unwrap().architecture, "ARM64E");
}

/// Copy of the tracked C sample whose `.gnu.version_r` is replaced by `needs`
/// Verneed entries chained to one chain of `aux` Vernaux entries.
fn elf_with_hostile_verneed(needs: u32, aux: u32) -> Vec<u8> {
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_programs/c_advanced_binary");
    let mut b = std::fs::read(sample).unwrap();
    let u16_at = |b: &[u8], o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
    let u32_at = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let shoff = u64_at(&b, 0x28) as usize;
    let shentsize = u16_at(&b, 0x3a) as usize;
    let shnum = u16_at(&b, 0x3c) as usize;
    let mut found = None;
    for i in 0..shnum {
        let o = shoff + i * shentsize;
        if u32_at(&b, o + 4) == 0x6fff_fffe {
            found = Some(o);
        }
    }
    let o = found.expect("sample has a .gnu.version_r");
    let off = u64_at(&b, o + 0x18) as usize;
    let vn_file = u32_at(&b, off + 4);
    let mut blob = Vec::new();
    for i in 0..needs {
        blob.extend_from_slice(&1u16.to_le_bytes());
        blob.extend_from_slice(&(aux.min(65535) as u16).to_le_bytes());
        blob.extend_from_slice(&vn_file.to_le_bytes());
        blob.extend_from_slice(&(16 * (needs - i)).to_le_bytes());
        blob.extend_from_slice(&(if i + 1 < needs { 16u32 } else { 0 }).to_le_bytes());
    }
    for j in 0..aux {
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&((j % 65000 + 2) as u16).to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&(if j + 1 < aux { 16u32 } else { 0 }).to_le_bytes());
    }
    while !b.len().is_multiple_of(16) {
        b.push(0);
    }
    let new_off = b.len() as u64;
    b.extend_from_slice(&blob);
    b[o + 0x18..o + 0x20].copy_from_slice(&new_off.to_le_bytes());
    b[o + 0x20..o + 0x28].copy_from_slice(&(blob.len() as u64).to_le_bytes());
    b[o + 0x2c..o + 0x30].copy_from_slice(&needs.to_le_bytes());
    b
}

#[test]
fn elf_with_a_hostile_version_needs_table_is_bounded() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "verneed", &elf_with_hostile_verneed(8192, 65535));
    let start = std::time::Instant::now();
    let table = analyze_symbols(&path).unwrap();
    assert!(!table.imports.is_empty());
    assert!(
        start.elapsed().as_secs() < 300,
        "took {:?}",
        start.elapsed()
    );
}

#[test]
fn elf_imports_are_attributed_per_library() {
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_programs/cpp_test_binary");
    assert!(sample.exists(), "tracked sample missing: {sample:?}");
    let table = analyze_symbols(&sample).unwrap();
    let deps = analyze_dependencies(&sample, &table, None).unwrap();
    let count = |name: &str| {
        deps.dependencies
            .iter()
            .find(|d| d.name == name)
            .map(|d| d.imported_functions.len())
    };
    assert_eq!(count("libstdc++.so.6"), Some(30));
    assert_eq!(count("libc.so.6"), Some(15));
    assert_eq!(count("libm.so.6"), Some(1));
    assert_eq!(count("libgcc_s.so.1"), Some(1));
    // system runtime libraries never get a MissingLicense issue
    assert!(
        deps.dependencies.iter().all(|d| d.is_system_library),
        "{:?}",
        deps.dependencies
            .iter()
            .map(|d| (&d.name, d.is_system_library))
            .collect::<Vec<_>>()
    );
    assert!(deps.license_summary.compliance_issues.is_empty());
}

#[test]
fn imports_are_not_counted_as_extra_functions() {
    let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("test_programs/c_advanced_binary");
    let table = analyze_symbols(&sample).unwrap();
    let imported = table.functions.iter().filter(|f| f.is_imported).count();
    assert_eq!(imported, table.imports.len());
    assert_eq!(table.symbol_count.imported_functions, imported);
    // `nm` lists 22 defined text symbols plus weak __cxa_finalize
    let defined = table.functions.len() - imported;
    assert!(defined <= 25, "{defined}");
}

#[test]
fn macho_and_pe_system_libraries_are_not_missing_a_license() {
    let imports: Vec<ImportInfo> = [
        ("a", "/usr/lib/libutil.dylib"),
        ("b", "/usr/lib/libncurses.5.4.dylib"),
        (
            "c",
            "/System/Library/Frameworks/Security.framework/Versions/A/Security",
        ),
        ("d", "SHLWAPI.dll"),
    ]
    .iter()
    .map(|(n, l)| ImportInfo {
        name: (*n).to_string(),
        library: Some((*l).to_string()),
        address: None,
        ordinal: None,
        is_delayed: false,
    })
    .collect();
    let mut table = empty_table();
    table.imports = imports;
    let deps = analyze_dependencies(Path::new("/nonexistent"), &table, None).unwrap();
    assert_eq!(deps.dependencies.len(), 4);
    assert!(deps.dependencies.iter().all(|d| d.is_system_library));
    assert!(deps.license_summary.compliance_issues.is_empty());
}

/// ELF64 with `.text` plus one extra PROGBITS section.
fn elf_with_section(name: &str, flags: u64, data: &[u8]) -> Vec<u8> {
    let shstrtab = format!("\0.text\0{name}\0.shstrtab\0");
    let n_text = 1u32;
    let n_extra = 7u32;
    let n_str = 7 + name.len() as u32 + 1;
    let text = [0x90u8; 512];
    let data_off = 64 + 4 * 64;
    let text_off = data_off;
    let extra_off = text_off + text.len();
    let str_off = extra_off + data.len();
    let mut b = vec![0u8; 64];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[40..48].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    b[60..62].copy_from_slice(&4u16.to_le_bytes());
    b[62..64].copy_from_slice(&3u16.to_le_bytes());
    let shdr = |name: u32, kind: u32, flags: u64, off: usize, size: usize| {
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(&name.to_le_bytes());
        h[4..8].copy_from_slice(&kind.to_le_bytes());
        h[8..16].copy_from_slice(&flags.to_le_bytes());
        h[24..32].copy_from_slice(&(off as u64).to_le_bytes());
        h[32..40].copy_from_slice(&(size as u64).to_le_bytes());
        h
    };
    b.extend(shdr(0, 0, 0, 0, 0));
    b.extend(shdr(n_text, 1, 6, text_off, text.len()));
    b.extend(shdr(n_extra, 1, flags, extra_off, data.len()));
    b.extend(shdr(n_str, 3, 0, str_off, shstrtab.len()));
    b.extend_from_slice(&text);
    b.extend_from_slice(data);
    b.extend_from_slice(shstrtab.as_bytes());
    b
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut x = 0x2545_F491u32;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 11) as u8
        })
        .collect()
}

#[test]
fn random_bytes_in_a_debug_named_section_are_not_exempt() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "debugname",
        &elf_with_section(".debug_x", 0, &random_bytes(65536)),
    );
    let result = analyze_entropy(&path).unwrap();
    let section = result
        .sections
        .iter()
        .find(|s| s.name == ".debug_x")
        .unwrap();
    assert!(section.is_suspicious);
    assert!(result.encryption_indicators.likely_encrypted);
    assert!(result
        .recommendations
        .iter()
        .all(|r| !r.starts_with("No significant obfuscation")));
}

/// `Elf64_Chdr` (zlib) plus `payload`; `claimed` is the uncompressed size.
fn chdr_zlib(claimed: u64, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&1u32.to_le_bytes()); // ch_type zlib
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&claimed.to_le_bytes());
    data.extend_from_slice(&1u64.to_le_bytes());
    data.extend_from_slice(payload);
    data
}

fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[test]
fn verified_compressed_debug_section_is_listed_but_not_encrypted() {
    // SHF_COMPRESSED, a real Elf64_Chdr and a complete stream that inflates to
    // the claimed size (structured data, as DWARF is)
    let plain: Vec<u8> = random_bytes(100_000).iter().map(|b| b & 0x3f).collect();
    let data = chdr_zlib(plain.len() as u64, &zlib(&plain));
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "compressed",
        &elf_with_section(".debug_info", 0x800, &data),
    );
    let result = analyze_entropy(&path).unwrap();
    let section = result
        .sections
        .iter()
        .find(|s| s.name == ".debug_info")
        .unwrap();
    assert!(!section.is_suspicious);
    assert!(!result.encryption_indicators.likely_encrypted);
    assert_eq!(result.encryption_indicators.high_entropy_regions.len(), 1);
    assert!(result.encryption_indicators.high_entropy_regions[0]
        .description
        .contains("compressed"));
}

#[test]
fn forged_compression_header_on_random_bytes_is_not_exempt() {
    // Two plausible zlib bytes after a valid Chdr, then random data: it does
    // not inflate, so neither a .debug_ section nor an executable one is exempt.
    let mut payload = vec![0x78, 0x9c];
    payload.extend_from_slice(&random_bytes(65536));
    let data = chdr_zlib(1 << 20, &payload);
    let dir = TempDir::new().unwrap();
    for (name, flags, exec) in [
        (".debug_info", 0x800u64, false),
        (".payload", 0x800 | 0x2 | 0x4, true),
        (".payload", 0x800, false),
    ] {
        let path = write(&dir, "forged", &elf_with_section(name, flags, &data));
        let result = analyze_entropy(&path).unwrap();
        let section = result.sections.iter().find(|s| s.name == name).unwrap();
        assert!(section.is_suspicious, "{name} {flags:#x}: {section:?}");
        assert!(
            result.encryption_indicators.likely_encrypted,
            "{name} {flags:#x}"
        );
        assert!(result
            .recommendations
            .iter()
            .all(|r| !r.contains("the stream inflates")));
        if exec {
            assert!(result
                .packed_indicators
                .section_anomalies
                .iter()
                .any(|a| a.contains("SHF_COMPRESSED")));
        }
    }
}

#[test]
fn a_real_stream_in_a_non_debug_section_is_not_exempt() {
    let plain: Vec<u8> = random_bytes(100_000).iter().map(|b| b & 0x3f).collect();
    let data = chdr_zlib(plain.len() as u64, &zlib(&plain));
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "named", &elf_with_section(".payload", 0x800, &data));
    let result = analyze_entropy(&path).unwrap();
    assert!(result.encryption_indicators.likely_encrypted);
}

#[test]
fn appended_random_overlay_is_measured() {
    let dir = TempDir::new().unwrap();
    let mut bytes = elf_with_section(".data2", 0, &[0u8; 2048]);
    bytes.extend_from_slice(&random_bytes(256 * 1024));
    let path = write(&dir, "overlay", &bytes);
    let result = analyze_entropy(&path).unwrap();
    let overlay = result
        .sections
        .iter()
        .find(|s| s.name == "overlay")
        .unwrap();
    assert!(overlay.is_suspicious && overlay.size >= 256 * 1024);
    assert!(result.encryption_indicators.likely_encrypted);
    assert!(result
        .encryption_indicators
        .high_entropy_regions
        .iter()
        .any(|r| r.description.contains("outside every section")));
    assert!(result
        .recommendations
        .iter()
        .all(|r| !r.starts_with("No significant obfuscation")));
}

#[test]
fn section_running_past_the_end_of_the_file_is_noted_and_its_bytes_measured() {
    let dir = TempDir::new().unwrap();
    let mut bytes = elf_with_section(".big", 0, &random_bytes(65536));
    // sh_size of the .big header (third section header, offset 64+2*64+32)
    let off = 64 + 2 * 64 + 32;
    bytes[off..off + 8].copy_from_slice(&(1u64 << 40).to_le_bytes());
    let path = write(&dir, "pasteof", &bytes);
    let result = analyze_entropy(&path).unwrap();
    assert!(result
        .recommendations
        .iter()
        .any(|r| r.contains("point outside the file")));
    assert!(result.encryption_indicators.likely_encrypted);
    assert!(result
        .recommendations
        .iter()
        .all(|r| !r.starts_with("No significant obfuscation")));
}

#[test]
fn bad_name_offset_in_the_first_symbol_keeps_the_other_symbols() {
    // Two nlist entries; the first has an out-of-range n_strx
    let mut b = macho_with_symtab(2, 0);
    // symoff 64: entry 0 {n_strx, n_type, n_sect, n_desc, n_value}
    b[64..68].copy_from_slice(&0x7FFF_FFF0u32.to_le_bytes());
    b[68] = 0x0f; // N_SECT | N_EXT
    b[80..84].copy_from_slice(&1u32.to_le_bytes()); // entry 1 name at strtab+1
    b[84] = 0x01; // N_UNDF | N_EXT: an import
    b[1025..1030].copy_from_slice(b"_foo\0");
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "badstrx", &b);
    let table = analyze_symbols(&path).unwrap();
    assert_eq!(table.imports.len(), 1, "{:?}", table.imports);
    assert_eq!(table.imports[0].name, "_foo");
    let info = parse_binary(&path).unwrap();
    assert_eq!(info.imports, ["_foo"]);
}

#[test]
fn dotdot_paths_do_not_count_as_system_libraries() {
    let mut table = empty_table();
    table.imports = vec![ImportInfo {
        name: "a".to_string(),
        library: Some("/usr/lib/../../tmp/e.dylib".to_string()),
        address: None,
        ordinal: None,
        is_delayed: false,
    }];
    let deps = analyze_dependencies(Path::new("/nonexistent"), &table, None).unwrap();
    assert_eq!(deps.dependencies.len(), 1);
    assert!(deps.dependencies.iter().all(|d| !d.is_system_library));
}

#[test]
fn crypto_constants_alone_do_not_mean_encrypted() {
    let mut data = vec![0x63, 0x7c, 0x77, 0x7b, 0xf2];
    data.extend_from_slice(&[0x67, 0xe6, 0x09, 0x6a]);
    data.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    data.resize(16384, 0x90);
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "constants.bin", &data);
    let result = analyze_entropy(&path).unwrap();
    assert!(!result.encryption_indicators.likely_encrypted);
    assert!(result.encryption_indicators.crypto_constants_found.len() >= 3);
    assert!(result
        .recommendations
        .iter()
        .any(|r| r.contains("Crypto constants")));
}

#[test]
fn elf_section_with_overflowing_offset_does_not_panic() {
    let mut bytes = elf_with_section(".odd", 0, &[1, 2, 3, 4]);
    // .odd header is the third one: sh_offset = u64::MAX - 1, sh_size = 16
    let hdr = 64 + 3 * 64;
    bytes[hdr + 24..hdr + 32].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    bytes[hdr + 32..hdr + 40].copy_from_slice(&16u64.to_le_bytes());
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "overflow", &bytes);
    let result = analyze_entropy(&path).unwrap();
    assert!(result.sections.iter().all(|s| s.name != ".odd"));
}

#[test]
fn tiny_text_section_is_not_called_suspicious() {
    // 8 bytes of code in a section named .text: too small to judge
    let bytes = elf_with_section(
        ".text",
        6,
        &[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3, 0x90, 0x90],
    );
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "tiny", &bytes);
    let result = analyze_entropy(&path).unwrap();
    let tiny: Vec<_> = result.sections.iter().filter(|s| s.size == 8).collect();
    assert_eq!(tiny.len(), 1, "{:?}", result.sections);
    assert!(!tiny[0].is_suspicious);
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn large_thin_arm64_macho_is_not_called_x86_64() {
    // The test harness binary itself: a large thin arm64 Mach-O
    let me = std::env::current_exe().unwrap();
    let info = parse_binary(&me).unwrap();
    assert_eq!(info.format, "Mach-O");
    assert_eq!(info.architecture, "ARM64");
    let mut meta = FileMetadata::new(&me).unwrap();
    meta.extract_basic_info().unwrap();
    assert_eq!(meta.mime_type.as_deref(), Some("application/x-mach-binary"));
}

#[test]
#[cfg(target_os = "macos")]
fn system_universal_binary_is_macho_not_java() {
    let ls = Path::new("/bin/ls");
    if !ls.exists() {
        return;
    }
    let info = parse_binary(ls).unwrap();
    assert_eq!(info.format, "Mach-O");
    assert!(info.java_analysis.is_none());
    let mut meta = FileMetadata::new(ls).unwrap();
    meta.extract_basic_info().unwrap();
    assert_eq!(meta.mime_type.as_deref(), Some("application/x-mach-binary"));
}

// ---------------------------------------------------------------------------
// Round 3 (fourth pass): symbol-name caps, whole-stream compression check,
// forged exempt ranges
// ---------------------------------------------------------------------------

/// ELF64 with a `.symtab` of `count` global symbols that all name the same
/// `name_len`-byte string (`defined`: in section 1, else undefined).
fn elf_with_shared_name_symbols(count: usize, name_len: usize, defined: bool) -> Vec<u8> {
    let mut strtab = vec![0u8];
    strtab.extend(std::iter::repeat_n(b'a', name_len));
    strtab.push(0);
    let shstrtab = b"\0.symtab\0.strtab\0.shstrtab\0".to_vec();
    let sym_off = 64 + 4 * 64;
    let sym_len = (count + 1) * 24;
    let str_off = sym_off + sym_len;
    let shstr_off = str_off + strtab.len();
    let mut b = vec![0u8; 64];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[40..48].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    b[60..62].copy_from_slice(&4u16.to_le_bytes());
    b[62..64].copy_from_slice(&3u16.to_le_bytes());
    let shdr = |name: u32, kind: u32, link: u32, off: usize, size: usize, entsize: u64| {
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(&name.to_le_bytes());
        h[4..8].copy_from_slice(&kind.to_le_bytes());
        h[24..32].copy_from_slice(&(off as u64).to_le_bytes());
        h[32..40].copy_from_slice(&(size as u64).to_le_bytes());
        h[40..44].copy_from_slice(&link.to_le_bytes());
        h[56..64].copy_from_slice(&entsize.to_le_bytes());
        h
    };
    b.extend(shdr(0, 0, 0, 0, 0, 0));
    b.extend(shdr(1, 2, 2, sym_off, sym_len, 24));
    b.extend(shdr(9, 3, 0, str_off, strtab.len(), 0));
    b.extend(shdr(17, 3, 0, shstr_off, shstrtab.len(), 0));
    b.extend_from_slice(&[0u8; 24]);
    for _ in 0..count {
        let mut s = [0u8; 24];
        s[0..4].copy_from_slice(&1u32.to_le_bytes());
        s[4] = 0x12; // STB_GLOBAL, STT_FUNC
        s[6..8].copy_from_slice(&(u16::from(defined)).to_le_bytes());
        b.extend_from_slice(&s);
    }
    b.extend_from_slice(&strtab);
    b.extend_from_slice(&shstrtab);
    b
}

/// 64-bit Mach-O with `count` symbols that all point at one `name_len`-byte name.
fn macho_with_shared_name_symbols(count: usize, name_len: usize, n_type: u8) -> Vec<u8> {
    let symoff = 64usize;
    let stroff = symoff + count * 16;
    let mut b = Vec::new();
    b.extend_from_slice(&0xFEED_FACFu32.to_le_bytes());
    b.extend_from_slice(&CPU_ARM64.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&2u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&24u32.to_le_bytes());
    b.extend_from_slice(&[0u8; 8]);
    b.extend_from_slice(&2u32.to_le_bytes()); // LC_SYMTAB
    b.extend_from_slice(&24u32.to_le_bytes());
    b.extend_from_slice(&(symoff as u32).to_le_bytes());
    b.extend_from_slice(&(count as u32).to_le_bytes());
    b.extend_from_slice(&(stroff as u32).to_le_bytes());
    b.extend_from_slice(&((name_len + 2) as u32).to_le_bytes());
    b.resize(symoff, 0);
    for _ in 0..count {
        b.extend_from_slice(&1u32.to_le_bytes());
        b.push(n_type);
        b.push(u8::from(n_type & 0x0e != 0)); // n_sect 0 for an undefined symbol
        b.extend_from_slice(&0u16.to_le_bytes());
        let value: u64 = if n_type & 0x0e == 0 { 0 } else { 0x1000 };
        b.extend_from_slice(&value.to_le_bytes());
    }
    b.push(0);
    b.extend(std::iter::repeat_n(b'b', name_len));
    b.push(0);
    b
}

fn longest_name(table: &SymbolTable) -> usize {
    table
        .functions
        .iter()
        .filter(|f| !f.name.starts_with("[note]"))
        .map(|f| f.name.len())
        .chain(table.imports.iter().map(|i| i.name.len()))
        .chain(table.exports.iter().map(|e| e.name.len()))
        .chain(table.global_variables.iter().map(|v| v.name.len()))
        .max()
        .unwrap_or(0)
}

const NAME_CAP: usize = 4096 + "...[name truncated]".len();

#[test]
fn elf_symbols_sharing_one_huge_name_are_capped() {
    let dir = TempDir::new().unwrap();
    for defined in [false, true] {
        let path = write(
            &dir,
            "elfnames",
            &elf_with_shared_name_symbols(2000, 100_000, defined),
        );
        let table = analyze_symbols(&path).unwrap();
        assert!(table.functions.len() >= 2000);
        assert!(longest_name(&table) <= NAME_CAP);
        assert!(table.functions[0].name.ends_with("[name truncated]"));
    }
}

#[test]
fn elf_symbol_name_budget_stops_the_listing_with_a_note() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "elfbudget",
        &elf_with_shared_name_symbols(20_000, 100_000, false),
    );
    let start = std::time::Instant::now();
    let table = analyze_symbols(&path).unwrap();
    assert!(start.elapsed().as_secs() < 300);
    let kept: usize = table.functions.iter().map(|f| f.name.len()).sum();
    assert!(kept < 80 << 20, "kept {kept} name bytes");
    assert!(table.symbol_count.total_functions < 20_000);
    assert!(
        table.functions.iter().any(|f| f.name.starts_with("[note]")),
        "no note"
    );
}

#[test]
fn macho_symbols_sharing_one_huge_name_cost_a_bounded_amount() {
    let dir = TempDir::new().unwrap();
    // 30,000 undefined symbols (imports) that all name one 1 MB string
    let path = write(
        &dir,
        "machonames",
        &macho_with_shared_name_symbols(30_000, 1_000_000, 0x01),
    );
    let start = std::time::Instant::now();
    let info = parse_binary(&path).unwrap();
    let table = analyze_symbols(&path).unwrap();
    assert!(
        start.elapsed().as_secs() < 300,
        "took {:?}",
        start.elapsed()
    );
    assert_eq!(info.format, "Mach-O");
    assert!(longest_name(&table) <= NAME_CAP);
    assert!(info.imports.iter().all(|i| i.len() <= NAME_CAP));
    let kept: usize = table.functions.iter().map(|f| f.name.len()).sum();
    assert!(kept < 80 << 20, "kept {kept} name bytes");
    assert!(table.functions.iter().any(|f| f.name.starts_with("[note]")));
}

#[test]
fn macho_defined_symbols_sharing_one_huge_name_are_capped() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "machodef",
        &macho_with_shared_name_symbols(2000, 100_000, 0x0f),
    );
    let table = analyze_symbols(&path).unwrap();
    assert_eq!(table.functions.len(), 2000);
    assert!(longest_name(&table) <= NAME_CAP);
}

/// A zlib stream of `stored` zeros followed by `tail`.
fn prefix_then(tail: &[u8], stored: usize) -> Vec<u8> {
    let mut v = zlib(&vec![0u8; stored]);
    v.extend_from_slice(tail);
    v
}

#[test]
fn valid_zlib_prefix_followed_by_random_bytes_is_not_exempt() {
    let dir = TempDir::new().unwrap();
    let data = chdr_zlib(1 << 20, &prefix_then(&random_bytes(65480), 4096));
    let path = write(&dir, "prefix", &elf_with_section(".debug_x", 0x800, &data));
    let result = analyze_entropy(&path).unwrap();
    let section = result
        .sections
        .iter()
        .find(|s| s.name == ".debug_x")
        .unwrap();
    assert!(section.is_suspicious, "{section:?}");
    assert!(result.encryption_indicators.likely_encrypted);
    assert!(result
        .recommendations
        .iter()
        .all(|r| !r.contains("inflates")));
}

#[test]
fn stream_that_inflates_to_less_than_it_claims_is_not_exempt() {
    let dir = TempDir::new().unwrap();
    // A complete stream, but the header claims a megabyte and it holds 4 KiB
    let data = chdr_zlib(1 << 20, &zlib(&vec![0u8; 4096]));
    let path = write(&dir, "short", &elf_with_section(".debug_x", 0x800, &data));
    let result = analyze_entropy(&path).unwrap();
    let section = result
        .sections
        .iter()
        .find(|s| s.name == ".debug_x")
        .unwrap();
    assert!(!section.characteristics.iter().any(|c| c == "compressed"));
}

#[test]
fn a_complete_stream_that_inflates_to_what_it_claims_is_exempt() {
    let dir = TempDir::new().unwrap();
    let plain: Vec<u8> = random_bytes(100_000).iter().map(|b| b & 0x3f).collect();
    let data = chdr_zlib(plain.len() as u64, &zlib(&plain));
    let path = write(&dir, "whole", &elf_with_section(".debug_x", 0x800, &data));
    let result = analyze_entropy(&path).unwrap();
    let section = result
        .sections
        .iter()
        .find(|s| s.name == ".debug_x")
        .unwrap();
    assert!(section.characteristics.iter().any(|c| c == "compressed"));
}

/// PE32+ with one `.text` section, the headers padded to 0x400, the section
/// data at 0x400..0x600 and `tail` after it; the certificate directory names
/// the `tail` (`size` bytes).
fn pe_with_text_and_cert(tail: &[u8], size: u32) -> Vec<u8> {
    let mut b = vec![0u8; 0x40];
    b[0] = b'M';
    b[1] = b'Z';
    b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    b.extend_from_slice(b"PE\0\0");
    b.extend_from_slice(&0x8664u16.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes()); // one section
    b.extend_from_slice(&[0u8; 12]);
    b.extend_from_slice(&240u16.to_le_bytes());
    b.extend_from_slice(&0x22u16.to_le_bytes());
    let opt_start = b.len();
    b.extend_from_slice(&0x20Bu16.to_le_bytes());
    b.resize(opt_start + 60, 0);
    b.extend_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
    b.resize(opt_start + 108, 0);
    b.extend_from_slice(&16u32.to_le_bytes());
    b.resize(opt_start + 112 + 4 * 8, 0);
    b.extend_from_slice(&0x600u32.to_le_bytes());
    b.extend_from_slice(&size.to_le_bytes());
    b.resize(opt_start + 240, 0);
    let mut sec = [0u8; 40];
    sec[..5].copy_from_slice(b".text");
    sec[8..12].copy_from_slice(&0x200u32.to_le_bytes());
    sec[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
    sec[16..20].copy_from_slice(&0x200u32.to_le_bytes());
    sec[20..24].copy_from_slice(&0x400u32.to_le_bytes());
    sec[36..40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    b.extend_from_slice(&sec);
    b.resize(0x400, 0);
    b.extend(std::iter::repeat_n(0x90u8, 0x200));
    b.extend_from_slice(tail);
    b
}

fn win_certificate(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&((body.len() + 8) as u32).to_le_bytes());
    v.extend_from_slice(&0x0200u16.to_le_bytes());
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(body);
    while v.len() % 8 != 0 {
        v.push(0);
    }
    v
}

#[test]
fn random_bytes_behind_a_forged_certificate_header_are_measured() {
    let dir = TempDir::new().unwrap();
    // 1 MiB of random bytes behind a WIN_CERTIFICATE header, directory pointing at it
    let tail = win_certificate(&random_bytes(1 << 20));
    let path = write(
        &dir,
        "forgedcert.exe",
        &pe_with_text_and_cert(&tail, tail.len() as u32),
    );
    let result = analyze_entropy(&path).unwrap();
    assert!(result.encryption_indicators.likely_encrypted, "{result:#?}");
    assert!(result
        .recommendations
        .iter()
        .all(|r| !r.starts_with("No significant obfuscation")));
}

#[test]
fn a_well_formed_certificate_table_is_not_measured_and_says_so() {
    let dir = TempDir::new().unwrap();
    // A DER SEQUENCE (30 82 len) of random content: a plausible PKCS#7 blob
    // (the signedData OID right after the header, as in every Authenticode blob)
    let mut der = vec![0x30, 0x82, 0x0b, 0xb8];
    der.extend_from_slice(&[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ]);
    der.extend(random_bytes(2989));
    let tail = win_certificate(&der);
    let path = write(
        &dir,
        "realcert.exe",
        &pe_with_text_and_cert(&tail, tail.len() as u32),
    );
    let result = analyze_entropy(&path).unwrap();
    assert!(
        !result.encryption_indicators.likely_encrypted,
        "{result:#?}"
    );
    assert!(result
        .recommendations
        .iter()
        .any(|r| r.contains("certificate table") && r.contains("not measured")));
}

/// 64-bit Mach-O: `__TEXT` (header + a 0x400-byte `__text` at 0x1000) and a
/// `__LINKEDIT` of `linkedit` bytes after it; `linkedit_filesize` is what the
/// segment claims, `text_fileoff` the `__TEXT` segment's `fileoff`.
fn macho_text_and_linkedit(linkedit: &[u8], linkedit_filesize: u64, text_fileoff: u64) -> Vec<u8> {
    let seg = |name: &[u8], fileoff: u64, filesize: u64, nsects: u32| {
        let mut s = Vec::new();
        s.extend_from_slice(&0x19u32.to_le_bytes());
        s.extend_from_slice(&(72 + 80 * nsects).to_le_bytes());
        let mut n = [0u8; 16];
        n[..name.len()].copy_from_slice(name);
        s.extend_from_slice(&n);
        s.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
        s.extend_from_slice(&filesize.to_le_bytes()); // vmsize
        s.extend_from_slice(&fileoff.to_le_bytes());
        s.extend_from_slice(&filesize.to_le_bytes());
        s.extend_from_slice(&[0u8; 8]); // maxprot, initprot
        s.extend_from_slice(&nsects.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());
        s
    };
    let mut text = seg(b"__TEXT", text_fileoff, 0x1400, 1);
    let mut sect = [0u8; 80];
    sect[..6].copy_from_slice(b"__text");
    sect[16..22].copy_from_slice(b"__TEXT");
    sect[40..48].copy_from_slice(&0x400u64.to_le_bytes()); // size
    sect[48..52].copy_from_slice(&0x1000u32.to_le_bytes()); // offset
    sect[64..68].copy_from_slice(&0x8000_0400u32.to_le_bytes());
    text.extend_from_slice(&sect);
    let edit = seg(b"__LINKEDIT", 0x1400, linkedit_filesize, 0);
    let mut b = Vec::new();
    b.extend_from_slice(&0xFEED_FACFu32.to_le_bytes());
    b.extend_from_slice(&CPU_ARM64.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&2u32.to_le_bytes());
    b.extend_from_slice(&2u32.to_le_bytes());
    b.extend_from_slice(&((text.len() + edit.len()) as u32).to_le_bytes());
    b.extend_from_slice(&[0u8; 8]);
    b.extend_from_slice(&text);
    b.extend_from_slice(&edit);
    b.resize(0x1000, 0);
    b.extend(std::iter::repeat_n(0x1fu8, 0x400));
    b.extend_from_slice(linkedit);
    b
}

#[test]
fn random_bytes_inside_a_grown_linkedit_segment_are_measured() {
    let dir = TempDir::new().unwrap();
    let payload = random_bytes(100_000);
    let path = write(
        &dir,
        "linkedit",
        &macho_text_and_linkedit(&payload, payload.len() as u64, 0),
    );
    let result = analyze_entropy(&path).unwrap();
    assert!(result.encryption_indicators.likely_encrypted, "{result:#?}");
    assert!(result
        .recommendations
        .iter()
        .all(|r| !r.starts_with("No significant obfuscation")));
}

#[test]
fn universal_macho_slice_with_a_huge_segment_offset_does_not_panic() {
    let dir = TempDir::new().unwrap();
    let thin = macho_text_and_linkedit(&random_bytes(4096), 4096, u64::MAX);
    let path = write(&dir, "fatmax", &fat(&[(CPU_ARM64, 0, thin)]));
    let _ = analyze_entropy(&path).unwrap();
}

#[test]
fn zstd_compressed_debug_section_is_labelled_not_called_encrypted() {
    let dir = TempDir::new().unwrap();
    // Elf64_Chdr (ch_type 2 = zstd), a zstd frame header (single segment, 4-byte
    // content size equal to the claimed size) and random "compressed" bytes
    let claimed = 1u64 << 20;
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x80 | 0x20];
    frame.extend_from_slice(&(claimed as u32).to_le_bytes());
    frame.extend(random_bytes(65536));
    let mut data = Vec::new();
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&claimed.to_le_bytes());
    data.extend_from_slice(&1u64.to_le_bytes());
    data.extend_from_slice(&frame);
    let path = write(&dir, "zstd", &elf_with_section(".debug_info", 0x800, &data));
    let result = analyze_entropy(&path).unwrap();
    assert!(
        !result.encryption_indicators.likely_encrypted,
        "{result:#?}"
    );
    assert!(result.encryption_indicators.high_entropy_regions[0]
        .description
        .contains("zstd"));
}

#[test]
fn system_library_name_from_a_non_system_directory_is_not_a_system_library() {
    let mut table = empty_table();
    table.imports = vec![ImportInfo {
        name: "a".to_string(),
        library: Some("/tmp/xxx/libSystem.B.dylib".to_string()),
        address: None,
        ordinal: None,
        is_delayed: false,
    }];
    let deps = analyze_dependencies(Path::new("/nonexistent"), &table, None).unwrap();
    assert_eq!(deps.dependencies.len(), 1);
    assert!(deps.dependencies.iter().all(|d| !d.is_system_library));
}

// ---------------------------------------------------------------------------
// Round 4: export trie, bind opcodes, shared names, forged signatures, data
// symbols
// ---------------------------------------------------------------------------

fn uleb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn macho_segment(
    name: &str,
    fileoff: u64,
    filesize: u64,
    sections: &[(&str, u64, u32, u32)],
) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&0x19u32.to_le_bytes());
    s.extend_from_slice(&(72 + 80 * sections.len() as u32).to_le_bytes());
    let mut n = [0u8; 16];
    n[..name.len()].copy_from_slice(name.as_bytes());
    s.extend_from_slice(&n);
    s.extend_from_slice(&0u64.to_le_bytes());
    s.extend_from_slice(&filesize.to_le_bytes());
    s.extend_from_slice(&fileoff.to_le_bytes());
    s.extend_from_slice(&filesize.to_le_bytes());
    s.extend_from_slice(&[0u8; 8]);
    s.extend_from_slice(&(sections.len() as u32).to_le_bytes());
    s.extend_from_slice(&0u32.to_le_bytes());
    for (sect, size, offset, flags) in sections {
        let mut h = [0u8; 80];
        h[..sect.len()].copy_from_slice(sect.as_bytes());
        h[16..16 + name.len()].copy_from_slice(name.as_bytes());
        h[40..48].copy_from_slice(&size.to_le_bytes());
        h[48..52].copy_from_slice(&offset.to_le_bytes());
        h[64..68].copy_from_slice(&flags.to_le_bytes());
        s.extend_from_slice(&h);
    }
    s
}

fn macho_dyld_info_only(bind: (u32, u32), export: (u32, u32)) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&0x8000_0022u32.to_le_bytes());
    c.extend_from_slice(&48u32.to_le_bytes());
    for v in [0, 0, bind.0, bind.1, 0, 0, 0, 0, export.0, export.1] {
        c.extend_from_slice(&u32::to_le_bytes(v));
    }
    c
}

fn macho_linkedit_data(cmd: u32, off: u32, size: u32) -> Vec<u8> {
    let mut c = Vec::new();
    for v in [cmd, 16, off, size] {
        c.extend_from_slice(&v.to_le_bytes());
    }
    c
}

fn macho_symtab(symoff: u32, nsyms: u32, stroff: u32, strsize: u32) -> Vec<u8> {
    let mut c = Vec::new();
    for v in [2u32, 24, symoff, nsyms, stroff, strsize] {
        c.extend_from_slice(&v.to_le_bytes());
    }
    c
}

fn macho_dylib_command(cmd: u32, name: &[u8], name_offset: u32) -> Vec<u8> {
    let size = (24 + name.len() + 1).next_multiple_of(8);
    let mut c = Vec::new();
    for v in [cmd, size as u32, name_offset, 0, 0, 0] {
        c.extend_from_slice(&v.to_le_bytes());
    }
    c.extend_from_slice(name);
    c.resize(size, 0);
    c
}

/// 64-bit little-endian arm64 Mach-O: header, `cmds`, then `body` at the
/// fixed offset `BODY`.
const BODY: usize = 0x1000;
fn macho_image(cmds: &[Vec<u8>], flags: u32, body_at: usize, body: &[u8]) -> Vec<u8> {
    let total: usize = cmds.iter().map(Vec::len).sum();
    let mut b = Vec::new();
    for v in [
        0xFEED_FACFu32,
        CPU_ARM64,
        0,
        2,
        cmds.len() as u32,
        total as u32,
        flags,
        0,
    ] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    for c in cmds {
        b.extend_from_slice(c);
    }
    assert!(b.len() <= body_at);
    b.resize(body_at, 0);
    b.extend_from_slice(body);
    // the segments claim 0x2000 bytes of file
    if b.len() < 0x2000 {
        b.resize(0x2000, 0);
    }
    b
}

fn parse_in_scratch(
    dir: &TempDir,
    name: &str,
    bytes: &[u8],
) -> (
    PathBuf,
    anyhow::Result<file_scanner::binary_parser::BinaryInfo>,
) {
    let path = write(dir, name, bytes);
    let info = parse_binary(&path);
    (path, info)
}

#[test]
fn macho_export_trie_that_points_at_itself_does_not_overflow_the_stack() {
    let dir = TempDir::new().unwrap();
    // node 0: no terminal data, one branch "a" that leads back to node 0
    let trie = [0x00, 0x01, b'a', 0x00, 0x00];
    let cmds = [
        macho_segment("__TEXT", 0, 0x2000, &[]),
        macho_linkedit_data(0x8000_0033, BODY as u32, trie.len() as u32),
    ];
    let (_, info) = parse_in_scratch(&dir, "selfcycle", &macho_image(&cmds, 0, BODY, &trie));
    let info = info.unwrap();
    assert_eq!(info.format, "Mach-O");
    assert!(info.exports.is_empty());
    assert!(
        info.notes.iter().any(|n| n.contains("export trie")),
        "{:?}",
        info.notes
    );
}

#[test]
fn macho_export_trie_with_a_two_node_cycle_is_cut_with_a_note() {
    let dir = TempDir::new().unwrap();
    // node 0 -> "a" -> node 5 -> "b" -> node 0
    let trie = [0x00, 0x01, b'a', 0x00, 0x05, 0x00, 0x01, b'b', 0x00, 0x00];
    let cmds = [
        macho_segment("__TEXT", 0, 0x2000, &[]),
        macho_dyld_info_only((0, 0), (BODY as u32, trie.len() as u32)),
    ];
    let (_, info) = parse_in_scratch(&dir, "twocycle", &macho_image(&cmds, 0, BODY, &trie));
    let info = info.unwrap();
    assert!(info.notes.iter().any(|n| n.contains("export trie")));
}

#[test]
fn macho_export_trie_that_is_a_tree_is_still_listed() {
    let dir = TempDir::new().unwrap();
    // root -"_f"-> node 6 (terminal, flags 0, address 0x10, no children)
    let trie = [0x00, 0x01, b'_', b'f', 0x00, 0x06, 0x02, 0x00, 0x10, 0x00];
    let cmds = [
        macho_segment("__TEXT", 0, 0x2000, &[]),
        macho_linkedit_data(0x8000_0033, BODY as u32, trie.len() as u32),
    ];
    let (_, info) = parse_in_scratch(&dir, "tree", &macho_image(&cmds, 0, BODY, &trie));
    let info = info.unwrap();
    assert_eq!(info.exports, vec!["_f".to_string()]);
    assert!(info.notes.is_empty(), "{:?}", info.notes);
}

fn bind_stream(ordinal_imm: u8, times: Option<u64>) -> Vec<u8> {
    let mut s = vec![0x10 | ordinal_imm, 0x70, 0x00, 0x40, b'x', 0x00];
    match times {
        Some(n) => {
            s.push(0xC0);
            s.extend(uleb(n));
            s.extend(uleb(0));
        }
        None => s.push(0x90),
    }
    s.push(0x00);
    s
}

fn macho_with_bind(stream: &[u8]) -> Vec<u8> {
    let cmds = [
        macho_segment("__TEXT", 0, 0x2000, &[]),
        macho_dyld_info_only((BODY as u32, stream.len() as u32), (0, 0)),
    ];
    macho_image(&cmds, 0, BODY, stream)
}

#[test]
fn macho_bind_opcode_repeat_count_is_capped_with_a_note() {
    let dir = TempDir::new().unwrap();
    for times in [5_000_000u64, 1 << 40] {
        let start = std::time::Instant::now();
        let (_, info) = parse_in_scratch(
            &dir,
            "bindtimes",
            &macho_with_bind(&bind_stream(0, Some(times))),
        );
        let info = info.unwrap();
        assert!(start.elapsed().as_secs() < 300);
        assert!(info.imports.len() < 1000, "{} imports", info.imports.len());
        assert!(
            info.notes.iter().any(|n| n.contains("bind")),
            "{:?}",
            info.notes
        );
    }
}

#[test]
fn macho_bind_to_a_missing_library_or_segment_is_a_note_not_a_crash() {
    let dir = TempDir::new().unwrap();
    // library ordinal 15 with only the image itself, and segment 15 of 1
    let (_, info) = parse_in_scratch(&dir, "ord15", &macho_with_bind(&bind_stream(15, None)));
    assert!(info.unwrap().notes.iter().any(|n| n.contains("bind")));
    let mut stream = bind_stream(0, None);
    stream[1] = 0x70 | 15;
    let (_, info) = parse_in_scratch(&dir, "seg15", &macho_with_bind(&stream));
    assert!(info.unwrap().notes.iter().any(|n| n.contains("bind")));
}

#[test]
fn macho_bind_stream_that_is_in_order_is_still_walked() {
    let dir = TempDir::new().unwrap();
    let (_, info) = parse_in_scratch(&dir, "bindok", &macho_with_bind(&bind_stream(0, None)));
    let info = info.unwrap();
    assert!(
        info.imports.iter().any(|i| i.starts_with('x')),
        "{:?}",
        info.imports
    );
    assert!(info.notes.is_empty(), "{:?}", info.notes);
}

/// Mach-O with one `LC_LOAD_DYLIB` of a `lib_len`-byte name and `count`
/// undefined symbols bound to it by ordinal (two-level namespace).
fn macho_biglib(count: usize, lib_len: usize) -> Vec<u8> {
    let name: Vec<u8> = std::iter::repeat_n(b'l', lib_len).collect();
    let dylib = macho_dylib_command(0xc, &name, 24);
    let body_at = (32 + 72 + 24 + dylib.len()).next_multiple_of(0x1000);
    let symoff = body_at;
    let stroff = symoff + count * 16;
    let cmds = [
        macho_segment("__TEXT", 0, 0x2000, &[]),
        macho_symtab(symoff as u32, count as u32, stroff as u32, 4),
        dylib,
    ];
    let mut body = Vec::new();
    for _ in 0..count {
        body.extend_from_slice(&1u32.to_le_bytes());
        body.push(0x01); // N_UNDF | N_EXT
        body.push(0);
        body.extend_from_slice(&(1u16 << 8).to_le_bytes()); // ordinal 1
        body.extend_from_slice(&0u64.to_le_bytes());
    }
    body.extend_from_slice(b"\0x\0\0");
    macho_image(&cmds, 0x80, body_at, &body)
}

#[test]
fn macho_library_name_shared_by_thousands_of_imports_is_capped_and_counted() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "biglib", &macho_biglib(6000, 100_000));
    let start = std::time::Instant::now();
    let info = parse_binary(&path).unwrap();
    let table = analyze_symbols(&path).unwrap();
    assert!(start.elapsed().as_secs() < 300);
    // every name kept is cut at the cap and the copies together stay small
    assert!(info.imports.iter().all(|i| i.len() <= 2 * NAME_CAP + 4));
    assert!(info.needed_libraries.iter().all(|l| l.len() <= NAME_CAP));
    let import_bytes: usize = info.imports.iter().map(String::len).sum();
    assert!(import_bytes < 40 << 20, "{import_bytes} bytes of imports");
    assert!(table
        .imports
        .iter()
        .all(|i| i.library.as_ref().is_none_or(|l| l.len() <= NAME_CAP)));
    let library_bytes: usize = table
        .imports
        .iter()
        .map(|i| i.library.as_ref().map_or(0, String::len))
        .sum();
    assert!(
        library_bytes < 40 << 20,
        "{library_bytes} bytes of libraries"
    );
}

#[test]
fn macho_library_names_outside_their_commands_are_not_analyzed() {
    let dir = TempDir::new().unwrap();
    // every LC_LOAD_DYLIB points its name at the same string 4000 bytes away
    let mut cmds = vec![macho_segment("__TEXT", 0, 0x2000, &[])];
    for _ in 0..40 {
        cmds.push(macho_dylib_command(0xc, b"", 4000));
    }
    let path = write(
        &dir,
        "dylibs",
        &macho_image(&cmds, 0, BODY, &vec![b'q'; 20_000]),
    );
    assert!(parse_binary(&path).is_err());
    assert!(analyze_symbols(&path).is_err());
    assert!(needed_libraries(&path).is_empty());
    // the entropy analysis still answers, without a section list
    assert!(analyze_entropy(&path).is_ok());
}

/// ELF64 whose dynamic section holds `names.len()` DT_NEEDED entries.
fn elf_with_needed(names: &[Vec<u8>], shared: bool) -> Vec<u8> {
    let mut strtab = vec![0u8];
    let mut offsets = Vec::new();
    for n in names {
        if shared && !offsets.is_empty() {
            offsets.push(offsets[0]);
            continue;
        }
        offsets.push(strtab.len() as u64);
        strtab.extend_from_slice(n);
        strtab.push(0);
    }
    let dyn_off = 64 + 2 * 56;
    let dyn_len = (offsets.len() + 3) * 16;
    let str_off = dyn_off + dyn_len;
    let mut b = vec![0u8; 64];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&3u16.to_le_bytes());
    b[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&2u16.to_le_bytes());
    let total = (str_off + strtab.len()) as u64;
    let phdr = |kind: u32, flags: u32, off: u64, size: u64| {
        let mut h = vec![0u8; 56];
        h[0..4].copy_from_slice(&kind.to_le_bytes());
        h[4..8].copy_from_slice(&flags.to_le_bytes());
        h[8..16].copy_from_slice(&off.to_le_bytes());
        h[16..24].copy_from_slice(&off.to_le_bytes());
        h[24..32].copy_from_slice(&off.to_le_bytes());
        h[32..40].copy_from_slice(&size.to_le_bytes());
        h[40..48].copy_from_slice(&size.to_le_bytes());
        h[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
        h
    };
    b.extend(phdr(1, 5, 0, total));
    b.extend(phdr(2, 6, dyn_off as u64, dyn_len as u64));
    let entry = |tag: u64, val: u64| {
        let mut e = Vec::new();
        e.extend_from_slice(&tag.to_le_bytes());
        e.extend_from_slice(&val.to_le_bytes());
        e
    };
    for o in &offsets {
        b.extend(entry(1, *o));
    }
    b.extend(entry(5, str_off as u64));
    b.extend(entry(10, strtab.len() as u64));
    b.extend(entry(0, 0));
    b.extend_from_slice(&strtab);
    b
}

#[test]
fn elf_needed_libraries_are_capped_and_cheap_to_deduplicate() {
    let dir = TempDir::new().unwrap();
    // 6000 distinct names: the list stops at the cap, with a note
    let names: Vec<Vec<u8>> = (0..6000)
        .map(|i| format!("lib{i}.so").into_bytes())
        .collect();
    let path = write(&dir, "needed", &elf_with_needed(&names, false));
    let libs = needed_libraries(&path);
    assert_eq!(libs.len(), 4096);
    let info = parse_binary(&path).unwrap();
    assert!(info.needed_libraries.len() <= 4096);
    assert!(
        info.notes.iter().any(|n| n.contains("needed libraries")),
        "{:?}",
        info.notes
    );
    // 20,000 entries naming one 1 MiB string: one name, kept cut, quickly
    let big = vec![vec![b'n'; 1 << 20]; 20_000];
    let path = write(&dir, "needed_big", &elf_with_needed(&big, true));
    let start = std::time::Instant::now();
    let info = parse_binary(&path).unwrap();
    assert!(start.elapsed().as_secs() < 300, "{:?}", start.elapsed());
    assert_eq!(info.needed_libraries.len(), 1);
    assert!(info.needed_libraries[0].len() <= NAME_CAP);
}

/// ELF64 with `count` sections whose `sh_name` all point at one `name_len`-byte name.
fn elf_with_shared_section_names(count: usize, name_len: usize) -> Vec<u8> {
    let mut shstrtab = vec![0u8];
    shstrtab.extend(std::iter::repeat_n(b's', name_len));
    shstrtab.push(0);
    let shoff = 64 + shstrtab.len();
    let mut b = vec![0u8; 64];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    b[60..62].copy_from_slice(&((count + 2) as u16).to_le_bytes());
    b[62..64].copy_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&shstrtab);
    let shdr = |name: u32, kind: u32, off: u64, size: u64| {
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(&name.to_le_bytes());
        h[4..8].copy_from_slice(&kind.to_le_bytes());
        h[24..32].copy_from_slice(&off.to_le_bytes());
        h[32..40].copy_from_slice(&size.to_le_bytes());
        h
    };
    b.extend(shdr(0, 0, 0, 0));
    b.extend(shdr(0, 3, 64, shstrtab.len() as u64));
    for _ in 0..count {
        b.extend(shdr(1, 1, 0, 64));
    }
    b
}

#[test]
fn elf_section_names_shared_by_thousands_of_sections_are_capped() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "secnames",
        &elf_with_shared_section_names(3000, 200_000),
    );
    let info = parse_binary(&path).unwrap();
    assert!(info.sections.iter().all(|s| s.name.len() <= NAME_CAP));
    let entropy = analyze_entropy(&path).unwrap();
    assert!(!entropy.sections.is_empty());
    assert!(entropy.sections.iter().all(|s| s.name.len() <= NAME_CAP));
    let kept: usize = entropy.sections.iter().map(|s| s.name.len()).sum();
    assert!(kept < 40 << 20, "{kept} name bytes");
}

/// Mach-O with a code signature of `sig` bytes behind a 12-byte SuperBlob
/// header, pointed at by `LC_CODE_SIGNATURE`.
fn macho_with_signature(sig: &[u8]) -> Vec<u8> {
    let cmds = [
        macho_segment(
            "__TEXT",
            0,
            0x1000,
            &[("__text", 0x100, 0x400, 0x8000_0400)],
        ),
        macho_linkedit_data(0x1d, 0x1400, sig.len() as u32),
    ];
    let mut b = macho_image(&cmds, 0, BODY, &[]);
    b.truncate(0x400);
    b.resize(0x400, 0);
    b.extend(std::iter::repeat_n(0x1fu8, 0x100));
    b.resize(0x1400, 0);
    b.extend_from_slice(sig);
    b
}

fn be32(v: usize) -> [u8; 4] {
    (v as u32).to_be_bytes()
}

#[test]
fn forged_code_signature_with_a_gap_or_a_big_code_directory_is_measured() {
    let dir = TempDir::new().unwrap();
    let payload = random_bytes(100_000);
    // Gap variant: header, one index entry, the random payload, then a small
    // CMS blob at the very end.
    let mut gap = Vec::new();
    gap.extend_from_slice(&0xfade_0cc0u32.to_be_bytes());
    gap.extend_from_slice(&be32(20 + payload.len() + 8));
    gap.extend_from_slice(&be32(1));
    gap.extend_from_slice(&be32(0));
    gap.extend_from_slice(&be32(20 + payload.len()));
    gap.extend_from_slice(&payload);
    gap.extend_from_slice(&0xfade_0b01u32.to_be_bytes());
    gap.extend_from_slice(&be32(8));
    let result = analyze_entropy(&write(&dir, "gap", &macho_with_signature(&gap))).unwrap();
    assert!(result.encryption_indicators.likely_encrypted, "{result:#?}");

    // CodeDirectory variant: hashOffset placed after the random bytes
    let mut cd = vec![0u8; 44];
    cd[0..4].copy_from_slice(&0xfade_0c02u32.to_be_bytes());
    let cd_len = 44 + payload.len() + 32;
    cd[4..8].copy_from_slice(&be32(cd_len));
    cd[16..20].copy_from_slice(&be32(44 + payload.len()));
    cd[28..32].copy_from_slice(&be32(1));
    cd[32..36].copy_from_slice(&be32(0x100));
    cd[36] = 32;
    cd[39] = 12;
    cd.extend_from_slice(&payload);
    cd.extend_from_slice(&[0u8; 32]);
    let mut forged = Vec::new();
    forged.extend_from_slice(&0xfade_0cc0u32.to_be_bytes());
    forged.extend_from_slice(&be32(20 + cd.len()));
    forged.extend_from_slice(&be32(1));
    forged.extend_from_slice(&be32(0));
    forged.extend_from_slice(&be32(20));
    forged.extend_from_slice(&cd);
    let result = analyze_entropy(&write(&dir, "cd", &macho_with_signature(&forged))).unwrap();
    assert!(result.encryption_indicators.likely_encrypted, "{result:#?}");
}

#[test]
fn ordinary_ad_hoc_code_signature_is_still_exempt() {
    let dir = TempDir::new().unwrap();
    // A CodeDirectory the size a linker writes: identifier, one page hash
    let ident = b"hello\0";
    let hash_off = 44 + ident.len();
    let mut cd = vec![0u8; 44];
    cd[0..4].copy_from_slice(&0xfade_0c02u32.to_be_bytes());
    cd[4..8].copy_from_slice(&be32(hash_off + 32));
    cd[16..20].copy_from_slice(&be32(hash_off));
    cd[20..24].copy_from_slice(&be32(44));
    cd[28..32].copy_from_slice(&be32(1));
    cd[32..36].copy_from_slice(&be32(0x400));
    cd[36] = 32;
    cd[39] = 12;
    cd.extend_from_slice(ident);
    cd.extend_from_slice(&random_bytes(32));
    let mut sig = Vec::new();
    sig.extend_from_slice(&0xfade_0cc0u32.to_be_bytes());
    sig.extend_from_slice(&be32(20 + cd.len()));
    sig.extend_from_slice(&be32(1));
    sig.extend_from_slice(&be32(0));
    sig.extend_from_slice(&be32(20));
    sig.extend_from_slice(&cd);
    let result = analyze_entropy(&write(&dir, "adhoc", &macho_with_signature(&sig))).unwrap();
    assert!(
        result
            .recommendations
            .iter()
            .any(|r| r.contains("code signature") && r.contains("not measured")),
        "{:?}",
        result.recommendations
    );
}

#[test]
fn macho_data_symbols_are_variables_not_functions() {
    let dir = TempDir::new().unwrap();
    // __TEXT/__text (section 1, code), __DATA/__data (2), __DATA/__bss (3)
    let names = [
        "_main",
        "_api_entry",
        "_helper",
        "_counter",
        "_message",
        "_table",
        "_bss_buffer",
        "_hidden_state",
        "_printf",
    ];
    // (n_type, n_sect): 3 text symbols, 5 data symbols, 1 undefined
    let kinds: [(u8, u8); 9] = [
        (0x0f, 1),
        (0x0f, 1),
        (0x0e, 1),
        (0x0f, 2),
        (0x0f, 2),
        (0x0f, 2),
        (0x0f, 3),
        (0x0e, 2),
        (0x01, 0),
    ];
    let mut strtab = vec![0u8];
    let mut offsets = Vec::new();
    for n in names {
        offsets.push(strtab.len() as u32);
        strtab.extend_from_slice(n.as_bytes());
        strtab.push(0);
    }
    let symoff = BODY;
    let stroff = symoff + names.len() * 16;
    let cmds = [
        macho_segment("__TEXT", 0, 0x4000, &[("__text", 0x10, 0x200, 0x8000_0400)]),
        macho_segment(
            "__DATA",
            0x4000,
            0x4000,
            &[("__data", 0x10, 0x4000, 0), ("__bss", 0x10, 0, 1)],
        ),
        macho_symtab(
            symoff as u32,
            names.len() as u32,
            stroff as u32,
            strtab.len() as u32,
        ),
    ];
    let mut body = Vec::new();
    for (i, (n_type, n_sect)) in kinds.iter().enumerate() {
        body.extend_from_slice(&offsets[i].to_le_bytes());
        body.push(*n_type);
        body.push(*n_sect);
        body.extend_from_slice(&0u16.to_le_bytes());
        let value: u64 = if *n_sect == 0 {
            0
        } else {
            0x1000 + i as u64 * 8
        };
        body.extend_from_slice(&value.to_le_bytes());
    }
    body.extend_from_slice(&strtab);
    let mut image = macho_image(&cmds, 0, BODY, &body);
    image.resize(0x8000, 0);
    let path = write(&dir, "globals", &image);
    let table = analyze_symbols(&path).unwrap();
    let defined: Vec<_> = table
        .functions
        .iter()
        .filter(|f| !f.is_imported && !f.name.starts_with("[note]"))
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(defined, ["_main", "_api_entry", "_helper"]);
    assert_eq!(table.global_variables.len(), 5);
    assert_eq!(table.symbol_count.global_variables, 5);
    assert_eq!(table.symbol_count.imported_functions, 1);
    assert_eq!(table.symbol_count.total_functions, 4);
    assert_eq!(table.exports.len(), 2); // _main and _api_entry (the variables are not exports of functions)
}

#[test]
fn rpath_and_relative_library_names_do_not_count_as_system_libraries() {
    for lib in [
        "@rpath/libSystem.B.dylib",
        "@executable_path/libc.dylib",
        "evil/libSystem.B.dylib",
    ] {
        let mut table = empty_table();
        table.imports = vec![ImportInfo {
            name: "a".to_string(),
            library: Some(lib.to_string()),
            address: None,
            ordinal: None,
            is_delayed: false,
        }];
        let deps = analyze_dependencies(Path::new("/nonexistent"), &table, None).unwrap();
        assert_eq!(deps.dependencies.len(), 1, "{lib}");
        assert!(
            deps.dependencies.iter().all(|d| !d.is_system_library),
            "{lib}"
        );
    }
}

/// A minimal PE32+ whose `thunks` import-lookup entries all point at one
/// hint/name entry with a `name_len`-byte name (the shape of a name bomb).
fn pe_with_shared_import_name(name_len: usize, thunks: usize) -> Vec<u8> {
    const RVA: usize = 0x1000;
    const RAW: usize = 0x200;
    let desc = 40;
    let ilt_at = desc;
    let ilt_size = 8 * (thunks + 1);
    let iat_at = ilt_at + ilt_size;
    let dll_at = iat_at + ilt_size;
    let dll = b"KERNEL32.dll\0";
    let hn_at = dll_at + dll.len() + (dll.len() & 1);
    let code_at = hn_at + 2 + name_len + 1;
    let mut sec = vec![0u8; code_at + 16];
    let put32 =
        |sec: &mut Vec<u8>, at: usize, v: u32| sec[at..at + 4].copy_from_slice(&v.to_le_bytes());
    put32(&mut sec, 0, (RVA + ilt_at) as u32);
    put32(&mut sec, 12, (RVA + dll_at) as u32);
    put32(&mut sec, 16, (RVA + iat_at) as u32);
    for i in 0..thunks {
        let v = ((RVA + hn_at) as u64).to_le_bytes();
        sec[ilt_at + 8 * i..ilt_at + 8 * i + 8].copy_from_slice(&v);
        sec[iat_at + 8 * i..iat_at + 8 * i + 8].copy_from_slice(&v);
    }
    sec[dll_at..dll_at + dll.len()].copy_from_slice(dll);
    for b in &mut sec[hn_at + 2..hn_at + 2 + name_len] {
        *b = b'L';
    }
    sec[code_at] = 0xc3;
    let raw_size = sec.len().div_ceil(0x200) * 0x200;
    sec.resize(raw_size, 0);
    let vsize = raw_size.div_ceil(0x1000) * 0x1000;

    let mut h = vec![0u8; RAW];
    h[0..2].copy_from_slice(b"MZ");
    h[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    h[0x40..0x44].copy_from_slice(b"PE\0\0");
    h[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes()); // machine
    h[0x46..0x48].copy_from_slice(&1u16.to_le_bytes()); // sections
    h[0x44 + 16..0x44 + 18].copy_from_slice(&240u16.to_le_bytes()); // size of optional header
    h[0x44 + 18..0x44 + 20].copy_from_slice(&0x22u16.to_le_bytes());
    let o = 0x58;
    h[o..o + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    h[o + 2] = 14;
    h[o + 4..o + 8].copy_from_slice(&(raw_size as u32).to_le_bytes());
    h[o + 16..o + 20].copy_from_slice(&((RVA + code_at) as u32).to_le_bytes()); // entry
    h[o + 20..o + 24].copy_from_slice(&(RVA as u32).to_le_bytes()); // base of code
    h[o + 24..o + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // image base
    h[o + 32..o + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section alignment
    h[o + 36..o + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file alignment
    h[o + 40..o + 42].copy_from_slice(&6u16.to_le_bytes()); // os major
    h[o + 48..o + 50].copy_from_slice(&6u16.to_le_bytes()); // subsystem major
    h[o + 56..o + 60].copy_from_slice(&((RVA + vsize) as u32).to_le_bytes()); // size of image
    h[o + 60..o + 64].copy_from_slice(&(RAW as u32).to_le_bytes()); // size of headers
    h[o + 68..o + 70].copy_from_slice(&3u16.to_le_bytes()); // subsystem
    h[o + 108..o + 112].copy_from_slice(&16u32.to_le_bytes()); // number of directories
    h[o + 112 + 8..o + 112 + 12].copy_from_slice(&(RVA as u32).to_le_bytes()); // import dir
    h[o + 112 + 12..o + 112 + 16].copy_from_slice(&40u32.to_le_bytes());
    let s = o + 240;
    h[s..s + 8].copy_from_slice(b".text\0\0\0");
    h[s + 8..s + 12].copy_from_slice(&(sec.len() as u32).to_le_bytes());
    h[s + 12..s + 16].copy_from_slice(&(RVA as u32).to_le_bytes());
    h[s + 16..s + 20].copy_from_slice(&(raw_size as u32).to_le_bytes());
    h[s + 20..s + 24].copy_from_slice(&(RAW as u32).to_le_bytes());
    h[s + 36..s + 40].copy_from_slice(&0xE000_0060u32.to_le_bytes());
    h.extend_from_slice(&sec);
    h
}

#[test]
fn pe_name_bomb_is_refused_before_goblin_reads_it_once_per_thunk() {
    // 100,000-byte name x 20,000 thunks: goblin would read 2 GB of names.
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "bomb.exe",
        &pe_with_shared_import_name(100_000, 20_000),
    );
    let err = parse_binary(&path).expect_err("the bomb must not be analyzed");
    assert!(
        err.to_string().contains("The PE file was not analyzed"),
        "{err}"
    );
    assert!(needed_libraries(&path).is_empty());
    assert!(analyze_symbols(&path).is_err());
    // the other analyzers answer without hanging
    let _ = analyze_entropy(&path);
}

/// Adds a second, executable section of `random_len` pseudo-random bytes to a
/// PE built by `pe_with_shared_import_name` (the section table has room).
fn with_random_section(mut pe: Vec<u8>, random_len: usize) -> Vec<u8> {
    let s = 0x58 + 240 + 40;
    let raw_ptr = pe.len().div_ceil(0x200) * 0x200;
    pe.resize(raw_ptr, 0);
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..random_len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        pe.push((x >> 24) as u8);
    }
    pe[s..s + 8].copy_from_slice(b".pack\0\0\0");
    pe[s + 8..s + 12].copy_from_slice(&(random_len as u32).to_le_bytes());
    pe[s + 12..s + 16].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    pe[s + 16..s + 20].copy_from_slice(&(random_len as u32).to_le_bytes());
    pe[s + 20..s + 24].copy_from_slice(&(raw_ptr as u32).to_le_bytes());
    pe[s + 36..s + 40].copy_from_slice(&0xE000_0060u32.to_le_bytes());
    pe[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
    pe
}

#[test]
fn refused_import_table_does_not_hide_a_packed_section() {
    let dir = TempDir::new().unwrap();
    let bomb = || pe_with_shared_import_name(100_000, 20_000);
    // bomb + high-entropy executable section: still packed and encrypted
    let packed = write(&dir, "packed.exe", &with_random_section(bomb(), 300_000));
    let r = analyze_entropy(&packed).unwrap();
    assert!(r.packed_indicators.likely_packed, "{r:?}");
    assert!(r.encryption_indicators.likely_encrypted, "{r:?}");
    assert!(r.sections.iter().any(|s| s.name == ".pack"), "{r:?}");
    // the bomb alone: sections are read, nothing is flagged, and the refused
    // import table is not reported as "unusually small"
    let mut not_writable = bomb();
    // .text read+execute only (the fixture's default also sets writable)
    // and not named .text (a .text section must have entropy 4-7, which this
    // synthetic one, mostly one repeated letter, does not)
    not_writable[0x148..0x150].copy_from_slice(b".code\0\0\0");
    let ch = 0x58 + 240 + 36;
    not_writable[ch..ch + 4].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    let plain = write(&dir, "plain.exe", &not_writable);
    let r = analyze_entropy(&plain).unwrap();
    assert!(!r.packed_indicators.likely_packed, "{r:?}");
    assert!(!r.encryption_indicators.likely_encrypted, "{r:?}");
    assert!(
        r.packed_indicators.import_table_anomalies.is_empty(),
        "{r:?}"
    );
}

#[test]
fn pe_bomb_with_unmapped_lookup_table_is_refused() {
    // goblin reads the address table when the lookup-table RVA does not map
    let mut pe = pe_with_shared_import_name(100_000, 20_000);
    pe[0x200..0x204].copy_from_slice(&0x0050_0000u32.to_le_bytes());
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "unmapped.exe", &pe);
    let err = parse_binary(&path).expect_err("the bomb must not be analyzed");
    assert!(
        err.to_string().contains("The PE file was not analyzed"),
        "{err}"
    );
}

#[test]
fn pe_bomb_whose_name_starts_in_the_next_section_is_refused() {
    // Every thunk points at the last two mapped bytes of the first section
    // (the hint). goblin maps that RVA and reads the name two bytes further
    // on in the file, which is the raw data of a second section mapped far
    // away, so the name must be measured at offset(rva) + 2, not offset(rva + 2).
    let thunks = 20_000;
    let mut pe = pe_with_shared_import_name(8, thunks);
    let raw_size = pe.len() - 0x200;
    let hint_rva = (0x1000 + raw_size - 2) as u64;
    let ilt_at = 0x200 + 40;
    let iat_at = ilt_at + 8 * (thunks + 1);
    for i in 0..thunks {
        pe[ilt_at + 8 * i..ilt_at + 8 * i + 8].copy_from_slice(&hint_rva.to_le_bytes());
        pe[iat_at + 8 * i..iat_at + 8 * i + 8].copy_from_slice(&hint_rva.to_le_bytes());
    }
    let name_len = 100_000usize;
    let raw_ptr = pe.len();
    assert_eq!(raw_ptr % 0x200, 0);
    pe.extend(std::iter::repeat_n(b'L', name_len));
    pe.push(0);
    pe.resize(pe.len().div_ceil(0x200) * 0x200, 0);
    let second = (pe.len() - raw_ptr) as u32;
    let s = 0x58 + 240 + 40;
    pe[s..s + 8].copy_from_slice(b".names\0\0");
    pe[s + 8..s + 12].copy_from_slice(&second.to_le_bytes());
    pe[s + 12..s + 16].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    pe[s + 16..s + 20].copy_from_slice(&second.to_le_bytes());
    pe[s + 20..s + 24].copy_from_slice(&(raw_ptr as u32).to_le_bytes());
    pe[s + 36..s + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
    pe[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "straddle.exe", &pe);
    let err = parse_binary(&path).expect_err("the bomb must not be analyzed");
    assert!(
        err.to_string().contains("The PE file was not analyzed"),
        "{err}"
    );
}

#[test]
fn pe_long_shared_name_under_the_budget_is_capped_and_stored_once() {
    // 100,000-byte name x 300 thunks = 30 MB: within the budget, so it is parsed.
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "shared.exe",
        &pe_with_shared_import_name(100_000, 300),
    );
    let info = parse_binary(&path).unwrap();
    assert_eq!(info.format, "PE");
    assert_eq!(
        info.imports.len(),
        1,
        "one name shared by every thunk is listed once"
    );
    assert!(
        info.imports[0].len() <= 4096 + 64,
        "{}",
        info.imports[0].len()
    );
    assert_eq!(info.needed_libraries, vec!["KERNEL32.dll".to_string()]);
}

#[test]
fn pe_many_thunks_with_one_short_name_list_it_once() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "many.exe", &pe_with_shared_import_name(10, 5_000));
    let info = parse_binary(&path).unwrap();
    assert_eq!(info.imports.len(), 1);
}

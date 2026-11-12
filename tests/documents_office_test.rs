//! Office macro analysis (CF14): compound files and OOXML packages built in the test.

use std::io::{Cursor, Write};

use file_scanner::ole_vba_analysis::{
    analyze_office, analyze_ole_vba, detect_auto_exec_entries, ovba_decompress, OleFileType,
    VbaModuleType,
};
use tempfile::TempDir;

/// MS-OVBA container made only of literal tokens (valid, just not small).
fn ovba_compress(data: &[u8]) -> Vec<u8> {
    let mut out = vec![1u8];
    for chunk in data.chunks(3600) {
        let mut body = Vec::new();
        for group in chunk.chunks(8) {
            body.push(0u8);
            body.extend_from_slice(group);
        }
        let size = body.len() + 2;
        let header = 0xB000u16 | (size as u16 - 3);
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(&body);
    }
    out
}

fn rec(id: u16, data: &[u8]) -> Vec<u8> {
    let mut out = id.to_le_bytes().to_vec();
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// (name, is_class) per module; every module's stream carries a 6-byte cache prefix.
fn dir_stream(project: &str, modules: &[(&str, bool)]) -> Vec<u8> {
    dir_stream_with(project, modules, None)
}

/// Like [`dir_stream`], but every module may name one shared stream.
fn dir_stream_with(project: &str, modules: &[(&str, bool)], stream: Option<&str>) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(rec(1, &3u32.to_le_bytes()));
    d.extend(rec(2, &1033u32.to_le_bytes()));
    d.extend(rec(0x14, &1033u32.to_le_bytes()));
    d.extend(rec(3, &1252u16.to_le_bytes()));
    d.extend(rec(4, project.as_bytes()));
    d.extend(rec(5, b""));
    d.extend(rec(0x40, b""));
    d.extend(rec(6, b""));
    d.extend(rec(0x3D, b""));
    d.extend(rec(7, &0u32.to_le_bytes()));
    d.extend(rec(8, &0u32.to_le_bytes()));
    d.extend_from_slice(&9u16.to_le_bytes());
    d.extend_from_slice(&4u32.to_le_bytes());
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend(rec(0x0C, b""));
    d.extend(rec(0x3C, b""));
    d.extend(rec(0x16, b"stdole"));
    d.extend(rec(0x3E, &utf16("stdole")));
    let libid =
        b"*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\stdole2.tlb#OLE Automation";
    let mut reg = (libid.len() as u32).to_le_bytes().to_vec();
    reg.extend_from_slice(libid);
    reg.extend_from_slice(&0u32.to_le_bytes());
    reg.extend_from_slice(&0u16.to_le_bytes());
    d.extend(rec(0x0D, &reg));
    d.extend(rec(0x0F, &(modules.len() as u16).to_le_bytes()));
    d.extend(rec(0x13, &0xFFFFu16.to_le_bytes()));
    for (name, is_class) in modules {
        d.extend(rec(0x19, name.as_bytes()));
        d.extend(rec(0x47, &utf16(name)));
        let stream_name = stream.unwrap_or(name);
        d.extend(rec(0x1A, stream_name.as_bytes()));
        d.extend(rec(0x32, &utf16(stream_name)));
        d.extend(rec(0x1C, b""));
        d.extend(rec(0x48, b""));
        d.extend(rec(0x31, &6u32.to_le_bytes()));
        d.extend(rec(0x1E, &0u32.to_le_bytes()));
        d.extend(rec(0x2C, &0xFFFFu16.to_le_bytes()));
        d.extend(rec(if *is_class { 0x22 } else { 0x21 }, b""));
        d.extend(rec(0x2B, b""));
    }
    d.extend(rec(0x10, b""));
    d
}

/// A compound file with a VBA project at `vba_dir` (for example `/Macros/VBA`).
fn vba_compound(vba_dir: &str, modules: &[(&str, &str, bool)]) -> Vec<u8> {
    let mut cfb = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    cfb.create_stream("/WordDocument")
        .unwrap()
        .write_all(b"doc")
        .unwrap();
    let mut path = String::new();
    for part in vba_dir.trim_start_matches('/').split('/') {
        path.push('/');
        path.push_str(part);
        cfb.create_storage(&path).unwrap();
    }
    let parent = vba_dir.rsplit_once('/').map_or("", |(p, _)| p);
    let names: Vec<(&str, bool)> = modules.iter().map(|(n, _, c)| (*n, *c)).collect();
    let project =
        "ID=\"{0}\"\r\nDocument=ThisDocument/&H00000000\r\nModule=Module1\r\nName=\"Evil\"\r\n";
    cfb.create_stream(format!("{parent}/PROJECT"))
        .unwrap()
        .write_all(project.as_bytes())
        .unwrap();
    cfb.create_stream(format!("{vba_dir}/dir"))
        .unwrap()
        .write_all(&ovba_compress(&dir_stream("Evil", &names)))
        .unwrap();
    for (name, source, _) in modules {
        let mut stream = vec![0u8; 6];
        stream.extend(ovba_compress(source.as_bytes()));
        cfb.create_stream(format!("{vba_dir}/{name}"))
            .unwrap()
            .write_all(&stream)
            .unwrap();
    }
    cfb.flush().unwrap();
    cfb.into_inner().into_inner()
}

const MACRO: &str = "Attribute VB_Name = \"ThisDocument\"\r\nSub AutoOpen()\r\n  ' AutoClose is only mentioned here\r\n  Set sh = CreateObject(\"WScript.Shell\")\r\n  sh.Run \"powershell -nop\"\r\nEnd Sub\r\n";

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn decompress_matches_a_hand_made_vector_with_a_copy_token() {
    assert_eq!(
        ovba_decompress(&[0x01, 0x05, 0xB0, 0x08, 0x61, 0x62, 0x63, 0x03, 0x20]).unwrap(),
        b"abcabcabc"
    );
    assert!(ovba_decompress(&[0x02, 0x00]).is_none());
    let big = MACRO.repeat(200);
    assert_eq!(
        ovba_decompress(&ovba_compress(big.as_bytes())).unwrap(),
        big.as_bytes()
    );
}

#[test]
fn ole_without_a_vba_project_has_no_macros() {
    let dir = TempDir::new().unwrap();
    let mut cfb = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    cfb.create_stream("/WordDocument")
        .unwrap()
        .write_all(b"text")
        .unwrap();
    cfb.flush().unwrap();
    let path = write(&dir, "plain.doc", &cfb.into_inner().into_inner());
    let analysis = analyze_ole_vba(&path).unwrap();
    assert!(!analysis.suspicious_indicators.has_macros);
    assert!(analysis.vba_project.is_none());
    assert!(analysis.macros.is_empty());
    assert!(analysis.security_assessment.risk_factors.is_empty());
}

#[test]
fn vba_storage_under_macros_is_found_and_decompressed() {
    let dir = TempDir::new().unwrap();
    let bytes = vba_compound(
        "/Macros/VBA",
        &[
            ("ThisDocument", MACRO, true),
            ("Module1", "Sub Hello()\r\nEnd Sub\r\n", false),
        ],
    );
    let report = analyze_office(&write(&dir, "word.doc", &bytes)).unwrap();
    assert_eq!(report.container, "ole2");
    assert_eq!(report.vba_storages, vec!["/Macros/VBA".to_string()]);
    assert_eq!(report.module_source.as_deref(), Some("dir stream"));
    let analysis = &report.analysis;
    assert!(analysis.suspicious_indicators.has_macros);
    let project = analysis.vba_project.as_ref().unwrap();
    assert_eq!(project.project_name, "Evil");
    assert_eq!(project.modules.len(), 2);
    let this = &project.modules[0];
    assert_eq!(this.name, "ThisDocument");
    assert!(matches!(this.module_type, VbaModuleType::Document));
    assert!(this
        .source_code
        .as_deref()
        .unwrap()
        .contains("CreateObject"));
    assert_eq!(project.references.len(), 1);
    assert_eq!(project.references[0].name, "stdole");
    // Auto-exec: the declaration counts, the comment mentioning AutoClose does not.
    assert_eq!(
        analysis.suspicious_indicators.auto_exec_macros,
        vec!["ThisDocument:AutoOpen".to_string()]
    );
    assert!(analysis.macros[0]
        .suspicious_patterns
        .iter()
        .any(|p| p.contains("wscript.shell")));
    assert!(matches!(
        analysis.security_assessment.overall_risk,
        file_scanner::ole_vba_analysis::RiskLevel::High
            | file_scanner::ole_vba_analysis::RiskLevel::Critical
    ));
}

#[test]
fn vba_storage_in_other_places_is_found() {
    let dir = TempDir::new().unwrap();
    for location in ["/VBA", "/_VBA_PROJECT_CUR/VBA"] {
        let bytes = vba_compound(
            location,
            &[("Module1", "Sub Auto_Open()\r\nEnd Sub\r\n", false)],
        );
        let analysis = analyze_ole_vba(&write(&dir, "x.xls", &bytes)).unwrap();
        assert!(analysis.suspicious_indicators.has_macros, "{location}");
        assert_eq!(
            analysis.suspicious_indicators.auto_exec_macros,
            vec!["Module1:Auto_Open".to_string()]
        );
    }
}

#[test]
fn ooxml_with_vbaproject_bin_is_analyzed() {
    let dir = TempDir::new().unwrap();
    let vba = vba_compound("/VBA", &[("ThisDocument", MACRO, true)]);
    let path = dir.path().join("evil.docm");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("[Content_Types].xml", options).unwrap();
    zip.write_all(&vec![b' '; 600]).unwrap();
    zip.start_file("word/vbaProject.bin", options).unwrap();
    zip.write_all(&vba).unwrap();
    zip.finish().unwrap();

    let report = analyze_office(&path).unwrap();
    assert_eq!(report.container, "ooxml");
    assert_eq!(report.vba_part.as_deref(), Some("word/vbaProject.bin"));
    assert!(matches!(
        report.analysis.file_type,
        OleFileType::OfficeOpenXml
    ));
    assert!(report.analysis.suspicious_indicators.has_macros);
    assert_eq!(
        report.analysis.suspicious_indicators.auto_exec_macros,
        vec!["ThisDocument:AutoOpen".to_string()]
    );
}

#[test]
fn ooxml_without_macros_and_plain_zip_are_distinguished() {
    let dir = TempDir::new().unwrap();
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let make = |name: &str, with_types: bool| {
        let path = dir.path().join(name);
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        if with_types {
            zip.start_file("[Content_Types].xml", options).unwrap();
            zip.write_all(&vec![b' '; 700]).unwrap();
        }
        zip.start_file("word/document.xml", options).unwrap();
        zip.write_all(&vec![b' '; 700]).unwrap();
        zip.finish().unwrap();
        path
    };
    let docx = analyze_office(&make("a.docx", true)).unwrap();
    assert!(matches!(
        docx.analysis.file_type,
        OleFileType::OfficeOpenXml
    ));
    assert!(!docx.analysis.suspicious_indicators.has_macros);
    assert!(docx.notes.iter().any(|n| n.contains("no vbaProject.bin")));
    let zipped = analyze_office(&make("b.zip", false)).unwrap();
    assert!(matches!(zipped.analysis.file_type, OleFileType::NotOleFile));
}

#[test]
fn a_vba_storage_without_a_readable_dir_stream_still_counts_as_macros() {
    let dir = TempDir::new().unwrap();
    let mut cfb = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    cfb.create_storage("/VBA").unwrap();
    cfb.create_stream("/VBA/dir")
        .unwrap()
        .write_all(b"garbage")
        .unwrap();
    cfb.create_stream("/VBA/Module1")
        .unwrap()
        .write_all(&[1, 2, 3])
        .unwrap();
    cfb.flush().unwrap();
    let report = analyze_office(&write(&dir, "odd.doc", &cfb.into_inner().into_inner())).unwrap();
    assert!(report.analysis.suspicious_indicators.has_macros);
    assert_eq!(report.module_source.as_deref(), Some("stream names"));
    assert_eq!(report.undecoded_modules, vec!["Module1".to_string()]);
}

#[test]
fn auto_exec_needs_a_declaration() {
    let source = "' Sub AutoOpen()\r\nx = \"Document_Open\"\r\nPrivate Sub Document_Open()\r\nEnd Sub\r\nPublic Function Workbook_Open()\r\n";
    let found = detect_auto_exec_entries(source, "M");
    let names: Vec<(&str, usize)> = found
        .iter()
        .map(|e| (e.procedure.as_str(), e.line))
        .collect();
    assert_eq!(names, vec![("Document_Open", 3), ("Workbook_Open", 5)]);
}

/// A compound file whose `dir` names `count` modules that all point at one stream.
fn shared_stream_compound(count: usize, source: &[u8]) -> Vec<u8> {
    let mut cfb = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    cfb.create_stream("/WordDocument")
        .unwrap()
        .write_all(b"d")
        .unwrap();
    cfb.create_storage("/Macros").unwrap();
    cfb.create_storage("/Macros/VBA").unwrap();
    let names: Vec<String> = (0..count).map(|i| format!("M{i}")).collect();
    let modules: Vec<(&str, bool)> = names.iter().map(|n| (n.as_str(), false)).collect();
    cfb.create_stream("/Macros/VBA/dir")
        .unwrap()
        .write_all(&ovba_compress(&dir_stream_with(
            "P",
            &modules,
            Some("Shared"),
        )))
        .unwrap();
    let mut stream = vec![0u8; 6];
    stream.extend(ovba_compress(source));
    cfb.create_stream("/Macros/VBA/Shared")
        .unwrap()
        .write_all(&stream)
        .unwrap();
    cfb.flush().unwrap();
    cfb.into_inner().into_inner()
}

#[test]
fn a_dir_that_reuses_one_big_stream_is_cut_off_by_the_work_budget() {
    let dir = TempDir::new().unwrap();
    let source = "Shell\n".repeat(100_000);
    let path = write(
        &dir,
        "shared.doc",
        &shared_stream_compound(300, source.as_bytes()),
    );
    let started = std::time::Instant::now();
    let report = analyze_office(&path).unwrap();
    assert!(started.elapsed().as_secs() < 20);
    let project = report.analysis.vba_project.unwrap();
    let decoded = project
        .modules
        .iter()
        .filter(|m| m.source_code.is_some())
        .count();
    assert!(decoded > 0 && decoded < 30, "{decoded}");
    assert!(report.undecoded_modules.len() > 250);
    assert!(
        report.notes.iter().any(|n| n.contains("Reading stopped")),
        "{:?}",
        report.notes
    );
    assert!(report.analysis.suspicious_indicators.has_macros);
}

#[test]
fn the_module_count_is_capped() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "many.doc",
        &shared_stream_compound(1500, b"Sub AutoOpen()\nEnd Sub\n"),
    );
    let report = analyze_office(&path).unwrap();
    assert_eq!(report.analysis.vba_project.unwrap().modules.len(), 1000);
    assert!(report
        .notes
        .iter()
        .any(|n| n.contains("more than 1000 modules")));
    assert!(report.analysis.suspicious_indicators.auto_exec_macros.len() <= 500);
    let factor = &report.analysis.security_assessment.risk_factors[1].description;
    assert!(factor.len() < 300, "{factor}");
}

#[test]
fn keywords_match_whole_words_and_urls_are_reported() {
    use file_scanner::ole_vba_analysis::{detect_external_connections, vba_keyword_hits};
    let hits = vba_keyword_hits("sh.Run \"powershell -enc AAAA\", 0\nx = Environment.Name\nSet s = CreateObject(\"WScript.Shell\")\n", "M");
    let words: Vec<&str> = hits.iter().map(|h| h.keyword.as_str()).collect();
    assert!(words.contains(&"powershell"), "{words:?}");
    assert!(
        !words.contains(&"shell") || hits.iter().any(|h| h.line == 3),
        "{hits:?}"
    );
    assert!(!hits.iter().any(|h| h.keyword == "environ"), "{hits:?}");
    assert!(
        !hits.iter().any(|h| h.keyword == "shell" && h.line == 1),
        "{hits:?}"
    );
    let conns = detect_external_connections("x = 1\nURL = \"http://evil.test/a.exe\"\n", "M");
    assert_eq!(conns[0].target, "http://evil.test/a.exe");
}

#[test]
fn encrypted_packages_unreadable_projects_and_tiny_files_are_reported() {
    let dir = TempDir::new().unwrap();
    let mut cfb = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    cfb.create_stream("/EncryptionInfo")
        .unwrap()
        .write_all(b"x")
        .unwrap();
    cfb.create_stream("/EncryptedPackage")
        .unwrap()
        .write_all(b"x")
        .unwrap();
    cfb.flush().unwrap();
    let path = write(&dir, "enc.docm", &cfb.into_inner().into_inner());
    let report = analyze_office(&path).unwrap();
    assert!(report
        .notes
        .iter()
        .any(|n| n.contains("password-protected")));
    assert!(!matches!(
        report.analysis.security_assessment.overall_risk,
        file_scanner::ole_vba_analysis::RiskLevel::Low
    ));

    // A VBA storage with no dir stream: macros exist but cannot be read, so not "low".
    let mut cfb = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    cfb.create_stream("/WordDocument")
        .unwrap()
        .write_all(b"d")
        .unwrap();
    cfb.create_storage("/Macros").unwrap();
    cfb.create_storage("/Macros/VBA").unwrap();
    cfb.create_stream("/Macros/VBA/Module1")
        .unwrap()
        .write_all(b"\x01\x02")
        .unwrap();
    cfb.flush().unwrap();
    let path = write(&dir, "unreadable.doc", &cfb.into_inner().into_inner());
    let report = analyze_office(&path).unwrap();
    assert!(report.analysis.suspicious_indicators.has_macros);
    assert!(!matches!(
        report.analysis.security_assessment.overall_risk,
        file_scanner::ole_vba_analysis::RiskLevel::Low
    ));

    // Short files starting with the signatures give a usable answer, not a read error.
    let short_ole = write(
        &dir,
        "short.doc",
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1 not a real file",
    );
    let error = format!("{:#}", analyze_office(&short_ole).unwrap_err());
    assert!(!error.contains("fill whole buffer"), "{error}");
    assert!(error.contains("analyze_file"), "{error}");
    let tiny = write(
        &dir,
        "tiny.zip",
        b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    );
    let report = analyze_office(&tiny).unwrap();
    assert!(!report.analysis.suspicious_indicators.has_macros);
}

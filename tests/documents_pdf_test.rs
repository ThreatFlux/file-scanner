//! Structural PDF scan (CF12): small benign PDFs built in the test.

use std::io::Write;

use file_scanner::pdf_analysis::RiskLevel;
use file_scanner::pdf_analysis::{analyze_pdf, scan_pdf, PdfScan};
use flate2::{write::ZlibEncoder, Compression};
use tempfile::TempDir;

fn write_pdf(dir: &TempDir, name: &str, body: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, body).unwrap();
    path
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn feature<'a>(
    scan: &'a PdfScan,
    name: &str,
) -> Option<&'a file_scanner::pdf_analysis::PdfFeature> {
    scan.features.iter().find(|f| f.name == name)
}

const BENIGN: &[u8] = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>\nendobj\n\
3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n\
4 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n\
5 0 obj\n<< /Producer (Test Maker) /Title (Hello) >>\nendobj\n\
xref\n0 6\ntrailer\n<< /Root 1 0 R /Info 5 0 R >>\nstartxref\n0\n%%EOF\n";

#[test]
fn version_pages_objects_and_info_come_from_the_file() {
    let dir = TempDir::new().unwrap();
    let path = write_pdf(&dir, "benign.pdf", BENIGN);
    let scan = scan_pdf(&path).unwrap();
    assert_eq!(scan.version, "1.7");
    assert_eq!(scan.page_count, 2);
    assert_eq!(scan.object_count, 5);
    assert_eq!(scan.xref_sections, 1);
    assert_eq!(
        scan.info.get("Producer").map(String::as_str),
        Some("Test Maker")
    );
    assert_eq!(scan.risk_score, 0);
    assert!(matches!(scan.overall_risk, RiskLevel::Low));

    // The legacy report carries the same facts, not constants.
    let analysis = analyze_pdf(&path).unwrap();
    assert_eq!(analysis.document_info.version, "1.7");
    assert_eq!(analysis.document_info.page_count, 2);
    assert_eq!(
        analysis.document_info.producer.as_deref(),
        Some("Test Maker")
    );
}

#[test]
fn open_action_javascript_uri_and_acroform_are_found_with_offsets() {
    let pdf = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R /AcroForm << /Fields [] >> >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n\
3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [6 0 R] >>\nendobj\n\
5 0 obj\n<< /S /JavaScript /JS (app.alert\\('hi'\\); eval\\(x\\);) >>\nendobj\n\
6 0 obj\n<< /Type /Annot /Subtype /Link /A << /S /URI /URI (http://example.test/x) >> >>\nendobj\n\
trailer\n<< /Root 1 0 R >>\n%%EOF\n";
    let dir = TempDir::new().unwrap();
    let path = write_pdf(&dir, "js.pdf", pdf);
    let scan = scan_pdf(&path).unwrap();

    let open = feature(&scan, "OpenAction").expect("OpenAction found");
    assert_eq!(open.count, 1);
    let at = open.evidence[0].offset as usize;
    assert_eq!(
        &pdf[at + 1..at + 11],
        b"OpenAction",
        "offset points at the name"
    );
    assert!(feature(&scan, "JavaScript").is_some());
    assert!(feature(&scan, "JS").is_some());
    assert!(feature(&scan, "AcroForm").is_some());
    assert_eq!(scan.open_action_type.as_deref(), Some("action"));
    assert_eq!(scan.scripts.len(), 1);
    assert!(scan.scripts[0].preview.contains("app.alert('hi')"));
    assert!(scan.scripts[0]
        .suspicious_patterns
        .contains(&"eval".to_string()));
    assert_eq!(scan.targets.len(), 1);
    assert_eq!(scan.targets[0].value, "http://example.test/x");
    assert!(scan.risk_score >= 60, "{}", scan.risk_score);
    assert!(matches!(scan.overall_risk, RiskLevel::Critical));
    assert_eq!(scan.page_count, 1);
}

#[test]
fn hex_escaped_names_are_decoded_and_flagged() {
    let pdf = b"%PDF-1.4\n1 0 obj\n<< /S /J#61vaScript /J#53 (app.alert\\(1\\)) /Open#41ction 1 0 R >>\nendobj\n";
    let dir = TempDir::new().unwrap();
    let scan = scan_pdf(write_pdf(&dir, "esc.pdf", pdf)).unwrap();
    assert!(
        feature(&scan, "JavaScript").is_some(),
        "{:?}",
        scan.features
    );
    assert!(feature(&scan, "JS").is_some());
    assert!(feature(&scan, "OpenAction").is_some());
    assert!(scan.escaped_names.contains(&"/JavaScript".to_string()));
    assert!(scan.risk_reasons.iter().any(|r| r.contains("#xx")));
    // Escapes in ordinary names (font names) are not an alarm.
    let font = b"%PDF-1.4\n1 0 obj\n<< /BaseFont /Arial#20Black >>\nendobj\n";
    let scan = scan_pdf(write_pdf(&dir, "font.pdf", font)).unwrap();
    assert!(scan.escaped_names.is_empty());
}

#[test]
fn features_inside_a_flate_object_stream_are_found() {
    let hidden = b"<< /S /Launch /Win << /F (cmd.exe) /P (/c calc.exe) >> >> << /Type /Action /S /URI /URI (http://evil.test/) >>";
    let compressed = zlib(hidden);
    let mut pdf =
        b"%PDF-1.5\n7 0 obj\n<< /Type /ObjStm /N 2 /First 0 /Filter /FlateDecode /Length ".to_vec();
    pdf.extend_from_slice(compressed.len().to_string().as_bytes());
    pdf.extend_from_slice(b" >>\nstream\n");
    pdf.extend_from_slice(&compressed);
    pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n");
    let dir = TempDir::new().unwrap();
    let scan = scan_pdf(write_pdf(&dir, "objstm.pdf", &pdf)).unwrap();
    let launch = feature(&scan, "Launch").expect("Launch inside the object stream");
    assert!(launch.evidence[0].in_stream);
    assert_eq!(launch.evidence[0].object, Some(7));
    assert!(feature(&scan, "ObjStm").is_some());
    assert_eq!(scan.object_streams.len(), 1);
    let launch_target = scan.targets.iter().find(|t| t.kind == "Launch").unwrap();
    assert!(launch_target.value.contains("cmd.exe"), "{launch_target:?}");
    assert!(launch_target.value.contains("calc.exe"));
    assert!(scan.targets.iter().any(|t| t.value == "http://evil.test/"));
    assert!(matches!(
        scan.overall_risk,
        RiskLevel::High | RiskLevel::Critical
    ));
}

#[test]
fn javascript_in_a_referenced_compressed_stream_is_read() {
    let js = zlib(b"this.exportDataObject({cName:'a'}); unescape('%u9090');");
    let mut pdf = b"%PDF-1.6\n1 0 obj\n<< /S /JavaScript /JS 4 0 R >>\nendobj\n4 0 obj\n<< /Filter /FlateDecode /Length 0 >>\nstream\n".to_vec();
    pdf.extend_from_slice(&js);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");
    let dir = TempDir::new().unwrap();
    let scan = scan_pdf(write_pdf(&dir, "refjs.pdf", &pdf)).unwrap();
    assert_eq!(scan.scripts.len(), 1);
    assert!(scan.scripts[0].preview.contains("exportDataObject"));
    assert!(scan.scripts[0]
        .suspicious_patterns
        .contains(&"exportDataObject".to_string()));
}

#[test]
fn encryption_embedded_files_and_signatures_are_reported() {
    let pdf = b"%PDF-1.6\n\
1 0 obj\n<< /Type /Catalog /Names << /EmbeddedFiles 2 0 R >> >>\nendobj\n\
3 0 obj\n<< /Type /Filespec /F (invoice.exe) /UF (invoice.exe) /EF << /F 4 0 R >> >>\nendobj\n\
4 0 obj\n<< /Type /EmbeddedFile /Length 5 >>\nstream\nMZ123\nendstream\nendobj\n\
6 0 obj\n<< /Type /Sig /ByteRange [0 10 20 30] >>\nendobj\n\
7 0 obj\n<< /Filter /Standard /V 2 /R 3 /Length 128 /O (abc) /U (def) >>\nendobj\n\
trailer\n<< /Root 1 0 R /Encrypt 7 0 R >>\n";
    let dir = TempDir::new().unwrap();
    let scan = scan_pdf(write_pdf(&dir, "mixed.pdf", pdf)).unwrap();
    assert!(scan.is_encrypted);
    let encryption = scan.encryption.as_ref().unwrap();
    assert_eq!(encryption.key_length, 128);
    assert_eq!(encryption.revision, 3);
    assert!(encryption.is_owner_password_set && encryption.is_user_password_set);
    assert!(scan.is_signed);
    assert_eq!(scan.attachments.len(), 1, "{:?}", scan.attachments);
    assert_eq!(scan.attachments[0].filename.as_deref(), Some("invoice.exe"));
    assert_eq!(scan.attachments[0].size, Some(5));
    assert!(scan.notes.iter().any(|n| n.contains("encrypted")));
}

#[test]
fn names_inside_strings_and_comments_do_not_count() {
    let pdf = b"%PDF-1.4\n% /JavaScript in a comment\n1 0 obj\n<< /Title (about /JavaScript and /Launch) >>\nendobj\n";
    let dir = TempDir::new().unwrap();
    let scan = scan_pdf(write_pdf(&dir, "text.pdf", pdf)).unwrap();
    assert!(scan.features.is_empty(), "{:?}", scan.features);
    assert_eq!(scan.risk_score, 0);
}

#[test]
fn junk_before_the_header_and_non_pdf_input() {
    let dir = TempDir::new().unwrap();
    let mut pdf = b"junkjunk".to_vec();
    pdf.extend_from_slice(BENIGN);
    let scan = scan_pdf(write_pdf(&dir, "junk.pdf", &pdf)).unwrap();
    assert_eq!(scan.header_offset, 8);
    assert!(scan.notes.iter().any(|n| n.contains("precede")));

    let error = scan_pdf(write_pdf(&dir, "no.pdf", b"hello world")).unwrap_err();
    assert!(
        format!("{error:#}").contains("Not a valid PDF"),
        "{error:#}"
    );
    assert!(scan_pdf(write_pdf(&dir, "empty.pdf", b"")).is_err());
}

#[test]
fn a_garbage_stream_and_unbalanced_parenthesis_do_not_hang_or_panic() {
    let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n".to_vec();
    pdf.extend(std::iter::repeat_n(0xAB_u8, 4096));
    pdf.extend_from_slice(b"\nendstream\nendobj\n2 0 obj\n<< /Title (never closed /JavaScript\n");
    let dir = TempDir::new().unwrap();
    let scan = scan_pdf(write_pdf(&dir, "bad.pdf", &pdf)).unwrap();
    assert_eq!(scan.stream_count, 1);
}

fn timed<T>(limit_secs: u64, work: impl FnOnce() -> T) -> T {
    let started = std::time::Instant::now();
    let out = work();
    assert!(
        started.elapsed().as_secs() < limit_secs,
        "took {:?}",
        started.elapsed()
    );
    out
}

#[test]
fn many_unterminated_strings_cost_a_bounded_amount_of_work() {
    let dir = TempDir::new().unwrap();
    let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (x) >> >>\nendobj\n2 0 obj\n".to_vec();
    pdf.extend(std::iter::repeat_n(b'(', 100_000));
    pdf.extend_from_slice(b"\nendobj\n");
    let path = write_pdf(&dir, "parens.pdf", &pdf);
    let scan = timed(5, || scan_pdf(&path).unwrap());
    assert_eq!(feature(&scan, "OpenAction").unwrap().count, 1);
    // The same shape inside a Flate stream.
    let mut body = b"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n".to_vec();
    body.extend(zlib(&vec![b'('; 2_000_000]));
    body.extend_from_slice(b"\nendstream\nendobj\n");
    let path = write_pdf(&dir, "parens_flate.pdf", &body);
    let scan = timed(5, || scan_pdf(&path).unwrap());
    assert_eq!(scan.stream_count, 1);
}

#[test]
fn many_references_to_one_script_stream_resolve_it_once() {
    let dir = TempDir::new().unwrap();
    let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n".to_vec();
    pdf.extend(zlib(&b"app.alert(1);".repeat(300_000)));
    pdf.extend_from_slice(b"\nendstream\nendobj\n2 0 obj\n<<");
    for _ in 0..3000 {
        pdf.extend_from_slice(b" /JS 1 0 R");
    }
    pdf.extend_from_slice(b" >>\nendobj\ntrailer\n<< >>\n");
    let path = write_pdf(&dir, "jsrefs.pdf", &pdf);
    let scan = timed(5, || scan_pdf(&path).unwrap());
    assert_eq!(scan.scripts.len(), 1);
    assert_eq!(scan.scripts_total, 3000);
    assert!(scan.notes.iter().any(|n| n.contains("3000 script")));
}

#[test]
fn many_launch_names_do_not_rescan_the_object() {
    let dir = TempDir::new().unwrap();
    let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /S /Launch /F (calc.exe) ".to_vec();
    for _ in 0..20_000 {
        pdf.extend_from_slice(b"/Launch /SubmitForm ");
    }
    pdf.extend_from_slice(b">>\nendobj\ntrailer\n<< >>\n");
    let path = write_pdf(&dir, "launch.pdf", &pdf);
    let scan = timed(5, || scan_pdf(&path).unwrap());
    assert_eq!(scan.targets.len(), 200);
    assert!(scan.action_targets_total > 30_000);
    assert!(scan.notes.iter().any(|n| n.contains("only the first 200")));
    assert!(scan.targets[0].value.contains("calc.exe"));
}

#[test]
fn a_stray_stream_keyword_does_not_hide_the_document() {
    let dir = TempDir::new().unwrap();
    let pdf = b"%PDF-1.4\nstream\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 4 >>\nstream\nq Q\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
    let scan = scan_pdf(write_pdf(&dir, "stray.pdf", pdf)).unwrap();
    assert_eq!(scan.object_count, 4);
    assert_eq!(scan.page_count, 1);
    assert_eq!(scan.stream_count, 1);
    assert_eq!(feature(&scan, "OpenAction").unwrap().count, 1);
    assert_eq!(scan.scripts.len(), 1);
    assert!(matches!(scan.overall_risk, RiskLevel::Critical));
    // A stream with no endstream is noted.
    let open = b"%PDF-1.4\n1 0 obj\n<< /Length 3 >>\nstream\nabc\n";
    let scan = scan_pdf(write_pdf(&dir, "open.pdf", open)).unwrap();
    assert!(scan.notes.iter().any(|n| n.contains("no endstream")));
}

#[test]
fn a_uri_action_counts_once_and_empty_or_unfinished_files_are_noted() {
    let dir = TempDir::new().unwrap();
    let mut pdf = b"%PDF-1.4\n1 0 obj\n<<".to_vec();
    for _ in 0..50 {
        pdf.extend_from_slice(b" /A << /S /URI /URI (http://e.test/) >>");
    }
    pdf.extend_from_slice(b" >>\nendobj\ntrailer\n<< >>\n");
    let scan = scan_pdf(write_pdf(&dir, "links.pdf", &pdf)).unwrap();
    assert_eq!(feature(&scan, "URI").unwrap().count, 50);
    assert_eq!(scan.links_total, 50);
    let scan = scan_pdf(write_pdf(&dir, "header_only.pdf", b"%PDF-")).unwrap();
    assert!(scan.notes.iter().any(|n| n.contains("No objects")));
    let scan = scan_pdf(write_pdf(
        &dir,
        "no_trailer.pdf",
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n",
    ))
    .unwrap();
    assert!(scan.notes.iter().any(|n| n.contains("No xref")));
}

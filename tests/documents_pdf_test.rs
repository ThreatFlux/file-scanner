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

/// A whole document placed inside the unfiltered stream of a dummy object; the xref table
/// points into the stream, as poppler follows it.
fn hidden_in_stream(endstream: bool, with_xref: bool) -> Vec<u8> {
    hidden_in_dict_stream("<< /Length 0 >>", endstream, with_xref)
}

fn hidden_in_dict_stream(dict: &str, endstream: bool, with_xref: bool) -> Vec<u8> {
    let mut out = format!("%PDF-1.7\n9 0 obj\n{dict}\nstream\n").into_bytes();
    let mut offsets = Vec::new();
    let objects: [&[u8]; 5] = [
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>",
        b"<< /Type /Action /S /JavaScript /JS (app.alert\\('hidden'\\); this.exportDataObject\\({cName:'x', nLaunch:2}\\);) >>",
        b"<< /Type /Action /S /Launch /F (cmd.exe) >>",
    ];
    for (index, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    if endstream {
        out.extend_from_slice(b"\nendstream\nendobj\n");
    }
    if with_xref {
        let xref = out.len();
        out.extend_from_slice(b"xref\n0 6\n0000000000 65535 f \n");
        for offset in offsets {
            out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!("trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
        );
    }
    out
}

#[test]
fn objects_hidden_in_a_dummy_stream_are_found_and_noted() {
    let dir = TempDir::new().unwrap();
    for (name, endstream, with_xref) in [
        ("h1.pdf", true, true),
        ("h2.pdf", false, true),
        ("h3.pdf", true, false),
        ("h4.pdf", false, false),
    ] {
        let pdf = hidden_in_stream(endstream, with_xref);
        let scan = scan_pdf(write_pdf(&dir, name, &pdf)).unwrap();
        assert_eq!(
            feature(&scan, "OpenAction").map(|f| f.count),
            Some(1),
            "{name}"
        );
        assert_eq!(feature(&scan, "Launch").map(|f| f.count), Some(1), "{name}");
        assert_eq!(scan.scripts.len(), 1, "{name}");
        assert_eq!(scan.page_count, 1, "{name}");
        assert!(
            scan.notes
                .iter()
                .any(|n| n.contains("stream data hold PDF objects")),
            "{name}: {:?}",
            scan.notes
        );
        assert!(
            matches!(scan.overall_risk, RiskLevel::Critical),
            "{name}: {:?} {}",
            scan.overall_risk,
            scan.risk_score
        );
        // Evidence offsets still point at the name in the file.
        let at = feature(&scan, "OpenAction").unwrap().evidence[0].offset as usize;
        assert_eq!(&pdf[at + 1..at + 11], b"OpenAction", "{name}");
    }
}

#[test]
fn a_disguised_dummy_stream_without_a_classic_xref_is_still_read() {
    // The cross-reference data is a stream or missing, so only a rebuild-style read finds the
    // document; the dummy stream calls itself an image, a font, a hex-filtered or a
    // Flate-filtered stream.
    let dir = TempDir::new().unwrap();
    for (name, dict) in [
        (
            "image",
            "<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /Length 0 >>",
        ),
        ("font", "<< /Length1 5 /Length 0 >>"),
        ("hex", "<< /Filter /ASCIIHexDecode /Length 0 >>"),
        ("flate", "<< /Filter /FlateDecode /Length 0 >>"),
        ("plain", "<< /Length 0 >>"),
    ] {
        for xref_stream in [false, true] {
            let mut pdf = hidden_in_dict_stream(dict, true, false);
            if name == "flate" {
                // Data that inflates to something small ahead of the objects.
                let at = pdf.windows(7).position(|w| w == b"stream\n").unwrap() + 7;
                let mut packed = zlib(b"x");
                packed.push(b'\n');
                pdf.splice(at..at, packed);
            }
            if xref_stream {
                pdf.extend_from_slice(
                    b"20 0 obj\n<< /Type /XRef /Size 21 /W [1 2 1] /Root 1 0 R /Length 0 >>\nstream\n\nendstream\nendobj\nstartxref\n0\n%%EOF\n",
                );
            } else {
                pdf.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
            }
            let label = format!("{name} xref_stream={xref_stream}");
            let scan = scan_pdf(write_pdf(&dir, "disguised.pdf", &pdf)).unwrap();
            assert_eq!(
                feature(&scan, "OpenAction").map(|f| f.count),
                Some(1),
                "{label}"
            );
            assert_eq!(scan.scripts.len(), 1, "{label}");
            assert!(
                matches!(scan.overall_risk, RiskLevel::Critical),
                "{label}: {:?} {}",
                scan.overall_risk,
                scan.risk_score
            );
        }
    }
}

#[test]
fn objects_inside_a_balanced_string_are_read_with_and_without_an_xref() {
    let mut out =
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 5 0 R /OpenAction 3 0 R /X (".to_vec();
    let mut offsets = vec![9usize];
    for (n, body) in [
        (2, "<< /Type /Pages /Kids [] /Count 0 >>"),
        (3, "<< /Type /Action /S /Launch /F (cmd.exe) >>"),
    ] {
        offsets.push(out.len());
        out.extend_from_slice(format!("{n} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    out.extend_from_slice(b") >>\nendobj\n");
    let mut with_xref = out.clone();
    let xref = with_xref.len();
    with_xref.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
    for offset in &offsets {
        with_xref.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    with_xref.extend_from_slice(
        format!("trailer\n<< /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    out.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    let dir = TempDir::new().unwrap();
    for (name, pdf) in [("xref.pdf", &with_xref), ("none.pdf", &out)] {
        let scan = scan_pdf(write_pdf(&dir, name, pdf)).unwrap();
        assert_eq!(feature(&scan, "Launch").map(|f| f.count), Some(1), "{name}");
        assert!(
            scan.notes
                .iter()
                .any(|n| n.contains("were missed by the first read")),
            "{name}: {:?}",
            scan.notes
        );
        assert!(
            !matches!(scan.overall_risk, RiskLevel::Low),
            "{name}: {}",
            scan.risk_score
        );
    }
}

#[test]
fn a_stray_classic_xref_entry_does_not_stop_the_whole_file_search() {
    // The hidden objects sit inside a balanced string; the only classic table is one free
    // entry (or lists only the dummy object), so it never leads to them.
    let mut base = b"%PDF-1.7\n9 0 obj\n<< /X (".to_vec();
    base.extend_from_slice(
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n\
          2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n\
          3 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj\n",
    );
    base.extend_from_slice(b") >>\nendobj\n");
    let free = b"xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 6 /Root 1 0 R >>\n";
    let dummy = b"xref\n9 1\n0000000009 00000 n \ntrailer\n<< /Size 10 >>\n";
    let dir = TempDir::new().unwrap();
    for (name, tail) in [("free.pdf", &free[..]), ("dummy.pdf", &dummy[..])] {
        let mut pdf = base.clone();
        pdf.extend_from_slice(tail);
        let scan = scan_pdf(write_pdf(&dir, name, &pdf)).unwrap();
        assert_eq!(feature(&scan, "Launch").map(|f| f.count), Some(1), "{name}");
        assert!(!matches!(scan.overall_risk, RiskLevel::Low), "{name}");
    }
}

#[test]
fn a_long_digit_or_space_run_before_obj_costs_linear_work() {
    let dir = TempDir::new().unwrap();
    let mut digits = b"%PDF-1.4\n".to_vec();
    digits.extend(std::iter::repeat_n(b'1', 400_000));
    digits.extend_from_slice(b" 0 obj\n<<>>\nendobj\n");
    let mut spaces = b"%PDF-1.4\n".to_vec();
    spaces.extend(std::iter::repeat_n(b'1', 100_000));
    spaces.extend_from_slice(b" 0");
    spaces.extend(std::iter::repeat_n(b' ', 100_000));
    spaces.extend_from_slice(b"obj\n<<>>\nendobj\n");
    for (name, pdf) in [("digits.pdf", digits), ("spaces.pdf", spaces)] {
        let path = write_pdf(&dir, name, &pdf);
        timed(10, || scan_pdf(path).unwrap());
    }
}

/// Hidden objects with the object header written in a way a reader accepts.
fn hidden_with_header(header: &str, tail: &[u8]) -> Vec<u8> {
    let mut pdf = b"%PDF-1.7\n9 0 obj\n<< /X (".to_vec();
    pdf.extend_from_slice(header.as_bytes());
    pdf.extend_from_slice(
        b"\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n\
          2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n\
          3 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj\n",
    );
    pdf.extend_from_slice(b") >>\nendobj\n");
    pdf.extend_from_slice(tail);
    pdf
}

#[test]
fn unusual_but_valid_object_headers_do_not_hide_the_document() {
    let free = b"xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 6 >>\n";
    let headers = [
        format!("1 0{}obj", " ".repeat(17)),
        format!("1 0{}obj", " ".repeat(5000)),
        format!("1{}0 obj", " ".repeat(20)),
        format!("1\t0{}obj", "\t".repeat(40)),
        "000000000001 0 obj".to_string(),
        "1 000000 obj".to_string(),
    ];
    let dir = TempDir::new().unwrap();
    for (i, header) in headers.iter().enumerate() {
        for (shape, tail) in [("free", &free[..]), ("none", &b""[..])] {
            let pdf = hidden_with_header(header, tail);
            let scan = scan_pdf(write_pdf(&dir, &format!("h{i}{shape}.pdf"), &pdf)).unwrap();
            assert_eq!(
                feature(&scan, "Launch").map(|f| f.count),
                Some(1),
                "header {i} {shape}"
            );
            assert!(!matches!(scan.overall_risk, RiskLevel::Low), "{i} {shape}");
        }
    }
    // The same header inside the data of an image stream.
    let mut stream = b"%PDF-1.7\n9 0 obj\n<< /Subtype /Image /Length 400 >>\nstream\n".to_vec();
    stream.extend_from_slice(format!("1 0{}obj", " ".repeat(30)).as_bytes());
    stream.extend_from_slice(
        b"\n<< /Type /Catalog /OpenAction << /S /Launch /F (cmd.exe) >> >>\nendobj\n\
          \nendstream\nendobj\n",
    );
    let scan = scan_pdf(write_pdf(&dir, "image.pdf", &stream)).unwrap();
    assert_eq!(feature(&scan, "Launch").map(|f| f.count), Some(1));
}

#[test]
fn an_object_cut_by_the_single_object_window_is_read_in_a_window_of_its_own() {
    // A decoy header without `endobj`, then padding, then the real catalog so that its header
    // ends exactly at the end of the 1 MiB window of the decoy (and 40 bytes before it).
    let window = 1024 * 1024;
    let dir = TempDir::new().unwrap();
    for shift in [0usize, 40] {
        // The objects sit in the data of a Flate object stream that is only a dummy, which
        // the first read does not look into.
        let mut pdf =
            b"%PDF-1.7\n9 0 obj\n<< /Type /ObjStm /N 1 /First 5 /Filter /FlateDecode >>\nstream\n"
                .to_vec();
        pdf.extend_from_slice(&zlib(b"11 0 (decoy)"));
        pdf.push(b'\n');
        let decoy_at = pdf.len();
        pdf.extend_from_slice(b"7 0 obj\n<< /Decoy true >>\n");
        let header = b"1 0 obj";
        while pdf.len() < decoy_at + window - shift {
            pdf.extend_from_slice(b"x\n");
        }
        pdf.truncate(decoy_at + window - shift - header.len() - 1);
        pdf.push(b'\n');
        pdf.extend_from_slice(header);
        pdf.extend_from_slice(
            b"\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> \
              /AA << /WC << /S /Launch /F (cmd.exe) >> >> >>\nendobj\n",
        );
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        let scan = scan_pdf(write_pdf(&dir, &format!("edge{shift}.pdf"), &pdf)).unwrap();
        assert_eq!(
            feature(&scan, "Launch").map(|f| f.count),
            Some(1),
            "{shift}"
        );
        assert!(feature(&scan, "JavaScript").is_some(), "{shift}");
        assert!(!matches!(scan.overall_risk, RiskLevel::Low), "{shift}");
    }
}

#[test]
fn a_file_of_attachment_names_costs_a_bounded_amount_of_work() {
    let mut pdf = b"%PDF-1.7\n1 0 obj\n<< ".to_vec();
    for _ in 0..200_000 {
        pdf.extend_from_slice(b"/EF ");
    }
    pdf.extend_from_slice(b">>\nendobj\n");
    let dir = TempDir::new().unwrap();
    let path = write_pdf(&dir, "ef.pdf", &pdf);
    let scan = timed(30, || scan_pdf(path).unwrap());
    assert!(scan.attachments_total >= 200_000);
}

#[test]
fn objects_a_swallowing_string_hides_are_read_from_the_xref_offsets() {
    // An unbalanced `(` in object 1 reaches the `)` inside object 9, so a linear read
    // never sees objects 2 and 3. The xref table points at them.
    let mut out = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 5 0 R /X (a\nendobj\n".to_vec();
    let mut offsets = Vec::new();
    offsets.push(9usize);
    for (n, body) in [
        (
            2,
            "<< /Type /Action /S /JavaScript /JS (app.alert\\(1\\);) >>",
        ),
        (3, "<< /Type /Action /S /Launch /F (cmd.exe) >>"),
    ] {
        offsets.push(out.len());
        out.extend_from_slice(format!("{n} 0 obj\n{body}\nendobj\n").as_bytes());
    }
    out.extend_from_slice(b"9 0 obj\n<< /Y (b) >>\nendobj\n");
    let xref = out.len();
    out.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
    for offset in &offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    let dir = TempDir::new().unwrap();
    let scan = scan_pdf(write_pdf(&dir, "swallow.pdf", &out)).unwrap();
    // Unbalanced strings give up at their opening parenthesis, so the plain read sees the
    // objects; the point is that either way they are counted once.
    assert_eq!(feature(&scan, "Launch").map(|f| f.count), Some(1));
    assert_eq!(scan.scripts.len(), 1);
}

#[test]
fn padding_streams_cannot_use_up_the_budget_before_the_object_stream() {
    // 12 Flate streams of 4 MiB of spaces, then an object stream with the catalog.
    let pad = zlib(&vec![b' '; 4 * 1024 * 1024 + 4096]);
    let mut pdf = b"%PDF-1.5\n".to_vec();
    for n in 1..=12 {
        pdf.extend_from_slice(
            format!(
                "{n} 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
                pad.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&pad);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
    }
    let inner = b"<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.launchURL\\('http://evil.test/'\\);) >> >>";
    let data = zlib(inner);
    pdf.extend_from_slice(
        format!(
            "20 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length {} /Filter /FlateDecode >>\nstream\n",
            data.len()
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(&data);
    pdf.extend_from_slice(b"\nendstream\nendobj\nstartxref\n0\n%%EOF\n");
    let dir = TempDir::new().unwrap();
    let scan = timed(20, || scan_pdf(write_pdf(&dir, "pad.pdf", &pdf)).unwrap());
    assert!(feature(&scan, "OpenAction").is_some(), "{:?}", scan.notes);
    assert_eq!(scan.scripts.len(), 1);
    assert!(matches!(
        scan.overall_risk,
        RiskLevel::High | RiskLevel::Critical
    ));
    assert!(scan
        .unread
        .iter()
        .any(|u| u.contains("page and other streams")));
    assert!(scan.notes.iter().any(|n| n.contains("stopped at")));
}

#[test]
fn an_object_stream_that_could_not_be_read_is_never_low_risk() {
    // An object stream with a filter the scan does not decode.
    let pdf = b"%PDF-1.5\n7 0 obj\n<< /Type /ObjStm /N 1 /First 0 /Filter /LZWDecode /Length 4 >>\nstream\nabcd\nendstream\nendobj\nstartxref\n0\n%%EOF\n";
    let dir = TempDir::new().unwrap();
    let scan = scan_pdf(write_pdf(&dir, "lzw.pdf", pdf)).unwrap();
    assert!(!scan.unread.is_empty());
    assert!(!matches!(scan.overall_risk, RiskLevel::Low));
    assert!(scan.notes.iter().any(|n| n.contains("could not be read")));
}

#[test]
fn a_cross_reference_stream_is_a_cross_reference() {
    let pdf = b"%PDF-1.5\n1 0 obj\n<< /Type /Catalog >>\nendobj\n2 0 obj\n<< /Type /XRef /Size 3 /W [1 1 1] /Length 0 >>\nstream\n\nendstream\nendobj\nstartxref\n0\n%%EOF\n";
    let dir = TempDir::new().unwrap();
    let scan = scan_pdf(write_pdf(&dir, "xrefstream.pdf", pdf)).unwrap();
    assert!(
        !scan.notes.iter().any(|n| n.contains("No xref")),
        "{:?}",
        scan.notes
    );
}

#[test]
fn an_attachment_without_the_embedded_file_type_still_scores() {
    let pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /Annots [4 0 R] >>\nendobj\n4 0 obj\n<< /Type /Annot /Subtype /FileAttachment /FS 5 0 R >>\nendobj\n5 0 obj\n<< /Type /Filespec /F (invoice.exe) /EF << /F 6 0 R >> >>\nendobj\n6 0 obj\n<< /Length 12 >>\nstream\nMZ\x90\x00AAAAAAAA\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";
    let dir = TempDir::new().unwrap();
    let scan = scan_pdf(write_pdf(&dir, "attach.pdf", pdf)).unwrap();
    assert_eq!(scan.attachments_total, 1);
    assert!(scan.risk_score >= 15, "{:?}", scan.risk_reasons);
    assert!(scan
        .risk_reasons
        .iter()
        .any(|r| r.contains("Embedded file")));
}

#[test]
fn the_link_reason_counts_every_link_not_the_listed_ones() {
    let mut pdf = b"%PDF-1.4\n1 0 obj\n<<".to_vec();
    for _ in 0..700 {
        pdf.extend_from_slice(b" /A << /S /URI /URI (http://e.test/) >>");
    }
    pdf.extend_from_slice(b" >>\nendobj\ntrailer\n<< >>\n");
    let dir = TempDir::new().unwrap();
    let scan = scan_pdf(write_pdf(&dir, "links700.pdf", &pdf)).unwrap();
    assert!(
        scan.risk_reasons.iter().any(|r| r == "700 link(s)"),
        "{:?}",
        scan.risk_reasons
    );
}

#[test]
fn many_repeated_encrypt_dictionaries_cost_one_parse() {
    let mut pdf = b"%PDF-1.4\n1 0 obj\n<<".to_vec();
    for _ in 0..200_000 {
        pdf.extend_from_slice(b" /Encrypt << /V 1 /R 2 >>");
    }
    pdf.extend_from_slice(b" >>\nendobj\ntrailer\n<< >>\n");
    let dir = TempDir::new().unwrap();
    let path = write_pdf(&dir, "encrypts.pdf", &pdf);
    let scan = timed(5, || scan_pdf(&path).unwrap());
    assert!(scan.is_encrypted);
}

#[test]
fn a_file_of_hidden_object_markers_stays_inside_the_work_budget() {
    // Many unfiltered streams, each holding object headers: the second pass must not
    // repeat work per stream.
    let mut pdf = b"%PDF-1.7\n".to_vec();
    for n in 1..=20_000 {
        pdf.extend_from_slice(
            format!("{n} 0 obj\n<< /Length 30 >>\nstream\n7 0 obj << /A 1 >> endobj\nendstream\nendobj\n")
                .as_bytes(),
        );
    }
    let dir = TempDir::new().unwrap();
    let path = write_pdf(&dir, "markers.pdf", &pdf);
    let scan = timed(10, || scan_pdf(&path).unwrap());
    assert_eq!(scan.stream_count, 20_000);
}

/// A dummy object stream whose data is `inner`, followed by the stream end.
fn dummy_objstm(inner: &[u8]) -> Vec<u8> {
    let mut pdf =
        b"%PDF-1.7\n9 0 obj\n<< /Type /ObjStm /N 1 /First 5 /Filter /FlateDecode >>\nstream\n"
            .to_vec();
    pdf.extend_from_slice(&zlib(b"11 0 (decoy)"));
    pdf.push(b'\n');
    pdf.extend_from_slice(inner);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");
    pdf
}

fn long_catalog(padding: usize) -> Vec<u8> {
    let mut inner = b"1 0 obj << /Type /Catalog /Pages 2 0 R ".to_vec();
    inner.extend(std::iter::repeat_n(b' ', padding));
    inner.extend_from_slice(
        b"/OpenAction << /S /JavaScript /JS (app.alert\\('hidden'\\);) >> \
          /AA << /WC << /S /Launch /F (cmd.exe) >> >> >> endobj\n\
          2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n\
          3 0 obj << /Type /Page /Parent 2 0 R >> endobj\n",
    );
    dummy_objstm(&inner)
}

#[test]
fn an_object_longer_than_the_single_object_window_is_noted_and_not_low() {
    let window = 1024 * 1024;
    let dir = TempDir::new().unwrap();
    let over = scan_pdf(write_pdf(&dir, "over.pdf", &long_catalog(window + 4096))).unwrap();
    assert!(!matches!(over.overall_risk, RiskLevel::Low), "{over:?}");
    assert!(
        over.notes.iter().any(|n| n.contains("run past the 1 MiB")),
        "{:?}",
        over.notes
    );
    assert!(!over.unread.is_empty());
    let under = scan_pdf(write_pdf(&dir, "under.pdf", &long_catalog(window - 4096))).unwrap();
    assert_eq!(feature(&under, "Launch").map(|f| f.count), Some(1));
    assert!(matches!(under.overall_risk, RiskLevel::Critical));
}

#[test]
fn a_script_object_without_endobj_inside_the_window_is_listed_and_counted() {
    let dir = TempDir::new().unwrap();
    let mut inner = b"1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS 4 0 R >> >> endobj\n\
        2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n\
        3 0 obj << /Type /Page /Parent 2 0 R >> endobj\n\
        4 0 obj (app.alert\\('hidden'\\);)\n"
        .to_vec();
    while inner.len() < 1024 * 1024 + 50_000 {
        inner.extend_from_slice(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n");
    }
    let scan = scan_pdf(write_pdf(&dir, "noendobj.pdf", &dummy_objstm(&inner))).unwrap();
    assert!(scan.object_count >= 4, "{}", scan.object_count);
    assert_eq!(scan.scripts_total, 1, "{:?}", scan.notes);
    assert!(scan.scripts.iter().any(|s| s.preview.contains("hidden")));
}

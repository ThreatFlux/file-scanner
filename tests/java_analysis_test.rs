#![allow(
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::collection_is_never_read,
    clippy::field_reassign_with_default,
    clippy::format_push_string,
    clippy::float_cmp,
    clippy::if_not_else,
    clippy::ignore_without_reason,
    clippy::items_after_statements,
    clippy::iter_on_single_items,
    clippy::large_futures,
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    clippy::manual_assert_eq,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::needless_collect,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_pass_by_value,
    clippy::no_effect_underscore_binding,
    clippy::option_if_let_else,
    clippy::ref_option,
    clippy::redundant_clone,
    clippy::redundant_pattern_matching,
    clippy::self_only_used_in_recursion,
    clippy::significant_drop_tightening,
    clippy::single_match_else,
    clippy::single_option_map,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unnecessary_debug_formatting,
    clippy::unreadable_literal,
    clippy::unused_async,
    clippy::unused_self,
    clippy::used_underscore_binding,
    clippy::useless_let_if_seq,
    clippy::wildcard_enum_match_arm,
    clippy::ignored_unit_patterns
)]

#[path = "../src/java_analysis/test_class_builder.rs"]
mod java_class_builder;

use anyhow::Result;
use file_scanner::java_analysis::*;
use java_class_builder::{
    axml, minimal_class, runtime_exec_class, zip_bytes, Av, AxmlEvent, ClassBuilder,
};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// Helper function to create a test JAR file
fn create_test_jar(temp_dir: &Path, name: &str) -> Result<std::path::PathBuf> {
    let jar_path = temp_dir.join(name);
    let file = File::create(&jar_path)?;
    let mut zip = ZipWriter::new(file);

    // Add manifest
    zip.start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())?;
    zip.write_all(
        b"Manifest-Version: 1.0
Main-Class: com.example.Main
Implementation-Title: Test Application
Implementation-Version: 1.0.0
Implementation-Vendor: Test Vendor
Specification-Title: Test Spec
Specification-Version: 1.0
Specification-Vendor: Test Vendor
Built-By: test-user
Build-Jdk: 11.0.12
Created-By: Apache Maven 3.8.1
Class-Path: lib/dependency1.jar lib/dependency2.jar
",
    )?;

    // Add a class file
    zip.start_file("com/example/Main.class", SimpleFileOptions::default())?;
    zip.write_all(&ClassBuilder::new("com/example/Main").major(55).build())?;

    // Add another class
    zip.start_file("com/example/Utils.class", SimpleFileOptions::default())?;
    zip.write_all(&minimal_class("com/example/Utils"))?;

    // Add a resource
    zip.start_file("config.properties", SimpleFileOptions::default())?;
    zip.write_all(b"app.name=Test Application\napp.version=1.0.0\n")?;

    // Add an image resource
    zip.start_file("icons/app.png", SimpleFileOptions::default())?;
    zip.write_all(&[0x89, 0x50, 0x4E, 0x47])?; // PNG header

    zip.finish()?;
    Ok(jar_path)
}

/// Helper function to create a test WAR file
fn create_test_war(temp_dir: &Path) -> Result<std::path::PathBuf> {
    let war_path = temp_dir.join("test.war");
    let file = File::create(&war_path)?;
    let mut zip = ZipWriter::new(file);

    // Add WEB-INF directory
    zip.start_file("WEB-INF/web.xml", SimpleFileOptions::default())?;
    zip.write_all(b"<?xml version=\"1.0\"?><web-app></web-app>")?;

    // Add manifest
    zip.start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())?;
    zip.write_all(b"Manifest-Version: 1.0\n")?;

    // Add class
    zip.start_file(
        "WEB-INF/classes/com/example/Servlet.class",
        SimpleFileOptions::default(),
    )?;
    zip.write_all(&minimal_class("com/example/Servlet"))?;

    zip.finish()?;
    Ok(war_path)
}

/// Helper function to create a test APK file
fn create_test_apk(temp_dir: &Path) -> Result<std::path::PathBuf> {
    let apk_path = temp_dir.join("test.apk");
    let file = File::create(&apk_path)?;
    let mut zip = ZipWriter::new(file);

    // Add AndroidManifest.xml (binary XML format, simplified)
    zip.start_file("AndroidManifest.xml", SimpleFileOptions::default())?;
    zip.write_all(&[0x03, 0x00, 0x08, 0x00])?; // Binary XML header

    // Add classes.dex
    zip.start_file("classes.dex", SimpleFileOptions::default())?;
    zip.write_all(b"dex\n035\x00")?; // DEX header

    // Add certificate
    zip.start_file("META-INF/CERT.RSA", SimpleFileOptions::default())?;
    zip.write_all(&[0x30, 0x82])?; // DER certificate header

    // Add resource
    zip.start_file("res/drawable/icon.png", SimpleFileOptions::default())?;
    zip.write_all(&[0x89, 0x50, 0x4E, 0x47])?; // PNG header

    zip.finish()?;
    Ok(apk_path)
}

/// Helper function to create a test EAR file
fn create_test_ear(temp_dir: &Path) -> Result<std::path::PathBuf> {
    let ear_path = temp_dir.join("test.ear");
    let file = File::create(&ear_path)?;
    let mut zip = ZipWriter::new(file);

    // Add application.xml
    zip.start_file("META-INF/application.xml", SimpleFileOptions::default())?;
    zip.write_all(b"<?xml version=\"1.0\"?><application></application>")?;

    // Add manifest
    zip.start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())?;
    zip.write_all(b"Manifest-Version: 1.0\n")?;

    // Add a WAR module
    zip.start_file("web-module.war", SimpleFileOptions::default())?;
    zip.write_all(b"PK")?; // ZIP header

    zip.finish()?;
    Ok(ear_path)
}

/// Helper function to create a test AAR file
fn create_test_aar(temp_dir: &Path) -> Result<std::path::PathBuf> {
    let aar_path = temp_dir.join("test.aar");
    let file = File::create(&aar_path)?;
    let mut zip = ZipWriter::new(file);

    // Add classes.jar
    zip.start_file("classes.jar", SimpleFileOptions::default())?;
    zip.write_all(b"PK")?; // ZIP header

    // Add R.txt
    zip.start_file("R.txt", SimpleFileOptions::default())?;
    zip.write_all(b"int drawable icon 0x7f020000\n")?;

    // Add AndroidManifest.xml
    zip.start_file("AndroidManifest.xml", SimpleFileOptions::default())?;
    zip.write_all(&[0x03, 0x00, 0x08, 0x00])?; // Binary XML header

    zip.finish()?;
    Ok(aar_path)
}

/// Helper function to create a test class file
fn create_test_class_file(temp_dir: &Path) -> Result<std::path::PathBuf> {
    let class_path = temp_dir.join("Test.class");
    let mut file = File::create(&class_path)?;

    // Write a minimal valid class file (Java 11)
    file.write_all(&ClassBuilder::new("com/example/Test").major(55).build())?;

    Ok(class_path)
}

#[test]
fn test_analyze_jar_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let jar_path = create_test_jar(temp_dir.path(), "test.jar")?;

    let result = analyze_java_archive(&jar_path)?;

    assert_eq!(result.archive_type, JavaArchiveType::Jar);
    assert!(result.manifest.is_some());

    let manifest = result.manifest.as_ref().unwrap();
    assert_eq!(manifest.main_class, Some("com.example.Main".to_string()));
    assert_eq!(
        manifest.implementation_title,
        Some("Test Application".to_string())
    );
    assert_eq!(manifest.implementation_version, Some("1.0.0".to_string()));
    assert_eq!(manifest.class_path.len(), 2);
    assert!(manifest
        .class_path
        .contains(&"lib/dependency1.jar".to_string()));

    assert_eq!(result.classes.len(), 2);
    // Resources list every file, the manifest included
    assert_eq!(result.resources.len(), 5);
    assert_eq!(result.metadata.total_entries, 5); // manifest + 2 classes + 1 properties + 1 png

    Ok(())
}

#[test]
fn test_analyze_war_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let war_path = create_test_war(temp_dir.path())?;

    let result = analyze_java_archive(&war_path)?;

    assert_eq!(result.archive_type, JavaArchiveType::War);
    assert!(result.resources.iter().any(|r| r.path == "WEB-INF/web.xml"));

    Ok(())
}

#[test]
fn test_analyze_apk_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let apk_path = create_test_apk(temp_dir.path())?;

    let result = analyze_java_archive(&apk_path)?;

    assert_eq!(result.archive_type, JavaArchiveType::Apk);
    // The sample manifest bytes are not valid binary XML: say so, invent nothing.
    assert!(result.android_manifest.is_none());
    assert!(result
        .limitations
        .iter()
        .any(|l| l.starts_with("AndroidManifest.xml was not parsed")));
    assert!(result.certificates.is_empty());
    assert_eq!(result.signature_files, vec!["META-INF/CERT.RSA"]);
    assert_eq!(result.dex_files.len(), 1);
    assert!(result.resources.iter().any(|r| r.path == "classes.dex"));

    Ok(())
}

#[test]
fn test_analyze_ear_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let ear_path = create_test_ear(temp_dir.path())?;

    let result = analyze_java_archive(&ear_path)?;

    assert_eq!(result.archive_type, JavaArchiveType::Ear);
    assert!(result
        .resources
        .iter()
        .any(|r| r.path == "META-INF/application.xml"));

    Ok(())
}

#[test]
fn test_analyze_aar_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let aar_path = create_test_aar(temp_dir.path())?;

    let result = analyze_java_archive(&aar_path)?;

    assert_eq!(result.archive_type, JavaArchiveType::Aar);
    assert!(result.resources.iter().any(|r| r.path == "classes.jar"));
    assert!(result.resources.iter().any(|r| r.path == "R.txt"));

    Ok(())
}

#[test]
fn test_analyze_class_file() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let class_path = create_test_class_file(temp_dir.path())?;

    let result = analyze_class_file(&class_path)?;

    assert_eq!(result.archive_type, JavaArchiveType::ClassFile);
    assert_eq!(result.classes.len(), 1);
    assert_eq!(result.classes[0].name, "com.example.Test");
    assert_eq!(result.classes[0].java_version, "Java 11 (major 55)");
    assert_eq!(result.metadata.total_entries, 1);
    assert_eq!(result.metadata.entry_count_by_type.get("class"), Some(&1));

    Ok(())
}

#[test]
fn test_invalid_class_file() {
    let temp_dir = TempDir::new().unwrap();
    let invalid_path = temp_dir.path().join("invalid.class");

    // Write invalid data
    std::fs::write(&invalid_path, b"INVALID").unwrap();

    let result = analyze_class_file(&invalid_path);
    assert!(result.is_err());
}

#[test]
fn test_empty_jar() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let jar_path = temp_dir.path().join("empty.jar");

    let file = File::create(&jar_path)?;
    let zip = ZipWriter::new(file);
    zip.finish()?;

    let result = analyze_java_archive(&jar_path)?;

    assert_eq!(result.metadata.total_entries, 0);
    assert_eq!(result.classes.len(), 0);
    assert_eq!(result.resources.len(), 0);

    Ok(())
}

#[test]
fn test_security_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let jar_path = create_test_jar(temp_dir.path(), "secure.jar")?;

    let result = analyze_java_archive(&jar_path)?;

    // Unsigned JAR should be detected
    assert_eq!(
        result.security_analysis.code_signing_status,
        CodeSigningStatus::Unsigned
    );
    assert!(result
        .security_analysis
        .certificate_issues
        .contains(&"Application is not signed".to_string()));
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::Low
    );

    Ok(())
}

#[test]
fn test_resource_classification() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let jar_path = temp_dir.path().join("resources.jar");

    let file = File::create(&jar_path)?;
    let mut zip = ZipWriter::new(file);

    // Add various resources
    let test_files = vec![
        ("image.png", ResourceType::Image),
        ("photo.jpg", ResourceType::Image),
        ("icon.gif", ResourceType::Image),
        ("layout/main.xml", ResourceType::Layout),
        ("values/strings.xml", ResourceType::String),
        ("lib/native.so", ResourceType::Library),
        ("lib/test.dll", ResourceType::Library),
        ("config.properties", ResourceType::Configuration),
        ("settings.json", ResourceType::Configuration),
        ("assets/data.txt", ResourceType::Asset),
        ("raw/audio.mp3", ResourceType::Raw),
        ("unknown.xyz", ResourceType::Other),
    ];

    for (name, _) in &test_files {
        zip.start_file(name, SimpleFileOptions::default())?;
        zip.write_all(b"test content")?;
    }

    zip.finish()?;

    let result = analyze_java_archive(&jar_path)?;

    // Check that resources are properly classified
    for (name, expected_type) in test_files {
        let resource = result.resources.iter().find(|r| r.path == name);
        assert!(resource.is_some(), "Resource {name} not found");
        assert_eq!(
            resource.unwrap().resource_type,
            expected_type,
            "Wrong type for {name}"
        );
    }

    Ok(())
}

#[test]
fn test_metadata_calculation() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let jar_path = create_test_jar(temp_dir.path(), "metadata.jar")?;

    let result = analyze_java_archive(&jar_path)?;

    assert!(result.metadata.total_size > 0);
    assert!(result.metadata.compressed_size > 0);
    assert!(result.metadata.compression_ratio > 0.0 && result.metadata.compression_ratio <= 1.0);
    assert!(!result.metadata.entry_count_by_type.is_empty());
    assert!(!result.metadata.largest_entries.is_empty());

    Ok(())
}

#[test]
fn test_manifest_parsing_with_custom_attributes() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let jar_path = temp_dir.path().join("manifest_test.jar");

    let file = File::create(&jar_path)?;
    let mut zip = ZipWriter::new(file);

    // Add manifest with custom attributes
    zip.start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())?;
    zip.write_all(
        br"Manifest-Version: 1.0
Main-Class: com.example.Main
Implementation-Title: Test App
Custom-Attribute: Custom Value
Another-Header: Another Value
Class-Path: lib1.jar lib2.jar lib3.jar
",
    )?;

    zip.finish()?;

    let result = analyze_java_archive(&jar_path)?;
    let manifest = result.manifest.as_ref().unwrap();

    assert_eq!(manifest.main_class, Some("com.example.Main".to_string()));
    assert_eq!(manifest.implementation_title, Some("Test App".to_string()));
    assert_eq!(manifest.class_path.len(), 3);
    assert_eq!(
        manifest.custom_attributes.get("Custom-Attribute"),
        Some(&"Custom Value".to_string())
    );
    assert_eq!(
        manifest.custom_attributes.get("Another-Header"),
        Some(&"Another Value".to_string())
    );

    Ok(())
}

#[test]
fn test_dangerous_permissions_in_apk() -> Result<()> {
    // We'll test the security analysis indirectly by creating an APK with permissions
    // and checking the security analysis results
    let temp_dir = TempDir::new()?;
    let apk_path = temp_dir.path().join("permissions_test.apk");

    let file = File::create(&apk_path)?;
    let mut zip = ZipWriter::new(file);

    // Add AndroidManifest.xml
    zip.start_file("AndroidManifest.xml", SimpleFileOptions::default())?;
    zip.write_all(&[0x03, 0x00, 0x08, 0x00])?; // Binary XML header

    // Add classes.dex to make it a valid APK
    zip.start_file("classes.dex", SimpleFileOptions::default())?;
    zip.write_all(b"dex\n035\x00")?;

    zip.finish()?;

    let result = analyze_java_archive(&apk_path)?;

    // The manifest is a bare header: it cannot be understood, so the APK is not rated
    // Low on "nothing found".
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::Medium
    );
    assert!(result
        .security_analysis
        .threat_basis
        .iter()
        .any(|b| b.contains("AndroidManifest.xml was not read or not understood")));
    assert_eq!(
        result.security_analysis.code_signing_status,
        CodeSigningStatus::Unsigned
    );

    Ok(())
}

#[test]
fn test_security_analysis_dangerous_apis() -> Result<()> {
    // We test dangerous API detection through the security analysis results
    let temp_dir = TempDir::new()?;
    let jar_path = temp_dir.path().join("dangerous_apis.jar");

    let file = File::create(&jar_path)?;
    let mut zip = ZipWriter::new(file);

    // Add manifest
    zip.start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())?;
    zip.write_all(b"Manifest-Version: 1.0\n")?;

    zip.start_file(
        "com/example/DangerousCode.class",
        SimpleFileOptions::default(),
    )?;
    zip.write_all(&runtime_exec_class("com/example/DangerousCode"))?;

    zip.finish()?;

    let result = analyze_java_archive(&jar_path)?;

    // CF02: the constant pool's Runtime.exec reference is found and sets the level.
    assert_eq!(
        result.security_analysis.dangerous_apis,
        vec!["java.lang.Runtime.exec"]
    );
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::High
    );
    assert_eq!(
        result.security_analysis.api_findings[0].category,
        "process_exec"
    );
    assert_eq!(
        result.security_analysis.api_findings[0].example_classes,
        vec!["com.example.DangerousCode"]
    );

    Ok(())
}

#[test]
fn test_jar_with_signed_content() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let jar_path = temp_dir.path().join("signed.jar");

    let file = File::create(&jar_path)?;
    let mut zip = ZipWriter::new(file);

    // Add manifest
    zip.start_file("META-INF/MANIFEST.MF", SimpleFileOptions::default())?;
    zip.write_all(b"Manifest-Version: 1.0\n")?;

    // Add signature files
    zip.start_file("META-INF/CERT.RSA", SimpleFileOptions::default())?;
    zip.write_all(&[0x30, 0x82])?; // DER certificate header

    zip.start_file("META-INF/CERT.SF", SimpleFileOptions::default())?;
    zip.write_all(b"Signature-Version: 1.0\n")?;

    zip.finish()?;

    let result = analyze_java_archive(&jar_path)?;

    // CF05: an entry name proves nothing; no certificate is invented and the
    // status says the signature was not verified.
    assert!(result.certificates.is_empty());
    assert_eq!(
        result.signature_files,
        vec!["META-INF/CERT.RSA", "META-INF/CERT.SF"]
    );
    assert_eq!(
        result.security_analysis.code_signing_status,
        CodeSigningStatus::SignatureFilesPresentUnverified
    );

    Ok(())
}

#[test]
fn test_non_existent_file() {
    let result = analyze_java_archive(Path::new("/non/existent/file.jar"));
    assert!(result.is_err());
}

#[test]
fn test_file_extension_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;

    // The kind comes from the entries, never the name: an empty ZIP is Unknown whatever
    // it is called, so cached answers cannot depend on the name that came first.
    let test_cases = vec![
        ("test.jar", JavaArchiveType::Unknown),
        ("test.war", JavaArchiveType::Unknown),
        ("test.ear", JavaArchiveType::Unknown),
        ("test.apk", JavaArchiveType::Unknown),
        ("test.aar", JavaArchiveType::Unknown),
    ];

    for (filename, expected_type) in test_cases {
        let path = temp_dir.path().join(filename);

        // Create minimal ZIP file
        let file = File::create(&path)?;
        let zip = ZipWriter::new(file);
        zip.finish()?;

        let result = analyze_java_archive(&path)?;
        assert_eq!(result.archive_type, expected_type, "Failed for {filename}");
    }

    Ok(())
}

fn write_zip(dir: &Path, name: &str, entries: &[(&str, &[u8])]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, zip_bytes(entries)).unwrap();
    path
}

#[test]
fn cf02_class_file_is_really_parsed() -> Result<()> {
    let dir = TempDir::new()?;
    let bytes = ClassBuilder::new("com/example/audit/Hello")
        .major(52)
        .access(0x0021)
        .interface("java/lang/Runnable")
        .field("secretKey", "Ljava/lang/String;", 0x0002)
        .method_with_code(
            "exec",
            "(Ljava/lang/String;I)V",
            0x0001,
            4,
            &["java/io/IOException"],
        )
        .calls("java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;")
        .calls(
            "java/lang/Runtime",
            "exec",
            "(Ljava/lang/String;)Ljava/lang/Process;",
        )
        .calls(
            "javax/crypto/Cipher",
            "getInstance",
            "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        )
        .refers_to("[Ljava/net/Socket;")
        .long_constant(42)
        .source_file("Hello.java")
        .build();
    let path = dir.path().join("Hello.class");
    std::fs::write(&path, bytes)?;

    let result = analyze_class_file_full(&path)?;
    let class = &result.classes[0];
    assert_eq!(class.name, "com.example.audit.Hello");
    assert_eq!(class.package, "com.example.audit");
    assert_eq!(class.super_class.as_deref(), Some("java.lang.Object"));
    assert_eq!(class.interfaces, vec!["java.lang.Runnable"]);
    assert_eq!(class.source_file.as_deref(), Some("Hello.java"));
    assert_eq!(class.java_version, "Java 8 (major 52)");
    assert!(class.is_public);
    assert_eq!(class.fields[0].name, "secretKey");
    assert!(class.fields[0].is_private);
    let method = &class.methods[0];
    assert_eq!(method.name, "exec");
    assert_eq!(method.parameter_count, 2);
    assert_eq!(method.local_variable_count, 4);
    assert_eq!(method.exception_table, vec!["java.io.IOException"]);
    assert!(class
        .referenced_classes
        .contains(&"java.net.Socket".to_string()));
    assert!(class
        .method_refs
        .contains(&"java.lang.Runtime.exec(Ljava/lang/String;)Ljava/lang/Process;".to_string()));
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::High
    );
    assert_eq!(result.java_versions.get("Java 8 (major 52)"), Some(&1));
    // The legacy result drops the per-class reference lists.
    let legacy = analyze_class_file(&path)?;
    assert!(legacy.classes[0].referenced_classes.is_empty());
    assert!(legacy.classes[0].method_refs.is_empty());
    Ok(())
}

#[test]
fn cf02_threat_levels_follow_findings() -> Result<()> {
    let dir = TempDir::new()?;
    let benign = write_zip(
        dir.path(),
        "benign.jar",
        &[("a/B.class", &minimal_class("a/B"))],
    );
    let result = analyze_java_archive(&benign)?;
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::Low
    );
    assert!(result.security_analysis.dangerous_apis.is_empty());

    let reflective = ClassBuilder::new("a/R")
        .calls(
            "java/lang/reflect/Method",
            "invoke",
            "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
        )
        .build();
    let path = write_zip(dir.path(), "reflective.jar", &[("a/R.class", &reflective)]);
    let result = analyze_java_archive(&path)?;
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::Medium
    );

    // Process execution + network + dynamic class loading in one class: the dropper shape.
    let dropper = ClassBuilder::new("a/D")
        .calls("java/lang/ProcessBuilder", "start", "()Ljava/lang/Process;")
        .calls("java/net/URL", "openStream", "()Ljava/io/InputStream;")
        .calls("java/net/URLClassLoader", "<init>", "([Ljava/net/URL;)V")
        .build();
    let path = write_zip(dir.path(), "dropper.jar", &[("a/D.class", &dropper)]);
    let result = analyze_java_archive(&path)?;
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::Critical
    );
    assert_eq!(result.security_analysis.malware_indicators.len(), 1);
    Ok(())
}

#[test]
fn cf02_obfuscated_names_are_flagged() -> Result<()> {
    let dir = TempDir::new()?;
    let names: Vec<String> = (0..12)
        .map(|i| format!("a/{}", (b'a' + i as u8) as char))
        .collect();
    let classes: Vec<(String, Vec<u8>)> = names
        .iter()
        .map(|n| (format!("{n}.class"), minimal_class(n)))
        .collect();
    let borrowed: Vec<(&str, &[u8])> = classes
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let path = write_zip(dir.path(), "obf.jar", &borrowed);
    let result = analyze_java_archive(&path)?;
    assert_eq!(result.security_analysis.obfuscation_indicators.len(), 1);
    Ok(())
}

#[test]
fn cf03_legacy_result_is_bounded() -> Result<()> {
    let dir = TempDir::new()?;
    let classes: Vec<(String, Vec<u8>)> = (0..200)
        .map(|i| (format!("p/C{i}.class"), minimal_class(&format!("p/C{i}"))))
        .collect();
    let borrowed: Vec<(&str, &[u8])> = classes
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let path = write_zip(dir.path(), "many.jar", &borrowed);
    let result = analyze_java_archive(&path)?;
    assert_eq!(result.classes.len(), LEGACY_LIST_CAP);
    assert_eq!(result.classes_total, 200);
    assert_eq!(result.resources.len(), LEGACY_LIST_CAP);
    assert_eq!(result.resources_total, 200);
    let json = serde_json::to_string(&result)?;
    assert!(json.len() < 40_000, "{} bytes", json.len());
    let full = analyze_java_archive_full(&path)?;
    assert_eq!(full.classes.len(), 200);
    Ok(())
}

#[test]
fn cf05_binary_android_manifest_is_parsed() -> Result<()> {
    let dir = TempDir::new()?;
    let manifest = axml(&[
        Some((
            "manifest",
            vec![
                ("package", Av::Str("com.example.audit")),
                ("versionCode", Av::Int(3)),
                ("versionName", Av::Str("0.3")),
            ],
        )),
        Some((
            "uses-sdk",
            vec![
                ("minSdkVersion", Av::Int(21)),
                ("targetSdkVersion", Av::Int(34)),
            ],
        )),
        None,
        Some((
            "uses-permission",
            vec![("name", Av::Str("android.permission.READ_CONTACTS"))],
        )),
        None,
        Some(("application", vec![])),
        Some(("receiver", vec![("name", Av::Str(".Boot"))])),
        Some(("intent-filter", vec![])),
        Some((
            "action",
            vec![("name", Av::Str("android.intent.action.BOOT_COMPLETED"))],
        )),
        None,
        None,
        None,
        Some((
            "provider",
            vec![("name", Av::Str(".Data")), ("exported", Av::Bool(false))],
        )),
        None,
        None,
        None,
    ]);
    let path = write_zip(dir.path(), "a.apk", &[("AndroidManifest.xml", &manifest)]);
    let result = analyze_java_archive(&path)?;
    let android = result.android_manifest.as_ref().unwrap();
    assert_eq!(android.package_name, "com.example.audit");
    assert_eq!(android.version_code, Some(3));
    assert_eq!(android.version_name.as_deref(), Some("0.3"));
    assert_eq!(android.min_sdk_version, Some(21));
    assert_eq!(android.target_sdk_version, Some(34));
    assert_eq!(
        android.permissions,
        vec!["android.permission.READ_CONTACTS"]
    );
    assert_eq!(result.permissions, android.permissions);
    assert_eq!(android.receivers[0].name, "com.example.audit.Boot");
    assert!(
        android.receivers[0].exported,
        "intent filter implies exported"
    );
    assert_eq!(
        android.receivers[0].intent_filters[0].actions,
        vec!["android.intent.action.BOOT_COMPLETED"]
    );
    assert!(!android.providers[0].exported);
    assert_eq!(
        result.security_analysis.suspicious_permissions,
        vec!["android.permission.READ_CONTACTS"]
    );
    assert_eq!(result.security_analysis.privacy_concerns.len(), 1);
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::Medium
    );
    Ok(())
}

#[test]
fn cf05_plain_text_android_manifest_is_parsed() -> Result<()> {
    let dir = TempDir::new()?;
    let xml = br#"<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.audit">
  <uses-permission android:name="android.permission.SEND_SMS"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <application><activity android:name=".Main" android:exported="true"/></application>
</manifest>"#;
    let path = write_zip(dir.path(), "t.apk", &[("AndroidManifest.xml", xml)]);
    let result = analyze_java_archive(&path)?;
    let android = result.android_manifest.as_ref().unwrap();
    assert_eq!(android.package_name, "com.example.audit");
    assert_eq!(android.permissions.len(), 2);
    assert_eq!(android.activities[0].name, "com.example.audit.Main");
    assert!(android.activities[0].exported);
    Ok(())
}

#[test]
fn cf06_oversized_entries_are_not_read() -> Result<()> {
    let dir = TempDir::new()?;
    let mut big = vec![0xCA, 0xFE, 0xBA, 0xBE];
    big.resize((MAX_CLASS_BYTES + 1) as usize, 0);
    let path = write_zip(
        dir.path(),
        "bomb.jar",
        &[
            ("Big.class", &big),
            ("ok/Ok.class", &minimal_class("ok/Ok")),
        ],
    );
    let result = analyze_java_archive_full(&path)?;
    assert_eq!(result.classes.len(), 1);
    assert_eq!(result.unparsed_classes, 1);
    assert!(result.warnings[0].contains("Big.class"));
    assert!(result.warnings[0].contains("read cap"));
    Ok(())
}

#[test]
fn cf08_manifest_continuation_lines_and_sections() -> Result<()> {
    let dir = TempDir::new()?;
    let manifest = b"Manifest-Version: 1.0\r\nClass-Path: lib/aaaaaaaaaaaaaaaaaaaaaaaa.jar lib/bbbbbbbbbbbbbbbb\r\n bbbbbbbb.jar lib/c.jar\r\nBundle-Description: first part,\r\n  second part\r\nCreated-By: 11 (Oracle)\r\n\r\nName: com/example/Main.class\r\nSHA-256-Digest: abc=\r\n\r\nName: other.class\r\nSHA-256-Digest: def=\r\n\r\n";
    let path = write_zip(dir.path(), "m.jar", &[("META-INF/MANIFEST.MF", manifest)]);
    let result = analyze_java_archive(&path)?;
    let m = result.manifest.unwrap();
    assert_eq!(
        m.class_path,
        vec![
            "lib/aaaaaaaaaaaaaaaaaaaaaaaa.jar",
            "lib/bbbbbbbbbbbbbbbbbbbbbbbb.jar",
            "lib/c.jar"
        ]
    );
    assert_eq!(
        m.custom_attributes
            .get("Bundle-Description")
            .map(String::as_str),
        Some("first part, second part")
    );
    assert_eq!(m.created_by.as_deref(), Some("11 (Oracle)"));
    // Per-entry sections are not merged into the main attributes.
    assert!(!m.custom_attributes.contains_key("SHA-256-Digest"));
    assert_eq!(m.entry_sections, 2);
    Ok(())
}

#[test]
fn cf09_undecodable_entries_do_not_stop_the_analysis() -> Result<()> {
    let dir = TempDir::new()?;
    let path = write_zip(
        dir.path(),
        "latin1.jar",
        &[
            (
                "META-INF/MANIFEST.MF",
                b"Manifest-Version: 1.0\nImplementation-Vendor: Soci\xe9t\xe9 Exemple\n",
            ),
            ("a/B.class", &minimal_class("a/B")),
            (
                "a/Broken.class",
                b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34\x00\x05garbage",
            ),
        ],
    );
    let result = analyze_java_archive(&path)?;
    let vendor = result.manifest.unwrap().implementation_vendor.unwrap();
    assert!(
        vendor.starts_with("Soci") && vendor.ends_with(" Exemple"),
        "{vendor}"
    );
    assert_eq!(result.classes.len(), 1);
    assert_eq!(result.unparsed_classes, 1);
    assert!(result.warnings.iter().any(|w| w.contains("Broken.class")));
    Ok(())
}

#[test]
fn cf10_nested_archives_are_opened_one_level_deep() -> Result<()> {
    let dir = TempDir::new()?;
    // AAR: classes.jar holds the code.
    let classes_jar = zip_bytes(&[(
        "com/example/Lib.class",
        &runtime_exec_class("com/example/Lib"),
    )]);
    let aar = write_zip(
        dir.path(),
        "lib.aar",
        &[
            ("classes.jar", &classes_jar),
            ("R.txt", b""),
            ("AndroidManifest.xml", b"<manifest package=\"x.y\"/>"),
        ],
    );
    let result = analyze_java_archive_full(&aar)?;
    assert_eq!(result.archive_type, JavaArchiveType::Aar);
    assert_eq!(result.classes.len(), 1);
    assert_eq!(result.classes[0].name, "com.example.Lib");
    assert_eq!(result.classes[0].container.as_deref(), Some("classes.jar"));
    assert!(result.nested_archives[0].opened);
    assert_eq!(result.nested_archives[0].classes, 1);
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::High
    );

    // EAR -> WAR -> WEB-INF/lib/inner.jar is opened too (two levels of nesting).
    let inner = zip_bytes(&[("deep/Deep.class", &minimal_class("deep/Deep"))]);
    let war = zip_bytes(&[
        (
            "WEB-INF/classes/w/Servlet.class",
            &minimal_class("w/Servlet"),
        ),
        ("WEB-INF/lib/inner.jar", &inner),
    ]);
    let ear = write_zip(
        dir.path(),
        "app.ear",
        &[
            ("META-INF/application.xml", b"<application/>"),
            ("web.war", &war),
        ],
    );
    let result = analyze_java_archive_full(&ear)?;
    let names: Vec<&str> = result.classes.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["w.Servlet", "deep.Deep"]);
    assert_eq!(result.nested_archives.len(), 2);
    assert!(result.nested_archives.iter().all(|n| n.opened));
    Ok(())
}

/// Second-level nested archives carry the full path from the analyzed file, so two
/// same-named libraries in different WARs can be told apart.
#[test]
fn nested_paths_are_full_paths_from_the_analyzed_file() -> Result<()> {
    let dir = TempDir::new()?;
    let evil = zip_bytes(&[("app/Loader.class", &runtime_exec_class("app/Loader"))]);
    let plain = zip_bytes(&[("app/Plain.class", &minimal_class("app/Plain"))]);
    let war_a = zip_bytes(&[("WEB-INF/lib/util.jar", &evil)]);
    let war_b = zip_bytes(&[("WEB-INF/lib/util.jar", &plain)]);
    let ear = write_zip(
        dir.path(),
        "two.ear",
        &[("a.war", &war_a), ("b.war", &war_b)],
    );
    let result = analyze_java_archive_full(&ear)?;
    let rows: Vec<&str> = result
        .nested_archives
        .iter()
        .map(|n| n.path.as_str())
        .collect();
    assert_eq!(
        rows,
        vec![
            "a.war",
            "a.war!WEB-INF/lib/util.jar",
            "b.war",
            "b.war!WEB-INF/lib/util.jar"
        ]
    );
    let containers: Vec<(&str, &str)> = result
        .classes
        .iter()
        .map(|c| (c.name.as_str(), c.container.as_deref().unwrap_or("")))
        .collect();
    assert!(containers.contains(&("app.Loader", "a.war!WEB-INF/lib/util.jar")));
    assert!(containers.contains(&("app.Plain", "b.war!WEB-INF/lib/util.jar")));
    let exec = result
        .security_analysis
        .api_findings
        .iter()
        .find(|f| f.api.contains("Runtime.exec"))
        .expect("Runtime.exec finding");
    assert_eq!(
        exec.example_classes,
        vec!["a.war!WEB-INF/lib/util.jar!app.Loader".to_string()]
    );
    Ok(())
}

#[test]
fn cf07_content_sniffing_ignores_extensions() -> Result<()> {
    let dir = TempDir::new()?;
    let class = dir.path().join("Hello.bin");
    std::fs::write(&class, minimal_class("x/Hello"))?;
    assert_eq!(sniff_java_input(&class)?, JavaInputKind::Class);
    assert_eq!(
        analyze_java_path(&class)?.archive_type,
        JavaArchiveType::ClassFile
    );

    let jar = write_zip(
        dir.path(),
        "renamed.class",
        &[("a/B.class", &minimal_class("a/B"))],
    );
    assert_eq!(sniff_java_input(&jar)?, JavaInputKind::Archive);
    assert_eq!(analyze_java_path(&jar)?.classes.len(), 1);

    let dex = dir.path().join("a.dex");
    std::fs::write(&dex, b"dex\n035\0")?;
    assert_eq!(sniff_java_input(&dex)?, JavaInputKind::Dex);
    assert!(analyze_java_path(&dex)
        .unwrap_err()
        .to_string()
        .contains("DEX"));

    // A Mach-O fat header shares the CAFEBABE magic but is not a class file.
    let fat = dir.path().join("fat");
    std::fs::write(&fat, [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2, 0, 0, 0, 0])?;
    assert_eq!(sniff_java_input(&fat)?, JavaInputKind::Other);
    Ok(())
}

// ---------------------------------------------------------------------------
// Round 3: memory and work stay bounded for tiny hostile inputs
// ---------------------------------------------------------------------------

/// Largest serialized result a hostile file may produce in these tests.
const RESULT_BOUND: usize = 20 * 1024 * 1024;

fn serialized_size(path: &Path) -> Result<(usize, JavaAnalysisResult)> {
    let result = analyze_java_path(path)?;
    Ok((serde_json::to_vec(&result)?.len(), result))
}

/// Generator h2 "methods": 65,535 methods and fields whose name and descriptor are one
/// 65,535-byte constant, in a class of a few hundred KB.
#[test]
fn hostile_member_lists_keep_a_bounded_result() -> Result<()> {
    let dir = TempDir::new()?;
    let big = "m".repeat(65_535);
    let mut builder = ClassBuilder::new("p/M");
    for _ in 0..65_535 {
        builder = builder.method(&big, &big, 1);
    }
    let class = builder.build();
    assert!(class.len() < 1_000_000, "{}", class.len());
    let path = write_zip(dir.path(), "methods.jar", &[("p/M.class", &class)]);
    let (size, result) = serialized_size(&path)?;
    assert!(size < RESULT_BOUND, "{size} bytes");
    let c = &result.classes[0];
    assert_eq!(c.method_count(), 65_535, "the real count is kept");
    assert!(c.methods.len() < 5_000, "{}", c.methods.len());
    assert!(c.methods.iter().all(|m| m.name.len() <= 256));
    assert!(c
        .parse_warning
        .as_deref()
        .is_some_and(|w| w.contains("member lists cut")));
    assert!(result.warnings.iter().any(|w| w.contains("partly read")));

    // Fields are cut the same way.
    let mut builder = ClassBuilder::new("p/F");
    for _ in 0..65_535 {
        builder = builder.field(&big, &big, 1);
    }
    let class = builder.build();
    let path = write_zip(dir.path(), "fields.jar", &[("p/F.class", &class)]);
    let (size, result) = serialized_size(&path)?;
    assert!(size < RESULT_BOUND, "{size} bytes");
    assert_eq!(result.classes[0].field_count(), 65_535);
    Ok(())
}

/// Generator h2 "ifaces": thousands of interface entries naming one 64 KB class.
#[test]
fn hostile_interface_lists_keep_a_bounded_result() -> Result<()> {
    let dir = TempDir::new()?;
    let big = "i".repeat(65_535);
    let mut builder = ClassBuilder::new("p/I");
    for _ in 0..65_535 {
        builder = builder.interface(&big);
    }
    let class = builder.build();
    let path = write_zip(dir.path(), "ifaces.jar", &[("p/I.class", &class)]);
    let (size, result) = serialized_size(&path)?;
    assert!(size < RESULT_BOUND, "{size} bytes");
    let c = &result.classes[0];
    assert_eq!(c.interface_count(), 65_535);
    assert!(c.interfaces.len() < 4_000, "{}", c.interfaces.len());
    assert!(c.interfaces.iter().all(|i| i.len() <= 512));
    Ok(())
}

/// Generator h3 "throws": one Exceptions attribute with a huge entry count.
#[test]
fn hostile_throws_lists_keep_a_bounded_result() -> Result<()> {
    let dir = TempDir::new()?;
    let big = "t".repeat(65_535);
    let throws: Vec<&str> = (0..30_000).map(|_| big.as_str()).collect();
    let class = ClassBuilder::new("p/T")
        .method_with_code("m", "()V", 1, 1, &throws)
        .build();
    let path = write_zip(dir.path(), "throws.jar", &[("p/T.class", &class)]);
    let (size, result) = serialized_size(&path)?;
    assert!(size < RESULT_BOUND, "{size} bytes");
    let m = &result.classes[0].methods[0];
    assert!(m.exception_table.len() <= 64, "{}", m.exception_table.len());
    Ok(())
}

/// Generators h3 "perms" and "attrs": thousands of elements sharing 32 K-unit strings.
#[test]
fn hostile_android_manifests_keep_a_bounded_result() -> Result<()> {
    let dir = TempDir::new()?;
    let big_permission = format!("android.permission.{}", "P".repeat(32_000));
    let mut events: Vec<AxmlEvent> = vec![Some(("manifest", vec![("package", Av::Str("com.x"))]))];
    for _ in 0..2_000 {
        events.push(Some((
            "uses-permission",
            vec![("name", Av::Text(big_permission.clone()))],
        )));
        events.push(None);
    }
    events.push(None);
    let manifest = axml(&events);
    let path = write_zip(
        dir.path(),
        "perms.apk",
        &[
            ("AndroidManifest.xml", &manifest),
            ("classes.dex", b"dex\n035\0"),
        ],
    );
    let (size, result) = serialized_size(&path)?;
    assert!(size < RESULT_BOUND, "{size} bytes");
    let android = result.android_manifest.as_ref().unwrap();
    assert!(android.permissions.len() <= 2_000);
    assert!(android.permissions.iter().all(|p| p.len() <= 512));
    assert!(!android.notes.is_empty(), "the cut is noted");

    // Distinct long permissions: the element budget stops the parse and says so.
    let mut events: Vec<AxmlEvent> = vec![Some(("manifest", vec![("package", Av::Str("com.x"))]))];
    for i in 0..100 {
        events.push(Some((
            "meta-data",
            vec![
                ("name", Av::Text(format!("{i}{}", "Q".repeat(32_000)))),
                ("scheme", Av::Text("S".repeat(32_000))),
                ("mimeType", Av::Text("M".repeat(32_000))),
                ("label", Av::Text("L".repeat(32_000))),
            ],
        )));
        events.push(None);
    }
    events.push(None);
    let manifest = axml(&events);
    let path = write_zip(
        dir.path(),
        "attrs.apk",
        &[
            ("AndroidManifest.xml", &manifest),
            ("classes.dex", b"dex\n035\0"),
        ],
    );
    let (size, result) = serialized_size(&path)?;
    assert!(size < RESULT_BOUND, "{size} bytes");
    assert!(result.android_manifest.is_some());
    Ok(())
}

/// The archive-wide budget: many hostile classes in one JAR still stay bounded and say so.
#[test]
fn many_hostile_classes_hit_the_archive_budget() -> Result<()> {
    let dir = TempDir::new()?;
    let big = "m".repeat(65_535);
    let mut owned: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..200 {
        let mut b = ClassBuilder::new(&format!("p/H{i}"));
        for k in 0..1_500 {
            // Distinct names so nothing deduplicates; the 64 KB constant is shared.
            b = b.method(&format!("{}{k}", &big[..250]), &big, 1);
        }
        owned.push((format!("p/H{i}.class"), b.build()));
    }
    let entries: Vec<(&str, &[u8])> = owned
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let path = write_zip(dir.path(), "many.jar", &entries);
    let (size, result) = serialized_size(&path)?;
    assert!(size < 100 * 1024 * 1024, "{size} bytes");
    assert!(
        result
            .warnings
            .iter()
            .any(|w| w.contains("archive-wide") || w.contains("passed")),
        "{:?}",
        result.warnings
    );
    assert!(result.classes.iter().all(|c| c.method_count() == 1_500));
    Ok(())
}

/// A class file followed by a JAR is opened as the JAR; trailing bytes are never silent.
#[test]
fn class_followed_by_jar_is_not_reported_as_a_clean_class() -> Result<()> {
    let dir = TempDir::new()?;
    let jar = zip_bytes(&[("com/acme/Evil.class", &runtime_exec_class("com/acme/Evil"))]);
    let mut combined = minimal_class("p/Benign");
    combined.extend(&jar);
    let path = dir.path().join("combined.bin");
    std::fs::write(&path, &combined)?;
    let result = analyze_java_path(&path)?;
    assert_eq!(result.archive_type, JavaArchiveType::Jar);
    assert!(result.classes.iter().any(|c| c.name == "com.acme.Evil"));
    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains("bytes into the file")));

    // Plain trailing bytes after a class are warned about.
    let mut padded = minimal_class("p/Benign");
    padded.extend([0u8; 40]);
    let path = dir.path().join("padded.class");
    std::fs::write(&path, &padded)?;
    let result = analyze_java_path(&path)?;
    assert_eq!(result.archive_type, JavaArchiveType::ClassFile);
    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains("40 bytes follow the end of the class file")));
    Ok(())
}

/// A prefixed JAR inside a WAR is opened and flagged; a damaged ZIP gets a next step.
#[test]
fn nested_prefixed_jar_and_damaged_zip() -> Result<()> {
    let dir = TempDir::new()?;
    let jar = zip_bytes(&[("com/acme/Evil.class", &runtime_exec_class("com/acme/Evil"))]);
    let mut prefixed = b"X".to_vec();
    prefixed.extend(&jar);
    let war = zip_bytes(&[
        ("WEB-INF/web.xml", b"<web-app/>"),
        ("WEB-INF/lib/evil.jar", &prefixed),
    ]);
    let path = dir.path().join("p.war");
    std::fs::write(&path, &war)?;
    let result = analyze_java_path(&path)?;
    assert!(result.classes.iter().any(|c| c.name == "com.acme.Evil"));
    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains("starts 1 bytes into the nested archive")));

    let cut = dir.path().join("cut.jar");
    std::fs::write(&cut, &jar[..jar.len() / 2])?;
    let error = analyze_java_path(&cut).unwrap_err().to_string();
    assert!(error.contains("damaged or cut short"), "{error}");
    Ok(())
}

/// Nested-archive rows have a cap and a note, whatever the entry count.
#[test]
fn nested_archive_rows_are_capped_with_a_note() -> Result<()> {
    let dir = TempDir::new()?;
    let names: Vec<String> = (0..MAX_NESTED_ROWS + 200)
        .map(|i| format!("lib/m{i}.jar"))
        .collect();
    let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), &b"x"[..])).collect();
    let path = write_zip(dir.path(), "many.war", &entries);
    let result = analyze_java_path(&path)?;
    assert_eq!(result.nested_archives.len(), MAX_NESTED_ROWS);
    assert_eq!(
        result.nested_total,
        MAX_NESTED_ROWS + 200,
        "totals count every entry"
    );
    assert!(result
        .warnings
        .iter()
        .any(|w| w.contains("nested-archive entries")));
    Ok(())
}

/// Per-entry work must not grow with the length of a name: 40 classes of 65,535
/// interfaces, fields and inner classes, all naming one long constant.
#[test]
fn hostile_member_lists_cost_little_cpu() -> Result<()> {
    let dir = TempDir::new()?;
    let big = "x".repeat(8_000);
    let inner: Vec<&str> = (0..65_535).map(|_| big.as_str()).collect();
    let mut b = ClassBuilder::new("p/C");
    for _ in 0..65_535 {
        b = b.interface(&big).field(&big, &big, 1);
    }
    let class = b.inner_classes(&inner).build();
    let names: Vec<String> = (0..40).map(|i| format!("p/C{i}.class")).collect();
    let entries: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), class.as_slice()))
        .collect();
    let path = write_zip(dir.path(), "cpu.jar", &entries);
    let started = std::time::Instant::now();
    let result = analyze_java_path(&path)?;
    let took = started.elapsed();
    assert!(took.as_secs() < 5, "took {took:?}");
    assert_eq!(result.classes[0].interface_count(), 65_535);
    assert!(result.classes[0].interfaces.len() < 4_000);
    assert!(result.classes[0]
        .parse_warning
        .as_deref()
        .is_some_and(|w| w.contains("member lists cut")));
    Ok(())
}

/// Short names cost real memory too: 140 classes of 3,000 one-character methods must not
/// build a result of hundreds of MB.
#[test]
fn short_member_names_are_charged_their_real_cost() -> Result<()> {
    let dir = TempDir::new()?;
    let mut owned: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..140 {
        let mut b = ClassBuilder::new(&format!("p/S{i}"));
        for k in 0..3_000 {
            b = b.method(&format!("m{k}"), "()V", 1);
        }
        owned.push((format!("p/S{i}.class"), b.build()));
    }
    let entries: Vec<(&str, &[u8])> = owned
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let path = write_zip(dir.path(), "short.jar", &entries);
    let (size, result) = serialized_size(&path)?;
    assert!(size < 40 * 1024 * 1024, "{size} bytes");
    let kept: usize = result.classes.iter().map(|c| c.methods.len()).sum();
    assert!(kept < 70_000, "{kept}");
    assert!(result.classes.iter().all(|c| c.method_count() == 3_000));
    assert!(result.warnings.iter().any(|w| w.contains("passed")));
    Ok(())
}

/// A throws list cut at the per-method cap is worded as that, not as a byte-budget cut.
#[test]
fn throws_cut_is_described_correctly() -> Result<()> {
    let dir = TempDir::new()?;
    let names: Vec<String> = (0..200).map(|i| format!("p/E{i}")).collect();
    let throws: Vec<&str> = names.iter().map(String::as_str).collect();
    let class = ClassBuilder::new("p/T")
        .method_with_code("m", "()V", 1, 1, &throws)
        .build();
    let path = write_zip(dir.path(), "t.jar", &[("p/T.class", &class)]);
    let result = analyze_java_path(&path)?;
    let warning = result.classes[0].parse_warning.as_deref().unwrap_or("");
    assert!(
        warning.contains("throws lists cut at 64 entries"),
        "{warning}"
    );
    assert!(!warning.contains("393216"), "{warning}");
    Ok(())
}

fn apk_with(dir: &Path, name: &str, events: &[AxmlEvent]) -> std::path::PathBuf {
    let manifest = axml(events);
    write_zip(
        dir,
        name,
        &[
            ("AndroidManifest.xml", &manifest),
            ("classes.dex", b"dex\n035\0"),
        ],
    )
}

/// Filler cannot hide a sensitive permission: after 2,000 other permissions, and after the
/// text budget is used up, READ_SMS and SEND_SMS are still reported and the level is not Low.
#[test]
fn sensitive_permissions_survive_the_manifest_caps() -> Result<()> {
    let dir = TempDir::new()?;
    let mut events: Vec<AxmlEvent> = vec![Some(("manifest", vec![("package", Av::Str("com.x"))]))];
    for i in 0..2_100 {
        events.push(Some((
            "uses-permission",
            vec![("name", Av::Text(format!("com.filler.P{i}")))],
        )));
        events.push(None);
    }
    for p in ["READ_SMS", "SEND_SMS"] {
        events.push(Some((
            "uses-permission",
            vec![("name", Av::Text(format!("android.permission.{p}")))],
        )));
        events.push(None);
    }
    events.push(None);
    let result = analyze_java_path(&apk_with(dir.path(), "perms.apk", &events))?;
    let suspicious = &result.security_analysis.suspicious_permissions;
    assert!(
        suspicious.iter().any(|p| p.ends_with("READ_SMS")),
        "{suspicious:?}"
    );
    assert!(suspicious.iter().any(|p| p.ends_with("SEND_SMS")));
    assert!(result.security_analysis.threat_level >= SecurityThreatLevel::Medium);

    // 60,000 filler elements use up the 4 MiB text budget before the permissions.
    let mut events: Vec<AxmlEvent> = vec![Some(("manifest", vec![("package", Av::Str("com.x"))]))];
    for i in 0..60_000 {
        events.push(Some((
            "meta-data",
            vec![("name", Av::Text(format!("k{i}")))],
        )));
        events.push(None);
    }
    for p in ["READ_SMS", "SEND_SMS"] {
        events.push(Some((
            "uses-permission",
            vec![("name", Av::Text(format!("android.permission.{p}")))],
        )));
        events.push(None);
    }
    events.push(None);
    let result = analyze_java_path(&apk_with(dir.path(), "budget.apk", &events))?;
    let android = result.android_manifest.as_ref().unwrap();
    assert!(android.partial, "{:?}", android.notes);
    let suspicious = &result.security_analysis.suspicious_permissions;
    assert!(
        suspicious.iter().any(|p| p.ends_with("READ_SMS")),
        "{suspicious:?}"
    );
    assert!(result.security_analysis.threat_level >= SecurityThreatLevel::Medium);

    // A partly read manifest is never rated "nothing found", whatever it holds.
    let mut events: Vec<AxmlEvent> = vec![Some(("manifest", vec![("package", Av::Str("com.x"))]))];
    for i in 0..60_000 {
        events.push(Some((
            "meta-data",
            vec![("name", Av::Text(format!("k{i}")))],
        )));
        events.push(None);
    }
    events.push(None);
    let result = analyze_java_path(&apk_with(dir.path(), "partial.apk", &events))?;
    assert!(result.security_analysis.threat_level >= SecurityThreatLevel::Medium);
    assert!(result
        .security_analysis
        .threat_basis
        .iter()
        .all(|b| !b.contains("no dangerous API references")));
    Ok(())
}

// ---------------------------------------------------------------------------
// Round 3 repair: constant work per pool entry, bounded API lists, permissions that
// cannot be pushed out, and content that was not read is never rated Low.
// ---------------------------------------------------------------------------

/// A name of 65,535 `[` named by tens of thousands of constants, in 20 classes, must not
/// cost a scan per constant (it cost 85 s of CPU in 9 KB of JAR before).
#[test]
fn long_array_names_cost_constant_work() -> Result<()> {
    let dir = TempDir::new()?;
    let brackets = "[".repeat(65_535);
    let classes = ClassBuilder::new("p/B")
        .repeated_classes(&brackets, 60_000)
        .build();
    let refs = ClassBuilder::new("p/R")
        .repeated_method_refs(&brackets, "m", "()V", 30_000)
        .build();
    let names: Vec<String> = (0..20).map(|i| format!("p/B{i}.class")).collect();
    let rnames: Vec<String> = (0..20).map(|i| format!("p/R{i}.class")).collect();
    let mut entries: Vec<(&str, &[u8])> = Vec::new();
    for n in &names {
        entries.push((n.as_str(), classes.as_slice()));
    }
    for n in &rnames {
        entries.push((n.as_str(), refs.as_slice()));
    }
    let path = write_zip(dir.path(), "brackets.jar", &entries);
    let started = std::time::Instant::now();
    let result = analyze_java_path(&path)?;
    let took = started.elapsed();
    assert!(took.as_secs() < 8, "took {took:?}");
    assert_eq!(result.classes.len(), 40);
    assert!(result
        .classes
        .iter()
        .all(|c| c.referenced_classes.iter().all(|r| r == "java.lang.Object")));
    Ok(())
}

/// InnerClasses entries that name the class itself add nothing and cost nothing.
#[test]
fn self_naming_inner_classes_cost_constant_work() -> Result<()> {
    let dir = TempDir::new()?;
    let me: Vec<&str> = (0..65_000).map(|_| "p/Me").collect();
    let class = ClassBuilder::new("p/Me").inner_classes(&me).build();
    let names: Vec<String> = (0..480).map(|i| format!("p/Me{i}.class")).collect();
    let entries: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), class.as_slice()))
        .collect();
    let path = write_zip(dir.path(), "self.jar", &entries);
    let started = std::time::Instant::now();
    let result = analyze_java_path(&path)?;
    assert!(started.elapsed().as_secs() < 8, "{:?}", started.elapsed());
    assert!(result.classes.iter().all(|c| c.inner_classes.is_empty()));
    Ok(())
}

/// Per-class dangerous-API lists are charged to a budget; later classes only feed the
/// aggregated findings, which stay exact.
#[test]
fn dangerous_api_lists_are_budgeted_and_findings_stay_exact() -> Result<()> {
    let dir = TempDir::new()?;
    let mut b = ClassBuilder::new("p/S");
    for i in 0..100 {
        b = b.calls(
            "sun/misc/Unsafe",
            &format!("{i:03}{}", "n".repeat(500)),
            "()V",
        );
    }
    let class = b.build();
    let names: Vec<String> = (0..1_200).map(|i| format!("p/S{i}.class")).collect();
    let entries: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), class.as_slice()))
        .collect();
    let path = write_zip(dir.path(), "apis.jar", &entries);
    let (size, result) = serialized_size(&path)?;
    assert!(size < 40 * 1024 * 1024, "{size} bytes");
    let kept: usize = result.classes.iter().map(|c| c.dangerous_apis.len()).sum();
    assert!(kept < 40_000, "{kept} rows kept");
    assert!(result.classes.iter().any(|c| c.dangerous_apis.is_empty()
        && c.parse_warning
            .as_deref()
            .is_some_and(|w| w.contains("dangerous-API list dropped"))));
    assert!(result.warnings.iter().any(|w| w.contains("dangerous-API")));
    let findings = &result.security_analysis.api_findings;
    assert_eq!(findings.len(), 100);
    assert!(findings.iter().all(|f| f.class_count == 1_200));
    assert!(findings.iter().all(|f| f.api.len() < 300));
    Ok(())
}

fn permission_events(fillers: usize, fakes: usize, tail: &[&str]) -> Vec<AxmlEvent> {
    let mut events: Vec<AxmlEvent> = vec![Some(("manifest", vec![("package", Av::Str("com.x"))]))];
    let mut add = |name: String| {
        events.push(Some(("uses-permission", vec![("name", Av::Text(name))])));
        events.push(None);
    };
    for i in 0..fillers {
        add(format!("com.filler.P{i}"));
    }
    for i in 0..fakes {
        add(format!("com.f{i}.CAMERA"));
    }
    for p in tail {
        add(format!("android.permission.{p}"));
    }
    events.push(None);
    events
}

/// Fake sensitive-looking names use up the heuristic slots; the exact dangerous names are
/// always kept, and a cut list is never reported as "nothing found".
#[test]
fn fake_sensitive_permissions_cannot_hide_real_ones() -> Result<()> {
    let dir = TempDir::new()?;
    let events = permission_events(
        2_000,
        500,
        &["READ_SMS", "SEND_SMS", "BIND_ACCESSIBILITY_SERVICE"],
    );
    let result = analyze_java_path(&apk_with(dir.path(), "fake.apk", &events))?;
    let suspicious = &result.security_analysis.suspicious_permissions;
    for p in ["READ_SMS", "SEND_SMS", "BIND_ACCESSIBILITY_SERVICE"] {
        assert!(
            suspicious.iter().any(|s| s.ends_with(p)),
            "{p}: {suspicious:?}"
        );
    }
    assert!(result.security_analysis.threat_level >= SecurityThreatLevel::Medium);

    // Past the heuristic slots the list is cut: that alone lifts the rating and says so.
    let events = permission_events(2_000, 700, &[]);
    let result = analyze_java_path(&apk_with(dir.path(), "cut.apk", &events))?;
    let android = result.android_manifest.as_ref().unwrap();
    assert!(android.permissions_dropped > 0);
    assert!(result.security_analysis.threat_level >= SecurityThreatLevel::Medium);
    assert!(!result
        .security_analysis
        .threat_basis
        .iter()
        .any(|b| b.contains("no dangerous API references")));
    Ok(())
}

/// A class whose attribute is bigger than the read cap keeps what its constant pool says.
#[test]
fn padded_class_keeps_its_findings() -> Result<()> {
    let dir = TempDir::new()?;
    let class = ClassBuilder::new("p/Evil")
        .calls("java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;")
        .calls(
            "java/lang/Runtime",
            "exec",
            "(Ljava/lang/String;)Ljava/lang/Process;",
        )
        .padding_attribute("Pad", 9 * 1024 * 1024)
        .build();
    let path = write_zip(dir.path(), "padded.jar", &[("p/Evil.class", &class)]);
    let result = analyze_java_path(&path)?;
    assert_eq!(result.classes.len(), 1);
    assert!(result
        .security_analysis
        .api_findings
        .iter()
        .any(|f| f.category == "process_exec"));
    assert!(result.security_analysis.threat_level >= SecurityThreatLevel::Medium);
    assert!(result.classes[0]
        .parse_warning
        .as_deref()
        .is_some_and(|w| w.contains("only the first")));
    Ok(())
}

/// Content that was not read is never rated Low with "nothing found".
#[test]
fn unread_content_is_never_rated_low() -> Result<()> {
    let dir = TempDir::new()?;
    let not_low = |result: &JavaAnalysisResult| {
        assert!(
            result.security_analysis.threat_level >= SecurityThreatLevel::Medium,
            "{:?}",
            result.security_analysis.threat_basis
        );
        assert!(!result
            .security_analysis
            .threat_basis
            .iter()
            .any(|b| b.contains("no dangerous API references")));
    };

    // A class file that cannot be parsed.
    let path = write_zip(
        dir.path(),
        "bad.jar",
        &[("p/Bad.class", b"\xCA\xFE\xBA\xBE\0\0\0\x34\0")],
    );
    not_low(&analyze_java_path(&path)?);

    // A manifest over the read cap.
    let mut manifest =
        b"<manifest package=\"x\"><uses-permission name=\"android.permission.SEND_SMS\"/><!--"
            .to_vec();
    manifest.resize(9 * 1024 * 1024, b'a');
    manifest.extend(b"--></manifest>");
    let path = write_zip(dir.path(), "big.apk", &[("AndroidManifest.xml", &manifest)]);
    not_low(&analyze_java_path(&path)?);

    // A manifest that does not parse.
    let path = write_zip(
        dir.path(),
        "garbage.apk",
        &[("AndroidManifest.xml", b"garbage")],
    );
    not_low(&analyze_java_path(&path)?);

    // The 501st nested archive is not opened.
    let inner = zip_bytes(&[("p/A.class", &minimal_class("p/A"))]);
    let names: Vec<String> = (0..501).map(|i| format!("lib/n{i}.jar")).collect();
    let entries: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), inner.as_slice()))
        .collect();
    let path = write_zip(dir.path(), "many.war", &entries);
    let result = analyze_java_path(&path)?;
    assert_eq!(result.nested_opened_total, 500);
    not_low(&result);
    Ok(())
}

/// Sets the ZIP "encrypted" flag (general-purpose bit 0) on the entry called `name`, in
/// both its local and its central header, leaving the data as it was.
fn set_encryption_flag(zip: &mut [u8], name: &str) {
    let needle = name.as_bytes();
    let mut at = 0;
    while at + 46 < zip.len() {
        let is_local = zip[at..].starts_with(b"PK\x03\x04");
        let is_central = zip[at..].starts_with(b"PK\x01\x02");
        if is_local || is_central {
            let (flag_at, name_at, len_at) = if is_local {
                (at + 6, at + 30, at + 26)
            } else {
                (at + 8, at + 46, at + 28)
            };
            let len = usize::from(u16::from_le_bytes([zip[len_at], zip[len_at + 1]]));
            if &zip[name_at..name_at + len] == needle {
                zip[flag_at] |= 1;
            }
        }
        at += 1;
    }
}

/// A 10-byte class that declares 65,534 constant-pool slots and holds none.
fn stub_pool_class() -> Vec<u8> {
    let mut stub = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 61];
    stub.extend(0xFFFFu16.to_be_bytes());
    stub
}

/// A constant pool is never allocated from its declared size, and classes that fail to
/// parse are charged to the work budget: 300,000 stubs in a nested JAR stay cheap.
#[test]
fn stub_classes_declaring_huge_pools_are_cheap_and_counted() -> Result<()> {
    let dir = TempDir::new()?;
    assert!(parse_class_bytes_fails(&stub_pool_class()));
    let stub = stub_pool_class();
    let names: Vec<String> = (0..300_000).map(|i| format!("p/S{i}.class")).collect();
    let entries: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), stub.as_slice()))
        .collect();
    let inner = zip_bytes(&entries);
    let path = write_zip(dir.path(), "stubs.jar", &[("lib/inner.jar", &inner)]);
    let started = std::time::Instant::now();
    let result = analyze_java_path(&path)?;
    let took = started.elapsed();
    // Before the fix this cost about 40 s: 130 microseconds of allocation per stub.
    assert!(took.as_secs() < 30, "took {took:?}");
    assert_eq!(result.unparsed_classes, 300_000);
    assert!(result.security_analysis.threat_level >= SecurityThreatLevel::Medium);
    Ok(())
}

fn parse_class_bytes_fails(bytes: &[u8]) -> bool {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("stub.class");
    std::fs::write(&path, bytes).unwrap();
    analyze_class_file(&path).is_err()
}

/// ZIP entry names are shortened once; 65,000-byte names cannot build a huge result.
#[test]
fn long_entry_names_are_clipped_once() -> Result<()> {
    let dir = TempDir::new()?;
    let class = minimal_class("p/A");
    let long: Vec<String> = (0..40)
        .map(|i| format!("{}{i}.class", "d/".repeat(32_000)))
        .collect();
    let long_jar: Vec<String> = (0..10)
        .map(|i| format!("{}{i}.jar", "e/".repeat(32_000)))
        .collect();
    let inner = zip_bytes(&[("p/B.class", &class)]);
    let mut entries: Vec<(&str, &[u8])> = long
        .iter()
        .map(|n| (n.as_str(), class.as_slice()))
        .collect();
    entries.extend(long_jar.iter().map(|n| (n.as_str(), inner.as_slice())));
    let path = write_zip(dir.path(), "names.jar", &entries);
    let (size, result) = serialized_size(&path)?;
    assert!(size < 400_000, "{size}");
    assert_eq!(result.classes_total, 50);
    for class in &result.classes {
        assert!(class.entry.len() < 1_100, "{}", class.entry.len());
        assert!(
            class.entry.ends_with(".class")
                || class.entry.ends_with(".jar")
                || !class.entry.is_empty()
        );
    }
    for row in &result.nested_archives {
        assert!(row.path.len() < 1_100);
    }
    assert!(result.nested_opened_total == 10);
    assert!(result.warnings.iter().any(|w| w.contains("shortened")));
    for resource in &result.resources {
        assert!(resource.path.len() < 1_100);
    }
    Ok(())
}

/// An EAR holding a WAR holding the dropper's JAR is read to the bottom.
#[test]
fn ear_war_jar_is_read_in_full() -> Result<()> {
    let dir = TempDir::new()?;
    let evil = zip_bytes(&[("com/acme/Evil.class", &runtime_exec_class("com/acme/Evil"))]);
    let war = zip_bytes(&[("WEB-INF/lib/evil.jar", &evil)]);
    let path = write_zip(
        dir.path(),
        "app.ear",
        &[
            ("META-INF/application.xml", b"<application/>"),
            ("app.war", &war),
        ],
    );
    let result = analyze_java_path(&path)?;
    assert!(result.classes.iter().any(|c| c.name == "com.acme.Evil"));
    assert!(result
        .security_analysis
        .api_findings
        .iter()
        .any(|f| f.category == "process_exec"));
    assert!(result.security_analysis.threat_level >= SecurityThreatLevel::High);
    assert_eq!(result.nested_opened_total, 2);
    Ok(())
}

/// Archives nested deeper than the limit are unread: Medium, a warning, an anomaly, and the
/// summary does not say nothing was found.
#[test]
fn archives_nested_too_deep_are_unread_not_clean() -> Result<()> {
    let dir = TempDir::new()?;
    let evil = zip_bytes(&[("com/acme/Evil.class", &runtime_exec_class("com/acme/Evil"))]);
    let l3 = zip_bytes(&[("lib/evil.jar", &evil)]);
    let l2 = zip_bytes(&[("lib/l3.jar", &l3)]);
    let l1 = zip_bytes(&[("lib/l2.jar", &l2)]);
    let path = write_zip(dir.path(), "deep.jar", &[("lib/l1.jar", &l1)]);
    let result = analyze_java_path(&path)?;
    let basis = result.security_analysis.threat_basis.join("; ");
    assert!(
        result.security_analysis.threat_level >= SecurityThreatLevel::Medium,
        "{basis}"
    );
    assert!(!basis.contains("no dangerous API references"), "{basis}");
    assert!(basis.contains("not opened"), "{basis}");
    assert!(result.warnings.iter().any(|w| w.contains("nested deeper")));
    assert!(!result.security_analysis.archive_anomalies.is_empty());
    Ok(())
}

/// An entry the ZIP reader refuses (here: the encryption flag) is never "nothing found".
#[test]
fn entries_the_zip_reader_refuses_are_unread_not_clean() -> Result<()> {
    let dir = TempDir::new()?;
    let evil_class = runtime_exec_class("com/acme/Evil");
    let evil_jar = zip_bytes(&[("com/acme/Evil.class", &evil_class)]);
    let manifest = axml(&[
        Some(("manifest", vec![("package", Av::Str("x.y"))])),
        Some((
            "uses-permission",
            vec![("name", Av::Str("android.permission.SEND_SMS"))],
        )),
        None,
        None,
    ]);
    type Case<'a> = (&'a str, Vec<(&'a str, Vec<u8>)>, &'a str);
    let cases: Vec<Case> = vec![
        (
            "flag_class.jar",
            vec![("com/acme/Evil.class", evil_class.clone())],
            "com/acme/Evil.class",
        ),
        (
            "flag_nested.war",
            vec![("WEB-INF/lib/evil.jar", evil_jar.clone())],
            "WEB-INF/lib/evil.jar",
        ),
        (
            "flag_manifest.apk",
            vec![("AndroidManifest.xml", manifest)],
            "AndroidManifest.xml",
        ),
    ];
    for (file, entries, flagged) in cases {
        let refs: Vec<(&str, &[u8])> = entries.iter().map(|(n, b)| (*n, b.as_slice())).collect();
        let mut bytes = zip_bytes(&refs);
        set_encryption_flag(&mut bytes, flagged);
        let path = dir.path().join(file);
        std::fs::write(&path, &bytes)?;
        let result = analyze_java_path(&path)?;
        let basis = result.security_analysis.threat_basis.join("; ");
        assert!(
            result.security_analysis.threat_level >= SecurityThreatLevel::Medium,
            "{file}: {basis}"
        );
        assert!(
            !basis.contains("no dangerous API references"),
            "{file}: {basis}"
        );
        assert!(
            result.warnings.iter().any(|w| w.contains(flagged)),
            "{file}: {:?}",
            result.warnings
        );
        assert!(
            result
                .security_analysis
                .archive_anomalies
                .iter()
                .any(|a| a.contains(flagged)),
            "{file}"
        );
    }
    // The same archive without the flag is read, and an ordinary clean one says how much.
    let clean = write_zip(
        dir.path(),
        "clean.jar",
        &[("p/A.class", &minimal_class("p/A"))],
    );
    let result = analyze_java_path(&clean)?;
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::Low
    );
    assert!(result
        .security_analysis
        .threat_basis
        .iter()
        .any(|b| b.contains("in the 1 entries read; 0 were not read")));
    Ok(())
}

/// Many references of a mild kind cannot push a severe API out of a class's rows.
#[test]
fn network_references_cannot_hide_runtime_exec() -> Result<()> {
    let dir = TempDir::new()?;
    let mut b = ClassBuilder::new("p/Many");
    let owners = [
        "java/net/Socket",
        "java/net/ServerSocket",
        "java/net/DatagramSocket",
        "java/net/MulticastSocket",
        "java/nio/channels/SocketChannel",
        "java/nio/channels/ServerSocketChannel",
        "java/nio/channels/DatagramChannel",
        "java/net/URLConnection",
        "java/net/HttpURLConnection",
        "javax/net/ssl/HttpsURLConnection",
        "java/net/http/HttpClient",
    ];
    let methods = [
        "<init>",
        "connect",
        "bind",
        "accept",
        "open",
        "getInputStream",
        "getOutputStream",
        "send",
        "sendAsync",
        "getResponseCode",
    ];
    let mut network = 0;
    for owner in owners {
        for method in methods {
            assert_eq!(classify_api(owner, method), Some("network"));
            b = b.calls(owner, method, "()V");
            network += 1;
        }
    }
    assert!(network > 100);
    let class = b
        .calls(
            "java/lang/Runtime",
            "exec",
            "(Ljava/lang/String;)Ljava/lang/Process;",
        )
        .build();
    let path = write_zip(dir.path(), "many.jar", &[("p/Many.class", &class)]);
    let result = analyze_java_path(&path)?;
    assert!(result
        .security_analysis
        .api_findings
        .iter()
        .any(|f| f.category == "process_exec"));
    assert!(result.security_analysis.threat_level >= SecurityThreatLevel::High);
    let class = &result.classes[0];
    assert!(class.dangerous_apis.len() <= 112);
    assert!(class
        .dangerous_apis
        .iter()
        .any(|a| a.category == "process_exec"));
    assert!(class
        .parse_warning
        .as_deref()
        .is_some_and(|w| w.contains("dangerous-API rows cut")));
    // The ordinary side: a class with few references is not marked.
    let plain = ClassBuilder::new("p/Plain")
        .calls("java/net/URL", "openConnection", "()V")
        .build();
    let path = write_zip(dir.path(), "plain.jar", &[("p/Plain.class", &plain)]);
    let result = analyze_java_path(&path)?;
    assert!(result.classes[0].parse_warning.is_none());
    assert!(!result
        .security_analysis
        .threat_basis
        .iter()
        .any(|b| b.contains("rows cut")));
    Ok(())
}

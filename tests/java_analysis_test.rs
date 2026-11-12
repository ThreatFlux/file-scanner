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
use java_class_builder::{axml, minimal_class, runtime_exec_class, zip_bytes, Av, ClassBuilder};
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

    // The basic implementation will not have permissions extracted from binary XML
    // but we can check the security analysis structure
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::Low
    );
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

    // EAR -> WAR (level 1) -> WEB-INF/lib/inner.jar (level 2): not opened.
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
    assert_eq!(names, vec!["w.Servlet"]);
    assert_eq!(result.nested_archives.len(), 2);
    let deep = result.nested_archives.iter().find(|n| !n.opened).unwrap();
    assert!(deep.path.ends_with("inner.jar"));
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

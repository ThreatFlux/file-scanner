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

use anyhow::Result;
use file_scanner::java_analysis::*;
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

    // Add a dummy class file
    zip.start_file("com/example/Main.class", SimpleFileOptions::default())?;
    // Minimal valid class file header
    zip.write_all(&[
        0xCA, 0xFE, 0xBA, 0xBE, // Magic number
        0x00, 0x00, // Minor version
        0x00, 0x37, // Major version (Java 11)
        0x00, 0x10, // Constant pool count
    ])?;

    // Add another class
    zip.start_file("com/example/Utils.class", SimpleFileOptions::default())?;
    zip.write_all(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x37, 0x00, 0x10])?;

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
    zip.write_all(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x37, 0x00, 0x10])?;

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

    // Write a minimal valid class file
    file.write_all(&[
        0xCA, 0xFE, 0xBA, 0xBE, // Magic number
        0x00, 0x00, // Minor version
        0x00, 0x37, // Major version (Java 11)
        0x00,
        0x10, // Constant pool count
              // ... rest would be constant pool, access flags, etc.
    ])?;

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
    // Resources include all files except the manifest which is parsed separately
    assert_eq!(result.resources.len(), 4);
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
    assert!(result.android_manifest.is_some());
    assert!(!result.certificates.is_empty());
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

    // Add a class file (even though we can't fully parse it in the basic implementation)
    zip.start_file(
        "com/example/DangerousCode.class",
        SimpleFileOptions::default(),
    )?;
    zip.write_all(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x37, 0x00, 0x10])?;

    zip.finish()?;

    let result = analyze_java_archive(&jar_path)?;

    // The basic implementation will not detect APIs from the binary class files
    // but we verify the structure is in place
    assert_eq!(result.security_analysis.dangerous_apis.len(), 0);
    assert_eq!(
        result.security_analysis.threat_level,
        SecurityThreatLevel::Low
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

    assert!(!result.certificates.is_empty());
    assert_eq!(
        result.security_analysis.code_signing_status,
        CodeSigningStatus::Signed
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

    // Test various extensions
    let test_cases = vec![
        ("test.jar", JavaArchiveType::Jar),
        ("test.war", JavaArchiveType::War),
        ("test.ear", JavaArchiveType::Ear),
        ("test.apk", JavaArchiveType::Apk),
        ("test.aar", JavaArchiveType::Aar),
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

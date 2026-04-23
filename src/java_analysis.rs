use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaAnalysisResult {
    pub archive_type: JavaArchiveType,
    pub manifest: Option<JavaManifest>,
    pub android_manifest: Option<AndroidManifest>,
    pub certificates: Vec<Certificate>,
    pub classes: Vec<ClassInfo>,
    pub resources: Vec<ResourceInfo>,
    pub permissions: Vec<String>,
    pub security_analysis: JavaSecurityAnalysis,
    pub metadata: JavaArchiveMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JavaArchiveType {
    Jar,       // Java Archive
    War,       // Web Application Archive
    Ear,       // Enterprise Application Archive
    Apk,       // Android Application Package
    Aar,       // Android Archive
    ClassFile, // Single Java class file
    Dex,       // Android Dalvik Executable
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaManifest {
    pub main_class: Option<String>,
    pub class_path: Vec<String>,
    pub implementation_title: Option<String>,
    pub implementation_version: Option<String>,
    pub implementation_vendor: Option<String>,
    pub specification_title: Option<String>,
    pub specification_version: Option<String>,
    pub specification_vendor: Option<String>,
    pub built_by: Option<String>,
    pub build_jdk: Option<String>,
    pub created_by: Option<String>,
    pub custom_attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidManifest {
    pub package_name: String,
    pub version_code: Option<u32>,
    pub version_name: Option<String>,
    pub min_sdk_version: Option<u32>,
    pub target_sdk_version: Option<u32>,
    pub compile_sdk_version: Option<u32>,
    pub permissions: Vec<String>,
    pub activities: Vec<AndroidComponent>,
    pub services: Vec<AndroidComponent>,
    pub receivers: Vec<AndroidComponent>,
    pub providers: Vec<AndroidComponent>,
    pub uses_features: Vec<String>,
    pub intent_filters: Vec<IntentFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidComponent {
    pub name: String,
    pub exported: bool,
    pub enabled: bool,
    pub intent_filters: Vec<IntentFilter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
    pub data_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub fingerprint_md5: String,
    pub fingerprint_sha1: String,
    pub fingerprint_sha256: String,
    pub is_self_signed: bool,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassInfo {
    pub name: String,
    pub package: String,
    pub access_flags: u16,
    pub super_class: Option<String>,
    pub interfaces: Vec<String>,
    pub methods: Vec<MethodInfo>,
    pub fields: Vec<FieldInfo>,
    pub is_public: bool,
    pub is_final: bool,
    pub is_abstract: bool,
    pub is_interface: bool,
    pub is_enum: bool,
    pub is_annotation: bool,
    pub source_file: Option<String>,
    pub inner_classes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodInfo {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
    pub is_public: bool,
    pub is_private: bool,
    pub is_protected: bool,
    pub is_static: bool,
    pub is_final: bool,
    pub is_synchronized: bool,
    pub is_native: bool,
    pub is_abstract: bool,
    pub parameter_count: u16,
    pub local_variable_count: u16,
    pub exception_table: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
    pub is_public: bool,
    pub is_private: bool,
    pub is_protected: bool,
    pub is_static: bool,
    pub is_final: bool,
    pub is_volatile: bool,
    pub is_transient: bool,
    pub constant_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub path: String,
    pub size: u64,
    pub is_compressed: bool,
    pub compression_method: String,
    pub crc32: u32,
    pub resource_type: ResourceType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResourceType {
    Image,
    Layout,
    String,
    Raw,
    Asset,
    Library,
    Configuration,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaSecurityAnalysis {
    pub threat_level: SecurityThreatLevel,
    pub suspicious_permissions: Vec<String>,
    pub dangerous_apis: Vec<String>,
    pub obfuscation_indicators: Vec<String>,
    pub security_vulnerabilities: Vec<SecurityVulnerability>,
    pub certificate_issues: Vec<String>,
    pub code_signing_status: CodeSigningStatus,
    pub privacy_concerns: Vec<String>,
    pub malware_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVulnerability {
    pub vulnerability_type: String,
    pub severity: SecurityThreatLevel,
    pub description: String,
    pub location: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CodeSigningStatus {
    Signed,
    Unsigned,
    InvalidSignature,
    ExpiredCertificate,
    SelfSigned,
    UnknownCA,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaArchiveMetadata {
    pub total_entries: usize,
    pub total_size: u64,
    pub compressed_size: u64,
    pub compression_ratio: f64,
    pub entry_count_by_type: HashMap<String, usize>,
    pub largest_entries: Vec<(String, u64)>,
    pub creation_time: Option<String>,
    pub modification_time: Option<String>,
}

/// Analyze a Java archive file (JAR/WAR/EAR/APK)
pub fn analyze_java_archive(file_path: &Path) -> Result<JavaAnalysisResult> {
    let file = std::fs::File::open(file_path)?;
    let mut archive = ZipArchive::new(file)?;

    let archive_type = detect_archive_type(file_path, &mut archive)?;

    let mut result = JavaAnalysisResult {
        archive_type: archive_type.clone(),
        manifest: None,
        android_manifest: None,
        certificates: Vec::new(),
        classes: Vec::new(),
        resources: Vec::new(),
        permissions: Vec::new(),
        security_analysis: JavaSecurityAnalysis {
            threat_level: SecurityThreatLevel::Low,
            suspicious_permissions: Vec::new(),
            dangerous_apis: Vec::new(),
            obfuscation_indicators: Vec::new(),
            security_vulnerabilities: Vec::new(),
            certificate_issues: Vec::new(),
            code_signing_status: CodeSigningStatus::Unsigned,
            privacy_concerns: Vec::new(),
            malware_indicators: Vec::new(),
        },
        metadata: JavaArchiveMetadata {
            total_entries: archive.len(),
            total_size: 0,
            compressed_size: 0,
            compression_ratio: 0.0,
            entry_count_by_type: HashMap::new(),
            largest_entries: Vec::new(),
            creation_time: None,
            modification_time: None,
        },
    };

    // Parse archive contents
    parse_archive_contents(&mut archive, &mut result)?;

    // Perform security analysis
    perform_security_analysis(&mut result);

    // Calculate metadata
    calculate_metadata(&mut result);

    Ok(result)
}

/// Analyze a single Java class file
pub fn analyze_class_file(file_path: &Path) -> Result<JavaAnalysisResult> {
    let class_data = std::fs::read(file_path)?;
    let class_info = parse_class_file(&class_data)?;

    let mut result = JavaAnalysisResult {
        archive_type: JavaArchiveType::ClassFile,
        manifest: None,
        android_manifest: None,
        certificates: Vec::new(),
        classes: vec![class_info],
        resources: Vec::new(),
        permissions: Vec::new(),
        security_analysis: JavaSecurityAnalysis {
            threat_level: SecurityThreatLevel::Low,
            suspicious_permissions: Vec::new(),
            dangerous_apis: Vec::new(),
            obfuscation_indicators: Vec::new(),
            security_vulnerabilities: Vec::new(),
            certificate_issues: Vec::new(),
            code_signing_status: CodeSigningStatus::Unsigned,
            privacy_concerns: Vec::new(),
            malware_indicators: Vec::new(),
        },
        metadata: JavaArchiveMetadata {
            total_entries: 1,
            total_size: class_data.len() as u64,
            compressed_size: class_data.len() as u64,
            compression_ratio: 1.0,
            entry_count_by_type: HashMap::from([("class".to_string(), 1)]),
            largest_entries: vec![(
                file_path.file_name().unwrap().to_string_lossy().to_string(),
                class_data.len() as u64,
            )],
            creation_time: None,
            modification_time: None,
        },
    };

    perform_security_analysis(&mut result);

    Ok(result)
}

fn detect_archive_type(
    file_path: &Path,
    archive: &mut ZipArchive<std::fs::File>,
) -> Result<JavaArchiveType> {
    // Check file extension first
    if let Some(extension) = file_path.extension() {
        match extension.to_str().unwrap_or("").to_lowercase().as_str() {
            "apk" => return Ok(JavaArchiveType::Apk),
            "aar" => return Ok(JavaArchiveType::Aar),
            "war" => return Ok(JavaArchiveType::War),
            "ear" => return Ok(JavaArchiveType::Ear),
            "jar" => return Ok(JavaArchiveType::Jar),
            "class" => return Ok(JavaArchiveType::ClassFile),
            "dex" => return Ok(JavaArchiveType::Dex),
            _ => {}
        }
    }

    // Collect file names first to avoid borrowing issues
    let mut file_names = Vec::new();
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        file_names.push(file.name().to_string());
    }

    // Check archive contents for more specific detection
    for name in &file_names {
        // Android-specific files
        if name == "AndroidManifest.xml" {
            return Ok(JavaArchiveType::Apk);
        }
        if name == "classes.dex" {
            return Ok(JavaArchiveType::Apk);
        }

        // Web application files
        if name.starts_with("WEB-INF/") {
            return Ok(JavaArchiveType::War);
        }

        // Enterprise application files
        if name.starts_with("META-INF/application.xml") {
            return Ok(JavaArchiveType::Ear);
        }

        // Android Archive Library files - check name pattern
        if name == "classes.jar" && file_names.iter().any(|f| f == "R.txt") {
            return Ok(JavaArchiveType::Aar);
        }
    }

    // Default to JAR if we find Java classes
    for name in &file_names {
        if name.ends_with(".class") {
            return Ok(JavaArchiveType::Jar);
        }
    }

    Ok(JavaArchiveType::Unknown)
}

fn parse_archive_contents(
    archive: &mut ZipArchive<std::fs::File>,
    result: &mut JavaAnalysisResult,
) -> Result<()> {
    let mut total_size = 0u64;
    let mut compressed_size = 0u64;
    let mut entry_sizes = Vec::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().to_string();

        total_size += file.size();
        compressed_size += file.compressed_size();
        entry_sizes.push((name.clone(), file.size()));

        // Count by type
        let extension = Path::new(&name)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("unknown")
            .to_lowercase();
        *result
            .metadata
            .entry_count_by_type
            .entry(extension)
            .or_insert(0) += 1;

        // Parse specific files
        match name.as_str() {
            "META-INF/MANIFEST.MF" => {
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                result.manifest = Some(parse_java_manifest(&contents)?);
            }
            "AndroidManifest.xml" => {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                result.android_manifest = Some(parse_android_manifest(&contents)?);
            }
            _ => {
                // Handle certificates
                if name.starts_with("META-INF/")
                    && (name.ends_with(".RSA") || name.ends_with(".DSA") || name.ends_with(".EC"))
                {
                    let mut cert_data = Vec::new();
                    file.read_to_end(&mut cert_data)?;
                    if let Ok(cert) = parse_certificate(&cert_data) {
                        result.certificates.push(cert);
                    }
                }

                // Handle class files
                if name.ends_with(".class") {
                    let mut class_data = Vec::new();
                    file.read_to_end(&mut class_data)?;
                    if let Ok(class_info) = parse_class_file(&class_data) {
                        result.classes.push(class_info);
                    }
                }

                // Handle resources
                let resource_type = classify_resource(&name);
                result.resources.push(ResourceInfo {
                    path: name,
                    size: file.size(),
                    is_compressed: file.compressed_size() < file.size(),
                    compression_method: format!("{:?}", file.compression()),
                    crc32: file.crc32(),
                    resource_type,
                });
            }
        }
    }

    // Update metadata
    result.metadata.total_size = total_size;
    result.metadata.compressed_size = compressed_size;
    result.metadata.compression_ratio = if total_size > 0 {
        compressed_size as f64 / total_size as f64
    } else {
        1.0
    };

    // Sort and keep largest entries
    entry_sizes.sort_by_key(|item| std::cmp::Reverse(item.1));
    result.metadata.largest_entries = entry_sizes.into_iter().take(10).collect();

    Ok(())
}

fn parse_java_manifest(contents: &str) -> Result<JavaManifest> {
    let mut manifest = JavaManifest {
        main_class: None,
        class_path: Vec::new(),
        implementation_title: None,
        implementation_version: None,
        implementation_vendor: None,
        specification_title: None,
        specification_version: None,
        specification_vendor: None,
        built_by: None,
        build_jdk: None,
        created_by: None,
        custom_attributes: HashMap::new(),
    };

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || !line.contains(':') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0].trim();
        let value = parts[1].trim();

        match key {
            "Main-Class" => manifest.main_class = Some(value.to_string()),
            "Class-Path" => {
                manifest.class_path = value.split_whitespace().map(|s| s.to_string()).collect()
            }
            "Implementation-Title" => manifest.implementation_title = Some(value.to_string()),
            "Implementation-Version" => manifest.implementation_version = Some(value.to_string()),
            "Implementation-Vendor" => manifest.implementation_vendor = Some(value.to_string()),
            "Specification-Title" => manifest.specification_title = Some(value.to_string()),
            "Specification-Version" => manifest.specification_version = Some(value.to_string()),
            "Specification-Vendor" => manifest.specification_vendor = Some(value.to_string()),
            "Built-By" => manifest.built_by = Some(value.to_string()),
            "Build-Jdk" => manifest.build_jdk = Some(value.to_string()),
            "Created-By" => manifest.created_by = Some(value.to_string()),
            _ => {
                manifest
                    .custom_attributes
                    .insert(key.to_string(), value.to_string());
            }
        }
    }

    Ok(manifest)
}

fn parse_android_manifest(_contents: &[u8]) -> Result<AndroidManifest> {
    // For now, return a minimal implementation
    // In a full implementation, this would parse the binary XML format
    Ok(AndroidManifest {
        package_name: "unknown".to_string(),
        version_code: None,
        version_name: None,
        min_sdk_version: None,
        target_sdk_version: None,
        compile_sdk_version: None,
        permissions: Vec::new(),
        activities: Vec::new(),
        services: Vec::new(),
        receivers: Vec::new(),
        providers: Vec::new(),
        uses_features: Vec::new(),
        intent_filters: Vec::new(),
    })
}

fn parse_certificate(_cert_data: &[u8]) -> Result<Certificate> {
    // Basic certificate parsing - in a full implementation this would use proper X.509 parsing
    Ok(Certificate {
        subject: "Unknown".to_string(),
        issuer: "Unknown".to_string(),
        serial_number: "Unknown".to_string(),
        not_before: "Unknown".to_string(),
        not_after: "Unknown".to_string(),
        signature_algorithm: "Unknown".to_string(),
        public_key_algorithm: "Unknown".to_string(),
        fingerprint_md5: "Unknown".to_string(),
        fingerprint_sha1: "Unknown".to_string(),
        fingerprint_sha256: "Unknown".to_string(),
        is_self_signed: false,
        key_usage: Vec::new(),
        extended_key_usage: Vec::new(),
    })
}

fn parse_class_file(class_data: &[u8]) -> Result<ClassInfo> {
    if class_data.len() < 10 {
        return Err(anyhow!("Invalid class file: too short"));
    }

    // Check magic number (0xCAFEBABE)
    if class_data[0..4] != [0xCA, 0xFE, 0xBA, 0xBE] {
        return Err(anyhow!("Invalid class file: bad magic number"));
    }

    // Basic parsing - in a full implementation this would parse the entire class file format
    let class_info = ClassInfo {
        name: "Unknown".to_string(),
        package: "unknown".to_string(),
        access_flags: 0,
        super_class: None,
        interfaces: Vec::new(),
        methods: Vec::new(),
        fields: Vec::new(),
        is_public: false,
        is_final: false,
        is_abstract: false,
        is_interface: false,
        is_enum: false,
        is_annotation: false,
        source_file: None,
        inner_classes: Vec::new(),
    };

    Ok(class_info)
}

fn classify_resource(name: &str) -> ResourceType {
    let path = Path::new(name);
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");

    match extension.to_lowercase().as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" => ResourceType::Image,
        "xml" if name.contains("layout") => ResourceType::Layout,
        "xml" if name.contains("values") => ResourceType::String,
        "so" | "dll" | "dylib" => ResourceType::Library,
        "properties" | "xml" | "json" => ResourceType::Configuration,
        _ => {
            if name.starts_with("res/") || name.starts_with("assets/") {
                ResourceType::Asset
            } else if name.starts_with("raw/") {
                ResourceType::Raw
            } else {
                ResourceType::Other
            }
        }
    }
}

fn perform_security_analysis(result: &mut JavaAnalysisResult) {
    let mut threat_level = SecurityThreatLevel::Low;

    // Analyze permissions (for Android)
    if let Some(android_manifest) = &result.android_manifest {
        for permission in &android_manifest.permissions {
            if is_dangerous_permission(permission) {
                result
                    .security_analysis
                    .suspicious_permissions
                    .push(permission.clone());
                if threat_level == SecurityThreatLevel::Low {
                    threat_level = SecurityThreatLevel::Medium;
                }
            }
        }
    }

    // Analyze classes for dangerous APIs
    for class in &result.classes {
        for method in &class.methods {
            if is_dangerous_api(&method.name) {
                result
                    .security_analysis
                    .dangerous_apis
                    .push(format!("{}.{}", class.name, method.name));
                if threat_level == SecurityThreatLevel::Low {
                    threat_level = SecurityThreatLevel::Medium;
                }
            }
        }
    }

    // Analyze certificate status
    if result.certificates.is_empty() {
        result.security_analysis.code_signing_status = CodeSigningStatus::Unsigned;
        result
            .security_analysis
            .certificate_issues
            .push("Application is not signed".to_string());
    } else {
        result.security_analysis.code_signing_status = CodeSigningStatus::Signed;
        for cert in &result.certificates {
            if cert.is_self_signed {
                result
                    .security_analysis
                    .certificate_issues
                    .push("Self-signed certificate detected".to_string());
                result.security_analysis.code_signing_status = CodeSigningStatus::SelfSigned;
            }
        }
    }

    result.security_analysis.threat_level = threat_level;
}

fn calculate_metadata(result: &mut JavaAnalysisResult) {
    // Metadata is mostly calculated during parsing, but we can add final touches here
    if let Some(manifest) = &result.manifest {
        if let Some(_created_by) = &manifest.created_by {
            // Parse creation time if available in Created-By field
            // This is a simplified implementation
        }
    }
}

fn is_dangerous_permission(permission: &str) -> bool {
    match permission {
        "android.permission.SEND_SMS"
        | "android.permission.CALL_PHONE"
        | "android.permission.READ_CONTACTS"
        | "android.permission.ACCESS_FINE_LOCATION"
        | "android.permission.CAMERA"
        | "android.permission.RECORD_AUDIO"
        | "android.permission.READ_EXTERNAL_STORAGE"
        | "android.permission.WRITE_EXTERNAL_STORAGE"
        | "android.permission.INSTALL_PACKAGES"
        | "android.permission.DELETE_PACKAGES"
        | "android.permission.SYSTEM_ALERT_WINDOW"
        | "android.permission.DEVICE_ADMIN" => true,
        _ => permission.contains("ADMIN") || permission.contains("ROOT"),
    }
}

fn is_dangerous_api(method_name: &str) -> bool {
    match method_name {
        "exec"
        | "getRuntime"
        | "loadLibrary"
        | "load"
        | "createClassLoader"
        | "defineClass"
        | "setSecurityManager"
        | "getSystemProperty"
        | "setSystemProperty"
        | "openFileOutput"
        | "openFileInput"
        | "getExternalStorageDirectory"
        | "getExternalFilesDir"
        | "sendTextMessage"
        | "sendMultipartTextMessage"
        | "startActivity"
        | "startService"
        | "sendBroadcast" => true,
        _ => {
            method_name.contains("reflect")
                || method_name.contains("invoke")
                || method_name.contains("crypto")
                || method_name.contains("cipher")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_jar() -> Result<(TempDir, std::path::PathBuf)> {
        let temp_dir = TempDir::new()?;
        let jar_path = temp_dir.path().join("test.jar");

        let file = std::fs::File::create(&jar_path)?;
        let mut zip = zip::ZipWriter::new(file);

        // Add manifest
        zip.start_file(
            "META-INF/MANIFEST.MF",
            zip::write::SimpleFileOptions::default(),
        )?;
        zip.write_all(b"Manifest-Version: 1.0\nMain-Class: com.example.Main\n")?;

        // Add a dummy class file
        zip.start_file(
            "com/example/Main.class",
            zip::write::SimpleFileOptions::default(),
        )?;
        zip.write_all(&[0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x37])?; // Java 7 class file header

        zip.finish()?;
        Ok((temp_dir, jar_path))
    }

    #[test]
    fn test_detect_archive_type_jar() {
        let (_temp_dir, jar_path) = create_test_jar().unwrap();
        let file = std::fs::File::open(&jar_path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();

        let archive_type = detect_archive_type(&jar_path, &mut archive).unwrap();
        assert_eq!(archive_type, JavaArchiveType::Jar);
    }

    #[test]
    fn test_parse_java_manifest() {
        let manifest_content =
            "Manifest-Version: 1.0\nMain-Class: com.example.Main\nImplementation-Title: Test App\n";
        let manifest = parse_java_manifest(manifest_content).unwrap();

        assert_eq!(manifest.main_class, Some("com.example.Main".to_string()));
        assert_eq!(manifest.implementation_title, Some("Test App".to_string()));
    }

    #[test]
    fn test_classify_resource() {
        assert_eq!(classify_resource("icon.png"), ResourceType::Image);
        assert_eq!(classify_resource("layout/main.xml"), ResourceType::Layout);
        assert_eq!(classify_resource("lib/native.so"), ResourceType::Library);
        assert_eq!(
            classify_resource("config.properties"),
            ResourceType::Configuration
        );
        assert_eq!(classify_resource("assets/data.txt"), ResourceType::Asset);
    }

    #[test]
    fn test_dangerous_permission_detection() {
        assert!(is_dangerous_permission("android.permission.SEND_SMS"));
        assert!(is_dangerous_permission("android.permission.CAMERA"));
        assert!(!is_dangerous_permission("android.permission.INTERNET"));
        assert!(is_dangerous_permission("android.permission.DEVICE_ADMIN"));
    }

    #[test]
    fn test_dangerous_api_detection() {
        assert!(is_dangerous_api("exec"));
        assert!(is_dangerous_api("loadLibrary"));
        assert!(is_dangerous_api("sendTextMessage"));
        assert!(!is_dangerous_api("toString"));
        assert!(is_dangerous_api("reflectMethod"));
    }

    #[test]
    fn test_security_threat_levels() {
        assert_eq!(SecurityThreatLevel::Low, SecurityThreatLevel::Low);
        assert_ne!(SecurityThreatLevel::Low, SecurityThreatLevel::High);
    }

    #[test]
    fn test_java_archive_types() {
        assert_eq!(JavaArchiveType::Jar, JavaArchiveType::Jar);
        assert_ne!(JavaArchiveType::Jar, JavaArchiveType::Apk);
    }
}

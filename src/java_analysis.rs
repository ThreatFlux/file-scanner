//! Static analysis of Java class files and archives (JAR/WAR/EAR/AAR/APK).
//!
//! Class files are parsed for real (constant pool, this/super class, interfaces,
//! fields, methods, `SourceFile`), and the dangerous-API findings come from the
//! constant pool's class and method references. Archives are read within hard
//! byte caps; an entry that cannot be read is reported in `warnings` and the scan
//! goes on. Nested archives (`classes.jar` in an AAR, `WEB-INF/lib/*.jar`, EAR
//! modules) are opened one level deep.
//!
//! What is not done, and is said so in `limitations`: signatures are listed but not
//! verified, `classes.dex` is not parsed.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{Cursor, Read, Seek};
use std::path::Path;
use zip::ZipArchive;

#[cfg(test)]
#[path = "java_analysis/test_class_builder.rs"]
pub(crate) mod test_class_builder;

/// Largest class file that is parsed (declared size).
pub const MAX_CLASS_BYTES: u64 = 8 * 1024 * 1024;
/// Largest `MANIFEST.MF` that is read.
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
/// Largest `AndroidManifest.xml` that is read.
pub const MAX_ANDROID_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
/// Largest nested archive that is opened.
pub const MAX_NESTED_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
/// Decompressed bytes read in one analysis, nested archives included.
pub const MAX_TOTAL_READ_BYTES: u64 = 256 * 1024 * 1024;
/// A declared entry size above this, or an extreme ratio, is reported as an anomaly.
pub const ANOMALY_ENTRY_BYTES: u64 = 16 * 1024 * 1024;
/// Most classes kept from one analysis.
pub const MAX_CLASSES: usize = 100_000;
/// Most resource rows kept from one analysis.
pub const MAX_RESOURCES: usize = 50_000;
/// Most nested archives opened in one analysis.
pub const MAX_NESTED_ARCHIVES: usize = 500;
/// Nested-archive rows kept in a result (rows for archives left unopened count too).
pub const MAX_NESTED_ROWS: usize = 5_000;
/// Most per-class references (classes, methods) kept.
pub const MAX_REFS_PER_CLASS: usize = 4_000;
/// Most warnings kept; the rest are counted.
pub const MAX_WARNINGS: usize = 50;
/// Class and resource rows the legacy (`analyze_java_archive`) result keeps.
pub const LEGACY_LIST_CAP: usize = 25;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaAnalysisResult {
    pub archive_type: JavaArchiveType,
    #[serde(default)]
    pub manifest: Option<JavaManifest>,
    #[serde(default)]
    pub android_manifest: Option<AndroidManifest>,
    /// Always empty: signature blocks are not decoded. See `signature_files`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<Certificate>,
    /// META-INF signature files found (`*.SF`, `*.RSA`, `*.DSA`, `*.EC`), not verified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature_files: Vec<String>,
    #[serde(default)]
    pub classes: Vec<ClassInfo>,
    #[serde(default)]
    pub resources: Vec<ResourceInfo>,
    /// Classes found (the `classes` list may hold fewer after `bounded`).
    #[serde(default)]
    pub classes_total: usize,
    /// Resource rows found (the `resources` list may hold fewer after `bounded`).
    #[serde(default)]
    pub resources_total: usize,
    /// Class entries that could not be parsed.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unparsed_classes: usize,
    /// Class files per Java version, e.g. `Java 8 (major 52)`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub java_versions: BTreeMap<String, usize>,
    /// `classes.dex` files present. They are not parsed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dex_files: Vec<NamedSize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nested_archives: Vec<NestedArchive>,
    /// Nested-archive entries found (`nested_archives` holds at most [`MAX_NESTED_ROWS`]).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub nested_total: usize,
    /// Nested archives actually opened (counted apart from the capped row list).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub nested_opened_total: usize,
    pub permissions: Vec<String>,
    pub security_analysis: JavaSecurityAnalysis,
    pub metadata: JavaArchiveMetadata,
    /// Problems met while reading (undecodable entries, caps hit). The scan went on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Warnings dropped after the first `MAX_WARNINGS`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub warnings_suppressed: usize,
    /// What this analysis does not cover.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
pub struct NamedSize {
    pub path: String,
    pub size: u64,
}

/// An archive inside the analyzed archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NestedArchive {
    pub path: String,
    pub size: u64,
    pub opened: bool,
    #[serde(default)]
    pub entries: usize,
    #[serde(default)]
    pub classes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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
    /// Every other main-section header.
    pub custom_attributes: BTreeMap<String, String>,
    /// Per-entry sections after the main section (digests in signed JARs).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub entry_sections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidManifest {
    pub package_name: String,
    pub version_code: Option<u32>,
    pub version_name: Option<String>,
    pub min_sdk_version: Option<u32>,
    pub target_sdk_version: Option<u32>,
    pub compile_sdk_version: Option<u32>,
    #[serde(default)]
    pub debuggable: Option<bool>,
    pub permissions: Vec<String>,
    pub activities: Vec<AndroidComponent>,
    pub services: Vec<AndroidComponent>,
    pub receivers: Vec<AndroidComponent>,
    pub providers: Vec<AndroidComponent>,
    pub uses_features: Vec<String>,
    /// Not filled: each component carries its own filters.
    pub intent_filters: Vec<IntentFilter>,
    /// What the parser left out (budget cuts, shortened values); empty when nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// The manifest text budget ran out, so later elements were not read in full (only
    /// sensitive permissions are still picked up).
    #[serde(default, skip_serializing_if = "is_false")]
    pub partial: bool,
    /// Permissions declared but not kept because a list cap was reached (never one of the
    /// exact dangerous permissions, which are always kept).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub permissions_dropped: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidComponent {
    pub name: String,
    /// `android:exported` when present; otherwise true when the component has an
    /// intent filter (the pre-Android-12 default).
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

/// Kept for compatibility; signature blocks are not decoded, so none is produced.
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
    /// Dotted binary name, e.g. `com.example.Hello`.
    pub name: String,
    /// Package of the class; empty for the default package.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub package: String,
    pub access_flags: u16,
    pub super_class: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<MethodInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldInfo>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_public: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_final: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_abstract: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_interface: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_enum: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_annotation: bool,
    pub source_file: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inner_classes: Vec<String>,
    /// Archive entry the class came from (empty for a bare class file).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub entry: String,
    /// Nested archive the entry is in, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default)]
    pub major_version: u16,
    #[serde(default)]
    pub minor_version: u16,
    /// `Java 8 (major 52)`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub java_version: String,
    /// Dangerous APIs the constant pool references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dangerous_apis: Vec<ApiRef>,
    /// Classes the constant pool names (dotted, sorted; capped).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub referenced_classes: Vec<String>,
    /// Methods the constant pool references: `owner.name(descriptor)` (sorted; capped).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub method_refs: Vec<String>,
    /// Set when the class parsed only in part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_warning: Option<String>,
    /// Declared methods in the file, set only when `methods` was cut by the detail budget.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub methods_total: usize,
    /// Declared fields in the file, set only when `fields` was cut.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub fields_total: usize,
    /// Declared interfaces in the file, set only when `interfaces` was cut.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub interfaces_total: usize,
    /// InnerClasses entries in the file, set only when `inner_classes` was cut.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub inner_classes_total: usize,
}

impl ClassInfo {
    /// Methods the class declares (the real count, also when the list was cut).
    pub fn method_count(&self) -> usize {
        self.methods_total.max(self.methods.len())
    }
    /// Fields the class declares (the real count, also when the list was cut).
    pub fn field_count(&self) -> usize {
        self.fields_total.max(self.fields.len())
    }
    /// Interfaces the class names (the real count, also when the list was cut).
    pub fn interface_count(&self) -> usize {
        self.interfaces_total.max(self.interfaces.len())
    }
    /// Bytes this class's member lists are charged against the archive-wide budget.
    fn detail_bytes(&self) -> usize {
        let strings = |v: &[String]| v.iter().map(|s| s.len() + STRING_OVERHEAD).sum::<usize>();
        strings(&self.interfaces)
            + strings(&self.inner_classes)
            + self
                .methods
                .iter()
                .map(|m| {
                    MEMBER_OVERHEAD
                        + m.name.len()
                        + m.descriptor.len()
                        + strings(&m.exception_table)
                })
                .sum::<usize>()
            + self
                .fields
                .iter()
                .map(|f| {
                    MEMBER_OVERHEAD
                        + f.name.len()
                        + f.descriptor.len()
                        + f.constant_value.as_ref().map_or(0, String::len)
                })
                .sum::<usize>()
    }
}

/// One dangerous API a class references.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApiRef {
    pub category: String,
    pub api: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodInfo {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_public: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_private: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_protected: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_static: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_final: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_synchronized: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_native: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_abstract: bool,
    pub parameter_count: u16,
    pub local_variable_count: u16,
    /// Exceptions in the `throws` clause.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exception_table: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub descriptor: String,
    pub access_flags: u16,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_public: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_private: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_protected: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_static: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_final: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_volatile: bool,
    #[serde(default, skip_serializing_if = "is_false")]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    /// Why the threat level is what it is (the findings that set it).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub threat_basis: Vec<String>,
    pub suspicious_permissions: Vec<String>,
    /// Distinct dangerous APIs referenced (see `api_findings` for the class counts).
    pub dangerous_apis: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_findings: Vec<ApiFinding>,
    pub obfuscation_indicators: Vec<String>,
    pub security_vulnerabilities: Vec<SecurityVulnerability>,
    pub certificate_issues: Vec<String>,
    pub code_signing_status: CodeSigningStatus,
    pub privacy_concerns: Vec<String>,
    pub malware_indicators: Vec<String>,
    /// Archive anomalies: oversized or extreme-ratio entries, data before the ZIP, unreadable parts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub archive_anomalies: Vec<String>,
}

/// A dangerous API and how many classes use it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiFinding {
    pub category: String,
    pub api: String,
    pub severity: SecurityThreatLevel,
    pub class_count: usize,
    pub example_classes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CodeSigningStatus {
    /// Never produced any more: nothing here verifies a signature.
    Signed,
    Unsigned,
    InvalidSignature,
    ExpiredCertificate,
    SelfSigned,
    UnknownCA,
    /// META-INF signature files exist; nothing was verified.
    SignatureFilesPresentUnverified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JavaArchiveMetadata {
    pub total_entries: usize,
    pub total_size: u64,
    pub compressed_size: u64,
    pub compression_ratio: f64,
    pub entry_count_by_type: BTreeMap<String, usize>,
    pub largest_entries: Vec<(String, u64)>,
    pub creation_time: Option<String>,
    pub modification_time: Option<String>,
}

impl JavaAnalysisResult {
    /// The result cut for a consumer that embeds it whole: at most `max` classes and
    /// resources, and no per-class reference lists. `classes_total` and
    /// `resources_total` keep the real counts.
    #[must_use]
    pub fn bounded(mut self, max: usize) -> Self {
        self.classes.truncate(max);
        for class in &mut self.classes {
            class.referenced_classes = Vec::new();
            class.method_refs = Vec::new();
        }
        self.resources.truncate(max);
        self
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// What a file's first bytes say it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JavaInputKind {
    Archive,
    Class,
    Dex,
    Other,
}

/// Decide class-versus-archive by content, never by extension.
pub fn sniff_java_input(path: &Path) -> Result<JavaInputKind> {
    let mut head = [0u8; 8];
    let mut file = std::fs::File::open(path)?;
    let n = file.read(&mut head)?;
    let head = &head[..n];
    if head.len() >= 4 && head[0] == b'P' && head[1] == b'K' && matches!(head[2], 3 | 5 | 7) {
        return Ok(JavaInputKind::Archive);
    }
    if head.len() >= 8 && head[..4] == [0xCA, 0xFE, 0xBA, 0xBE] {
        // A Mach-O fat header has the same magic; its next u32 is a small arch count.
        let major = u16::from_be_bytes([head[6], head[7]]);
        if (45..=120).contains(&major) {
            return Ok(JavaInputKind::Class);
        }
    }
    if head.len() >= 4 && &head[..4] == b"dex\n" {
        return Ok(JavaInputKind::Dex);
    }
    // A ZIP may carry a prefix (launcher script, stub); its central directory still opens.
    if ZipArchive::new(std::fs::File::open(path)?).is_ok() {
        return Ok(JavaInputKind::Archive);
    }
    Ok(JavaInputKind::Other)
}

/// Analyze a Java file whatever its extension: archive, class file, or an error that
/// says what the file looks like instead. Returns the full result (all classes).
pub fn analyze_java_path(path: &Path) -> Result<JavaAnalysisResult> {
    match sniff_java_input(path)? {
        JavaInputKind::Archive => analyze_java_archive_full(path),
        // A class file followed by a JAR opens as a JAR through the central directory.
        JavaInputKind::Class
            if std::fs::File::open(path)
                .ok()
                .is_some_and(|f| ZipArchive::new(f).is_ok()) =>
        {
            analyze_java_archive_full(path)
        }
        JavaInputKind::Class => analyze_class_file_full(path),
        JavaInputKind::Dex => Err(anyhow!(
            "This is a Dalvik DEX file; DEX is not supported by analyze_java_file. Analyze the \
             enclosing APK to see its manifest, or use analyze_file for hashes and strings."
        )),
        JavaInputKind::Other => Err(anyhow!(
            "Not a Java archive or class file: it is neither a ZIP (JAR/WAR/EAR/AAR/APK) nor a \
             class file (magic CAFEBABE with a Java version). Use analyze_file to identify it."
        )),
    }
}

/// Analyze a Java archive file (JAR/WAR/EAR/APK/AAR). The lists are cut to
/// [`LEGACY_LIST_CAP`] entries; use [`analyze_java_archive_full`] for everything.
pub fn analyze_java_archive(file_path: &Path) -> Result<JavaAnalysisResult> {
    Ok(analyze_java_archive_full(file_path)?.bounded(LEGACY_LIST_CAP))
}

/// Analyze a single Java class file (lists cut like [`analyze_java_archive`]).
pub fn analyze_class_file(file_path: &Path) -> Result<JavaAnalysisResult> {
    Ok(analyze_class_file_full(file_path)?.bounded(LEGACY_LIST_CAP))
}

/// Analyze a Java archive; every class and resource is in the result.
pub fn analyze_java_archive_full(file_path: &Path) -> Result<JavaAnalysisResult> {
    let file = std::fs::File::open(file_path)?;
    let mut archive = ZipArchive::new(file).map_err(|error| {
        anyhow!(
            "ZIP archive is damaged or cut short ({error}); analyze_file can still give its \
             hashes and strings."
        )
    })?;
    let names = entry_names(&mut archive);
    let archive_type = detect_archive_type_from_names(&names);

    let mut scanner = Scanner::new(archive_type, archive.len());
    if archive.offset() > 0 {
        scanner.warn(format!(
            "ZIP data starts {} bytes into the file (launcher script, stub or other prefix)",
            archive.offset()
        ));
        scanner.anomaly(format!(
            "ZIP data starts {} bytes into the file",
            archive.offset()
        ));
    }
    scanner.scan_archive(&mut archive, None, 0);
    Ok(scanner.finish())
}

/// Analyze a single Java class file; its class is the only entry.
pub fn analyze_class_file_full(file_path: &Path) -> Result<JavaAnalysisResult> {
    let size = std::fs::metadata(file_path)?.len();
    if size > MAX_CLASS_BYTES {
        return Err(anyhow!(
            "Class file is {size} bytes; the limit is {MAX_CLASS_BYTES} bytes."
        ));
    }
    let class_data = std::fs::read(file_path)?;
    let (class_info, class_end) = parse_class_file_ending(&class_data, false).map_err(|error| {
        anyhow!(
            "Class file is damaged or cut short ({error}); analyze_file can still give its \
             hashes and strings."
        )
    })?;

    let mut scanner = Scanner::new(JavaArchiveType::ClassFile, 1);
    if let Some(end) = class_end.filter(|end| *end < class_data.len()) {
        let trailing = class_data.len() - end;
        scanner.warn(format!(
            "{trailing} bytes follow the end of the class file and were not analyzed"
        ));
        scanner.anomaly(format!("{trailing} bytes after the end of the class file"));
    }
    scanner.result.metadata.total_size = class_data.len() as u64;
    scanner.result.metadata.compressed_size = class_data.len() as u64;
    scanner.result.metadata.compression_ratio = 1.0;
    scanner
        .result
        .metadata
        .entry_count_by_type
        .insert("class".to_string(), 1);
    // Named from the class itself so the result does not depend on the file's name.
    let entry = format!("{}.class", class_info.name.replace('.', "/"));
    scanner.result.metadata.largest_entries = vec![(entry.clone(), class_data.len() as u64)];
    let mut class_info = class_info;
    class_info.entry = entry;
    scanner.fold_apis(&class_info);
    scanner.result.classes.push(class_info);
    scanner.class_count = 1;
    Ok(scanner.finish())
}

fn entry_names<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Vec<String> {
    let mut names = Vec::with_capacity(archive.len().min(100_000));
    for i in 0..archive.len() {
        match archive.by_index_raw(i) {
            Ok(file) => names.push(entry_name(&file)),
            Err(_) => names.push(String::new()),
        }
    }
    names
}

fn entry_name<R: Read>(file: &zip::read::ZipFile<'_, R>) -> String {
    match file.name() {
        Ok(name) => name.into_owned(),
        Err(_) => String::from_utf8_lossy(file.name_raw()).into_owned(),
    }
}

/// The archive kind, decided by the entry names alone (never by the file name, so the
/// same bytes always give the same answer and the cached result is path-independent).
fn detect_archive_type_from_names(file_names: &[String]) -> JavaArchiveType {
    let has = |wanted: &str| file_names.iter().any(|n| n == wanted);
    if has("classes.dex") {
        return JavaArchiveType::Apk;
    }
    if has("classes.jar") && (has("R.txt") || has("AndroidManifest.xml")) {
        return JavaArchiveType::Aar;
    }
    if has("AndroidManifest.xml") {
        return JavaArchiveType::Apk;
    }
    if file_names.iter().any(|n| n.starts_with("WEB-INF/")) {
        return JavaArchiveType::War;
    }
    if file_names
        .iter()
        .any(|n| n.starts_with("META-INF/application.xml"))
    {
        return JavaArchiveType::Ear;
    }
    if has("META-INF/MANIFEST.MF") || file_names.iter().any(|n| n.ends_with(".class")) {
        return JavaArchiveType::Jar;
    }
    JavaArchiveType::Unknown
}

// ---------------------------------------------------------------------------
// Archive scanning
// ---------------------------------------------------------------------------

struct Scanner {
    result: JavaAnalysisResult,
    remaining: u64,
    class_count: usize,
    nested_opened: usize,
    total_size: u64,
    compressed_size: u64,
    entry_sizes: Vec<(String, u64)>,
    budget_warned: bool,
    class_cap_warned: bool,
    resource_cap_warned: bool,
    ref_bytes: usize,
    ref_count: usize,
    ref_budget_warned: bool,
    detail_bytes: usize,
    detail_budget_warned: bool,
    nested_rows_warned: bool,
    /// Pool entries and declared members visited so far (see [`MAX_WORK_UNITS`]).
    work: u64,
    work_warned: bool,
    api_bytes: usize,
    api_warned: bool,
    fixed_bytes: usize,
    fixed_warned: bool,
    facts: ScanFacts,
}

/// What the scan saw that the final security analysis needs, kept compact and independent
/// of which per-class lists were shed to stay within the memory budgets.
struct ScanFacts {
    /// Every dangerous API with its class count and up to five example classes.
    api_groups: BTreeMap<(String, String), (usize, Vec<String>)>,
    /// Distinct APIs that did not fit [`MAX_API_GROUPS`], and the worst severity among them.
    groups_dropped: usize,
    dropped_severity: SecurityThreatLevel,
    /// First class with the downloader / dropper shape.
    dropper: Option<String>,
    /// Nested archives not opened because of a cap, the read budget or damage.
    nested_unread: usize,
    /// `AndroidManifest.xml` was present but not read or not understood.
    manifest_unread: bool,
}

impl Scanner {
    fn new(archive_type: JavaArchiveType, total_entries: usize) -> Self {
        Self {
            result: JavaAnalysisResult {
                archive_type,
                manifest: None,
                android_manifest: None,
                certificates: Vec::new(),
                signature_files: Vec::new(),
                classes: Vec::new(),
                resources: Vec::new(),
                classes_total: 0,
                resources_total: 0,
                unparsed_classes: 0,
                java_versions: BTreeMap::new(),
                dex_files: Vec::new(),
                nested_archives: Vec::new(),
                nested_total: 0,
                nested_opened_total: 0,
                permissions: Vec::new(),
                security_analysis: JavaSecurityAnalysis {
                    threat_level: SecurityThreatLevel::Low,
                    threat_basis: Vec::new(),
                    suspicious_permissions: Vec::new(),
                    dangerous_apis: Vec::new(),
                    api_findings: Vec::new(),
                    obfuscation_indicators: Vec::new(),
                    security_vulnerabilities: Vec::new(),
                    certificate_issues: Vec::new(),
                    code_signing_status: CodeSigningStatus::Unsigned,
                    privacy_concerns: Vec::new(),
                    malware_indicators: Vec::new(),
                    archive_anomalies: Vec::new(),
                },
                metadata: JavaArchiveMetadata {
                    total_entries,
                    total_size: 0,
                    compressed_size: 0,
                    compression_ratio: 0.0,
                    entry_count_by_type: BTreeMap::new(),
                    largest_entries: Vec::new(),
                    creation_time: None,
                    modification_time: None,
                },
                warnings: Vec::new(),
                warnings_suppressed: 0,
                limitations: Vec::new(),
            },
            remaining: MAX_TOTAL_READ_BYTES,
            class_count: 0,
            nested_opened: 0,
            total_size: 0,
            compressed_size: 0,
            entry_sizes: Vec::new(),
            budget_warned: false,
            class_cap_warned: false,
            resource_cap_warned: false,
            ref_bytes: 0,
            ref_count: 0,
            ref_budget_warned: false,
            detail_bytes: 0,
            detail_budget_warned: false,
            nested_rows_warned: false,
            work: 0,
            work_warned: false,
            api_bytes: 0,
            api_warned: false,
            fixed_bytes: 0,
            fixed_warned: false,
            facts: ScanFacts {
                api_groups: BTreeMap::new(),
                groups_dropped: 0,
                dropped_severity: SecurityThreatLevel::Low,
                dropper: None,
                nested_unread: 0,
                manifest_unread: false,
            },
        }
    }

    /// Adds a class's dangerous APIs to the aggregated findings (every class, whether or
    /// not its own list is kept) and checks the dropper shape.
    fn fold_apis(&mut self, class: &ClassInfo) {
        for api in &class.dangerous_apis {
            let key = (api.category.clone(), api.api.clone());
            if let Some(entry) = self.facts.api_groups.get_mut(&key) {
                entry.0 += 1;
                if entry.1.len() < 5 {
                    entry.1.push(class.name.clone());
                }
            } else if self.facts.api_groups.len() < MAX_API_GROUPS {
                self.facts
                    .api_groups
                    .insert(key, (1, vec![class.name.clone()]));
            } else {
                self.facts.groups_dropped += 1;
                self.facts.dropped_severity = self
                    .facts
                    .dropped_severity
                    .max(category_severity(&api.category));
            }
        }
        if self.facts.dropper.is_none() {
            let has = |category: &str| class.dangerous_apis.iter().any(|a| a.category == category);
            if has("network")
                && (has("process_exec") || has("native_loading"))
                && has("class_loading")
            {
                self.facts.dropper = Some(class.name.clone());
            }
        }
    }

    fn warn(&mut self, message: String) {
        if self.result.warnings.len() < MAX_WARNINGS {
            self.result.warnings.push(message);
        } else {
            self.result.warnings_suppressed += 1;
        }
    }

    fn anomaly(&mut self, message: String) {
        if self.result.security_analysis.archive_anomalies.len() < MAX_WARNINGS {
            self.result
                .security_analysis
                .archive_anomalies
                .push(message);
        }
    }

    /// Reads at most `cap` bytes of an entry (and never more than the total budget
    /// left). `None` when the entry is over the cap, the budget is gone or reading fails.
    fn read_entry<R: Read>(
        &mut self,
        file: &mut R,
        declared: u64,
        cap: u64,
        what: &str,
        truncate: bool,
    ) -> Option<Vec<u8>> {
        if declared > cap {
            if !truncate {
                self.warn(format!(
                    "{what}: declares {declared} bytes, over the {cap}-byte read cap; not read"
                ));
                return None;
            }
            self.warn(format!(
                "{what}: declares {declared} bytes, over the {cap}-byte read cap; only the \
                 first {cap} bytes were read"
            ));
        }
        if self.remaining == 0 {
            if !self.budget_warned {
                self.budget_warned = true;
                self.warn(format!(
                    "Read budget of {MAX_TOTAL_READ_BYTES} decompressed bytes used up; \
                     later entries were not parsed"
                ));
            }
            return None;
        }
        let limit = cap.min(self.remaining);
        let mut buf = Vec::new();
        match Read::by_ref(file).take(limit).read_to_end(&mut buf) {
            Ok(n) => {
                self.remaining = self.remaining.saturating_sub(n as u64);
                Some(buf)
            }
            Err(error) => {
                self.warn(format!("{what}: could not be read ({error}); skipped"));
                None
            }
        }
    }

    fn scan_archive<R: Read + Seek>(
        &mut self,
        archive: &mut ZipArchive<R>,
        container: Option<&str>,
        depth: u8,
    ) {
        for i in 0..archive.len() {
            let raw_name = archive
                .by_index_raw(i)
                .map_or_else(|_| format!("#{i}"), |f| entry_name(&f));
            let mut file = match archive.by_index(i) {
                Ok(file) => file,
                Err(error) => {
                    self.warn(format!(
                        "Entry {raw_name} could not be opened ({error}); skipped"
                    ));
                    continue;
                }
            };
            let name = entry_name(&file);
            let size = file.size();
            let packed = file.compressed_size();
            let label = container.map_or_else(|| name.clone(), |c| format!("{c}!{name}"));

            if depth == 0 {
                self.total_size = self.total_size.saturating_add(size);
                self.compressed_size = self.compressed_size.saturating_add(packed);
                self.entry_sizes.push((name.clone(), size));
                let extension = if name.ends_with('/') {
                    "dir".to_string()
                } else {
                    Path::new(&name)
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .unwrap_or("unknown")
                        .to_lowercase()
                };
                *self
                    .result
                    .metadata
                    .entry_count_by_type
                    .entry(extension)
                    .or_insert(0) += 1;
            }
            if size > ANOMALY_ENTRY_BYTES || (size > 1024 * 1024 && size / packed.max(1) > 1000) {
                self.anomaly(format!(
                    "{label}: declares {size} bytes from {packed} compressed ({}:1)",
                    size / packed.max(1)
                ));
            }
            if name.ends_with('/') {
                continue;
            }

            if depth == 0 {
                if self.result.resources.len() < MAX_RESOURCES {
                    self.result.resources.push(ResourceInfo {
                        path: name.clone(),
                        size,
                        is_compressed: packed < size,
                        compression_method: format!("{:?}", file.compression()),
                        crc32: file.crc32(),
                        resource_type: classify_resource(&name),
                    });
                } else if !self.resource_cap_warned {
                    self.resource_cap_warned = true;
                    self.warn(format!(
                        "More than {MAX_RESOURCES} entries; the resource list stops there"
                    ));
                }
                self.result.resources_total += 1;
            }

            let lower = name.to_ascii_lowercase();
            if depth == 0 && name == "META-INF/MANIFEST.MF" {
                if let Some(bytes) =
                    self.read_entry(&mut file, size, MAX_MANIFEST_BYTES, &label, false)
                {
                    if std::str::from_utf8(&bytes).is_err() {
                        self.warn(
                            "META-INF/MANIFEST.MF is not valid UTF-8; undecodable bytes were \
                             replaced with U+FFFD"
                                .to_string(),
                        );
                    }
                    self.result.manifest = Some(parse_java_manifest_bytes(&bytes));
                }
                continue;
            }
            if depth == 0 && name == "AndroidManifest.xml" {
                let read =
                    self.read_entry(&mut file, size, MAX_ANDROID_MANIFEST_BYTES, &label, false);
                if read.is_none() {
                    self.facts.manifest_unread = true;
                    self.result.limitations.push(
                        "AndroidManifest.xml was not read (over the size cap, budget used up \
                         or unreadable); package, permissions and components are unknown"
                            .to_string(),
                    );
                }
                if let Some(bytes) = read {
                    match parse_android_manifest(&bytes) {
                        Ok(manifest) => {
                            for note in manifest.notes.clone() {
                                self.warn(format!("AndroidManifest.xml: {note}"));
                            }
                            self.result.android_manifest = Some(manifest);
                        }
                        Err(error) => {
                            self.facts.manifest_unread = true;
                            self.result.limitations.push(format!(
                                "AndroidManifest.xml was not parsed ({error}); package, \
                                 permissions and components are unknown"
                            ));
                        }
                    }
                }
                continue;
            }
            if depth == 0 && is_signature_file(&lower) {
                self.result.signature_files.push(name.clone());
            }
            if lower.ends_with(".dex") && depth == 0 {
                self.result.dex_files.push(NamedSize {
                    path: name.clone(),
                    size,
                });
            }

            if lower.ends_with(".class") {
                self.scan_class(&mut file, &name, size, container, &label);
            } else if depth <= 1
                && (lower.ends_with(".jar")
                    || lower.ends_with(".war")
                    || lower.ends_with(".ear")
                    || lower.ends_with(".aar"))
            {
                self.open_nested(&mut file, &name, size, &label, depth);
            }
        }
    }

    fn scan_class<R: Read>(
        &mut self,
        file: &mut R,
        name: &str,
        size: u64,
        container: Option<&str>,
        label: &str,
    ) {
        if self.class_count >= MAX_CLASSES {
            if !self.class_cap_warned {
                self.class_cap_warned = true;
                self.warn(format!(
                    "More than {MAX_CLASSES} classes; the rest were not parsed"
                ));
            }
            self.result.unparsed_classes += 1;
            return;
        }
        let Some(bytes) = self.read_entry(file, size, MAX_CLASS_BYTES, label, true) else {
            self.result.unparsed_classes += 1;
            return;
        };
        let light = self.work >= MAX_WORK_UNITS;
        match parse_class_file_ending(&bytes, light).map(|(class, _)| class) {
            Ok(mut class) => {
                class.entry = name.to_string();
                class.container = container.map(str::to_string);
                if size > MAX_CLASS_BYTES {
                    let note = format!(
                        "class is {size} bytes; only the first {MAX_CLASS_BYTES} were read \
                         (its constant pool was read in full)"
                    );
                    class.parse_warning = Some(match class.parse_warning.take() {
                        Some(w) => format!("{w}; {note}"),
                        None => note,
                    });
                }
                if light && !self.work_warned {
                    self.work_warned = true;
                    self.warn(format!(
                        "More than {MAX_WORK_UNITS} constant-pool entries and members were \
                         visited; later classes keep only counts and dangerous-API references"
                    ));
                }
                self.work += (class.method_count()
                    + class.field_count()
                    + class.interface_count()
                    + class.inner_classes_total.max(class.inner_classes.len()))
                    as u64
                    + class_pool_entries(&bytes);
                self.charge_class(&mut class);
                self.class_count += 1;
                self.result.classes.push(class);
            }
            Err(error) => {
                self.result.unparsed_classes += 1;
                self.warn(format!("{label}: not a readable class file ({error})"));
            }
        }
    }

    /// Folds a class into the aggregated findings, then charges what it keeps against the
    /// archive-wide budgets, shedding lists once a budget is used up.
    fn charge_class(&mut self, class: &mut ClassInfo) {
        self.fold_apis(class);
        let note_for = |class: &mut ClassInfo, note: &str| {
            class.parse_warning = Some(match class.parse_warning.take() {
                Some(w) => format!("{w}; {note}"),
                None => note.to_string(),
            });
        };

        let api_len: usize = class
            .dangerous_apis
            .iter()
            .map(|a| a.category.len() + a.api.len() + 2 * STRING_OVERHEAD)
            .sum();
        if self.api_bytes + api_len > MAX_API_BYTES_TOTAL {
            class.dangerous_apis.clear();
            note_for(
                class,
                "dangerous-API list dropped: archive-wide budget used up (view=findings still \
                 counts this class)",
            );
            if !self.api_warned {
                self.api_warned = true;
                self.warn(format!(
                    "Per-class dangerous-API lists passed {MAX_API_BYTES_TOTAL} bytes in total; \
                     later classes feed the findings but keep no list of their own"
                ));
            }
        } else {
            self.api_bytes += api_len;
        }

        let fixed_len = class.name.len()
            + class.package.len()
            + class.super_class.as_ref().map_or(0, String::len)
            + class.source_file.as_ref().map_or(0, String::len)
            + class.entry.len()
            + class.container.as_ref().map_or(0, String::len)
            + class.java_version.len()
            + 4 * STRING_OVERHEAD;
        if self.fixed_bytes + fixed_len > MAX_FIXED_BYTES_TOTAL {
            class.package.clear();
            class.super_class = None;
            class.source_file = None;
            if !self.fixed_warned {
                self.fixed_warned = true;
                self.warn(format!(
                    "Class names and entry paths passed {MAX_FIXED_BYTES_TOTAL} bytes in \
                     total; later classes omit package, super class and source file"
                ));
            }
        } else {
            self.fixed_bytes += fixed_len;
        }

        let ref_len: usize = class
            .referenced_classes
            .iter()
            .chain(class.method_refs.iter())
            .map(|s| s.len() + STRING_OVERHEAD)
            .sum();
        let ref_count = class.referenced_classes.len() + class.method_refs.len();
        if self.ref_bytes + ref_len > MAX_REF_BYTES_TOTAL
            || self.ref_count + ref_count > MAX_REF_COUNT_TOTAL
        {
            class.referenced_classes.clear();
            class.method_refs.clear();
            note_for(
                class,
                "reference lists dropped: archive-wide budget used up",
            );
            if !self.ref_budget_warned {
                self.ref_budget_warned = true;
                self.warn(format!(
                    "Class and method reference lists passed {MAX_REF_BYTES_TOTAL} \
                     bytes in total; later classes keep only their dangerous-API list"
                ));
            }
        } else {
            self.ref_bytes += ref_len;
            self.ref_count += ref_count;
        }

        let detail_len = class.detail_bytes();
        if self.detail_bytes + detail_len > MAX_DETAIL_BYTES_TOTAL {
            class.methods_total = class.method_count();
            class.fields_total = class.field_count();
            class.interfaces_total = class.interface_count();
            class.inner_classes_total = class.inner_classes_total.max(class.inner_classes.len());
            class.methods.clear();
            class.fields.clear();
            class.interfaces.clear();
            class.inner_classes.clear();
            note_for(class, "member lists dropped: archive-wide budget used up");
            if !self.detail_budget_warned {
                self.detail_budget_warned = true;
                self.warn(format!(
                    "Member lists (methods, fields, interfaces) passed \
                     {MAX_DETAIL_BYTES_TOTAL} bytes in total; later classes keep only \
                     their counts"
                ));
            }
        } else {
            self.detail_bytes += detail_len;
        }
    }

    /// Adds a nested-archive row, up to [`MAX_NESTED_ROWS`] (then it only warns, once).
    /// Returns the row's index when it was kept. The totals count every row.
    fn push_nested(&mut self, row: NestedArchive) -> Option<usize> {
        self.result.nested_total += 1;
        if row.opened {
            self.result.nested_opened_total += 1;
        }
        if self.result.nested_archives.len() < MAX_NESTED_ROWS {
            self.result.nested_archives.push(row);
            return Some(self.result.nested_archives.len() - 1);
        }
        if !self.nested_rows_warned {
            self.nested_rows_warned = true;
            self.warn(format!(
                "More than {MAX_NESTED_ROWS} nested-archive entries; the list stops there \
                 (counts.nested_archives and nested_archives_opened still count them all)"
            ));
        }
        None
    }

    fn open_nested<R: Read>(
        &mut self,
        file: &mut R,
        name: &str,
        size: u64,
        label: &str,
        depth: u8,
    ) {
        if depth >= 1 {
            self.push_nested(NestedArchive {
                path: label.to_string(),
                size,
                opened: false,
                entries: 0,
                classes: 0,
                note: Some("nested two levels deep; not opened".to_string()),
            });
            return;
        }
        if self.nested_opened >= MAX_NESTED_ARCHIVES {
            if self.nested_opened == MAX_NESTED_ARCHIVES {
                self.nested_opened += 1;
                self.warn(format!(
                    "More than {MAX_NESTED_ARCHIVES} nested archives; the rest were not opened"
                ));
            }
            self.facts.nested_unread += 1;
            self.push_nested(NestedArchive {
                path: label.to_string(),
                size,
                opened: false,
                entries: 0,
                classes: 0,
                note: Some("nested archive limit reached".to_string()),
            });
            return;
        }
        let mut nested = NestedArchive {
            path: name.to_string(),
            size,
            opened: false,
            entries: 0,
            classes: 0,
            note: None,
        };
        let Some(bytes) = self.read_entry(file, size, MAX_NESTED_ARCHIVE_BYTES, label, false)
        else {
            nested.note = Some(format!(
                "not opened: larger than {MAX_NESTED_ARCHIVE_BYTES} bytes or unreadable"
            ));
            self.facts.nested_unread += 1;
            self.push_nested(nested);
            return;
        };
        self.nested_opened += 1;
        let starts_with_pk = bytes.starts_with(b"PK");
        match ZipArchive::new(Cursor::new(bytes)) {
            Ok(mut inner) => {
                if inner.offset() > 0 {
                    self.warn(format!(
                        "{label}: ZIP data starts {} bytes into the nested archive",
                        inner.offset()
                    ));
                    self.anomaly(format!(
                        "{label}: ZIP data starts {} bytes into the nested archive",
                        inner.offset()
                    ));
                }
                nested.opened = true;
                nested.entries = inner.len();
                let before = self.class_count;
                // The row goes in first so it precedes the rows of archives inside it.
                let row = self.push_nested(nested.clone());
                self.scan_archive(&mut inner, Some(name), 1);
                if let Some(at) = row {
                    self.result.nested_archives[at].classes = self.class_count - before;
                }
                return;
            }
            Err(error) => {
                if starts_with_pk {
                    self.facts.nested_unread += 1;
                }
                nested.note = Some(if starts_with_pk {
                    format!("not opened: {error}")
                } else {
                    "not opened: not a ZIP archive".to_string()
                });
            }
        }
        self.push_nested(nested);
    }

    fn finish(mut self) -> JavaAnalysisResult {
        let result = &mut self.result;
        if result.archive_type != JavaArchiveType::ClassFile {
            result.metadata.total_size = self.total_size;
            result.metadata.compressed_size = self.compressed_size;
            result.metadata.compression_ratio = if self.total_size > 0 {
                self.compressed_size as f64 / self.total_size as f64
            } else {
                1.0
            };
            self.entry_sizes
                .sort_by_key(|item| std::cmp::Reverse(item.1));
            result.metadata.largest_entries = self.entry_sizes.into_iter().take(10).collect();
        }
        result.classes_total = result.classes.len();
        let partial = result
            .classes
            .iter()
            .filter(|c| c.parse_warning.is_some())
            .count();
        if partial > 0 {
            let first = result
                .classes
                .iter()
                .find(|c| c.parse_warning.is_some())
                .map(|c| format!("{}: {}", c.name, c.parse_warning.as_deref().unwrap_or("")))
                .unwrap_or_default();
            let message = format!(
                "{partial} class(es) were only partly read or had reference lists cut; \
                 first: {first}"
            );
            if result.warnings.len() < MAX_WARNINGS {
                result.warnings.push(message);
            } else {
                result.warnings_suppressed += 1;
            }
        }
        for class in &result.classes {
            if !class.java_version.is_empty() {
                *result
                    .java_versions
                    .entry(class.java_version.clone())
                    .or_insert(0) += 1;
            }
        }
        if let Some(manifest) = &result.android_manifest {
            result.permissions = manifest.permissions.clone();
        }
        if self.total_size > MAX_TOTAL_READ_BYTES
            && self.total_size / self.compressed_size.max(1) > 100
        {
            let note = format!(
                "archive expands to {} bytes from {} compressed",
                self.total_size, self.compressed_size
            );
            result.security_analysis.archive_anomalies.push(note);
        }
        add_limitations(result);
        perform_security_analysis(result, &self.facts);
        self.result
    }
}

fn is_signature_file(lower_name: &str) -> bool {
    lower_name.strip_prefix("meta-inf/").is_some_and(|rest| {
        !rest.contains('/')
            && [".sf", ".rsa", ".dsa", ".ec"]
                .iter()
                .any(|ext| rest.ends_with(ext))
    })
}

fn add_limitations(result: &mut JavaAnalysisResult) {
    if !result.signature_files.is_empty() {
        result.limitations.push(
            "Signature files are listed, not verified: no signer, digest or validity is checked."
                .to_string(),
        );
    }
    if result.archive_type == JavaArchiveType::Apk {
        if !result.dex_files.is_empty() {
            result.limitations.push(
                "classes.dex is present but not parsed: code in DEX files is not analyzed, so \
                 API findings and the threat level cover only .class files and the manifest."
                    .to_string(),
            );
        }
        result.limitations.push(
            "APK v2/v3 signing blocks are not inspected; 'no signature files' means no META-INF \
             signature files only."
                .to_string(),
        );
    }
    if result.android_manifest.is_none()
        && matches!(
            result.archive_type,
            JavaArchiveType::Apk | JavaArchiveType::Aar
        )
        && !result
            .limitations
            .iter()
            .any(|l| l.starts_with("AndroidManifest.xml"))
    {
        result
            .limitations
            .push("AndroidManifest.xml was not found or not read; permissions and components are unknown.".to_string());
    }
}

// ---------------------------------------------------------------------------
// MANIFEST.MF
// ---------------------------------------------------------------------------

fn parse_java_manifest_bytes(bytes: &[u8]) -> JavaManifest {
    parse_java_manifest_text(&String::from_utf8_lossy(bytes))
}

fn parse_java_manifest(contents: &str) -> Result<JavaManifest> {
    Ok(parse_java_manifest_text(contents))
}

/// Parses the main section (up to the first blank line), unfolding continuation lines
/// (a line starting with one space continues the previous header), and counts the
/// per-entry sections after it.
fn parse_java_manifest_text(contents: &str) -> JavaManifest {
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
        custom_attributes: BTreeMap::new(),
        entry_sections: 0,
    };

    // Split into sections of unfolded header lines.
    let normalized = contents.replace("\r\n", "\n").replace('\r', "\n");
    let mut sections: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    for line in normalized.split('\n') {
        if line.is_empty() {
            if !current.is_empty() {
                sections.push(std::mem::take(&mut current));
            }
        } else if let Some(rest) = line.strip_prefix(' ') {
            if let Some(last) = current.last_mut() {
                last.push_str(rest);
            }
        } else {
            current.push(line.to_string());
        }
    }
    if !current.is_empty() {
        sections.push(current);
    }
    if sections.is_empty() {
        return manifest;
    }
    manifest.entry_sections = sections.len() - 1;

    for line in &sections[0] {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "main-class" => manifest.main_class = Some(value.to_string()),
            "class-path" => {
                manifest.class_path = value
                    .split_whitespace()
                    .map(std::string::ToString::to_string)
                    .collect();
            }
            "implementation-title" => manifest.implementation_title = Some(value.to_string()),
            "implementation-version" => manifest.implementation_version = Some(value.to_string()),
            "implementation-vendor" => manifest.implementation_vendor = Some(value.to_string()),
            "specification-title" => manifest.specification_title = Some(value.to_string()),
            "specification-version" => manifest.specification_version = Some(value.to_string()),
            "specification-vendor" => manifest.specification_vendor = Some(value.to_string()),
            "built-by" => manifest.built_by = Some(value.to_string()),
            "build-jdk" => manifest.build_jdk = Some(value.to_string()),
            "created-by" => manifest.created_by = Some(value.to_string()),
            _ => {
                manifest
                    .custom_attributes
                    .insert(key.to_string(), value.to_string());
            }
        }
    }
    manifest
}

// ---------------------------------------------------------------------------
// Class files
// ---------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| anyhow!("truncated at byte {}", self.pos))?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

#[derive(Clone)]
enum Cp {
    Empty,
    Utf8(String),
    Integer(i32),
    Long(i64),
    Class(u16),
    Str(u16),
    /// Field, method or interface-method reference: (class index, name-and-type index,
    /// true for a method).
    Ref(u16, u16, bool),
    NameAndType(u16, u16),
    Other,
}

struct Pool(Vec<Cp>);

impl Pool {
    fn utf8(&self, index: u16) -> Option<&str> {
        match self.0.get(usize::from(index)) {
            Some(Cp::Utf8(s)) => Some(s),
            _ => None,
        }
    }
    fn class_name(&self, index: u16) -> Option<&str> {
        match self.0.get(usize::from(index)) {
            Some(Cp::Class(n)) => self.utf8(*n),
            _ => None,
        }
    }
}

/// Java version for a class-file major number.
fn java_version_label(major: u16, minor: u16) -> String {
    let name = match major {
        45 => "1.1".to_string(),
        46 => "1.2".to_string(),
        47 => "1.3".to_string(),
        48 => "1.4".to_string(),
        m if m >= 49 => (m - 44).to_string(),
        m => format!("? (major {m})"),
    };
    let preview = if minor == 0xFFFF { " preview" } else { "" };
    format!("Java {name}{preview} (major {major})")
}

fn dotted(internal: &str) -> String {
    internal.replace('/', ".")
}

/// Constant-pool slot count a class file declares (0 when too short): the cost the work
/// counter charges for reading its pool.
fn class_pool_entries(bytes: &[u8]) -> u64 {
    bytes
        .get(8..10)
        .map_or(0, |b| u64::from(u16::from_be_bytes([b[0], b[1]])))
}

/// Class name for a `Class` constant: array classes name their element class. Constant
/// time: the JVM allows 255 array dimensions, so no more than 256 leading bytes are
/// looked at (a name of 65,000 `[` costs the same as `[[Lx;`). Deeper names give `None`.
fn element_class(name: &str) -> Option<&str> {
    let dims = name
        .as_bytes()
        .iter()
        .take(256)
        .take_while(|b| **b == b'[')
        .count();
    if dims == 0 {
        return Some(name);
    }
    if dims > 255 {
        return None;
    }
    name[dims..]
        .strip_prefix('L')
        .and_then(|s| s.strip_suffix(';'))
}

fn count_parameters(descriptor: &str) -> u16 {
    let Some(inner) = descriptor.strip_prefix('(') else {
        return 0;
    };
    let mut count = 0u16;
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            ')' => break,
            '[' => continue,
            'L' => {
                for d in chars.by_ref() {
                    if d == ';' {
                        break;
                    }
                }
                count = count.saturating_add(1);
            }
            _ => count = count.saturating_add(1),
        }
    }
    count
}

fn parse_class_file(class_data: &[u8]) -> Result<ClassInfo> {
    parse_class_file_ending(class_data, false).map(|(info, _)| info)
}

/// Parses a class file; also returns where the class ended when its tail was read in full.
fn parse_class_file_ending(class_data: &[u8], light: bool) -> Result<(ClassInfo, Option<usize>)> {
    if class_data.len() < 10 {
        return Err(anyhow!("Invalid class file: too short"));
    }
    if class_data[0..4] != [0xCA, 0xFE, 0xBA, 0xBE] {
        return Err(anyhow!("Invalid class file: bad magic number"));
    }
    let mut r = Reader {
        data: class_data,
        pos: 4,
    };
    let minor = r.u16()?;
    let major = r.u16()?;
    if !(45..=120).contains(&major) {
        return Err(anyhow!(
            "Invalid class file: unsupported major version {major}"
        ));
    }

    // Constant pool
    let count = usize::from(r.u16()?);
    if count == 0 {
        return Err(anyhow!("Invalid class file: empty constant pool"));
    }
    let mut pool = vec![Cp::Empty; count];
    let mut i = 1usize;
    while i < count {
        let tag = r.u8()?;
        pool[i] = match tag {
            1 => {
                let len = usize::from(r.u16()?);
                Cp::Utf8(String::from_utf8_lossy(r.take(len)?).into_owned())
            }
            3 => Cp::Integer(r.u32()? as i32),
            4 | 17 | 18 => {
                // Float; Dynamic and InvokeDynamic carry two u16s (4 bytes) as well.
                r.take(4)?;
                Cp::Other
            }
            5 | 6 => {
                let hi = u64::from(r.u32()?);
                let lo = u64::from(r.u32()?);
                pool[i] = if tag == 5 {
                    Cp::Long(((hi << 32) | lo) as i64)
                } else {
                    Cp::Other
                };
                i += 2; // longs and doubles take two slots
                continue;
            }
            7 => Cp::Class(r.u16()?),
            8 => Cp::Str(r.u16()?),
            9..=11 => {
                let class = r.u16()?;
                let nat = r.u16()?;
                Cp::Ref(class, nat, tag != 9)
            }
            12 => {
                let name = r.u16()?;
                let descriptor = r.u16()?;
                Cp::NameAndType(name, descriptor)
            }
            15 => {
                r.take(3)?;
                Cp::Other
            }
            16 | 19 | 20 => {
                r.take(2)?;
                Cp::Other
            }
            other => {
                return Err(anyhow!(
                    "Invalid class file: unknown constant pool tag {other} at entry {i}"
                ))
            }
        };
        i += 1;
    }
    let pool = Pool(pool);

    let mut info = ClassInfo {
        name: String::new(),
        package: String::new(),
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
        entry: String::new(),
        container: None,
        major_version: major,
        minor_version: minor,
        java_version: java_version_label(major, minor),
        dangerous_apis: Vec::new(),
        referenced_classes: Vec::new(),
        method_refs: Vec::new(),
        parse_warning: None,
        methods_total: 0,
        fields_total: 0,
        interfaces_total: 0,
        inner_classes_total: 0,
    };

    // Everything from the pool is available even if the rest is damaged.
    let (referenced, method_refs, apis, refs_cut) = collect_references(&pool, light);
    info.referenced_classes = referenced;
    info.method_refs = method_refs;
    info.dangerous_apis = apis;

    let tail = parse_class_tail(&mut r, &pool, &mut info, light);
    let end = tail.is_ok().then_some(r.pos);
    if info.name.is_empty() {
        return Err(tail
            .err()
            .unwrap_or_else(|| anyhow!("Invalid class file: this_class does not name a class")));
    }
    let mut notes: Vec<String> = info.parse_warning.take().into_iter().collect();
    if let Err(error) = tail {
        notes.push(format!("members not fully read: {error}"));
    } else if refs_cut && !light {
        notes.push(format!(
            "reference lists cut: more than {MAX_REF_BYTES_PER_CLASS} bytes of class or method \
             references, or more than {MAX_REFS_PER_CLASS} of them"
        ));
    }
    if !notes.is_empty() {
        info.parse_warning = Some(notes.join("; "));
    }
    let own = info.name.clone();
    info.referenced_classes.retain(|c| *c != own);
    if let Some((package, _)) = info.name.rsplit_once('.') {
        info.package = package.to_string();
    }
    Ok((info, end))
}

/// Longest owner, method name or descriptor kept in a reference string.
const MAX_REF_PART_CHARS: usize = 512;
/// Bytes of reference strings kept per class (classes and methods each).
const MAX_REF_BYTES_PER_CLASS: usize = 64 * 1024;
/// Most dangerous-API rows kept per class.
const MAX_API_REFS_PER_CLASS: usize = 100;
/// Longest owner or method name kept in a dangerous-API row.
const MAX_API_PART_CHARS: usize = 128;
/// Bytes of per-class dangerous-API rows kept across one analysis (later classes only
/// feed the aggregated findings).
const MAX_API_BYTES_TOTAL: usize = 4 * 1024 * 1024;
/// Distinct dangerous APIs kept in the aggregated findings.
const MAX_API_GROUPS: usize = 20_000;
/// Bytes of the fixed per-class strings (names, package, super, source file, warning)
/// kept across one analysis.
const MAX_FIXED_BYTES_TOTAL: usize = 24 * 1024 * 1024;
/// Constant-pool entries plus declared members visited across one analysis, after which
/// later classes are read in a light mode (dangerous APIs only).
const MAX_WORK_UNITS: u64 = 60_000_000;
/// Reference-string bytes kept across one whole analysis.
const MAX_REF_BYTES_TOTAL: usize = 16 * 1024 * 1024;

/// Longest member name or descriptor kept (longer ones are cut; the list says so).
const MAX_MEMBER_PART_CHARS: usize = 256;
/// Longest class name kept for `this`, super, interface, throws and inner-class names.
const MAX_CLASS_NAME_CHARS: usize = 512;
/// Bytes of member lists (interfaces, fields, methods, throws, inner classes) kept per class.
const MAX_CLASS_DETAIL_BYTES: usize = 2 * 1024 * 1024;
/// Member-list bytes kept across one whole analysis.
const MAX_DETAIL_BYTES_TOTAL: usize = 32 * 1024 * 1024;
/// Throws entries kept per method.
const MAX_THROWS_PER_METHOD: usize = 64;
/// Bytes charged for one field or method on top of its strings.
const MEMBER_OVERHEAD: usize = 512;
/// Bytes charged for one string in a list on top of its text.
const STRING_OVERHEAD: usize = 64;
/// InnerClasses entries visited per class, over all its attributes.
const MAX_INNER_VISITS: usize = 65_535;
/// Most class and method reference strings kept across one analysis.
const MAX_REF_COUNT_TOTAL: usize = 500_000;

/// Charges the member lists of one class against its byte budget.
struct DetailBudget {
    used: usize,
    /// The archive's work budget is used up: members are counted, not kept.
    light: bool,
    cut: bool,
    clipped: bool,
    /// Throws lists were cut at [`MAX_THROWS_PER_METHOD`] entries.
    throws_cut: bool,
    /// InnerClasses entries beyond [`MAX_INNER_VISITS`] were not read.
    inner_capped: bool,
}

impl DetailBudget {
    fn take(&mut self, bytes: usize) -> bool {
        if self.used + bytes > MAX_CLASS_DETAIL_BYTES {
            self.cut = true;
            false
        } else {
            self.used += bytes;
            true
        }
    }
    /// A name cut to `max` characters, noting when something was cut.
    fn name(&mut self, s: &str, max: usize) -> String {
        let clipped = clip_chars(s, max);
        if clipped.len() < s.len() {
            self.clipped = true;
        }
        clipped.to_string()
    }
}

/// `s` cut to at most `max` bytes, on a character boundary. Constant time: the cost
/// must not grow with the length of a name taken from the file.
fn clip_chars(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut at = max;
    while !s.is_char_boundary(at) {
        at -= 1;
    }
    &s[..at]
}

/// Returns the class, method and dangerous-API references of a constant pool, plus
/// whether any were left out because of the byte budgets. In `light` mode (the archive's
/// work budget is used up) only the dangerous APIs are collected.
///
/// Work per pool entry is constant: every name is looked at through [`clip_chars`], and an
/// entry that repeats a class or method already seen costs one set lookup.
fn collect_references(pool: &Pool, light: bool) -> (Vec<String>, Vec<String>, Vec<ApiRef>, bool) {
    let mut classes = BTreeSet::new();
    let mut methods = BTreeSet::new();
    let mut apis = BTreeSet::new();
    let mut seen_classes: HashSet<u16> = HashSet::new();
    let mut seen_refs: HashSet<(u16, u16)> = HashSet::new();
    let mut class_bytes = 0usize;
    let mut method_bytes = 0usize;
    let mut cut = false;
    for entry in &pool.0 {
        match entry {
            Cp::Class(_) if light => {}
            Cp::Class(name_index) => {
                if classes.len() >= MAX_REFS_PER_CLASS || class_bytes >= MAX_REF_BYTES_PER_CLASS {
                    // Past the budget: no lookup, no copy, no allocation.
                    cut = true;
                    continue;
                }
                if !seen_classes.insert(*name_index) {
                    continue;
                }
                if let Some(name) = pool.utf8(*name_index).and_then(element_class) {
                    let dotted_name = dotted(clip_chars(name, MAX_REF_PART_CHARS));
                    if class_bytes + dotted_name.len() <= MAX_REF_BYTES_PER_CLASS {
                        if classes.insert(dotted_name.clone()) {
                            class_bytes += dotted_name.len();
                        }
                    } else {
                        cut = true;
                    }
                }
            }
            Cp::Ref(class, nat, true) => {
                if !seen_refs.insert((*class, *nat)) {
                    continue;
                }
                let Some(owner) = pool.class_name(*class).and_then(element_class) else {
                    continue;
                };
                let Some(Cp::NameAndType(name, descriptor)) = pool.0.get(usize::from(*nat)) else {
                    continue;
                };
                let (Some(name), Some(descriptor)) = (pool.utf8(*name), pool.utf8(*descriptor))
                else {
                    continue;
                };
                let owner = clip_chars(owner, MAX_REF_PART_CHARS);
                let name = clip_chars(name, MAX_REF_PART_CHARS);
                let api_category = classify_api(owner, name);
                if (light || methods.len() >= MAX_REFS_PER_CLASS)
                    && api_category.is_none_or(|_| apis.len() >= MAX_API_REFS_PER_CLASS)
                {
                    cut = true;
                    continue;
                }
                let owner_dotted = dotted(owner);
                if !light {
                    let text = format!(
                        "{owner_dotted}.{name}{}",
                        clip_chars(descriptor, MAX_REF_PART_CHARS)
                    );
                    if methods.len() < MAX_REFS_PER_CLASS
                        && method_bytes + text.len() <= MAX_REF_BYTES_PER_CLASS
                    {
                        if methods.insert(text.clone()) {
                            method_bytes += text.len();
                        }
                    } else {
                        cut = true;
                    }
                }
                if let Some(category) = api_category {
                    if apis.len() < MAX_API_REFS_PER_CLASS {
                        apis.insert(ApiRef {
                            category: category.to_string(),
                            api: format!(
                                "{}.{}",
                                clip_chars(&owner_dotted, MAX_API_PART_CHARS),
                                clip_chars(name, MAX_API_PART_CHARS)
                            ),
                        });
                    } else {
                        cut = true;
                    }
                }
            }
            _ => {}
        }
    }
    (
        classes.into_iter().collect(),
        methods.into_iter().collect(),
        apis.into_iter().collect(),
        cut,
    )
}

fn parse_class_tail(
    r: &mut Reader<'_>,
    pool: &Pool,
    info: &mut ClassInfo,
    light: bool,
) -> Result<()> {
    let mut budget = DetailBudget {
        // Light mode: nothing fits, so members are only counted.
        used: if light { MAX_CLASS_DETAIL_BYTES } else { 0 },
        light,
        cut: false,
        clipped: false,
        throws_cut: false,
        inner_capped: false,
    };
    let result = parse_class_tail_inner(r, pool, info, &mut budget);
    let mut notes = Vec::new();
    if budget.light {
        notes.push("member and reference lists skipped: archive work budget used up".to_string());
    } else if budget.cut {
        let mut cut: Vec<String> = Vec::new();
        for (label, kept, real) in [
            ("interfaces", info.interfaces.len(), info.interface_count()),
            ("fields", info.fields.len(), info.field_count()),
            ("methods", info.methods.len(), info.method_count()),
            (
                "inner classes",
                info.inner_classes.len(),
                info.inner_classes_total.max(info.inner_classes.len()),
            ),
        ] {
            if kept < real {
                cut.push(format!("{kept} of {real} {label}"));
            }
        }
        if !cut.is_empty() {
            notes.push(format!(
                "member lists cut at {MAX_CLASS_DETAIL_BYTES} bytes ({} kept)",
                cut.join(", ")
            ));
        } else {
            notes.push(format!(
                "throws lists cut at the byte budget of {MAX_CLASS_DETAIL_BYTES} bytes"
            ));
        }
    }
    if budget.throws_cut {
        notes.push(format!(
            "throws lists cut at {MAX_THROWS_PER_METHOD} entries per method"
        ));
    }
    if budget.inner_capped {
        notes.push(format!(
            "InnerClasses read only up to {MAX_INNER_VISITS} entries"
        ));
    }
    if budget.clipped {
        notes.push(format!(
            "names longer than {MAX_MEMBER_PART_CHARS} bytes (members) or \
             {MAX_CLASS_NAME_CHARS} (classes) were cut"
        ));
    }
    if !notes.is_empty() {
        info.parse_warning = Some(notes.join("; "));
    }
    result
}

fn parse_class_tail_inner(
    r: &mut Reader<'_>,
    pool: &Pool,
    info: &mut ClassInfo,
    budget: &mut DetailBudget,
) -> Result<()> {
    let access = r.u16()?;
    let this_class = r.u16()?;
    let super_class = r.u16()?;
    info.access_flags = access;
    info.is_public = access & 0x0001 != 0;
    info.is_final = access & 0x0010 != 0;
    info.is_interface = access & 0x0200 != 0;
    info.is_abstract = access & 0x0400 != 0;
    info.is_annotation = access & 0x2000 != 0;
    info.is_enum = access & 0x4000 != 0;
    if let Some(name) = pool.class_name(this_class) {
        info.name = dotted(&budget.name(name, MAX_CLASS_NAME_CHARS));
    }
    info.super_class = pool
        .class_name(super_class)
        .map(|n| dotted(&budget.name(n, MAX_CLASS_NAME_CHARS)));

    let interface_count = r.u16()?;
    let mut interface_named = 0usize;
    for _ in 0..interface_count {
        let index = r.u16()?;
        if let Some(name) = pool.class_name(index) {
            interface_named += 1;
            let name = clip_chars(name, MAX_CLASS_NAME_CHARS);
            if budget.take(name.len() + STRING_OVERHEAD) {
                info.interfaces.push(dotted(name));
            }
        }
    }
    if info.interfaces.len() < interface_named {
        info.interfaces_total = interface_named;
    }

    let field_count = r.u16()?;
    let mut fields_seen = 0usize;
    for _ in 0..field_count {
        let access = r.u16()?;
        let name = clip_chars(pool.utf8(r.u16()?).unwrap_or("?"), MAX_MEMBER_PART_CHARS);
        let descriptor = clip_chars(pool.utf8(r.u16()?).unwrap_or("?"), MAX_MEMBER_PART_CHARS);
        fields_seen += 1;
        let keep = budget.take(MEMBER_OVERHEAD + name.len() + descriptor.len());
        let mut constant_value = None;
        for _ in 0..r.u16()? {
            let attr_name = pool.utf8(r.u16()?).unwrap_or("");
            let len = r.u32()? as usize;
            let body = r.take(len)?;
            if keep && attr_name == "ConstantValue" && body.len() == 2 {
                let index = usize::from(u16::from_be_bytes([body[0], body[1]]));
                constant_value = match pool.0.get(index) {
                    Some(Cp::Str(s)) => pool.utf8(*s).map(|s| clip_chars(s, 200).to_string()),
                    Some(Cp::Integer(n)) => Some(n.to_string()),
                    Some(Cp::Long(n)) => Some(n.to_string()),
                    _ => None,
                };
                if let Some(v) = &constant_value {
                    // Charged by its real length; a value that does not fit is dropped.
                    if !budget.take(v.len() + STRING_OVERHEAD) {
                        constant_value = None;
                    }
                }
            }
        }
        if !keep {
            continue;
        }
        info.fields.push(FieldInfo {
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            access_flags: access,
            is_public: access & 0x0001 != 0,
            is_private: access & 0x0002 != 0,
            is_protected: access & 0x0004 != 0,
            is_static: access & 0x0008 != 0,
            is_final: access & 0x0010 != 0,
            is_volatile: access & 0x0040 != 0,
            is_transient: access & 0x0080 != 0,
            constant_value,
        });
    }
    if info.fields.len() < fields_seen {
        info.fields_total = fields_seen;
    }

    let method_count = r.u16()?;
    let mut methods_seen = 0usize;
    for _ in 0..method_count {
        let access = r.u16()?;
        let name = clip_chars(pool.utf8(r.u16()?).unwrap_or("?"), MAX_MEMBER_PART_CHARS);
        let descriptor = clip_chars(pool.utf8(r.u16()?).unwrap_or("?"), MAX_MEMBER_PART_CHARS);
        methods_seen += 1;
        let keep = budget.take(MEMBER_OVERHEAD + name.len() + descriptor.len());
        let mut locals = 0u16;
        let mut throws = Vec::new();
        for _ in 0..r.u16()? {
            let attr_name = pool.utf8(r.u16()?).unwrap_or("");
            let len = r.u32()? as usize;
            let body = r.take(len)?;
            if !keep {
                continue;
            }
            if attr_name == "Code" && body.len() >= 4 {
                locals = u16::from_be_bytes([body[2], body[3]]);
            } else if attr_name == "Exceptions" && body.len() >= 2 {
                let n = usize::from(u16::from_be_bytes([body[0], body[1]]));
                for k in 0..n.min(body.len() / 2) {
                    let at = 2 + 2 * k;
                    if at + 2 > body.len() {
                        break;
                    }
                    let index = u16::from_be_bytes([body[at], body[at + 1]]);
                    if let Some(name) = pool.class_name(index) {
                        let name = clip_chars(name, MAX_CLASS_NAME_CHARS);
                        if throws.len() >= MAX_THROWS_PER_METHOD {
                            budget.throws_cut = true;
                            break;
                        }
                        if !budget.take(name.len() + STRING_OVERHEAD) {
                            break;
                        }
                        throws.push(dotted(name));
                    }
                }
            }
        }
        if !keep {
            continue;
        }
        info.methods.push(MethodInfo {
            parameter_count: count_parameters(descriptor),
            name: name.to_string(),
            descriptor: descriptor.to_string(),
            access_flags: access,
            is_public: access & 0x0001 != 0,
            is_private: access & 0x0002 != 0,
            is_protected: access & 0x0004 != 0,
            is_static: access & 0x0008 != 0,
            is_final: access & 0x0010 != 0,
            is_synchronized: access & 0x0020 != 0,
            is_native: access & 0x0100 != 0,
            is_abstract: access & 0x0400 != 0,
            local_variable_count: locals,
            exception_table: throws,
        });
    }
    if info.methods.len() < methods_seen {
        info.methods_total = methods_seen;
    }

    let mut inner_named = 0usize;
    let mut inner_visited = 0usize;
    let mut inner_seen: HashSet<u16> = HashSet::new();
    let this_name_index = match pool.0.get(usize::from(this_class)) {
        Some(Cp::Class(n)) => Some(*n),
        _ => None,
    };
    for _ in 0..r.u16()? {
        let attr_name = pool.utf8(r.u16()?).unwrap_or("");
        let len = r.u32()? as usize;
        let body = r.take(len)?;
        match attr_name {
            "SourceFile" if body.len() == 2 => {
                let index = u16::from_be_bytes([body[0], body[1]]);
                info.source_file = pool
                    .utf8(index)
                    .map(|s| budget.name(s, MAX_MEMBER_PART_CHARS));
            }
            "InnerClasses" if body.len() >= 2 => {
                let n = usize::from(u16::from_be_bytes([body[0], body[1]]));
                for k in 0..n {
                    let at = 2 + 8 * k;
                    if at + 2 > body.len() {
                        break;
                    }
                    if inner_visited >= MAX_INNER_VISITS {
                        budget.inner_capped = true;
                        break;
                    }
                    inner_visited += 1;
                    let index = u16::from_be_bytes([body[at], body[at + 1]]);
                    // Compared by pool index, never by text: an entry naming the class
                    // itself, or one already seen, costs one lookup.
                    let Some(Cp::Class(name_index)) = pool.0.get(usize::from(index)) else {
                        continue;
                    };
                    if Some(*name_index) == this_name_index || !inner_seen.insert(*name_index) {
                        continue;
                    }
                    if let Some(name) = pool.utf8(*name_index) {
                        if budget.cut {
                            // Past the budget entries are only counted: no copy, no scan.
                            inner_named += 1;
                            continue;
                        }
                        let name = dotted(clip_chars(name, MAX_CLASS_NAME_CHARS));
                        inner_named += 1;
                        if budget.take(name.len() + STRING_OVERHEAD) {
                            info.inner_classes.push(name);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if info.inner_classes.len() < inner_named {
        info.inner_classes_total = inner_named;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Dangerous APIs
// ---------------------------------------------------------------------------

const NETWORK_OWNERS: &[&str] = &[
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
const NETWORK_METHODS: &[&str] = &[
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

/// Category of a referenced method (`owner` in slash form), if it is one of the APIs
/// the scanner flags: process execution, reflection, class loading, native loading,
/// network, crypto, deserialization, JNDI, scripting, `Unsafe`, SMS.
pub fn classify_api(owner: &str, name: &str) -> Option<&'static str> {
    let category = match (owner, name) {
        ("java/lang/Runtime", "exec") | ("java/lang/ProcessBuilder", "start") => "process_exec",
        ("java/lang/System" | "java/lang/Runtime", "load" | "loadLibrary") => "native_loading",
        (
            "java/lang/reflect/Method" | "java/lang/reflect/Constructor" | "java/lang/Class",
            "invoke"
            | "newInstance"
            | "forName"
            | "getDeclaredMethod"
            | "getMethod"
            | "getDeclaredConstructor",
        )
        | (
            "java/lang/reflect/Method"
            | "java/lang/reflect/Field"
            | "java/lang/reflect/Constructor"
            | "java/lang/reflect/AccessibleObject",
            "setAccessible",
        ) => "reflection",
        ("java/net/URL", "openConnection" | "openStream") => "network",
        ("java/net/URLClassLoader", "<init>" | "newInstance")
        | (
            "dalvik/system/DexClassLoader"
            | "dalvik/system/PathClassLoader"
            | "dalvik/system/InMemoryDexClassLoader",
            "<init>",
        )
        | ("java/lang/invoke/MethodHandles$Lookup", "defineClass" | "defineHiddenClass") => {
            "class_loading"
        }
        (o, "defineClass") if o.ends_with("ClassLoader") => "class_loading",
        ("java/io/ObjectInputStream", "readObject" | "readUnshared")
        | ("java/beans/XMLDecoder", "readObject") => "deserialization",
        ("javax/naming/InitialContext" | "javax/naming/Context", "lookup" | "doLookup") => {
            "jndi_lookup"
        }
        ("javax/script/ScriptEngine", "eval") | ("groovy/lang/GroovyShell", "evaluate") => {
            "scripting"
        }
        ("sun/misc/Unsafe" | "jdk/internal/misc/Unsafe", _) => "unsafe",
        ("java/lang/System", "setSecurityManager") => "security_manager",
        ("android/telephony/SmsManager", "sendTextMessage" | "sendMultipartTextMessage") => "sms",
        ("javax/crypto/Cipher", "getInstance" | "doFinal")
        | ("javax/crypto/spec/SecretKeySpec", "<init>")
        | ("javax/crypto/KeyGenerator", "getInstance") => "crypto",
        (o, m) if NETWORK_OWNERS.contains(&o) && NETWORK_METHODS.contains(&m) => "network",
        _ => return None,
    };
    Some(category)
}

/// Severity of a category on its own.
pub fn category_severity(category: &str) -> SecurityThreatLevel {
    match category {
        "process_exec" | "native_loading" | "class_loading" | "jndi_lookup" | "scripting"
        | "unsafe" | "sms" => SecurityThreatLevel::High,
        "reflection" | "network" | "deserialization" | "security_manager" => {
            SecurityThreatLevel::Medium
        }
        _ => SecurityThreatLevel::Low,
    }
}

// ---------------------------------------------------------------------------
// Android manifest (binary AXML and plain XML)
// ---------------------------------------------------------------------------

enum XmlEvent {
    Start(String, Vec<(String, String)>),
    End,
}

/// Longest attribute value or element name kept from a manifest.
const MAX_XML_VALUE_CHARS: usize = 512;
/// Longest element name kept from a manifest.
const MAX_XML_TAG_CHARS: usize = 64;
/// Text bytes (plus overhead per event and attribute) kept from one manifest.
const MAX_XML_EVENT_BYTES: usize = 4 * 1024 * 1024;
/// Bytes charged per element and per kept attribute on top of their text.
const XML_ITEM_OVERHEAD: usize = 48;
/// Most entries kept in each manifest list (permissions, features, components, ...).
const MAX_MANIFEST_LIST: usize = 2_000;
/// Sensitive permissions kept on top of [`MAX_MANIFEST_LIST`], so filler cannot hide them.
const MAX_SENSITIVE_PERMISSIONS: usize = 500;
/// Intent filters kept per component, and entries kept per filter list.
const MAX_FILTERS_PER_COMPONENT: usize = 20;
const MAX_FILTER_ENTRIES: usize = 20;
/// Manifest attributes the analysis reads; every other attribute is dropped at parse time.
const KEPT_ATTRIBUTES: &[&str] = &[
    "package",
    "versionCode",
    "versionName",
    "compileSdkVersion",
    "minSdkVersion",
    "targetSdkVersion",
    "debuggable",
    "exported",
    "enabled",
    "name",
    "scheme",
    "mimeType",
];

/// The elements read from a manifest, with what the byte budget left out.
struct XmlEvents {
    events: Vec<XmlEvent>,
    used: usize,
    /// Parsing stopped early because the text budget was used up.
    cut: bool,
    /// Some name or value was longer than the limit and was shortened.
    clipped: bool,
    /// Sensitive permissions declared after the budget ran out (kept, up to a cap).
    late_sensitive: Vec<String>,
    /// How many of those are heuristic matches (capped), and how many were not kept.
    late_heuristic: usize,
    late_dropped: usize,
}

impl XmlEvents {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            used: 0,
            cut: false,
            clipped: false,
            late_sensitive: Vec::new(),
            late_heuristic: 0,
            late_dropped: 0,
        }
    }
    fn clip(&mut self, s: &str, max: usize) -> String {
        let clipped = clip_chars(s, max);
        if clipped.len() < s.len() {
            self.clipped = true;
        }
        clipped.to_string()
    }
    /// Adds an element when its text fits the budget; false once the budget is used up.
    fn start(&mut self, tag: &str, attrs: Vec<(String, String)>) -> bool {
        let cost = XML_ITEM_OVERHEAD
            + tag.len()
            + attrs
                .iter()
                .map(|(k, v)| XML_ITEM_OVERHEAD + k.len() + v.len())
                .sum::<usize>();
        if self.cut || self.used + cost > MAX_XML_EVENT_BYTES {
            self.cut = true;
            // The rest of the manifest is only scanned for sensitive permissions, so
            // filler elements cannot push them out of view.
            if matches!(tag, "uses-permission" | "uses-permission-sdk-23") {
                if let Some((_, name)) = attrs.iter().find(|(k, _)| k == "name") {
                    if is_exact_dangerous_permission(name) {
                        if !self.late_sensitive.contains(name) {
                            self.late_sensitive.push(name.clone());
                        }
                    } else if is_sensitive_permission(name) {
                        if self.late_heuristic < MAX_SENSITIVE_PERMISSIONS {
                            if !self.late_sensitive.contains(name) {
                                self.late_sensitive.push(name.clone());
                                self.late_heuristic += 1;
                            }
                        } else {
                            self.late_dropped += 1;
                        }
                    }
                }
            }
            return false;
        }
        self.used += cost;
        self.events.push(XmlEvent::Start(tag.to_string(), attrs));
        true
    }
    fn end(&mut self) -> bool {
        if self.cut || self.used + XML_ITEM_OVERHEAD > MAX_XML_EVENT_BYTES {
            self.cut = true;
            return false;
        }
        self.used += XML_ITEM_OVERHEAD;
        self.events.push(XmlEvent::End);
        true
    }
}

fn parse_android_manifest(contents: &[u8]) -> Result<AndroidManifest> {
    let events = if contents.len() >= 8 && contents[0] == 0x03 && contents[1] == 0x00 {
        parse_axml(contents)?
    } else {
        let trimmed = contents
            .strip_prefix(&[0xEF, 0xBB, 0xBF])
            .unwrap_or(contents);
        if trimmed.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'<') {
            parse_text_xml(trimmed)?
        } else {
            return Err(anyhow!("neither binary Android XML nor text XML"));
        }
    };
    let mut manifest = build_manifest(&events.events)?;
    if events.cut {
        manifest.partial = true;
        manifest.permissions_dropped += events.late_dropped;
        for name in &events.late_sensitive {
            if !manifest.permissions.contains(name) {
                manifest.permissions.push(name.clone());
            }
        }
        manifest.notes.push(format!(
            "the manifest holds more than {MAX_XML_EVENT_BYTES} bytes of element and attribute \
             text; elements after that point were not read except for sensitive permissions \
             ({} found there), so other late permissions and components are missing",
            events.late_sensitive.len()
        ));
    }
    if events.clipped {
        manifest.notes.push(format!(
            "names and values longer than {MAX_XML_VALUE_CHARS} bytes were cut"
        ));
    }
    Ok(manifest)
}

fn u16_at(data: &[u8], at: usize) -> Result<u16> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| anyhow!("truncated binary XML"))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| anyhow!("truncated binary XML"))
}

/// Longest single string decoded from a binary-XML string pool.
const MAX_POOL_STRING_UNITS: usize = 64 * 1024;
/// Bytes decoded from one string pool in total.
const MAX_POOL_DECODED_BYTES: usize = 8 * 1024 * 1024;

fn parse_string_pool(chunk: &[u8]) -> Result<Vec<String>> {
    let count = u32_at(chunk, 8)? as usize;
    let flags = u32_at(chunk, 16)?;
    let strings_start = u32_at(chunk, 20)? as usize;
    let header = usize::from(u16_at(chunk, 2)?);
    if count > 1_000_000 || header + count * 4 > chunk.len() {
        return Err(anyhow!("string pool does not fit its chunk"));
    }
    let utf8 = flags & 0x100 != 0;
    let mut out = Vec::with_capacity(count);
    let mut decoded = 0usize;
    for i in 0..count {
        let offset = strings_start.saturating_add(u32_at(chunk, header + i * 4)? as usize);
        let text = read_pool_string(chunk, offset, utf8).unwrap_or_default();
        decoded += text.len();
        if decoded > MAX_POOL_DECODED_BYTES {
            return Err(anyhow!(
                "string pool decodes to more than {MAX_POOL_DECODED_BYTES} bytes"
            ));
        }
        out.push(text);
    }
    Ok(out)
}

fn read_pool_string(chunk: &[u8], mut at: usize, utf8: bool) -> Result<String> {
    if utf8 {
        // char length, then byte length, each one or two bytes
        let skip_len = |at: &mut usize| -> Result<usize> {
            let first = usize::from(*chunk.get(*at).ok_or_else(|| anyhow!("truncated"))?);
            *at += 1;
            if first & 0x80 != 0 {
                let second = usize::from(*chunk.get(*at).ok_or_else(|| anyhow!("truncated"))?);
                *at += 1;
                Ok(((first & 0x7F) << 8) | second)
            } else {
                Ok(first)
            }
        };
        skip_len(&mut at)?;
        let bytes = skip_len(&mut at)?;
        if bytes > MAX_POOL_STRING_UNITS {
            return Err(anyhow!("string longer than {MAX_POOL_STRING_UNITS} bytes"));
        }
        let data = chunk
            .get(at..at.saturating_add(bytes))
            .ok_or_else(|| anyhow!("truncated string"))?;
        Ok(String::from_utf8_lossy(data).into_owned())
    } else {
        let mut len = usize::from(u16_at(chunk, at)?);
        at += 2;
        if len & 0x8000 != 0 {
            len = ((len & 0x7FFF) << 16) | usize::from(u16_at(chunk, at)?);
            at += 2;
        }
        if len > MAX_POOL_STRING_UNITS {
            return Err(anyhow!("string longer than {MAX_POOL_STRING_UNITS} units"));
        }
        let data = chunk
            .get(at..at + len * 2)
            .ok_or_else(|| anyhow!("truncated string"))?;
        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes(*b))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }
}

/// Attribute names for resource ids, used when the string pool stripped the names.
fn attribute_for_resource_id(id: u32) -> Option<&'static str> {
    Some(match id {
        0x0101_0003 => "name",
        0x0101_000e => "enabled",
        0x0101_0010 => "exported",
        0x0101_000f => "debuggable",
        0x0101_021b => "versionCode",
        0x0101_021c => "versionName",
        0x0101_020c => "minSdkVersion",
        0x0101_0270 => "targetSdkVersion",
        0x0101_0572 => "compileSdkVersion",
        0x0101_0027 => "scheme",
        0x0101_0026 => "mimeType",
        _ => return None,
    })
}

fn parse_axml(data: &[u8]) -> Result<XmlEvents> {
    let total = (u32_at(data, 4)? as usize).min(data.len());
    let mut pos = usize::from(u16_at(data, 2)?).max(8);
    let mut strings: Vec<String> = Vec::new();
    let mut resource_ids: Vec<u32> = Vec::new();
    let mut out = XmlEvents::new();
    let string_at = |strings: &[String], index: u32| -> Option<usize> {
        if index == u32::MAX || index as usize >= strings.len() {
            None
        } else {
            Some(index as usize)
        }
    };

    while pos + 8 <= total {
        let chunk_type = u16_at(data, pos)?;
        let header = usize::from(u16_at(data, pos + 2)?);
        let size = u32_at(data, pos + 4)? as usize;
        if size < 8 || pos + size > total {
            if out.events.is_empty() {
                return Err(anyhow!("binary XML chunk at byte {pos} overruns the file"));
            }
            break;
        }
        let chunk = &data[pos..pos + size];
        match chunk_type {
            0x0001 => strings = parse_string_pool(chunk)?,
            0x0180 => {
                resource_ids = chunk[header.min(size)..]
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| u32::from_le_bytes(*b))
                    .collect();
            }
            0x0102 => {
                let ext = header;
                let name_index = u32_at(chunk, ext + 4)?;
                let attr_start = usize::from(u16_at(chunk, ext + 8)?);
                let attr_size = usize::from(u16_at(chunk, ext + 10)?).max(20);
                let attr_count = usize::from(u16_at(chunk, ext + 12)?);
                let name = string_at(&strings, name_index)
                    .map(|i| out.clip(&strings[i], MAX_XML_TAG_CHARS))
                    .unwrap_or_default();
                let mut attrs = Vec::new();
                for k in 0..attr_count {
                    let at = ext + attr_start + k * attr_size;
                    if at + 20 > chunk.len() {
                        break;
                    }
                    let attr_name_index = u32_at(chunk, at + 4)?;
                    let mut attr_name = string_at(&strings, attr_name_index)
                        .map(|i| strings[i].as_str())
                        .unwrap_or_default();
                    if attr_name.is_empty() {
                        if let Some(n) = resource_ids
                            .get(attr_name_index as usize)
                            .and_then(|id| attribute_for_resource_id(*id))
                        {
                            attr_name = n;
                        }
                    }
                    // Only the attributes the analysis reads are copied out of the pool.
                    if !KEPT_ATTRIBUTES.contains(&attr_name) {
                        continue;
                    }
                    let attr_name = attr_name.to_string();
                    let raw = u32_at(chunk, at + 8)?;
                    let data_type = chunk[at + 15];
                    let value = u32_at(chunk, at + 16)?;
                    let pooled =
                        |index: u32| string_at(&strings, index).map(|i| strings[i].as_str());
                    let text = match data_type {
                        0x03 => pooled(value)
                            .or_else(|| pooled(raw))
                            .map(|t| out.clip(t, MAX_XML_VALUE_CHARS))
                            .unwrap_or_default(),
                        0x10 => (value as i32).to_string(),
                        0x11 => format!("0x{value:x}"),
                        0x12 => (value != 0).to_string(),
                        0x01 => format!("@0x{value:x}"),
                        _ => pooled(raw)
                            .map(|t| out.clip(t, MAX_XML_VALUE_CHARS))
                            .unwrap_or_else(|| value.to_string()),
                    };
                    attrs.push((attr_name, text));
                }
                out.start(&name, attrs);
            }
            0x0103 => {
                out.end();
            }
            _ => {}
        }
        pos += size;
    }
    if out.events.is_empty() {
        return Err(anyhow!("binary XML holds no elements"));
    }
    Ok(out)
}

fn parse_text_xml(data: &[u8]) -> Result<XmlEvents> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_reader(data);
    let mut out = XmlEvents::new();
    let attrs_of =
        |e: &quick_xml::events::BytesStart<'_>, out: &mut XmlEvents| -> Vec<(String, String)> {
            let mut kept = Vec::new();
            for a in e.attributes().flatten() {
                let key = a.key.as_ref().to_string();
                let key = key.rsplit(':').next().unwrap_or(&key);
                if !KEPT_ATTRIBUTES.contains(&key) {
                    continue;
                }
                let value = a
                    .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    .map_or_else(|_| String::new(), |v| out.clip(&v, MAX_XML_VALUE_CHARS));
                kept.push((key.to_string(), value));
            }
            kept
        };
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = out.clip(e.name().as_ref(), MAX_XML_TAG_CHARS);
                let attrs = attrs_of(&e, &mut out);
                out.start(&tag, attrs);
            }
            Ok(Event::Empty(e)) => {
                let tag = out.clip(e.name().as_ref(), MAX_XML_TAG_CHARS);
                let attrs = attrs_of(&e, &mut out);
                if out.start(&tag, attrs) {
                    out.end();
                }
            }
            Ok(Event::End(_)) => {
                out.end();
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => return Err(anyhow!("XML error: {error}")),
        }
    }
    if out.events.is_empty() {
        return Err(anyhow!("XML holds no elements"));
    }
    Ok(out)
}

fn attr<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn qualify(package: &str, name: &str) -> String {
    if name.starts_with('.') {
        format!("{package}{name}")
    } else if !name.contains('.') && !package.is_empty() {
        format!("{package}.{name}")
    } else {
        name.to_string()
    }
}

fn build_manifest(events: &[XmlEvent]) -> Result<AndroidManifest> {
    let mut manifest = AndroidManifest {
        package_name: String::new(),
        version_code: None,
        version_name: None,
        min_sdk_version: None,
        target_sdk_version: None,
        compile_sdk_version: None,
        debuggable: None,
        permissions: Vec::new(),
        activities: Vec::new(),
        services: Vec::new(),
        receivers: Vec::new(),
        providers: Vec::new(),
        uses_features: Vec::new(),
        intent_filters: Vec::new(),
        notes: Vec::new(),
        partial: false,
        permissions_dropped: 0,
    };
    let mut cut_lists: BTreeSet<&'static str> = BTreeSet::new();
    let mut seen_permissions: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut seen_features: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut stack: Vec<String> = Vec::new();
    let mut component: Option<(String, AndroidComponent, bool)> = None;
    let mut filter: Option<IntentFilter> = None;
    let mut saw_manifest = false;

    for event in events {
        match event {
            XmlEvent::Start(tag, attrs) => {
                let parent = stack.last().map(String::as_str);
                match tag.as_str() {
                    "manifest" => {
                        saw_manifest = true;
                        manifest.package_name = attr(attrs, "package").unwrap_or("").to_string();
                        manifest.version_code =
                            attr(attrs, "versionCode").and_then(|v| v.parse().ok());
                        manifest.version_name = attr(attrs, "versionName").map(str::to_string);
                        manifest.compile_sdk_version =
                            attr(attrs, "compileSdkVersion").and_then(|v| v.parse().ok());
                    }
                    "uses-sdk" => {
                        manifest.min_sdk_version =
                            attr(attrs, "minSdkVersion").and_then(|v| v.parse().ok());
                        manifest.target_sdk_version =
                            attr(attrs, "targetSdkVersion").and_then(|v| v.parse().ok());
                    }
                    "uses-permission" | "uses-permission-sdk-23" => {
                        if let Some(name) = attr(attrs, "name") {
                            if seen_permissions.contains(name) {
                                // a repeated declaration adds nothing
                            } else if is_exact_dangerous_permission(name)
                                || manifest.permissions.len() < MAX_MANIFEST_LIST
                                || (is_sensitive_permission(name)
                                    && manifest.permissions.len()
                                        < MAX_MANIFEST_LIST + MAX_SENSITIVE_PERMISSIONS)
                            {
                                // The exact dangerous names are a short fixed set, so
                                // they need no cap and filler cannot push them out.
                                seen_permissions.insert(name.to_string());
                                manifest.permissions.push(name.to_string());
                            } else {
                                manifest.permissions_dropped += 1;
                                cut_lists.insert("permissions");
                            }
                        }
                    }
                    "uses-feature" => {
                        if let Some(name) = attr(attrs, "name") {
                            if seen_features.contains(name) {
                                // a repeated declaration adds nothing
                            } else if manifest.uses_features.len() < MAX_MANIFEST_LIST {
                                seen_features.insert(name.to_string());
                                manifest.uses_features.push(name.to_string());
                            } else {
                                cut_lists.insert("uses-feature");
                            }
                        }
                    }
                    "application" => {
                        manifest.debuggable = attr(attrs, "debuggable").map(|v| v == "true");
                    }
                    "activity" | "activity-alias" | "service" | "receiver" | "provider"
                        if parent == Some("application") =>
                    {
                        let name =
                            qualify(&manifest.package_name, attr(attrs, "name").unwrap_or(""));
                        let explicit = attr(attrs, "exported");
                        component = Some((
                            tag.clone(),
                            AndroidComponent {
                                name,
                                exported: explicit == Some("true"),
                                enabled: attr(attrs, "enabled") != Some("false"),
                                intent_filters: Vec::new(),
                            },
                            explicit.is_some(),
                        ));
                    }
                    "intent-filter" if component.is_some() => {
                        filter = Some(IntentFilter {
                            actions: Vec::new(),
                            categories: Vec::new(),
                            data_schemes: Vec::new(),
                            data_types: Vec::new(),
                        });
                    }
                    "action" => {
                        if let (Some(f), Some(n)) = (filter.as_mut(), attr(attrs, "name")) {
                            if f.actions.len() < MAX_FILTER_ENTRIES {
                                f.actions.push(n.to_string());
                            } else {
                                cut_lists.insert("intent-filter entries");
                            }
                        }
                    }
                    "category" => {
                        if let (Some(f), Some(n)) = (filter.as_mut(), attr(attrs, "name")) {
                            if f.categories.len() < MAX_FILTER_ENTRIES {
                                f.categories.push(n.to_string());
                            } else {
                                cut_lists.insert("intent-filter entries");
                            }
                        }
                    }
                    "data" => {
                        if let Some(f) = filter.as_mut() {
                            if let Some(s) = attr(attrs, "scheme") {
                                if f.data_schemes.len() < MAX_FILTER_ENTRIES {
                                    f.data_schemes.push(s.to_string());
                                } else {
                                    cut_lists.insert("intent-filter entries");
                                }
                            }
                            if let Some(t) = attr(attrs, "mimeType") {
                                if f.data_types.len() < MAX_FILTER_ENTRIES {
                                    f.data_types.push(t.to_string());
                                } else {
                                    cut_lists.insert("intent-filter entries");
                                }
                            }
                        }
                    }
                    _ => {}
                }
                stack.push(tag.clone());
            }
            XmlEvent::End => {
                let Some(tag) = stack.pop() else { continue };
                match tag.as_str() {
                    "intent-filter" => {
                        if let (Some(f), Some((_, c, _))) = (filter.take(), component.as_mut()) {
                            if c.intent_filters.len() < MAX_FILTERS_PER_COMPONENT {
                                c.intent_filters.push(f);
                            } else {
                                cut_lists.insert("intent filters per component");
                            }
                        }
                    }
                    "activity" | "activity-alias" | "service" | "receiver" | "provider"
                        if component.as_ref().is_some_and(|(t, _, _)| *t == tag) =>
                    {
                        if let Some((kind, mut c, explicit)) = component.take() {
                            if !explicit {
                                c.exported = kind != "provider" && !c.intent_filters.is_empty();
                            }
                            let list = match kind.as_str() {
                                "service" => &mut manifest.services,
                                "receiver" => &mut manifest.receivers,
                                "provider" => &mut manifest.providers,
                                _ => &mut manifest.activities,
                            };
                            if list.len() < MAX_MANIFEST_LIST {
                                list.push(c);
                            } else {
                                cut_lists.insert("components");
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    if !saw_manifest {
        return Err(anyhow!("no <manifest> element"));
    }
    if !cut_lists.is_empty() {
        manifest.notes.push(format!(
            "lists cut at their limits ({}): {MAX_MANIFEST_LIST} per list, \
             {MAX_FILTERS_PER_COMPONENT} filters per component, {MAX_FILTER_ENTRIES} entries per \
             filter",
            cut_lists.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Resources and security analysis
// ---------------------------------------------------------------------------

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

const PRIVACY_PERMISSIONS: &[&str] = &[
    "READ_CONTACTS",
    "READ_SMS",
    "RECEIVE_SMS",
    "READ_CALL_LOG",
    "ACCESS_FINE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO",
    "CAMERA",
];

fn perform_security_analysis(result: &mut JavaAnalysisResult, facts: &ScanFacts) {
    let mut level = SecurityThreatLevel::Low;
    let mut basis: Vec<String> = Vec::new();

    // Android permissions
    if let Some(android_manifest) = &result.android_manifest {
        for permission in &android_manifest.permissions {
            if is_dangerous_permission(permission) {
                result
                    .security_analysis
                    .suspicious_permissions
                    .push(permission.clone());
            }
            if PRIVACY_PERMISSIONS
                .iter()
                .any(|p| permission.ends_with(&format!(".{p}")))
            {
                result
                    .security_analysis
                    .privacy_concerns
                    .push(format!("Requests {permission}"));
            }
        }
        if !result.security_analysis.suspicious_permissions.is_empty() {
            level = level.max(SecurityThreatLevel::Medium);
            basis.push(format!(
                "{} sensitive Android permission(s) requested",
                result.security_analysis.suspicious_permissions.len()
            ));
        }
        if android_manifest.debuggable == Some(true) {
            result
                .security_analysis
                .security_vulnerabilities
                .push(SecurityVulnerability {
                    vulnerability_type: "debuggable".to_string(),
                    severity: SecurityThreatLevel::Medium,
                    description: "The application sets android:debuggable=true".to_string(),
                    location: "AndroidManifest.xml".to_string(),
                    recommendation: "Release builds must not be debuggable".to_string(),
                });
            level = level.max(SecurityThreatLevel::Medium);
            basis.push("application is debuggable".to_string());
        }
    }

    // Dangerous APIs, from constant-pool references
    let mut findings: Vec<ApiFinding> = facts
        .api_groups
        .iter()
        .map(
            |((category, api), (class_count, example_classes))| ApiFinding {
                severity: category_severity(category),
                category: category.clone(),
                api: api.clone(),
                class_count: *class_count,
                example_classes: example_classes.clone(),
            },
        )
        .collect();
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.class_count.cmp(&a.class_count))
            .then(a.api.cmp(&b.api))
    });
    let categories: BTreeSet<&str> = findings.iter().map(|f| f.category.as_str()).collect();
    for finding in &findings {
        level = level.max(finding.severity);
    }
    let mut by_category: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in &findings {
        *by_category.entry(finding.category.as_str()).or_insert(0) += finding.class_count;
    }
    let mut ranked: Vec<(&&str, &usize)> = by_category.iter().collect();
    ranked.sort_by_key(|(c, n)| {
        (
            std::cmp::Reverse(category_severity(c)),
            std::cmp::Reverse(**n),
        )
    });
    for (category, classes) in ranked.into_iter().take(5) {
        if category_severity(category) > SecurityThreatLevel::Low {
            basis.push(format!(
                "{category} APIs referenced ({classes} class reference(s))"
            ));
        }
    }
    // The dropper shape must meet in one class; spread over a large archive it is just
    // what libraries look like.
    if let Some(class) = &facts.dropper {
        level = SecurityThreatLevel::Critical;
        let note = format!(
            "Class {class} uses network access, process execution or native loading, and dynamic \
             class loading together: the shape of a downloader or dropper"
        );
        basis.push(note.clone());
        result.security_analysis.malware_indicators.push(note);
    }
    if categories.contains("sms")
        && result
            .security_analysis
            .suspicious_permissions
            .iter()
            .any(|p| p.ends_with("SEND_SMS"))
    {
        result
            .security_analysis
            .malware_indicators
            .push("Sends SMS and holds the SEND_SMS permission".to_string());
    }
    result.security_analysis.dangerous_apis = findings.iter().map(|f| f.api.clone()).collect();
    result.security_analysis.api_findings = findings;

    // Obfuscation: most class names one or two characters long
    let named: Vec<&ClassInfo> = result
        .classes
        .iter()
        .filter(|c| c.name != "module-info" && c.name != "package-info")
        .collect();
    let short = named
        .iter()
        .filter(|c| {
            c.name
                .rsplit('.')
                .next()
                .is_some_and(|simple| simple.chars().count() <= 2)
        })
        .count();
    if named.len() >= 10 && short * 2 > named.len() {
        result
            .security_analysis
            .obfuscation_indicators
            .push(format!(
                "{short} of {} classes have one- or two-character names (ProGuard-style renaming)",
                named.len()
            ));
    }

    // Signing: only the presence of signature files is known
    if result.signature_files.is_empty() {
        result.security_analysis.code_signing_status = CodeSigningStatus::Unsigned;
        let note = if result.archive_type == JavaArchiveType::Apk {
            "No META-INF signature files (APK v2/v3 signing blocks are not inspected)"
        } else {
            "Application is not signed"
        };
        result
            .security_analysis
            .certificate_issues
            .push(note.to_string());
    } else {
        result.security_analysis.code_signing_status =
            CodeSigningStatus::SignatureFilesPresentUnverified;
    }

    if !result.security_analysis.archive_anomalies.is_empty() {
        basis.push("archive anomalies found (see archive_anomalies)".to_string());
    }
    if result.android_manifest.as_ref().is_some_and(|m| m.partial) {
        // Something was not read: never report "nothing found" on it.
        level = level.max(SecurityThreatLevel::Medium);
        basis.push(
            "AndroidManifest.xml was only partly read (text budget used up); permissions after \
             that point were not all examined (see android_manifest.notes)"
                .to_string(),
        );
    }
    if facts.groups_dropped > 0 {
        level = level
            .max(facts.dropped_severity)
            .max(SecurityThreatLevel::Medium);
        basis.push(format!(
            "{} further dangerous API reference(s) beyond the {MAX_API_GROUPS} listed in \
             findings were counted, not listed (worst severity {:?})",
            facts.groups_dropped, facts.dropped_severity
        ));
    }
    // Anything that was not read is not "clean": say what, and never report "nothing found".
    let not_read = |n: usize, what: &str| format!("{n} {what}");
    let mut unexamined: Vec<String> = Vec::new();
    if result.unparsed_classes > 0 {
        unexamined.push(not_read(
            result.unparsed_classes,
            "class file(s) were not analyzed (over the read cap, past the read budget, or \
             damaged)",
        ));
    }
    if facts.nested_unread > 0 {
        unexamined.push(not_read(
            facts.nested_unread,
            "nested archive(s) were not opened (size cap, count cap, read budget or damage)",
        ));
    }
    if facts.manifest_unread {
        unexamined.push(
            "AndroidManifest.xml was not read or not understood; its permissions are unknown"
                .to_string(),
        );
    }
    if let Some(m) = &result.android_manifest {
        if m.permissions_dropped > 0 {
            unexamined.push(not_read(
                m.permissions_dropped,
                "permission(s) beyond the list caps were not examined",
            ));
        }
    }
    if !unexamined.is_empty() {
        level = level.max(SecurityThreatLevel::Medium);
        for item in unexamined {
            basis.push(format!("{item} (see warnings)"));
        }
    }
    if basis.is_empty() && level == SecurityThreatLevel::Low {
        basis.push(if result.security_analysis.api_findings.is_empty() {
            "no dangerous API references or sensitive permissions found".to_string()
        } else {
            "only low-severity API references found (see findings)".to_string()
        });
    }
    result.security_analysis.threat_level = level;
    result.security_analysis.threat_basis = basis;
}

/// A permission the analysis reports on: dangerous or privacy-related.
fn is_sensitive_permission(permission: &str) -> bool {
    is_dangerous_permission(permission)
        || PRIVACY_PERMISSIONS
            .iter()
            .any(|p| permission.strip_suffix(p).is_some_and(|r| r.ends_with('.')))
}

fn is_dangerous_permission(permission: &str) -> bool {
    is_exact_dangerous_permission(permission)
        || permission.contains("ADMIN")
        || permission.contains("ROOT")
}

/// The fixed set of dangerous permission names (a short list, so it is never capped).
fn is_exact_dangerous_permission(permission: &str) -> bool {
    matches!(
        permission,
        "android.permission.SEND_SMS"
            | "android.permission.READ_SMS"
            | "android.permission.RECEIVE_SMS"
            | "android.permission.READ_CALL_LOG"
            | "android.permission.CALL_PHONE"
            | "android.permission.READ_CONTACTS"
            | "android.permission.ACCESS_FINE_LOCATION"
            | "android.permission.CAMERA"
            | "android.permission.RECORD_AUDIO"
            | "android.permission.READ_EXTERNAL_STORAGE"
            | "android.permission.WRITE_EXTERNAL_STORAGE"
            | "android.permission.INSTALL_PACKAGES"
            | "android.permission.REQUEST_INSTALL_PACKAGES"
            | "android.permission.DELETE_PACKAGES"
            | "android.permission.SYSTEM_ALERT_WINDOW"
            | "android.permission.BIND_ACCESSIBILITY_SERVICE"
            | "android.permission.DEVICE_ADMIN"
    )
}

/// Legacy name-only check, kept for callers that have a bare method name.
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

        let archive_type = detect_archive_type_from_names(&entry_names(&mut archive));
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

    #[test]
    fn test_count_parameters() {
        assert_eq!(count_parameters("()V"), 0);
        assert_eq!(count_parameters("(IJ[ILjava/lang/String;[[D)V"), 5);
    }

    #[test]
    fn test_truncated_class_keeps_what_the_pool_gave() {
        use test_class_builder::ClassBuilder;
        let full = ClassBuilder::new("a/B")
            .method("m", "()V", 1)
            .calls(
                "java/lang/Runtime",
                "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;",
            )
            .build();
        // Cut inside the member tables: the pool is intact, the members are not.
        let cut = &full[..full.len() - 4];
        let class = parse_class_file(cut).unwrap();
        assert_eq!(class.name, "a.B");
        assert!(class.parse_warning.is_some());
        assert_eq!(class.dangerous_apis[0].api, "java.lang.Runtime.exec");
        // Cut inside the pool: not a class.
        assert!(parse_class_file(&full[..30]).is_err());
        // Garbage tag.
        let mut bad = full.clone();
        bad[10] = 0xEE;
        assert!(parse_class_file(&bad).is_err());
    }

    #[test]
    fn test_classify_api() {
        assert_eq!(
            classify_api("java/lang/Runtime", "exec"),
            Some("process_exec")
        );
        assert_eq!(classify_api("java/net/Socket", "<init>"), Some("network"));
        assert_eq!(
            classify_api("my/Loader/ClassLoader", "defineClass"),
            Some("class_loading")
        );
        assert_eq!(classify_api("java/lang/String", "length"), None);
        assert_eq!(classify_api("java/lang/Runtime", "getRuntime"), None);
    }

    #[test]
    fn test_manifest_main_section_only() {
        let m =
            parse_java_manifest("Manifest-Version: 1.0\n\nName: a\nMain-Class: wrong\n").unwrap();
        assert_eq!(m.main_class, None);
        assert_eq!(m.entry_sections, 1);
    }

    fn pool_chunk(offsets: &[u32], strings: &[u8]) -> Vec<u8> {
        let header = 28u32;
        let strings_start = header + 4 * offsets.len() as u32;
        let mut c = Vec::new();
        c.extend(1u16.to_le_bytes());
        c.extend(28u16.to_le_bytes());
        c.extend((strings_start + strings.len() as u32).to_le_bytes());
        c.extend((offsets.len() as u32).to_le_bytes());
        c.extend(0u32.to_le_bytes());
        c.extend(0u32.to_le_bytes()); // UTF-16
        c.extend(strings_start.to_le_bytes());
        c.extend(0u32.to_le_bytes());
        for o in offsets {
            c.extend(o.to_le_bytes());
        }
        c.extend(strings);
        c
    }

    /// Blocker: many offsets onto one big string must not multiply into memory.
    #[test]
    fn string_pool_decoding_is_budgeted() {
        // 30,000 UTF-16 units (60 KB) read by 400 offsets = 24 MB decoded: over budget.
        let mut strings = Vec::new();
        strings.extend(30_000u16.to_le_bytes());
        strings.extend([b'a', 0].repeat(30_000));
        let chunk = pool_chunk(&[0; 400], &strings);
        let error = parse_string_pool(&chunk).unwrap_err().to_string();
        assert!(error.contains("decodes to more than"), "{error}");
        // A string over the per-string cap reads as empty instead of allocating.
        let mut huge = Vec::new();
        huge.extend((0x8000u16 | 0x0020).to_le_bytes()); // 0x200000 units declared
        huge.extend(0u16.to_le_bytes());
        let chunk = pool_chunk(&[0; 100], &huge);
        let pool = parse_string_pool(&chunk).unwrap();
        assert!(pool.iter().all(String::is_empty));
        // Normal pools still decode.
        let mut ok = Vec::new();
        ok.extend(3u16.to_le_bytes());
        ok.extend(vec![b'h', 0, b'i', 0, b'!', 0]);
        ok.extend(0u16.to_le_bytes());
        let pool = parse_string_pool(&pool_chunk(&[0], &ok)).unwrap();
        assert_eq!(pool, vec!["hi!".to_string()]);
    }

    /// Blocker: a class whose Methodrefs share huge names keeps small reference lists.
    #[test]
    fn reference_lists_are_cut_to_a_byte_budget() {
        let owner = "o".repeat(60_000);
        let name = "n".repeat(60_000);
        let mut b = test_class_builder::ClassBuilder::new("com/example/Bomb");
        for i in 0..600 {
            b = b.calls(
                &owner,
                &name,
                &format!("(I{})V", "J".repeat(i % 50 + 1) + &i.to_string()),
            );
        }
        let bytes = b.build();
        let class = parse_class_file(&bytes).unwrap();
        let total: usize = class.method_refs.iter().map(String::len).sum();
        assert!(total <= MAX_REF_BYTES_PER_CLASS, "{total}");
        assert!(class.method_refs.iter().all(|m| m.len() < 2_000));
        assert!(class
            .parse_warning
            .as_deref()
            .is_some_and(|w| w.contains("reference lists cut")));
    }
}

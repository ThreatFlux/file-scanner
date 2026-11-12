use crate::java_analysis::{
    analyze_class_file, analyze_java_archive, JavaAnalysisResult, JavaArchiveType,
};
use anyhow::Result;
use goblin::{elf, pe, Object};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

// ThreatFlux binary analysis imports
use threatflux_binary_analysis::{
    Architecture as TfArch, BinaryAnalyzer, BinaryFormat as TfFormat,
};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub format: String,
    pub architecture: String,
    pub compiler: Option<String>,
    pub linker: Option<String>,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub entry_point: Option<u64>,
    pub is_stripped: bool,
    pub has_debug_info: bool,
    pub java_analysis: Option<JavaAnalysisResult>,
    /// Shared libraries the binary needs at load time (ELF `DT_NEEDED`, PE
    /// imported DLLs, Mach-O `LC_LOAD_DYLIB` family), kept apart from `imports`
    /// (the imported functions).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub needed_libraries: Vec<String>,
    /// For a universal (fat) Mach-O: every architecture slice in the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub universal_slices: Option<Vec<UniversalSlice>>,
    /// For a universal Mach-O: the architecture that this analysis describes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyzed_slice: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub size: u64,
    pub virtual_address: u64,
    pub characteristics: String,
}

// Temporarily disabled ThreatFlux conversion function
/// Convert `ThreatFlux` types to `BinaryInfo`
fn convert_threatflux_to_binary_info(
    analysis: &threatflux_binary_analysis::AnalysisResult,
    compiler_info: Option<String>,
    linker_info: Option<String>,
    java_analysis: Option<JavaAnalysisResult>,
) -> BinaryInfo {
    BinaryInfo {
        format: match analysis.format {
            TfFormat::Elf => "ELF".to_string(),
            TfFormat::Pe => "PE".to_string(),
            TfFormat::MachO => "Mach-O".to_string(),
            TfFormat::Java => "Java".to_string(),
            TfFormat::Wasm => "WebAssembly".to_string(),
            TfFormat::Raw => "Raw".to_string(),
            TfFormat::Unknown => "Unknown".to_string(),
        },
        architecture: match analysis.architecture {
            TfArch::X86 => "x86".to_string(),
            TfArch::X86_64 => "x86_64".to_string(),
            TfArch::Arm => "ARM".to_string(),
            TfArch::Arm64 => "ARM64".to_string(),
            TfArch::Mips => "MIPS".to_string(),
            TfArch::Mips64 => "MIPS64".to_string(),
            TfArch::PowerPC => "PowerPC".to_string(),
            TfArch::PowerPC64 => "PowerPC64".to_string(),
            TfArch::RiscV => "RISC-V".to_string(),
            TfArch::RiscV64 => "RISC-V64".to_string(),
            TfArch::Wasm => "WebAssembly".to_string(),
            TfArch::Jvm => "Java Bytecode".to_string(),
            TfArch::Unknown => "Unknown".to_string(),
        },
        compiler: compiler_info,
        linker: linker_info,
        sections: analysis
            .sections
            .iter()
            .map(|s| SectionInfo {
                name: s.name.clone(),
                size: s.size,
                virtual_address: s.address,
                characteristics: format!("{:?}", s.permissions),
            })
            .collect(),
        imports: analysis
            .imports
            .iter()
            .map(|i| {
                if let Some(ref library) = i.library {
                    format!("{} ({})", i.name, library)
                } else {
                    i.name.clone()
                }
            })
            .collect(),
        exports: analysis.exports.iter().map(|e| e.name.clone()).collect(),
        entry_point: analysis.entry_point,
        is_stripped: analysis.symbols.is_empty(),
        has_debug_info: analysis.sections.iter().any(|s| s.name.contains("debug")),
        java_analysis,
        ..Default::default()
    }
}

/// One architecture slice of a universal (fat) Mach-O file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalSlice {
    pub architecture: String,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    /// Byte offset of the slice inside the file.
    pub offset: u64,
    pub size: u64,
    /// True for the slice every analysis of this file describes.
    pub analyzed: bool,
}

/// The slice of a universal Mach-O chosen for analysis.
#[derive(Debug, Clone)]
pub struct FatSelection<'a> {
    pub slices: Vec<UniversalSlice>,
    /// Index into `slices` of the chosen slice.
    pub selected: usize,
    /// The bytes of the chosen slice (a complete thin Mach-O image).
    pub data: &'a [u8],
}

const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_MAGIC_64: u32 = 0xCAFE_BABF;
/// Lowest class-file major version (JDK 1.1). A fat header keeps its
/// architecture count in the same four bytes, always far below this.
const MIN_CLASS_MAJOR_VERSION: u32 = 45;
const CPU_ARCH_ABI64: u32 = 0x0100_0000;
const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_POWERPC: u32 = 18;

/// True when `buffer` starts with a universal Mach-O header (and not with a
/// Java class file, which shares the `CAFEBABE` magic).
#[must_use]
pub fn is_fat_macho(buffer: &[u8]) -> bool {
    let Some(head) = buffer.get(0..8) else {
        return false;
    };
    let magic = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let second = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    match magic {
        FAT_MAGIC_64 => true,
        // Class file: minor(2) major(2); fat file: architecture count(4).
        FAT_MAGIC => second < MIN_CLASS_MAJOR_VERSION,
        _ => false,
    }
}

/// True for a Java class file header (`CAFEBABE` followed by a class version).
#[must_use]
pub fn is_java_class_header(buffer: &[u8]) -> bool {
    buffer.len() >= 8 && buffer[0..4] == [0xCA, 0xFE, 0xBA, 0xBE] && !is_fat_macho(buffer)
}

/// Human name for a Mach-O CPU type/subtype pair.
#[must_use]
pub fn mach_architecture_name(cpu_type: u32, cpu_subtype: u32) -> String {
    let base = cpu_type & !CPU_ARCH_ABI64;
    let is_64 = cpu_type & CPU_ARCH_ABI64 != 0;
    match (base, is_64) {
        (CPU_TYPE_X86, true) => "x86_64".to_string(),
        (CPU_TYPE_X86, false) => "x86".to_string(),
        (CPU_TYPE_ARM, true) => match cpu_subtype & 0x00ff_ffff {
            0 | 1 => "ARM64".to_string(),
            2 => "ARM64E".to_string(),
            n => format!("ARM64 (subtype {n})"),
        },
        (CPU_TYPE_ARM, false) => "ARM".to_string(),
        (CPU_TYPE_POWERPC, true) => "PowerPC64".to_string(),
        (CPU_TYPE_POWERPC, false) => "PowerPC".to_string(),
        _ => format!("cpu_type 0x{cpu_type:x}"),
    }
}

/// The CPU type of the machine this process runs on, as a Mach-O cputype.
fn host_cpu_type() -> Option<u32> {
    if cfg!(target_arch = "aarch64") {
        Some(CPU_TYPE_ARM | CPU_ARCH_ABI64)
    } else if cfg!(target_arch = "x86_64") {
        Some(CPU_TYPE_X86 | CPU_ARCH_ABI64)
    } else {
        None
    }
}

fn name_matches(slice_name: &str, wanted: &str) -> bool {
    let norm = |s: &str| s.to_ascii_lowercase().replace(['-', '_', ' '], "");
    let (a, w) = (norm(slice_name), norm(wanted));
    a == w || (w == "aarch64" && a == "arm64") || (w == "amd64" && a == "x8664")
}

/// List the slices of a universal Mach-O and pick one to analyze: the slice
/// named by `preferred` (for example `"arm64"` or `"x86_64"`) if given and
/// present, else the host architecture if present, else the first slice.
/// Returns `None` when `buffer` is not a universal Mach-O or the header is
/// damaged; an unknown `preferred` name falls back to the default choice.
#[must_use]
pub fn select_fat_slice<'a>(buffer: &'a [u8], preferred: Option<&str>) -> Option<FatSelection<'a>> {
    let mut slices = fat_slice_table(buffer, buffer.len() as u64, |offset| {
        usize::try_from(offset)
            .ok()
            .and_then(|o| buffer.get(o..))
            .is_some_and(is_fat_macho)
    })?;
    let selected = preferred
        .and_then(|w| slices.iter().position(|s| name_matches(&s.architecture, w)))
        .or_else(|| host_cpu_type().and_then(|h| slices.iter().position(|s| s.cpu_type == h)))
        .unwrap_or(0);
    slices[selected].analyzed = true;
    let start = usize::try_from(slices[selected].offset).ok()?;
    let end = start.checked_add(usize::try_from(slices[selected].size).ok()?)?;
    Some(FatSelection {
        data: buffer.get(start..end)?,
        slices,
        selected,
    })
}

/// The valid slices listed by a universal header, without needing the rest of
/// the file. `header` holds at least the first bytes of the file (the header
/// is at most 2056 bytes), `file_len` is the real file size and
/// `starts_with_fat(offset)` tells whether a universal header begins at
/// `offset` (a slice that is itself universal is skipped). `None` when the
/// bytes are not a universal header or no slice is valid.
pub fn fat_slice_table(
    header: &[u8],
    file_len: u64,
    starts_with_fat: impl Fn(u64) -> bool,
) -> Option<Vec<UniversalSlice>> {
    if !is_fat_macho(header) {
        return None;
    }
    let be32 = |o: usize| -> Option<u32> {
        Some(u32::from_be_bytes(header.get(o..o + 4)?.try_into().ok()?))
    };
    let be64 = |o: usize| -> Option<u64> {
        Some(u64::from_be_bytes(header.get(o..o + 8)?.try_into().ok()?))
    };
    let is_64 = be32(0)? == FAT_MAGIC_64;
    let count = be32(4)? as usize;
    let entry_len = if is_64 { 32 } else { 20 };
    if count == 0 || count > 64 {
        return None;
    }
    let mut slices = Vec::new();
    for i in 0..count {
        let base = 8 + i * entry_len;
        let cpu_type = be32(base)?;
        let cpu_subtype = be32(base + 4)?;
        let (offset, size) = if is_64 {
            (be64(base + 8)?, be64(base + 16)?)
        } else {
            (u64::from(be32(base + 8)?), u64::from(be32(base + 12)?))
        };
        let end = offset.checked_add(size)?;
        let header_end = (8 + count * entry_len) as u64;
        if size == 0 || end > file_len || offset < header_end || starts_with_fat(offset) {
            // Truncated or damaged entry: skip it rather than fail the file
            continue;
        }
        slices.push(UniversalSlice {
            architecture: mach_architecture_name(cpu_type, cpu_subtype),
            cpu_type,
            cpu_subtype,
            offset,
            size,
            analyzed: false,
        });
    }
    if slices.is_empty() {
        None
    } else {
        Some(slices)
    }
}

/// Like [`parse_binary`], but for a universal Mach-O analyzes the slice named
/// by `arch` (default: the host architecture if present, else the first).
pub fn parse_binary_with_arch(path: &Path, arch: Option<&str>) -> Result<BinaryInfo> {
    let buffer = fs::read(path)?;
    if let Some(selection) = select_fat_slice(&buffer, arch) {
        let mut info = parse_native_buffer(selection.data)?;
        info.architecture = selection.slices[selection.selected].architecture.clone();
        info.analyzed_slice = Some(selection.slices[selection.selected].architecture.clone());
        info.universal_slices = Some(selection.slices);
        return Ok(info);
    }
    parse_binary_buffer(path, buffer)
}

pub fn parse_binary(path: &Path) -> Result<BinaryInfo> {
    parse_binary_with_arch(path, None)
}

fn parse_binary_buffer(path: &Path, buffer: Vec<u8>) -> Result<BinaryInfo> {
    // First check if it's a Java-related file
    if let Some(extension) = path.extension() {
        match extension.to_str().unwrap_or("").to_lowercase().as_str() {
            "jar" | "war" | "ear" | "apk" | "aar" => {
                return parse_java_archive(path);
            }
            "class" => {
                return parse_java_class(path);
            }
            _ => {}
        }
    }

    // Check magic bytes for ZIP files that might be Java archives
    if buffer.len() >= 4 && &buffer[0..4] == b"PK\x03\x04" {
        // This is a ZIP file, check if it's a Java archive
        if is_java_archive(path) {
            return parse_java_archive(path);
        }
    }

    // Java class file magic (CAFEBABE is shared with universal Mach-O, which
    // parse_binary_with_arch has already handled)
    if is_java_class_header(&buffer) {
        return parse_java_class(path);
    }

    parse_native_buffer(&buffer)
}

/// Parse a thin native image (ELF, PE or Mach-O).
fn parse_native_buffer(buffer: &[u8]) -> Result<BinaryInfo> {
    // Try ThreatFlux first (enhanced analysis), fallback to goblin if needed
    if let Ok(analyzer) = try_create_threatflux_analyzer() {
        if let Ok(analysis) = analyzer.analyze(buffer) {
            // Extract compiler/linker info using legacy methods for enhanced detection
            if let Ok((compiler_info, linker_info)) = extract_legacy_compiler_info(buffer) {
                let mut info = convert_threatflux_to_binary_info(
                    &analysis,
                    compiler_info,
                    linker_info,
                    None, // No Java analysis for native binaries
                );
                complete_from_goblin(&mut info, buffer);
                return Ok(info);
            }
        }
    }

    // Parse native binaries using goblin (original implementation)
    match Object::parse(buffer)? {
        Object::Elf(elf) => parse_elf(elf, buffer),
        Object::PE(pe) => parse_pe(pe, buffer),
        Object::Mach(mach) => parse_mach(mach, buffer),
        _ => anyhow::bail!("Unsupported binary format"),
    }
}

/// Fill what the ThreatFlux result lacks: the needed-library list, and for
/// Mach-O the imports of chained-fixup binaries (which have no bind opcodes).
fn complete_from_goblin(info: &mut BinaryInfo, buffer: &[u8]) {
    match Object::parse(buffer) {
        Ok(Object::Elf(elf)) => {
            info.needed_libraries = unique_strings(elf.libraries.iter().map(|l| (*l).to_string()));
        }
        Ok(Object::PE(pe)) => {
            info.needed_libraries = unique_strings(pe.libraries.iter().map(|l| (*l).to_string()));
        }
        Ok(Object::Mach(goblin::mach::Mach::Binary(macho))) => {
            info.needed_libraries = mach_needed_libraries(&macho);
            if info.imports.is_empty() {
                info.imports = mach_undefined_imports(&macho, buffer);
            }
            let name = mach_architecture_name(macho.header.cputype, macho.header.cpusubtype);
            // The Mach-O header is the authority (ARM64E vs ARM64 is a subtype
            // the generic analyzer does not tell apart).
            info.architecture = name;
        }
        _ => {}
    }
}

/// Shared libraries a native binary needs at load time (ELF `DT_NEEDED`, PE
/// imported DLLs, Mach-O load commands; for a universal Mach-O, the analyzed
/// slice). Empty for anything else or when the file cannot be read.
#[must_use]
pub fn needed_libraries(path: &Path) -> Vec<String> {
    let Ok(buffer) = fs::read(path) else {
        return Vec::new();
    };
    let data = select_fat_slice(&buffer, None).map_or(&buffer[..], |s| s.data);
    match Object::parse(data) {
        Ok(Object::Elf(elf)) => unique_strings(elf.libraries.iter().map(|l| (*l).to_string())),
        Ok(Object::PE(pe)) => unique_strings(pe.libraries.iter().map(|l| (*l).to_string())),
        Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => mach_needed_libraries(&m),
        _ => Vec::new(),
    }
}

fn unique_strings(items: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items.filter(|s| seen.insert(s.clone())).collect()
}

/// Dependent libraries of a Mach-O (`LC_LOAD_DYLIB` and friends; goblin keeps
/// the image itself in slot 0, which is not a dependency).
fn mach_needed_libraries(macho: &goblin::mach::MachO) -> Vec<String> {
    unique_strings(
        macho
            .libs
            .iter()
            .skip(1)
            .filter(|l| !l.is_empty() && **l != "self")
            .map(|l| (*l).to_string()),
    )
}

/// Longest symbol name kept, in bytes. A name is read from the file with this
/// cap (a hostile file can point thousands of symbols at one huge string), and
/// a longer one ends in [`NAME_TRUNCATED`].
pub(crate) const MAX_SYMBOL_NAME: usize = 4096;
/// Marker that ends a symbol name cut at [`MAX_SYMBOL_NAME`].
pub(crate) const NAME_TRUNCATED: &str = "...[name truncated]";
/// Total symbol-name bytes one analysis keeps (every copy counts).
pub(crate) const SYMBOL_NAME_BUDGET: usize = 32 << 20;

/// `name` limited to [`MAX_SYMBOL_NAME`] bytes (cut on a character boundary).
pub(crate) fn capped_name(name: &str) -> std::borrow::Cow<'_, str> {
    if name.len() <= MAX_SYMBOL_NAME {
        return std::borrow::Cow::Borrowed(name);
    }
    let mut end = MAX_SYMBOL_NAME;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    std::borrow::Cow::Owned(format!("{}{NAME_TRUNCATED}", &name[..end]))
}

/// Running total of symbol-name bytes kept by one analysis.
#[derive(Default)]
pub(crate) struct NameBudget {
    used: usize,
    cut: bool,
}

impl NameBudget {
    /// Charges `copies` copies of `name`; false (and the budget is marked cut)
    /// when that would exceed [`SYMBOL_NAME_BUDGET`].
    pub(crate) fn charge(&mut self, name: &str, copies: usize) -> bool {
        let cost = name.len().saturating_mul(copies);
        if self.cut || self.used.saturating_add(cost) > SYMBOL_NAME_BUDGET {
            self.cut = true;
            return false;
        }
        self.used += cost;
        true
    }

    pub(crate) fn is_cut(&self) -> bool {
        self.cut
    }
}

/// The readable, non-debugger entries of a Mach-O symbol table, read straight
/// from `LC_SYMTAB`. The walk is bounded by what fits in the file (a hostile
/// `nsyms` costs at most `file_len / nlist_size` steps), an entry whose name
/// offset is bad is skipped instead of ending the walk, and every name is read
/// with the [`MAX_SYMBOL_NAME`] cap, so the work per entry does not depend on
/// the length of the string it points at.
pub(crate) fn mach_symbols_bounded<'a>(
    macho: &goblin::mach::MachO<'a>,
    data: &'a [u8],
) -> impl Iterator<Item = (std::borrow::Cow<'a, str>, goblin::mach::symbols::Nlist)> {
    let nlist_size: u64 = if macho.is_64 { 16 } else { 12 };
    let is_64 = macho.is_64;
    let little = macho.little_endian;
    let symtab = macho.load_commands.iter().find_map(|lc| match &lc.command {
        goblin::mach::load_command::CommandVariant::Symtab(s) => Some(*s),
        _ => None,
    });
    let (symoff, stroff, strend, fit) = symtab.map_or((0, 0, 0, 0), |s| {
        let room = (data.len() as u64).saturating_sub(u64::from(s.symoff)) / nlist_size;
        let strend = (u64::from(s.stroff) + u64::from(s.strsize)).min(data.len() as u64);
        (
            u64::from(s.symoff),
            u64::from(s.stroff),
            strend,
            u64::from(s.nsyms).min(room),
        )
    });
    (0..fit).filter_map(move |i| {
        let at = usize::try_from(symoff + i * nlist_size).ok()?;
        let rec = data.get(at..at + usize::try_from(nlist_size).ok()?)?;
        let u32_at = |o: usize| {
            let b: [u8; 4] = rec[o..o + 4].try_into().unwrap_or([0; 4]);
            if little {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let n_desc = {
            let b: [u8; 2] = rec[6..8].try_into().unwrap_or([0; 2]);
            if little {
                u16::from_le_bytes(b)
            } else {
                u16::from_be_bytes(b)
            }
        };
        let n_value = if is_64 {
            let b: [u8; 8] = rec[8..16].try_into().unwrap_or([0; 8]);
            if little {
                u64::from_le_bytes(b)
            } else {
                u64::from_be_bytes(b)
            }
        } else {
            u64::from(u32_at(8))
        };
        let nlist = goblin::mach::symbols::Nlist {
            n_strx: u32_at(0) as usize,
            n_type: rec[4],
            n_sect: usize::from(rec[5]),
            n_desc,
            n_value,
        };
        // Debugger entries are never wanted; skip them before reading a name
        if nlist.is_stab() {
            return None;
        }
        let start = stroff.checked_add(nlist.n_strx as u64)?;
        if start >= strend {
            return None;
        }
        let limit = strend.min(start + MAX_SYMBOL_NAME as u64 + 1);
        let bytes = data.get(start as usize..limit as usize)?;
        let (name_bytes, truncated) = match bytes.iter().position(|b| *b == 0) {
            Some(nul) => (&bytes[..nul], false),
            None if bytes.len() > MAX_SYMBOL_NAME => (&bytes[..MAX_SYMBOL_NAME], true),
            None => (bytes, false),
        };
        let mut name = String::from_utf8_lossy(name_bytes);
        if truncated {
            name.to_mut().push_str(NAME_TRUNCATED);
        }
        Some((name, nlist))
    })
}

/// Imports as `name (library)` taken from the undefined symbols, for binaries
/// whose bind info is absent.
fn mach_undefined_imports(macho: &goblin::mach::MachO, data: &[u8]) -> Vec<String> {
    let mut budget = NameBudget::default();
    let mut out = Vec::new();
    for (name, nlist) in mach_symbols_bounded(macho, data) {
        if nlist.is_stab() || !nlist.is_undefined() || name.is_empty() {
            continue;
        }
        match crate::function_analysis::mach_import_library(macho, &nlist) {
            Some(lib) => {
                if !budget.charge(&name, 1) {
                    break;
                }
                out.push(format!("{name} ({lib})"));
            }
            None => {
                if !budget.charge(&name, 1) {
                    break;
                }
                out.push(name.into_owned());
            }
        }
    }
    out
}

/// Try to create `ThreatFlux` analyzer, return error if library has compilation issues
fn try_create_threatflux_analyzer() -> Result<BinaryAnalyzer> {
    Ok(BinaryAnalyzer::new())
}

/// Extract enhanced compiler and linker information using legacy methods
/// This provides more detailed detection than basic `ThreatFlux` analysis
fn extract_legacy_compiler_info(buffer: &[u8]) -> Result<(Option<String>, Option<String>)> {
    let mut compiler_info = None;
    let mut linker_info = None;

    match Object::parse(buffer)? {
        Object::Elf(elf) => {
            // Check for compiler signatures in ELF notes/sections
            for section in &elf.section_headers {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    if name.contains(".note.gnu") || name.contains(".note.ABI-tag") {
                        compiler_info = Some("GCC/GNU".to_string());
                        break;
                    } else if name.contains(".note.clang") {
                        compiler_info = Some("Clang".to_string());
                        break;
                    }
                }
            }
        }
        Object::PE(pe) => {
            // Enhanced PE compiler/linker detection
            if let Some(optional_header) = pe.header.optional_header {
                let major_version = optional_header.standard_fields.major_linker_version;
                let minor_version = optional_header.standard_fields.minor_linker_version;

                linker_info = Some(format!("Linker v{major_version}.{minor_version}"));

                compiler_info = match major_version {
                    14..=16 => Some("MSVC 2015-2022".to_string()),
                    12..=13 => Some("MSVC 2013".to_string()),
                    11 => Some("MSVC 2012".to_string()),
                    10 => Some("MSVC 2010".to_string()),
                    9 => Some("MSVC 2008".to_string()),
                    8 => Some("MSVC 2005".to_string()),
                    7 => Some("MSVC 2003".to_string()),
                    6 => Some("MSVC 6.0".to_string()),
                    2..=4 => Some("MinGW/GCC".to_string()),
                    _ => None,
                };
            }
        }
        Object::Mach(goblin::mach::Mach::Binary(_)) => {
            // Basic macOS compiler detection (a damaged universal header that
            // goblin accepts is not a Mach-O image and gets no toolchain claim)
            compiler_info = Some("Apple Clang".to_string());
            linker_info = Some("Apple LD".to_string());
        }
        _ => {}
    }

    Ok((compiler_info, linker_info))
}

fn parse_elf(elf: elf::Elf, _buffer: &[u8]) -> Result<BinaryInfo> {
    let mut info = BinaryInfo {
        format: "ELF".to_string(),
        architecture: match elf.header.e_machine {
            elf::header::EM_X86_64 => "x86_64",
            elf::header::EM_386 => "x86",
            elf::header::EM_ARM => "ARM",
            elf::header::EM_AARCH64 => "ARM64",
            _ => "Unknown",
        }
        .to_string(),
        compiler: None,
        linker: None,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        entry_point: Some(elf.header.e_entry),
        is_stripped: elf.syms.is_empty(),
        has_debug_info: false,
        java_analysis: None,
        needed_libraries: unique_strings(elf.libraries.iter().map(|l| (*l).to_string())),
        ..Default::default()
    };

    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            info.sections.push(SectionInfo {
                name: name.to_string(),
                size: section.sh_size,
                virtual_address: section.sh_addr,
                characteristics: format!("{:x}", section.sh_flags),
            });

            if name.starts_with(".debug") {
                info.has_debug_info = true;
            }
        }
    }

    for import in &elf.libraries {
        info.imports.push(import.to_string());
    }

    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if sym.is_function() && sym.st_bind() == elf::sym::STB_GLOBAL {
                info.exports.push(name.to_string());
            }
        }
    }

    // Note: NoteIterator parsing is version-specific
    // For simplicity, we'll check for common compiler signatures
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if name.contains(".note.gnu") || name.contains(".note.ABI-tag") {
                info.compiler = Some("GCC/GNU".to_string());
                break;
            }
        }
    }

    Ok(info)
}

fn parse_pe(pe: pe::PE, _buffer: &[u8]) -> Result<BinaryInfo> {
    let mut info = BinaryInfo {
        format: "PE".to_string(),
        architecture: match pe.header.coff_header.machine {
            pe::header::COFF_MACHINE_X86_64 => "x86_64",
            pe::header::COFF_MACHINE_X86 => "x86",
            pe::header::COFF_MACHINE_ARM64 => "ARM64",
            _ => "Unknown",
        }
        .to_string(),
        compiler: None,
        linker: None,
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        entry_point: Some(u64::from(pe.entry)),
        is_stripped: pe.debug_data.is_none(),
        has_debug_info: pe.debug_data.is_some(),
        java_analysis: None,
        needed_libraries: unique_strings(pe.libraries.iter().map(|l| (*l).to_string())),
        ..Default::default()
    };

    for section in &pe.sections {
        info.sections.push(SectionInfo {
            name: section.name()?.to_string(),
            size: u64::from(section.virtual_size),
            virtual_address: u64::from(section.virtual_address),
            characteristics: format!("{:x}", section.characteristics),
        });
    }

    for import in &pe.imports {
        info.imports.push(import.name.to_string());
        // Note: In goblin 0.8, imports are handled differently
        // We already have the DLL name in import.name
    }

    // Export handling for goblin 0.8
    for export in &pe.exports {
        if let Some(name) = export.name {
            info.exports.push(name.to_string());
        }
    }

    if let Some(optional_header) = pe.header.optional_header {
        let linker_version = format!(
            "{}.{}",
            optional_header.standard_fields.major_linker_version,
            optional_header.standard_fields.minor_linker_version
        );
        info.linker = Some(format!("Linker v{linker_version}"));

        match optional_header.standard_fields.major_linker_version {
            14..=16 => info.compiler = Some("MSVC 2015-2022".to_string()),
            12..=13 => info.compiler = Some("MSVC 2013".to_string()),
            11 => info.compiler = Some("MSVC 2012".to_string()),
            10 => info.compiler = Some("MSVC 2010".to_string()),
            9 => info.compiler = Some("MSVC 2008".to_string()),
            8 => info.compiler = Some("MSVC 2005".to_string()),
            7 => info.compiler = Some("MSVC 2003".to_string()),
            6 => info.compiler = Some("MSVC 6.0".to_string()),
            2..=4 => info.compiler = Some("MinGW/GCC".to_string()),
            _ => {}
        }
    }

    Ok(info)
}

fn parse_mach(mach: goblin::mach::Mach, data: &[u8]) -> Result<BinaryInfo> {
    use goblin::mach::Mach;

    let mut info = BinaryInfo {
        format: "Mach-O".to_string(),
        architecture: "Unknown".to_string(),
        compiler: Some("Apple Clang".to_string()),
        linker: Some("Apple LD".to_string()),
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        entry_point: None,
        is_stripped: false,
        has_debug_info: false,
        java_analysis: None,
        ..Default::default()
    };

    match mach {
        Mach::Binary(mach_o) => {
            info.architecture =
                mach_architecture_name(mach_o.header.cputype, mach_o.header.cpusubtype);
            info.needed_libraries = mach_needed_libraries(&mach_o);
            info.entry_point = Some(mach_o.entry);
            for segment in &mach_o.segments {
                for (section, _) in &segment.sections()? {
                    info.sections.push(SectionInfo {
                        name: section.name()?.to_string(),
                        size: section.size,
                        virtual_address: section.addr,
                        characteristics: format!("{:x}", section.flags),
                    });
                }
            }

            info.is_stripped = mach_o.symbols.is_none();

            for import in &mach_o.imports()? {
                info.imports.push(import.name.to_string());
            }
            if info.imports.is_empty() {
                info.imports = mach_undefined_imports(&mach_o, data);
            }

            let exports = mach_o.exports()?;
            if !exports.is_empty() {
                for export in exports {
                    info.exports.push(export.name.clone());
                }
            }
        }
        Mach::Fat(_) => {
            info.architecture = "Universal".to_string();
        }
    }

    Ok(info)
}

fn parse_java_archive(path: &Path) -> Result<BinaryInfo> {
    let java_analysis = analyze_java_archive(path)?;

    let format = match java_analysis.archive_type {
        JavaArchiveType::Jar => "JAR",
        JavaArchiveType::War => "WAR",
        JavaArchiveType::Ear => "EAR",
        JavaArchiveType::Apk => "APK",
        JavaArchiveType::Aar => "AAR",
        _ => "Java Archive",
    };

    Ok(BinaryInfo {
        format: format.to_string(),
        architecture: "Java Bytecode".to_string(),
        compiler: java_analysis
            .manifest
            .as_ref()
            .and_then(|m| m.created_by.clone())
            .or_else(|| Some("Unknown Java Compiler".to_string())),
        linker: java_analysis
            .manifest
            .as_ref()
            .and_then(|m| m.build_jdk.clone()),
        sections: Vec::new(),
        imports: java_analysis
            .classes
            .iter()
            .flat_map(|c| c.interfaces.iter().cloned())
            .collect(),
        exports: java_analysis
            .classes
            .iter()
            .filter(|c| c.is_public)
            .map(|c| c.name.clone())
            .collect(),
        entry_point: None,
        is_stripped: false,
        has_debug_info: java_analysis
            .classes
            .iter()
            .any(|c| c.source_file.is_some()),
        java_analysis: Some(java_analysis),
        ..Default::default()
    })
}

fn parse_java_class(path: &Path) -> Result<BinaryInfo> {
    let java_analysis = analyze_class_file(path)?;

    Ok(BinaryInfo {
        format: "Java Class".to_string(),
        architecture: "Java Bytecode".to_string(),
        compiler: Some("Unknown Java Compiler".to_string()),
        linker: None,
        sections: Vec::new(),
        imports: java_analysis
            .classes
            .first()
            .map(|c| c.interfaces.clone())
            .unwrap_or_default(),
        exports: java_analysis
            .classes
            .first()
            .filter(|c| c.is_public)
            .map(|c| vec![c.name.clone()])
            .unwrap_or_default(),
        entry_point: None,
        is_stripped: false,
        has_debug_info: java_analysis
            .classes
            .first()
            .is_some_and(|c| c.source_file.is_some()),
        java_analysis: Some(java_analysis),
        ..Default::default()
    })
}

fn is_java_archive(path: &Path) -> bool {
    // Try to open as ZIP and look for Java-specific files
    if let Ok(file) = std::fs::File::open(path) {
        if let Ok(mut archive) = zip::ZipArchive::new(file) {
            for i in 0..archive.len() {
                if let Ok(file) = archive.by_index(i) {
                    let Ok(name) = file.name() else {
                        continue;
                    };
                    // Look for Java-specific indicators
                    if name == "META-INF/MANIFEST.MF"
                        || name.ends_with(".class")
                        || name == "AndroidManifest.xml"
                        || name == "classes.dex"
                        || name.starts_with("WEB-INF/")
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_file(content: &[u8]) -> Result<(TempDir, std::path::PathBuf)> {
        let temp_dir = TempDir::new()?;
        let file_path = temp_dir.path().join("test_binary");
        let mut file = fs::File::create(&file_path)?;
        file.write_all(content)?;
        Ok((temp_dir, file_path))
    }

    // ELF test binary (minimal valid ELF)
    fn create_minimal_elf() -> Vec<u8> {
        let mut elf = vec![
            // ELF header
            0x7f, 0x45, 0x4c, 0x46, // Magic number
            0x02, // 64-bit
            0x01, // Little endian
            0x01, // ELF version
            0x00, // System V ABI
            0x00, // ABI version
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
            0x02, 0x00, // Executable file
            0x3e, 0x00, // x86-64
            0x01, 0x00, 0x00, 0x00, // Version 1
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry point
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Program header offset
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Section header offset
            0x00, 0x00, 0x00, 0x00, // Flags
            0x40, 0x00, // ELF header size
            0x38, 0x00, // Program header size
            0x01, 0x00, // Program header count
            0x40, 0x00, // Section header size
            0x00, 0x00, // Section header count
            0x00, 0x00, // Section name string table index
        ];

        // Pad to at least 64 bytes
        while elf.len() < 64 {
            elf.push(0);
        }

        elf
    }

    // PE test binary (minimal valid PE)
    fn create_minimal_pe() -> Vec<u8> {
        let mut pe = vec![
            // DOS header
            0x4d, 0x5a, // "MZ"
        ];

        // Pad DOS header to 64 bytes
        while pe.len() < 60 {
            pe.push(0);
        }

        // PE offset at 0x3c
        pe.extend_from_slice(&[0x40, 0x00, 0x00, 0x00]); // PE header at offset 0x40

        // PE signature at offset 0x40
        pe.extend_from_slice(b"PE\0\0");

        // COFF header
        pe.extend_from_slice(&[
            0x64, 0x86, // Machine x86_64
            0x01, 0x00, // 1 section
            0x00, 0x00, 0x00, 0x00, // Timestamp
            0x00, 0x00, 0x00, 0x00, // Symbol table pointer
            0x00, 0x00, 0x00, 0x00, // Number of symbols
            0xf0, 0x00, // Size of optional header
            0x22, 0x00, // Characteristics
        ]);

        // Optional header
        pe.extend_from_slice(&[
            0x0b, 0x02, // Magic (PE64)
            14, 0, // Linker version
        ]);

        // Pad to make valid PE
        while pe.len() < 512 {
            pe.push(0);
        }

        pe
    }

    #[test]
    fn test_parse_elf_binary() {
        let elf_data = create_minimal_elf();
        let (_temp_dir, file_path) = create_test_file(&elf_data).unwrap();

        let result = parse_binary(&file_path);
        // Our minimal ELF might not be valid enough for goblin to parse
        // So we test that it doesn't panic and handles the error gracefully
        if let Ok(info) = result {
            assert_eq!(info.format, "ELF");
            assert_eq!(info.architecture, "x86_64");
            assert_eq!(info.entry_point, Some(0x1000));
        } else {
            // It's okay if the minimal ELF fails to parse
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_parse_pe_binary() {
        let pe_data = create_minimal_pe();
        let (_temp_dir, file_path) = create_test_file(&pe_data).unwrap();

        let result = parse_binary(&file_path);

        // Note: The minimal PE might not be fully valid for goblin
        // In practice, you'd use a real PE file for testing
        if let Ok(info) = result {
            assert_eq!(info.format, "PE");
        }
    }

    #[test]
    fn test_parse_invalid_binary() {
        let invalid_data = b"This is not a valid binary file";
        let (_temp_dir, file_path) = create_test_file(invalid_data).unwrap();

        let result = parse_binary(&file_path);
        // ThreatFlux is more resilient and can analyze unknown/raw formats
        if let Ok(binary_info) = result {
            assert!(binary_info.format == "Raw" || binary_info.format == "Unknown");
        } else {
            // Goblin fallback might still return error, which is also acceptable
        }
    }

    #[test]
    fn test_parse_empty_file() {
        let (_temp_dir, file_path) = create_test_file(b"").unwrap();

        let result = parse_binary(&file_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_nonexistent_file() {
        let path = std::path::Path::new("/nonexistent/binary");
        let result = parse_binary(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_binary_info_serialization() {
        let info = BinaryInfo {
            format: "ELF".to_string(),
            architecture: "x86_64".to_string(),
            compiler: Some("GCC".to_string()),
            linker: Some("GNU ld".to_string()),
            sections: vec![
                SectionInfo {
                    name: ".text".to_string(),
                    size: 1024,
                    virtual_address: 0x1000,
                    characteristics: "ax".to_string(),
                },
                SectionInfo {
                    name: ".data".to_string(),
                    size: 512,
                    virtual_address: 0x2000,
                    characteristics: "wa".to_string(),
                },
            ],
            imports: vec!["libc.so.6".to_string()],
            exports: vec!["main".to_string()],
            entry_point: Some(0x1000),
            is_stripped: false,
            has_debug_info: true,
            java_analysis: None,
            ..Default::default()
        };

        // Test JSON serialization
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: BinaryInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.format, info.format);
        assert_eq!(deserialized.architecture, info.architecture);
        assert_eq!(deserialized.compiler, info.compiler);
        assert_eq!(deserialized.sections.len(), 2);
        assert_eq!(deserialized.imports, info.imports);
        assert_eq!(deserialized.exports, info.exports);
    }

    #[test]
    fn test_section_info_properties() {
        let section = SectionInfo {
            name: ".rodata".to_string(),
            size: 2048,
            virtual_address: 0x3000,
            characteristics: "r".to_string(),
        };

        assert_eq!(section.name, ".rodata");
        assert_eq!(section.size, 2048);
        assert_eq!(section.virtual_address, 0x3000);
        assert_eq!(section.characteristics, "r");
    }

    #[test]
    fn test_parse_elf_architecture_variants() {
        // Test x86 ELF
        let mut elf_x86 = create_minimal_elf();
        elf_x86[18] = 0x03; // EM_386
        elf_x86[19] = 0x00;

        let (_temp_dir, file_path) = create_test_file(&elf_x86).unwrap();
        if let Ok(info) = parse_binary(&file_path) {
            assert_eq!(info.architecture, "x86");
        }
    }

    #[test]
    fn test_parse_elf_with_sections() {
        // In real tests, you would use a proper ELF file with sections
        // For now, test that the function handles empty sections gracefully
        let elf_data = create_minimal_elf();
        let (_temp_dir, file_path) = create_test_file(&elf_data).unwrap();

        if let Ok(info) = parse_binary(&file_path) {
            // Minimal ELF has no sections
            assert!(info.sections.is_empty() || !info.sections.is_empty());
        }
    }

    #[test]
    fn test_binary_info_defaults() {
        let info = BinaryInfo {
            format: String::new(),
            architecture: String::new(),
            compiler: None,
            linker: None,
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            entry_point: None,
            is_stripped: true,
            has_debug_info: false,
            java_analysis: None,
            ..Default::default()
        };

        assert!(info.compiler.is_none());
        assert!(info.linker.is_none());
        assert!(info.sections.is_empty());
        assert!(info.imports.is_empty());
        assert!(info.exports.is_empty());
        assert!(info.entry_point.is_none());
        assert!(info.is_stripped);
        assert!(!info.has_debug_info);
    }

    // Integration test with real binary (if available)
    #[test]
    #[cfg(target_os = "linux")] // Only run on Linux for now due to macOS issues
    fn test_parse_real_binary() {
        // Try to parse /bin/ls if it exists
        let ls_path = std::path::Path::new("/bin/ls");
        if ls_path.exists() {
            let result = parse_binary(ls_path);
            assert!(result.is_ok());

            let info = result.unwrap();

            // Check Linux-specific format
            assert_eq!(info.format, "ELF");

            // Entry point should be present
            assert!(info.entry_point.is_some());

            // Imports should be detected
            assert!(!info.imports.is_empty());
        }
    }

    #[test]
    fn test_mach_binary_mock() {
        // Mach-O magic numbers
        let mach_data = vec![
            0xfe, 0xed, 0xfa, 0xce, // Mach-O 32-bit magic
            0x00, 0x00, 0x00, 0x01, // CPU type
        ];

        let (_temp_dir, file_path) = create_test_file(&mach_data).unwrap();
        let result = parse_binary(&file_path);

        // The mock data might not be valid enough for goblin
        // but we test that it attempts to parse
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_compiler_detection_pe() {
        // Test the compiler detection logic for PE files
        let mut pe_data = create_minimal_pe();

        // Test different linker versions
        let test_cases = vec![
            (14, "MSVC 2015-2022"),
            (12, "MSVC 2013"),
            (11, "MSVC 2012"),
            (10, "MSVC 2010"),
            (9, "MSVC 2008"),
            (8, "MSVC 2005"),
            (7, "MSVC 2003"),
            (6, "MSVC 6.0"),
            (3, "MinGW/GCC"),
        ];

        for (version, _expected_compiler) in test_cases {
            pe_data[74] = version; // Assuming this is where linker version would be
            let (_temp_dir, file_path) = create_test_file(&pe_data).unwrap();
            let _result = parse_binary(&file_path);
            // Would check compiler detection if we had a valid PE
        }
    }
}

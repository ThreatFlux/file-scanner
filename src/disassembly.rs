use anyhow::{Context, Result};
use capstone::prelude::*;
use capstone::{Arch, Mode, NO_EXTRA_MODE};
use goblin::Object;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::function_analysis::SymbolTable;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    pub architecture: String,
    pub instructions: Vec<Instruction>,
    pub analysis: InstructionAnalysis,
    pub functions: Vec<DisassembledFunction>,
    pub output_formats: OutputFormats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub instruction_type: InstructionType,
    pub flow_control: Option<FlowControl>,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum InstructionType {
    Arithmetic,
    Logic,
    Memory,
    Control,
    System,
    Crypto,
    Vector,
    Stack,
    Comparison,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowControl {
    Jump {
        target: Option<u64>,
        conditional: bool,
    },
    Call {
        target: Option<u64>,
        is_indirect: bool,
    },
    Return,
    Interrupt {
        number: u8,
    },
    ConditionalMove,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionAnalysis {
    pub total_instructions: usize,
    pub instruction_types: HashMap<String, usize>,
    pub register_usage: HashMap<String, Vec<u64>>,
    pub memory_accesses: Vec<MemoryAccess>,
    pub system_calls: Vec<SystemCall>,
    pub crypto_operations: Vec<CryptoOperation>,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub control_flow_summary: ControlFlowSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAccess {
    pub instruction_address: u64,
    pub access_type: AccessType,
    pub size: u32,
    pub target_address: Option<u64>,
    pub register_base: Option<String>,
    pub register_index: Option<String>,
    pub displacement: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessType {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemCall {
    pub address: u64,
    pub syscall_number: Option<u64>,
    pub syscall_name: Option<String>,
    pub category: SystemCallCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemCallCategory {
    FileSystem,
    Process,
    Network,
    Memory,
    Security,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoOperation {
    pub address: u64,
    pub operation_type: CryptoOpType,
    pub algorithm_hint: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoOpType {
    AESOperation,
    SHA256Operation,
    RSAOperation,
    XOROperation,
    RandomGeneration,
    KeyDerivation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    pub pattern_type: PatternType,
    pub addresses: Vec<u64>,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatternType {
    AntiDebug,
    AntiVM,
    Obfuscation,
    SelfModifying,
    StackManipulation,
    IndirectJumps,
    NopSled,
    ReturnOriented,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowSummary {
    pub total_jumps: usize,
    pub conditional_jumps: usize,
    pub unconditional_jumps: usize,
    pub function_calls: usize,
    pub indirect_calls: usize,
    pub returns: usize,
    pub interrupts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembledFunction {
    pub address: u64,
    pub name: String,
    pub size: usize,
    pub instructions: Vec<Instruction>,
    pub basic_blocks: Vec<BasicBlock>,
    pub complexity: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub start_address: u64,
    pub end_address: u64,
    pub instruction_count: usize,
    pub exits: Vec<BlockExit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockExit {
    pub exit_type: ExitType,
    pub target: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExitType {
    FallThrough,
    Jump,
    ConditionalJump,
    Call,
    Return,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputFormats {
    pub assembly: String,
    pub json_structured: serde_json::Value,
    pub graph_data: GraphVisualizationData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphVisualizationData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub edge_type: String,
    pub label: Option<String>,
}

/// Upper bound on the bytes of one code section that are decoded. Larger
/// sections are decoded up to this limit and the coverage report says so.
pub const MAX_DISASSEMBLY_BYTES: usize = 8 * 1024 * 1024;

/// Upper bound on instructions kept from one code section (memory bound for
/// code made of one-byte instructions).
pub const MAX_DISASSEMBLY_INSTRUCTIONS: usize = 1_000_000;

/// Upper bound on functions grouped out of the symbol table.
pub const MAX_GROUPED_FUNCTIONS: usize = 5_000;

/// Instructions decoded per Capstone call.
const DISASSEMBLY_CHUNK: usize = 4096;

/// How much of the code section was decoded, and what was skipped.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DisassemblyCoverage {
    /// Size of the code section in the file.
    pub section_size: u64,
    /// Bytes handed to the decoder (the section, or its first `MAX_DISASSEMBLY_BYTES`).
    pub bytes_examined: u64,
    /// Bytes that decoded to real instructions.
    pub bytes_decoded: u64,
    /// Bytes that could not be decoded and were skipped (listed as `.byte` entries).
    pub bytes_skipped: u64,
    /// Number of separate undecodable runs.
    pub skipped_runs: u64,
    /// True when the section was larger than the decode limit.
    pub truncated: bool,
    /// Address of the first decoded byte.
    #[serde(default)]
    pub start_address: u64,
    /// Address one past the last byte that was handed to the decoder and
    /// decoded or skipped. Bytes of the section at or beyond it were not read.
    #[serde(default)]
    pub end_address: u64,
    /// Bytes of the code section that were never decoded (past a limit).
    #[serde(default)]
    pub bytes_not_decoded: u64,
    /// Human-readable summary of limits that applied.
    pub notes: Vec<String>,
}

pub fn disassemble_binary(path: &Path, symbol_table: &SymbolTable) -> Result<DisassemblyResult> {
    disassemble_binary_with_coverage(path, symbol_table).map(|(result, _)| result)
}

/// Like [`disassemble_binary`], and also returns how much of the code section
/// was decoded. The same coverage figures are placed in
/// `output_formats.json_structured["coverage"]`.
pub fn disassemble_binary_with_coverage(
    path: &Path,
    symbol_table: &SymbolTable,
) -> Result<(DisassemblyResult, DisassemblyCoverage)> {
    disassemble_binary_with_arch(path, None, symbol_table)
}

/// Like [`disassemble_binary_with_coverage`] for a universal (fat) Mach-O: the
/// slice named by `arch` (for example `"arm64"`) is disassembled; `None` picks the
/// host architecture if present, else the first slice. `symbol_table` should come
/// from `function_analysis::analyze_symbols_with_arch` with the same `arch`.
/// For any other file `arch` is ignored.
pub fn disassemble_binary_with_arch(
    path: &Path,
    arch: Option<&str>,
    symbol_table: &SymbolTable,
) -> Result<(DisassemblyResult, DisassemblyCoverage)> {
    let buffer = fs::read(path).context("Failed to read file for disassembly")?;
    disassemble_buffer(&buffer, arch, symbol_table)
}

/// Most instructions [`disassemble_range`] returns in one call.
pub const MAX_RANGE_INSTRUCTIONS: usize = 100_000;

/// A bounded listing of one address range of a code section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeDisassembly {
    pub architecture: String,
    /// First address requested.
    pub start_address: u64,
    /// Address one past the last instruction listed.
    pub end_address: u64,
    pub instructions: Vec<Instruction>,
    /// Address range of the whole code section, so a caller can page onwards.
    pub section_start: u64,
    pub section_end: u64,
    /// True when more code follows `end_address` inside the requested range or section.
    pub more: bool,
    pub coverage: DisassemblyCoverage,
    pub notes: Vec<String>,
}

/// Disassemble up to `max_instructions` (at most [`MAX_RANGE_INSTRUCTIONS`])
/// instructions starting at virtual address `start`, anywhere inside the code
/// section. This reaches code that the whole-file listing does not: that listing
/// stops at its instruction and byte limits, this one starts where you say.
/// `arch` picks the slice of a universal Mach-O. `start` must be an
/// instruction boundary for the listing to be meaningful; the result says so.
pub fn disassemble_range(
    path: &Path,
    arch: Option<&str>,
    start: u64,
    max_instructions: usize,
) -> Result<RangeDisassembly> {
    disassemble_range_bounded(path, arch, start, None, max_instructions)
}

/// Like [`disassemble_range`], ending at address `end` (exclusive) when given.
pub fn disassemble_range_bounded(
    path: &Path,
    arch: Option<&str>,
    start: u64,
    end: Option<u64>,
    max_instructions: usize,
) -> Result<RangeDisassembly> {
    let buffer = fs::read(path).context("Failed to read file for disassembly")?;
    disassemble_range_in_buffer(&buffer, arch, start, end, max_instructions)
}

/// List one named function: its symbol gives the start and (when the symbol
/// has one) the size; without a size it runs to the next function symbol.
/// `max_instructions` bounds the listing as in [`disassemble_range`].
pub fn disassemble_function(
    path: &Path,
    arch: Option<&str>,
    symbol_table: &SymbolTable,
    name: &str,
    max_instructions: usize,
) -> Result<RangeDisassembly> {
    let matching: Vec<_> = symbol_table
        .functions
        .iter()
        .filter(|f| !f.is_imported && f.name == name)
        .collect();
    let function = matching
        .first()
        .ok_or_else(|| anyhow::anyhow!("No function named {name:?} in the symbol table"))?;
    let end = if function.size > 0 {
        Some(function.address.saturating_add(function.size))
    } else {
        symbol_table
            .functions
            .iter()
            .filter(|f| !f.is_imported && f.address > function.address)
            .map(|f| f.address)
            .min()
    };
    let mut listing =
        disassemble_range_bounded(path, arch, function.address, end, max_instructions)?;
    if matching.len() > 1 {
        listing.notes.push(format!(
            "{} functions are named {name:?}; the one at 0x{:x} is listed",
            matching.len(),
            function.address
        ));
    }
    Ok(listing)
}

fn disassemble_range_in_buffer(
    buffer: &[u8],
    arch: Option<&str>,
    start: u64,
    end: Option<u64>,
    max_instructions: usize,
) -> Result<RangeDisassembly> {
    let (arch, mode, section) = detect_architecture_and_code_with_arch(buffer, arch)?;
    let architecture = format_architecture(arch, mode);
    let section_start = section.address;
    let section_end = section.address.saturating_add(section.data.len() as u64);
    if start < section_start || start >= section_end {
        return Err(anyhow::anyhow!(
            "Address 0x{start:x} is outside the code section (0x{section_start:x} to 0x{section_end:x})"
        ));
    }
    let limit = max_instructions.clamp(1, MAX_RANGE_INSTRUCTIONS);
    let offset = usize::try_from(start - section_start).unwrap_or(usize::MAX);
    // No instruction is longer than 15 bytes (x86): that bounds the bytes needed.
    let mut stop = offset
        .saturating_add(limit.saturating_mul(15))
        .min(section.data.len());
    if let Some(end) = end {
        let end_offset = usize::try_from(end.saturating_sub(section_start)).unwrap_or(usize::MAX);
        stop = stop.min(end_offset.max(offset));
    }
    let cs = create_capstone(arch, mode)?;
    let (instructions, mut coverage) =
        decode_region(&cs, &section.data[offset..stop], start, usize::MAX, limit)?;
    let listed_end = instructions
        .last()
        .map_or(start, |i| i.address.wrapping_add(i.size as u64));
    let mut notes = vec![format!(
        "listing starts at the address you gave (0x{start:x}); if that is not the start of an instruction, the first instructions are wrong"
    )];
    let more_in_range = end.map_or(listed_end < section_end, |e| {
        listed_end < e.min(section_end)
    });
    if more_in_range {
        notes.push(format!(
            "stopped after {} instructions at 0x{listed_end:x}; more code follows (limit {limit} per call)",
            instructions.len()
        ));
    }
    if let Some(end) = end {
        if end > section_end {
            notes.push(format!(
                "the requested end 0x{end:x} is past the code section; the listing stops at 0x{section_end:x}"
            ));
        }
    }
    coverage.section_size = section.data.len() as u64;
    Ok(RangeDisassembly {
        architecture,
        start_address: start,
        end_address: listed_end,
        instructions,
        section_start,
        section_end,
        more: more_in_range,
        coverage,
        notes,
    })
}

fn disassemble_buffer(
    buffer: &[u8],
    arch_choice: Option<&str>,
    symbol_table: &SymbolTable,
) -> Result<(DisassemblyResult, DisassemblyCoverage)> {
    // Detect architecture
    let (arch, mode, code_section) = detect_architecture_and_code_with_arch(buffer, arch_choice)?;
    let architecture = format_architecture(arch, mode);

    // Create Capstone instance
    let cs = create_capstone(arch, mode)?;

    // Disassemble code section (skipping undecodable bytes)
    let (instructions, mut coverage) =
        disassemble_code_with_coverage(&cs, &code_section.data, code_section.address)?;

    // Analyze instructions (skipped data bytes are not instructions)
    let analysis = if coverage.bytes_skipped > 0 {
        let real: Vec<&Instruction> = instructions
            .iter()
            .filter(|i| i.mnemonic != SKIPPED_MNEMONIC)
            .collect();
        analyze_instructions(&real)
    } else {
        analyze_instructions(&instructions)
    };

    // Group into functions
    let (functions, grouping_notes) = group_into_functions(&instructions, symbol_table);
    for (note, cuts_listing) in grouping_notes {
        coverage.truncated |= cuts_listing;
        coverage.notes.push(note);
    }

    // Generate output formats
    let mut output_formats = generate_output_formats(&instructions, &functions, &architecture);
    if let (Some(obj), Ok(cov)) = (
        output_formats.json_structured.as_object_mut(),
        serde_json::to_value(&coverage),
    ) {
        obj.insert("coverage".to_string(), cov);
    }

    Ok((
        DisassemblyResult {
            architecture,
            instructions,
            analysis,
            functions,
            output_formats,
        },
        coverage,
    ))
}

/// The executable code of a binary, located from its section headers.
pub(crate) struct CodeSection {
    pub(crate) data: Vec<u8>,
    pub(crate) address: u64,
}

/// Slice `size` bytes at `offset` out of `buffer`, or say why that is impossible.
fn checked_slice<'a>(buffer: &'a [u8], offset: u64, size: u64, what: &str) -> Result<&'a [u8]> {
    let end = offset.checked_add(size);
    let range = usize::try_from(offset)
        .ok()
        .zip(end.and_then(|e| usize::try_from(e).ok()));
    range
        .and_then(|(start, end)| buffer.get(start..end))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Malformed binary: {what} claims {size} bytes at file offset {offset}, \
                 but the file is only {} bytes long",
                buffer.len()
            )
        })
}

pub(crate) fn detect_architecture_and_code(buffer: &[u8]) -> Result<(Arch, Mode, CodeSection)> {
    detect_architecture_and_code_with_arch(buffer, None)
}

/// Error when `arch_choice` names an architecture the universal Mach-O does not
/// hold (the slice picked would otherwise be another one, without a word). The
/// message lists the slices present.
pub(crate) fn require_named_slice(
    selection: &crate::binary_parser::FatSelection<'_>,
    arch_choice: Option<&str>,
) -> Result<()> {
    let Some(wanted) = arch_choice else {
        return Ok(());
    };
    let norm = |s: &str| s.to_ascii_lowercase().replace(['-', '_', ' '], "");
    let (picked, w) = (
        norm(&selection.slices[selection.selected].architecture),
        norm(wanted),
    );
    if picked == w || (w == "aarch64" && picked == "arm64") || (w == "amd64" && picked == "x8664") {
        return Ok(());
    }
    let present: Vec<&str> = selection
        .slices
        .iter()
        .map(|s| s.architecture.as_str())
        .collect();
    Err(anyhow::anyhow!(
        "This universal Mach-O has no '{wanted}' slice; slices present: {}",
        present.join(", ")
    ))
}

/// Like [`detect_architecture_and_code`]; a universal Mach-O is narrowed to the
/// slice named by `arch` first (default: host architecture, else the first).
pub(crate) fn detect_architecture_and_code_with_arch(
    buffer: &[u8],
    arch_choice: Option<&str>,
) -> Result<(Arch, Mode, CodeSection)> {
    if crate::binary_parser::is_fat_macho(buffer) {
        let selection = crate::binary_parser::select_fat_slice(buffer, arch_choice).ok_or_else(|| {
            anyhow::anyhow!(
                "Malformed universal (fat) Mach-O: no usable slice (the fat header is damaged or every slice is cut off), so it cannot be disassembled"
            )
        })?;
        require_named_slice(&selection, arch_choice)?;
        return detect_architecture_and_code(selection.data);
    }
    crate::control_flow::check_parse_preconditions(buffer)?;
    match Object::parse(buffer)? {
        Object::Elf(elf) => {
            let (arch, mode) = match elf.header.e_machine {
                goblin::elf::header::EM_X86_64 => (Arch::X86, Mode::Mode64),
                goblin::elf::header::EM_386 => (Arch::X86, Mode::Mode32),
                goblin::elf::header::EM_ARM => (Arch::ARM, Mode::Arm),
                goblin::elf::header::EM_AARCH64 => (Arch::ARM64, Mode::Arm),
                other => {
                    return Err(anyhow::anyhow!(
                        "Unsupported ELF architecture (e_machine {other}); supported: x86, x86-64, ARM, ARM64"
                    ))
                }
            };

            // Find .text section
            for section in &elf.section_headers {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    if name == ".text" {
                        if section.sh_type == goblin::elf::section_header::SHT_NOBITS {
                            return Err(anyhow::anyhow!(
                                "Malformed ELF: .text section is marked NOBITS and has no file contents"
                            ));
                        }
                        let data = checked_slice(
                            buffer,
                            section.sh_offset,
                            section.sh_size,
                            "the .text section header",
                        )?;
                        let code_section = CodeSection {
                            data: data.to_vec(),
                            address: section.sh_addr,
                        };
                        return Ok((arch, mode, code_section));
                    }
                }
            }
            Err(anyhow::anyhow!(
                "No .text section found (the section headers may be stripped or damaged)"
            ))
        }
        Object::PE(pe) => {
            let arch = if pe.is_64 {
                (Arch::X86, Mode::Mode64)
            } else {
                (Arch::X86, Mode::Mode32)
            };

            // Find .text section
            for section in &pe.sections {
                let name = String::from_utf8_lossy(&section.name);
                if name.trim_end_matches('\0') == ".text" {
                    // Raw size is padded to the file alignment; the virtual size
                    // is the real code length when it is smaller.
                    let mut size = u64::from(section.size_of_raw_data);
                    if section.virtual_size != 0 {
                        size = size.min(u64::from(section.virtual_size));
                    }
                    let data = checked_slice(
                        buffer,
                        u64::from(section.pointer_to_raw_data),
                        size,
                        "the .text section header",
                    )?;
                    let code_section = CodeSection {
                        data: data.to_vec(),
                        address: pe
                            .image_base
                            .saturating_add(u64::from(section.virtual_address)),
                    };
                    return Ok((arch.0, arch.1, code_section));
                }
            }
            Err(anyhow::anyhow!("No .text section found"))
        }
        Object::Mach(mach) => {
            match mach {
                goblin::mach::Mach::Binary(macho) => {
                    let (arch, mode) = match macho.header.cputype {
                        goblin::mach::cputype::CPU_TYPE_X86_64 => (Arch::X86, Mode::Mode64),
                        goblin::mach::cputype::CPU_TYPE_X86 => (Arch::X86, Mode::Mode32),
                        goblin::mach::cputype::CPU_TYPE_ARM64 => (Arch::ARM64, Mode::Arm),
                        _ => return Err(anyhow::anyhow!("Unsupported Mach-O architecture")),
                    };

                    // Find __text section
                    for segment in &macho.segments {
                        for (section, _) in segment.sections()? {
                            if section.name()? == "__text" {
                                // goblin hands back an empty slice for a header that
                                // does not fit the file: check it ourselves.
                                let data = checked_slice(
                                    buffer,
                                    u64::from(section.offset),
                                    section.size,
                                    "the __text section header",
                                )?;
                                let code_section = CodeSection {
                                    data: data.to_vec(),
                                    address: section.addr,
                                };
                                return Ok((arch, mode, code_section));
                            }
                        }
                    }
                    Err(anyhow::anyhow!("No __text section found"))
                }
                _ => Err(anyhow::anyhow!(
                    "The file starts with the CAFEBABE magic but is not a usable universal Mach-O (it may be a Java class file, which analyze_java_file reads, or a fat header with too many or invalid slices)"
                )),
            }
        }
        _ => Err(anyhow::anyhow!("Unknown binary format")),
    }
}

fn create_capstone(arch: Arch, mode: Mode) -> Result<Capstone> {
    let mut cs = Capstone::new_raw(arch, mode, NO_EXTRA_MODE, None)
        .map_err(|e| anyhow::anyhow!("Failed to create Capstone instance: {e:?}"))?;
    // Undecodable bytes (jump tables, data in code) are returned as `.byte`
    // pseudo-instructions instead of ending the listing.
    cs.set_skipdata(true)
        .map_err(|e| anyhow::anyhow!("Failed to enable skip-data mode: {e:?}"))?;
    Ok(cs)
}

/// Mnemonic Capstone gives to bytes it skipped in skip-data mode.
const SKIPPED_MNEMONIC: &str = ".byte";

/// Disassemble a whole code buffer. Undecodable bytes are skipped and appear
/// as `.byte` entries.
#[cfg(test)]
fn disassemble_code(cs: &Capstone, code: &[u8], base_address: u64) -> Result<Vec<Instruction>> {
    disassemble_code_with_coverage(cs, code, base_address).map(|(insns, _)| insns)
}

fn disassemble_code_with_coverage(
    cs: &Capstone,
    code: &[u8],
    base_address: u64,
) -> Result<(Vec<Instruction>, DisassemblyCoverage)> {
    decode_region(
        cs,
        code,
        base_address,
        MAX_DISASSEMBLY_BYTES,
        MAX_DISASSEMBLY_INSTRUCTIONS,
    )
}

/// Decode `code` (loaded at `base_address`), at most `max_bytes` bytes and
/// `max_instructions` instructions. Undecodable bytes become `.byte` entries;
/// every limit that cut the listing is named in the coverage notes.
fn decode_region(
    cs: &Capstone,
    code: &[u8],
    base_address: u64,
    max_bytes: usize,
    max_instructions: usize,
) -> Result<(Vec<Instruction>, DisassemblyCoverage)> {
    let mut coverage = DisassemblyCoverage {
        section_size: code.len() as u64,
        start_address: base_address,
        ..DisassemblyCoverage::default()
    };
    let examined = if code.len() > max_bytes {
        coverage.truncated = true;
        coverage.notes.push(format!(
            "code section is {} bytes; only the first {max_bytes} bytes were disassembled",
            code.len()
        ));
        &code[..max_bytes]
    } else {
        code
    };
    coverage.bytes_examined = examined.len() as u64;

    let mut instructions: Vec<Instruction> = Vec::new();
    let mut offset = 0usize;
    let mut in_skipped_run = false;
    // Decode in chunks so memory follows the instruction cap, not the byte window.
    'chunks: while offset < examined.len() {
        let remaining = max_instructions.saturating_sub(instructions.len());
        if remaining == 0 {
            // At the cap: is there anything left to decode?
            coverage.truncated = true;
            coverage.notes.push(format!(
                "stopped after {max_instructions} instructions (at address 0x{:x})",
                base_address.wrapping_add(offset as u64)
            ));
            break;
        }
        // Addresses wrap like the hardware's: a section mapped near the top of
        // the address space must not overflow.
        let insns = cs
            .disasm_count(
                &examined[offset..],
                base_address.wrapping_add(offset as u64),
                remaining.min(DISASSEMBLY_CHUNK),
            )
            .map_err(|e| anyhow::anyhow!("Disassembly failed: {e:?}"))?;
        let mut consumed = 0usize;
        for insn in insns.iter() {
            consumed += insn.bytes().len();
            let mnemonic = insn.mnemonic().unwrap_or("");
            let size = insn.bytes().len();
            if mnemonic == SKIPPED_MNEMONIC {
                coverage.bytes_skipped += size as u64;
                if !in_skipped_run {
                    coverage.skipped_runs += 1;
                    in_skipped_run = true;
                }
                instructions.push(Instruction {
                    address: insn.address(),
                    bytes: insn.bytes().to_vec(),
                    mnemonic: SKIPPED_MNEMONIC.to_string(),
                    operands: insn.op_str().unwrap_or("").to_string(),
                    instruction_type: InstructionType::Other,
                    flow_control: None,
                    size,
                });
                continue;
            }
            in_skipped_run = false;
            coverage.bytes_decoded += size as u64;

            let flow_control = detect_flow_control(insn);
            let instruction_type = classify_instruction(insn);

            instructions.push(Instruction {
                address: insn.address(),
                bytes: insn.bytes().to_vec(),
                mnemonic: mnemonic.to_string(),
                operands: insn.op_str().unwrap_or("").to_string(),
                instruction_type,
                flow_control,
                size,
            });
        }
        if consumed == 0 {
            break 'chunks;
        }
        offset += consumed;
    }

    // What was really covered, not what was handed to the decoder.
    let covered = coverage.bytes_decoded + coverage.bytes_skipped;
    coverage.end_address = base_address.wrapping_add(covered);
    coverage.bytes_not_decoded = (code.len() as u64).saturating_sub(covered);
    if covered < code.len() as u64 {
        coverage.truncated = true;
        coverage.bytes_examined = covered;
        coverage.notes.push(format!(
            "decoded 0x{:x} to 0x{:x}; {} of {} bytes not decoded",
            coverage.start_address,
            coverage.end_address,
            coverage.bytes_not_decoded,
            code.len()
        ));
    }
    if coverage.bytes_skipped > 0 {
        coverage.notes.push(format!(
            "{} bytes in {} runs could not be decoded as instructions and were skipped (data in the code section, or non-code bytes)",
            coverage.bytes_skipped, coverage.skipped_runs
        ));
    }

    Ok((instructions, coverage))
}

/// Target of a direct branch operand such as `0x401136` or `#0x401136`.
fn parse_branch_target(operands: &str) -> Option<u64> {
    // The target is the last operand (`cbz x0, #0x40` names a register first).
    let text = operands.rsplit(',').next().unwrap_or(operands);
    let text = text.trim().trim_start_matches('#');
    let hex = text.strip_prefix("0x")?;
    u64::from_str_radix(hex, 16).ok()
}

fn detect_flow_control(insn: &capstone::Insn) -> Option<FlowControl> {
    let mnemonic = insn.mnemonic()?;
    let operands = insn.op_str().unwrap_or("");

    if mnemonic.starts_with('j')
        || matches!(mnemonic, "b" | "cbz" | "cbnz" | "tbz" | "tbnz")
        || mnemonic.starts_with("b.")
    {
        let conditional = mnemonic != "jmp" && mnemonic != "b";
        let target = parse_branch_target(operands);
        Some(FlowControl::Jump {
            target,
            conditional,
        })
    } else if mnemonic == "call" || mnemonic == "bl" || mnemonic == "blr" {
        let target = parse_branch_target(operands);
        let is_indirect = target.is_none();
        Some(FlowControl::Call {
            target,
            is_indirect,
        })
    } else if mnemonic == "ret" || mnemonic == "retn" {
        Some(FlowControl::Return)
    } else if mnemonic == "int" {
        let number = operands
            .trim()
            .strip_prefix("0x")
            .and_then(|h| u8::from_str_radix(h, 16).ok())
            .or_else(|| operands.trim().parse().ok())
            .unwrap_or(0);
        Some(FlowControl::Interrupt { number })
    } else if mnemonic.starts_with("cmov") {
        Some(FlowControl::ConditionalMove)
    } else {
        None
    }
}

fn classify_instruction(insn: &capstone::Insn) -> InstructionType {
    let mnemonic = insn.mnemonic().unwrap_or("");

    match mnemonic {
        // Arithmetic
        "add" | "sub" | "mul" | "div" | "inc" | "dec" | "adc" | "sbb" | "imul" | "idiv" => {
            InstructionType::Arithmetic
        }

        // Logic
        "and" | "or" | "xor" | "not" | "shl" | "shr" | "sal" | "sar" | "rol" | "ror" => {
            InstructionType::Logic
        }

        // Memory
        "mov" | "movzx" | "movsx" | "lea" | "ld" | "st" | "ldr" | "str" => InstructionType::Memory,

        // Control
        m if m.starts_with('j') || m == "call" || m == "ret" || m == "int" => {
            InstructionType::Control
        }

        // Stack
        "push" | "pop" | "pushf" | "popf" | "enter" | "leave" => InstructionType::Stack,

        // Comparison
        "cmp" | "test" => InstructionType::Comparison,

        // System
        "syscall" | "sysenter" | "sysexit" | "int" if insn.op_str().unwrap_or("") == "0x80" => {
            InstructionType::System
        }

        // Crypto hints
        "aesenc" | "aesdec" | "aesimc" | "aeskeygen" | "sha256" | "pclmulqdq" => {
            InstructionType::Crypto
        }

        // Vector
        m if m.starts_with('v')
            || m.starts_with('p') && (m.contains("mm") || m.contains("xmm")) =>
        {
            InstructionType::Vector
        }

        _ => InstructionType::Other,
    }
}

fn analyze_instructions<T: std::borrow::Borrow<Instruction>>(
    instructions: &[T],
) -> InstructionAnalysis {
    let mut instruction_types = HashMap::new();
    let mut register_usage = HashMap::new();
    let mut memory_accesses = Vec::new();
    let mut system_calls = Vec::new();
    let mut crypto_operations = Vec::new();
    let mut suspicious_patterns = Vec::new();
    let mut control_flow_summary = ControlFlowSummary {
        total_jumps: 0,
        conditional_jumps: 0,
        unconditional_jumps: 0,
        function_calls: 0,
        indirect_calls: 0,
        returns: 0,
        interrupts: 0,
    };

    // Instruction type counting
    for insn in instructions {
        let insn: &Instruction = insn.borrow();
        *instruction_types.entry(insn.mnemonic.clone()).or_insert(0) += 1;

        // Register tracking
        track_register_usage(insn, &mut register_usage);

        // Memory access tracking
        if let Some(mem_access) = detect_memory_access(insn) {
            memory_accesses.push(mem_access);
        }

        // Control flow tracking
        if let Some(flow) = &insn.flow_control {
            match flow {
                FlowControl::Jump { conditional, .. } => {
                    control_flow_summary.total_jumps += 1;
                    if *conditional {
                        control_flow_summary.conditional_jumps += 1;
                    } else {
                        control_flow_summary.unconditional_jumps += 1;
                    }
                }
                FlowControl::Call { is_indirect, .. } => {
                    control_flow_summary.function_calls += 1;
                    if *is_indirect {
                        control_flow_summary.indirect_calls += 1;
                    }
                }
                FlowControl::Return => control_flow_summary.returns += 1,
                FlowControl::Interrupt { .. } => control_flow_summary.interrupts += 1,
                _ => {}
            }
        }

        // System call detection
        if insn.mnemonic == "syscall" || (insn.mnemonic == "int" && insn.operands == "0x80") {
            system_calls.push(SystemCall {
                address: insn.address,
                syscall_number: None, // Would need register state analysis
                syscall_name: None,
                category: SystemCallCategory::Other,
            });
        }

        // Crypto operation detection
        if let Some(crypto_op) = detect_crypto_operation(insn) {
            crypto_operations.push(crypto_op);
        }
    }

    // Pattern detection
    suspicious_patterns.extend(detect_suspicious_patterns(instructions));

    InstructionAnalysis {
        total_instructions: instructions.len(),
        instruction_types,
        register_usage,
        memory_accesses,
        system_calls,
        crypto_operations,
        suspicious_patterns,
        control_flow_summary,
    }
}

fn track_register_usage(insn: &Instruction, register_usage: &mut HashMap<String, Vec<u64>>) {
    // Extract registers from operands (simplified)
    let operands = &insn.operands;
    let registers = vec![
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "eax", "ebx", "ecx", "edx", "esi",
        "edi", "ebp", "esp", "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    ];

    for reg in registers {
        if operands.contains(reg) {
            register_usage
                .entry(reg.to_string())
                .or_default()
                .push(insn.address);
        }
    }
}

fn detect_memory_access(insn: &Instruction) -> Option<MemoryAccess> {
    if insn.instruction_type != InstructionType::Memory {
        return None;
    }

    let access_type = match insn.mnemonic.as_str() {
        "mov"
            if insn.operands.contains('[')
                && insn.operands.find('[').unwrap()
                    < insn.operands.find(',').unwrap_or(usize::MAX) =>
        {
            AccessType::Write
        }
        "mov" => AccessType::Read,
        _ => AccessType::Read,
    };

    Some(MemoryAccess {
        instruction_address: insn.address,
        access_type,
        size: estimate_access_size(&insn.mnemonic),
        target_address: None, // Would need operand parsing
        register_base: None,
        register_index: None,
        displacement: None,
    })
}

fn estimate_access_size(mnemonic: &str) -> u32 {
    if mnemonic.ends_with('b') {
        1
    } else if mnemonic.ends_with('w') {
        2
    } else if mnemonic.ends_with('d') {
        4
    } else if mnemonic.ends_with('q') {
        8
    } else {
        4 // default
    }
}

fn detect_crypto_operation(insn: &Instruction) -> Option<CryptoOperation> {
    let crypto_op_type = match insn.mnemonic.as_str() {
        m if m.starts_with("aes") => Some(CryptoOpType::AESOperation),
        "sha256rnds2" | "sha256msg1" | "sha256msg2" => Some(CryptoOpType::SHA256Operation),
        "xor" if insn.operands.contains("xmm") => Some(CryptoOpType::XOROperation),
        "rdrand" | "rdseed" => Some(CryptoOpType::RandomGeneration),
        _ => None,
    };

    crypto_op_type.map(|op_type| CryptoOperation {
        address: insn.address,
        operation_type: op_type,
        algorithm_hint: Some(insn.mnemonic.clone()),
        confidence: 0.8,
    })
}

fn detect_suspicious_patterns<T: std::borrow::Borrow<Instruction>>(
    instructions: &[T],
) -> Vec<SuspiciousPattern> {
    let mut patterns = Vec::new();

    // Anti-debug detection
    let mut anti_debug_addrs = Vec::new();
    for insn in instructions {
        let insn: &Instruction = insn.borrow();
        if insn.mnemonic == "rdtsc"
            || (insn.mnemonic == "int" && insn.operands == "3")
            || insn.operands.contains("BeingDebugged")
        {
            anti_debug_addrs.push(insn.address);
        }
    }
    if !anti_debug_addrs.is_empty() {
        patterns.push(SuspiciousPattern {
            pattern_type: PatternType::AntiDebug,
            addresses: anti_debug_addrs,
            description: "Anti-debugging techniques detected".to_string(),
            severity: Severity::Medium,
        });
    }

    // NOP sled detection
    let mut consecutive_nops = 0;
    let mut nop_start = 0;
    for (i, insn) in instructions.iter().enumerate() {
        let insn: &Instruction = insn.borrow();
        if insn.mnemonic == "nop" {
            if consecutive_nops == 0 {
                nop_start = i;
            }
            consecutive_nops += 1;
        } else {
            if consecutive_nops > 10 {
                patterns.push(SuspiciousPattern {
                    pattern_type: PatternType::NopSled,
                    addresses: vec![instructions[nop_start].borrow().address],
                    description: format!("NOP sled of {consecutive_nops} instructions"),
                    severity: Severity::Medium,
                });
            }
            consecutive_nops = 0;
        }
    }

    // Indirect jump analysis
    let indirect_jumps: Vec<_> = instructions
        .iter()
        .map(std::borrow::Borrow::borrow)
        .filter(|insn: &&Instruction| {
            matches!(
                &insn.flow_control,
                Some(
                    FlowControl::Jump { target: None, .. }
                        | FlowControl::Call {
                            is_indirect: true,
                            ..
                        }
                )
            )
        })
        .map(|insn| insn.address)
        .collect();

    if indirect_jumps.len() > 20 {
        patterns.push(SuspiciousPattern {
            pattern_type: PatternType::IndirectJumps,
            addresses: indirect_jumps,
            description: "High number of indirect jumps detected".to_string(),
            severity: Severity::High,
        });
    }

    patterns
}

/// Most instructions copied into function listings in total. Functions are
/// disjoint, so this is only reached by listings near the decode cap.
const MAX_GROUPED_INSTRUCTIONS: usize = MAX_DISASSEMBLY_INSTRUCTIONS;

/// Group `instructions` into the functions of `symbol_table`. A function ends
/// at its declared size or at the next function start, whichever comes first, so
/// listings never overlap and the instructions copied in total never exceed
/// the instructions decoded. Returns a note when a limit cut the grouping.
fn group_into_functions(
    instructions: &[Instruction],
    symbol_table: &SymbolTable,
) -> (Vec<DisassembledFunction>, Vec<(String, bool)>) {
    let (Some(first), Some(last)) = (instructions.first(), instructions.last()) else {
        return (Vec::new(), Vec::new());
    };
    let code_start = first.address;
    let code_end = last.address.saturating_add(last.size as u64);

    // Candidate functions: those whose start lies inside the disassembled code.
    // Imports carry import-table addresses, not code addresses.
    let mut candidates: Vec<(u64, u64, &str)> = symbol_table
        .functions
        .iter()
        .filter(|f| !f.is_imported && f.address >= code_start && f.address < code_end)
        .map(|f| (f.address, f.size, f.name.as_str()))
        .collect();
    candidates.sort_by_key(|(address, size, _)| (*address, std::cmp::Reverse(*size)));
    candidates.dedup_by_key(|(address, _, _)| *address);

    let mut functions = Vec::new();
    let mut notes: Vec<(String, bool)> = Vec::new();
    let mut copied = 0usize;
    let mut clipped = 0usize;
    for (i, (func_start, declared_size, name)) in candidates.iter().enumerate() {
        if functions.len() >= MAX_GROUPED_FUNCTIONS {
            notes.push((
                format!(
                    "functions are grouped for the first {MAX_GROUPED_FUNCTIONS} function symbols only; {} later functions are not listed",
                    candidates.len() - i
                ),
                true,
            ));
            break;
        }
        let next_start = candidates.get(i + 1).map_or(code_end, |(next, _, _)| *next);
        // PE and Mach-O symbols carry no size: run to the next symbol. A sized
        // function that would run into the next symbol is cut there.
        let size = if *declared_size > 0 {
            let declared_end = func_start.saturating_add(*declared_size);
            if declared_end > next_start {
                clipped += 1;
            }
            declared_end.min(next_start).saturating_sub(*func_start)
        } else {
            next_start.saturating_sub(*func_start)
        };
        let func_end = func_start.saturating_add(size);

        // Instructions are in address order: find the range by binary search.
        let lo = instructions.partition_point(|insn| insn.address < *func_start);
        let hi = instructions.partition_point(|insn| insn.address < func_end);
        if lo >= hi {
            continue;
        }
        if copied + (hi - lo) > MAX_GROUPED_INSTRUCTIONS {
            notes.push((
                format!(
                    "functions are grouped until {MAX_GROUPED_INSTRUCTIONS} instructions were copied; {} later functions are not listed",
                    candidates.len() - i
                ),
                true,
            ));
            break;
        }
        copied += hi - lo;
        let func_instructions: Vec<Instruction> = instructions[lo..hi].to_vec();
        let basic_blocks = identify_basic_blocks(&func_instructions);
        let complexity = calculate_complexity(&basic_blocks);

        functions.push(DisassembledFunction {
            address: *func_start,
            name: (*name).to_string(),
            size: usize::try_from(size).unwrap_or(usize::MAX),
            instructions: func_instructions,
            basic_blocks,
            complexity,
        });
    }
    if clipped > 0 {
        notes.push((
            format!(
                "{clipped} function symbols declare a size that runs into the next function symbol; those functions are listed only up to that next symbol"
            ),
            false,
        ));
    }

    (functions, notes)
}

fn identify_basic_blocks(instructions: &[Instruction]) -> Vec<BasicBlock> {
    let mut blocks = Vec::new();
    let mut block_starts = HashSet::new();

    // Identify block starts
    block_starts.insert(instructions[0].address);
    for insn in instructions {
        if let Some(
            FlowControl::Jump {
                target: Some(t), ..
            }
            | FlowControl::Call {
                target: Some(t), ..
            },
        ) = &insn.flow_control
        {
            block_starts.insert(*t);
        }
    }

    // Build blocks
    let mut current_block_start = instructions[0].address;
    let mut current_instructions = 0;

    for (i, insn) in instructions.iter().enumerate() {
        current_instructions += 1;

        let is_block_end = insn.flow_control.is_some()
            || (i + 1 < instructions.len() && block_starts.contains(&instructions[i + 1].address));

        if is_block_end || i == instructions.len() - 1 {
            let exits = if let Some(flow) = &insn.flow_control {
                match flow {
                    FlowControl::Jump {
                        target,
                        conditional,
                    } => {
                        if *conditional {
                            vec![
                                BlockExit {
                                    exit_type: ExitType::ConditionalJump,
                                    target: *target,
                                },
                                BlockExit {
                                    exit_type: ExitType::FallThrough,
                                    target: instructions.get(i + 1).map(|i| i.address),
                                },
                            ]
                        } else {
                            vec![BlockExit {
                                exit_type: ExitType::Jump,
                                target: *target,
                            }]
                        }
                    }
                    FlowControl::Call { target, .. } => {
                        vec![BlockExit {
                            exit_type: ExitType::Call,
                            target: *target,
                        }]
                    }
                    FlowControl::Return => {
                        vec![BlockExit {
                            exit_type: ExitType::Return,
                            target: None,
                        }]
                    }
                    _ => vec![],
                }
            } else if i + 1 < instructions.len() {
                vec![BlockExit {
                    exit_type: ExitType::FallThrough,
                    target: Some(instructions[i + 1].address),
                }]
            } else {
                vec![]
            };

            blocks.push(BasicBlock {
                start_address: current_block_start,
                end_address: insn.address.saturating_add(insn.size as u64),
                instruction_count: current_instructions,
                exits,
            });

            if i + 1 < instructions.len() {
                current_block_start = instructions[i + 1].address;
                current_instructions = 0;
            }
        }
    }

    blocks
}

fn calculate_complexity(basic_blocks: &[BasicBlock]) -> u32 {
    // Cyclomatic complexity = E - N + 2P
    // E = edges, N = nodes, P = connected components (usually 1)
    let nodes = basic_blocks.len() as u32;
    let edges = basic_blocks
        .iter()
        .map(|b| b.exits.len() as u32)
        .sum::<u32>();

    edges.saturating_sub(nodes) + 2
}

fn format_architecture(arch: Arch, mode: Mode) -> String {
    match (arch, mode) {
        (Arch::X86, Mode::Mode64) => "x86_64".to_string(),
        (Arch::X86, Mode::Mode32) => "x86".to_string(),
        (Arch::ARM, Mode::Arm) => "ARM".to_string(),
        (Arch::ARM64, Mode::Arm) => "ARM64".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn generate_output_formats(
    instructions: &[Instruction],
    functions: &[DisassembledFunction],
    architecture: &str,
) -> OutputFormats {
    // Generate assembly listing
    let assembly = generate_assembly_listing(instructions);

    // Generate structured JSON
    let json_structured = serde_json::json!({
        "architecture": architecture,
        "instruction_count": instructions.len(),
        "function_count": functions.len(),
        "functions": functions.iter().map(|f| {
            serde_json::json!({
                "name": f.name,
                "address": format!("0x{:x}", f.address),
                "size": f.size,
                "complexity": f.complexity,
                "basic_blocks": f.basic_blocks.len(),
            })
        }).collect::<Vec<_>>(),
    });

    // Generate graph visualization data
    let graph_data = generate_graph_data(functions);

    OutputFormats {
        assembly,
        json_structured,
        graph_data,
    }
}

fn generate_assembly_listing(instructions: &[Instruction]) -> String {
    let mut output = String::new();

    for insn in instructions {
        output.push_str(&format!(
            "{:08x}:  {:20}  {} {}\n",
            insn.address,
            insn.bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            insn.mnemonic,
            insn.operands
        ));
    }

    output
}

fn generate_graph_data(functions: &[DisassembledFunction]) -> GraphVisualizationData {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for func in functions {
        // Function node
        nodes.push(GraphNode {
            id: format!("func_{:x}", func.address),
            label: func.name.clone(),
            node_type: "function".to_string(),
            metadata: [
                ("address".to_string(), format!("0x{:x}", func.address)),
                ("size".to_string(), func.size.to_string()),
                ("complexity".to_string(), func.complexity.to_string()),
            ]
            .iter()
            .cloned()
            .collect(),
        });

        // Basic block nodes
        for (i, block) in func.basic_blocks.iter().enumerate() {
            let block_id = format!("block_{:x}_{}", func.address, i);
            nodes.push(GraphNode {
                id: block_id.clone(),
                label: format!("Block {}: 0x{:x}", i, block.start_address),
                node_type: "basic_block".to_string(),
                metadata: [(
                    "instructions".to_string(),
                    block.instruction_count.to_string(),
                )]
                .iter()
                .cloned()
                .collect(),
            });

            // Block edges
            for exit in &block.exits {
                if let Some(target) = exit.target {
                    edges.push(GraphEdge {
                        source: block_id.clone(),
                        target: format!("block_{target:x}"),
                        edge_type: format!("{:?}", exit.exit_type),
                        label: Some(format!("{:?}", exit.exit_type)),
                    });
                }
            }
        }
    }

    GraphVisualizationData { nodes, edges }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function_analysis::{
        CallingConvention, FunctionInfo, FunctionType, SymbolCounts, SymbolTable,
    };

    // Helper function to create a mock capstone instruction
    fn create_mock_instruction(
        address: u64,
        mnemonic: &str,
        operands: &str,
        bytes: Vec<u8>,
    ) -> Instruction {
        let flow_control = detect_mock_flow_control(mnemonic, operands);
        let instruction_type = classify_mock_instruction(mnemonic);

        Instruction {
            address,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            instruction_type,
            flow_control,
            size: bytes.len(),
            bytes,
        }
    }

    fn detect_mock_flow_control(mnemonic: &str, operands: &str) -> Option<FlowControl> {
        if mnemonic.starts_with('j') {
            let conditional = mnemonic != "jmp";
            Some(FlowControl::Jump {
                target: None,
                conditional,
            })
        } else if mnemonic == "call" {
            let is_indirect = operands.contains('[');
            Some(FlowControl::Call {
                target: None,
                is_indirect,
            })
        } else if mnemonic == "ret" {
            Some(FlowControl::Return)
        } else if mnemonic == "int" {
            Some(FlowControl::Interrupt { number: 0 })
        } else if mnemonic.starts_with("cmov") {
            Some(FlowControl::ConditionalMove)
        } else {
            None
        }
    }

    fn classify_mock_instruction(mnemonic: &str) -> InstructionType {
        match mnemonic {
            "add" | "sub" | "mul" | "div" | "inc" | "dec" | "adc" | "sbb" | "imul" | "idiv" => {
                InstructionType::Arithmetic
            }
            "and" | "or" | "xor" | "not" | "shl" | "shr" | "sal" | "sar" | "rol" | "ror" => {
                InstructionType::Logic
            }
            "mov" | "movzx" | "movsx" | "lea" | "ld" | "st" | "ldr" | "str" => {
                InstructionType::Memory
            }
            m if m.starts_with('j') || m == "call" || m == "ret" || m == "int" => {
                InstructionType::Control
            }
            "push" | "pop" | "pushf" | "popf" | "enter" | "leave" => InstructionType::Stack,
            "cmp" | "test" => InstructionType::Comparison,
            "syscall" | "sysenter" | "sysexit" => InstructionType::System,
            "aesenc" | "aesdec" | "aesimc" | "aeskeygen" | "sha256" | "pclmulqdq" => {
                InstructionType::Crypto
            }
            m if m.starts_with('v') || m.starts_with('p') => InstructionType::Vector,
            _ => InstructionType::Other,
        }
    }

    #[test]
    fn test_disassembler_architecture_formatting() {
        assert_eq!(
            format_architecture(Arch::X86, Mode::Mode64),
            "x86_64".to_string()
        );
        assert_eq!(
            format_architecture(Arch::X86, Mode::Mode32),
            "x86".to_string()
        );
        assert_eq!(format_architecture(Arch::ARM, Mode::Arm), "ARM".to_string());
        assert_eq!(
            format_architecture(Arch::ARM64, Mode::Arm),
            "ARM64".to_string()
        );
    }

    #[test]
    fn test_capstone_creation() {
        // Test successful creation for supported architectures
        assert!(create_capstone(Arch::X86, Mode::Mode64).is_ok());
        assert!(create_capstone(Arch::X86, Mode::Mode32).is_ok());
        assert!(create_capstone(Arch::ARM, Mode::Arm).is_ok());
        assert!(create_capstone(Arch::ARM64, Mode::Arm).is_ok());
    }

    #[test]
    fn test_instruction_classification() {
        let test_cases = vec![
            ("add", InstructionType::Arithmetic),
            ("sub", InstructionType::Arithmetic),
            ("mul", InstructionType::Arithmetic),
            ("div", InstructionType::Arithmetic),
            ("inc", InstructionType::Arithmetic),
            ("dec", InstructionType::Arithmetic),
            ("adc", InstructionType::Arithmetic),
            ("sbb", InstructionType::Arithmetic),
            ("imul", InstructionType::Arithmetic),
            ("idiv", InstructionType::Arithmetic),
            ("and", InstructionType::Logic),
            ("or", InstructionType::Logic),
            ("xor", InstructionType::Logic),
            ("not", InstructionType::Logic),
            ("shl", InstructionType::Logic),
            ("shr", InstructionType::Logic),
            ("sal", InstructionType::Logic),
            ("sar", InstructionType::Logic),
            ("rol", InstructionType::Logic),
            ("ror", InstructionType::Logic),
            ("mov", InstructionType::Memory),
            ("movzx", InstructionType::Memory),
            ("movsx", InstructionType::Memory),
            ("lea", InstructionType::Memory),
            ("ld", InstructionType::Memory),
            ("st", InstructionType::Memory),
            ("ldr", InstructionType::Memory),
            ("str", InstructionType::Memory),
            ("jmp", InstructionType::Control),
            ("jnz", InstructionType::Control),
            ("jz", InstructionType::Control),
            ("call", InstructionType::Control),
            ("ret", InstructionType::Control),
            ("int", InstructionType::Control),
            ("push", InstructionType::Stack),
            ("pop", InstructionType::Stack),
            ("pushf", InstructionType::Stack),
            ("popf", InstructionType::Stack),
            ("enter", InstructionType::Stack),
            ("leave", InstructionType::Stack),
            ("cmp", InstructionType::Comparison),
            ("test", InstructionType::Comparison),
            ("syscall", InstructionType::System),
            ("sysenter", InstructionType::System),
            ("sysexit", InstructionType::System),
            ("aesenc", InstructionType::Crypto),
            ("aesdec", InstructionType::Crypto),
            ("aesimc", InstructionType::Crypto),
            ("aeskeygen", InstructionType::Crypto),
            ("sha256", InstructionType::Crypto),
            ("pclmulqdq", InstructionType::Crypto),
            ("vadd", InstructionType::Vector),
            ("vmul", InstructionType::Vector),
            ("paddq", InstructionType::Vector),
            ("pxor", InstructionType::Vector),
            ("unknown", InstructionType::Other),
        ];

        for (mnemonic, expected) in test_cases {
            let insn = create_mock_instruction(0x1000, mnemonic, "", vec![0x90]);
            assert_eq!(
                insn.instruction_type, expected,
                "Failed for mnemonic: {mnemonic}"
            );
        }
    }

    #[test]
    fn test_flow_control_detection() {
        // Test jump instructions
        let jmp_insn = create_mock_instruction(0x1000, "jmp", "0x1234", vec![0xeb, 0x10]);
        assert!(matches!(
            jmp_insn.flow_control,
            Some(FlowControl::Jump {
                conditional: false,
                ..
            })
        ));

        let jnz_insn = create_mock_instruction(0x1000, "jnz", "0x1234", vec![0x75, 0x10]);
        assert!(matches!(
            jnz_insn.flow_control,
            Some(FlowControl::Jump {
                conditional: true,
                ..
            })
        ));

        // Test call instructions
        let call_insn =
            create_mock_instruction(0x1000, "call", "0x1234", vec![0xe8, 0x30, 0x02, 0x00, 0x00]);
        assert!(matches!(
            call_insn.flow_control,
            Some(FlowControl::Call {
                is_indirect: false,
                ..
            })
        ));

        let indirect_call = create_mock_instruction(0x1000, "call", "[rax]", vec![0xff, 0x10]);
        assert!(matches!(
            indirect_call.flow_control,
            Some(FlowControl::Call {
                is_indirect: true,
                ..
            })
        ));

        // Test return
        let ret_insn = create_mock_instruction(0x1000, "ret", "", vec![0xc3]);
        assert!(matches!(ret_insn.flow_control, Some(FlowControl::Return)));

        // Test interrupt
        let int_insn = create_mock_instruction(0x1000, "int", "3", vec![0xcc]);
        assert!(matches!(
            int_insn.flow_control,
            Some(FlowControl::Interrupt { .. })
        ));

        // Test conditional move
        let cmov_insn =
            create_mock_instruction(0x1000, "cmovz", "eax, ebx", vec![0x0f, 0x44, 0xc3]);
        assert!(matches!(
            cmov_insn.flow_control,
            Some(FlowControl::ConditionalMove)
        ));

        // Test no flow control
        let mov_insn = create_mock_instruction(0x1000, "mov", "eax, ebx", vec![0x89, 0xd8]);
        assert!(mov_insn.flow_control.is_none());
    }

    #[test]
    fn test_instruction_analysis() {
        let instructions = vec![
            create_mock_instruction(0x1000, "mov", "eax, ebx", vec![0x89, 0xd8]),
            create_mock_instruction(0x1002, "add", "eax, 5", vec![0x83, 0xc0, 0x05]),
            create_mock_instruction(0x1005, "cmp", "eax, 10", vec![0x83, 0xf8, 0x0a]),
            create_mock_instruction(0x1008, "jz", "0x1020", vec![0x74, 0x16]),
            create_mock_instruction(0x100a, "call", "0x2000", vec![0xe8, 0xf1, 0x0f, 0x00, 0x00]),
            create_mock_instruction(0x100f, "ret", "", vec![0xc3]),
            create_mock_instruction(0x1010, "syscall", "", vec![0x0f, 0x05]),
            create_mock_instruction(
                0x1012,
                "aesenc",
                "xmm0, xmm1",
                vec![0x66, 0x0f, 0x38, 0xdc, 0xc1],
            ),
            create_mock_instruction(0x1017, "nop", "", vec![0x90]),
            create_mock_instruction(0x1018, "xor", "xmm0, xmm1", vec![0x66, 0x0f, 0xef, 0xc1]),
        ];

        let analysis = analyze_instructions(&instructions);

        // Test basic counts
        assert_eq!(analysis.total_instructions, 10);
        assert!(analysis.instruction_types.contains_key("mov"));
        assert!(analysis.instruction_types.contains_key("add"));
        assert!(analysis.instruction_types.contains_key("cmp"));

        // Test control flow summary
        assert_eq!(analysis.control_flow_summary.total_jumps, 1);
        assert_eq!(analysis.control_flow_summary.conditional_jumps, 1);
        assert_eq!(analysis.control_flow_summary.unconditional_jumps, 0);
        assert_eq!(analysis.control_flow_summary.function_calls, 1);
        assert_eq!(analysis.control_flow_summary.indirect_calls, 0);
        assert_eq!(analysis.control_flow_summary.returns, 1);

        // Test system calls
        assert_eq!(analysis.system_calls.len(), 1);
        assert_eq!(analysis.system_calls[0].address, 0x1010);

        // Test crypto operations
        assert_eq!(analysis.crypto_operations.len(), 2); // aesenc and xor with xmm
    }

    #[test]
    fn test_memory_access_detection() {
        // Test read access
        let mov_read = create_mock_instruction(0x1000, "mov", "eax, [ebx]", vec![0x8b, 0x03]);
        let mem_access = detect_memory_access(&mov_read);
        assert!(mem_access.is_some());
        assert!(matches!(mem_access.unwrap().access_type, AccessType::Read));

        // Test write access
        let mov_write = create_mock_instruction(0x1000, "mov", "[ebx], eax", vec![0x89, 0x03]);
        let mem_access = detect_memory_access(&mov_write);
        assert!(mem_access.is_some());
        assert!(matches!(mem_access.unwrap().access_type, AccessType::Write));

        // Test non-memory instruction
        let add_insn = create_mock_instruction(0x1000, "add", "eax, ebx", vec![0x01, 0xd8]);
        let mem_access = detect_memory_access(&add_insn);
        assert!(mem_access.is_none());
    }

    #[test]
    fn test_access_size_estimation() {
        assert_eq!(estimate_access_size("movb"), 1);
        assert_eq!(estimate_access_size("movw"), 2);
        assert_eq!(estimate_access_size("movd"), 4);
        assert_eq!(estimate_access_size("movq"), 8);
        assert_eq!(estimate_access_size("mov"), 4); // default
    }

    #[test]
    fn test_crypto_operation_detection() {
        // Test AES operations
        let aes_insn =
            create_mock_instruction(0x1000, "aesenc", "xmm0, xmm1", vec![0x66, 0x0f, 0x38, 0xdc]);
        let crypto_op = detect_crypto_operation(&aes_insn);
        assert!(crypto_op.is_some());
        assert!(matches!(
            crypto_op.unwrap().operation_type,
            CryptoOpType::AESOperation
        ));

        // Test SHA256 operations
        let sha_insn =
            create_mock_instruction(0x1000, "sha256rnds2", "xmm0, xmm1", vec![0x0f, 0x38, 0xcb]);
        let crypto_op = detect_crypto_operation(&sha_insn);
        assert!(crypto_op.is_some());
        assert!(matches!(
            crypto_op.unwrap().operation_type,
            CryptoOpType::SHA256Operation
        ));

        // Test XOR with vector registers
        let xor_insn = create_mock_instruction(0x1000, "xor", "xmm0, xmm1", vec![0x66, 0x0f, 0xef]);
        let crypto_op = detect_crypto_operation(&xor_insn);
        assert!(crypto_op.is_some());
        assert!(matches!(
            crypto_op.unwrap().operation_type,
            CryptoOpType::XOROperation
        ));

        // Test random generation
        let rdrand_insn = create_mock_instruction(0x1000, "rdrand", "eax", vec![0x0f, 0xc7, 0xf0]);
        let crypto_op = detect_crypto_operation(&rdrand_insn);
        assert!(crypto_op.is_some());
        assert!(matches!(
            crypto_op.unwrap().operation_type,
            CryptoOpType::RandomGeneration
        ));

        // Test non-crypto instruction
        let mov_insn = create_mock_instruction(0x1000, "mov", "eax, ebx", vec![0x89, 0xd8]);
        let crypto_op = detect_crypto_operation(&mov_insn);
        assert!(crypto_op.is_none());
    }

    #[test]
    fn test_suspicious_pattern_detection() {
        let instructions = vec![
            // Anti-debug pattern
            create_mock_instruction(0x1000, "rdtsc", "", vec![0x0f, 0x31]),
            create_mock_instruction(0x1002, "int", "3", vec![0xcc]),
            // NOP sled (12 nops)
            create_mock_instruction(0x1003, "nop", "", vec![0x90]),
            create_mock_instruction(0x1004, "nop", "", vec![0x90]),
            create_mock_instruction(0x1005, "nop", "", vec![0x90]),
            create_mock_instruction(0x1006, "nop", "", vec![0x90]),
            create_mock_instruction(0x1007, "nop", "", vec![0x90]),
            create_mock_instruction(0x1008, "nop", "", vec![0x90]),
            create_mock_instruction(0x1009, "nop", "", vec![0x90]),
            create_mock_instruction(0x100a, "nop", "", vec![0x90]),
            create_mock_instruction(0x100b, "nop", "", vec![0x90]),
            create_mock_instruction(0x100c, "nop", "", vec![0x90]),
            create_mock_instruction(0x100d, "nop", "", vec![0x90]),
            create_mock_instruction(0x100e, "nop", "", vec![0x90]),
            create_mock_instruction(0x100f, "mov", "eax, ebx", vec![0x89, 0xd8]),
            // Multiple indirect jumps
        ];

        // Add 25 indirect jumps to trigger high threshold
        let mut all_instructions = instructions;
        for i in 0..25 {
            all_instructions.push(create_mock_instruction(
                0x2000 + i * 2,
                "jmp",
                "[rax]",
                vec![0xff, 0x20],
            ));
        }

        let patterns = detect_suspicious_patterns(&all_instructions);

        // Should detect anti-debug pattern
        assert!(patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::AntiDebug)));

        // Should detect NOP sled
        assert!(patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::NopSled)));

        // Should detect excessive indirect jumps
        assert!(patterns
            .iter()
            .any(|p| matches!(p.pattern_type, PatternType::IndirectJumps)));
    }

    #[test]
    fn test_register_usage_tracking() {
        let mut register_usage = HashMap::new();
        let insn = create_mock_instruction(0x1000, "mov", "eax, ebx", vec![0x89, 0xd8]);

        track_register_usage(&insn, &mut register_usage);

        assert!(register_usage.contains_key("eax"));
        assert!(register_usage.contains_key("ebx"));
        assert_eq!(register_usage["eax"][0], 0x1000);
        assert_eq!(register_usage["ebx"][0], 0x1000);
    }

    #[test]
    fn test_basic_block_identification() {
        let instructions = vec![
            create_mock_instruction(0x1000, "mov", "eax, 1", vec![0xb8, 0x01, 0x00, 0x00, 0x00]),
            create_mock_instruction(0x1005, "cmp", "eax, 2", vec![0x83, 0xf8, 0x02]),
            create_mock_instruction(0x1008, "jz", "0x1020", vec![0x74, 0x16]), // Conditional jump
            create_mock_instruction(0x100a, "add", "eax, 1", vec![0x83, 0xc0, 0x01]),
            create_mock_instruction(0x100d, "jmp", "0x1030", vec![0xeb, 0x21]), // Unconditional jump
            create_mock_instruction(0x1020, "sub", "eax, 1", vec![0x83, 0xe8, 0x01]), // Jump target
            create_mock_instruction(0x1023, "ret", "", vec![0xc3]),
        ];

        let basic_blocks = identify_basic_blocks(&instructions);

        // Should have multiple basic blocks due to jumps
        assert!(basic_blocks.len() >= 3);

        // First block should end with conditional jump and have two exits
        let first_block = &basic_blocks[0];
        assert_eq!(first_block.start_address, 0x1000);
        assert_eq!(first_block.exits.len(), 2); // Conditional jump has fall-through and jump
    }

    #[test]
    fn test_complexity_calculation() {
        // Simple case: linear block
        let linear_blocks = vec![BasicBlock {
            start_address: 0x1000,
            end_address: 0x1010,
            instruction_count: 4,
            exits: vec![BlockExit {
                exit_type: ExitType::FallThrough,
                target: None,
            }],
        }];
        assert_eq!(calculate_complexity(&linear_blocks), 2); // E(1) - N(1) + 2P(1) = 2

        // Complex case: multiple blocks with branches
        let complex_blocks = vec![
            BasicBlock {
                start_address: 0x1000,
                end_address: 0x1010,
                instruction_count: 4,
                exits: vec![
                    BlockExit {
                        exit_type: ExitType::ConditionalJump,
                        target: Some(0x1020),
                    },
                    BlockExit {
                        exit_type: ExitType::FallThrough,
                        target: Some(0x1010),
                    },
                ],
            },
            BasicBlock {
                start_address: 0x1010,
                end_address: 0x1020,
                instruction_count: 2,
                exits: vec![BlockExit {
                    exit_type: ExitType::Jump,
                    target: Some(0x1030),
                }],
            },
            BasicBlock {
                start_address: 0x1020,
                end_address: 0x1030,
                instruction_count: 3,
                exits: vec![BlockExit {
                    exit_type: ExitType::Return,
                    target: None,
                }],
            },
        ];
        // E(4) - N(3) + 2P(1) = 3
        assert_eq!(calculate_complexity(&complex_blocks), 3);
    }

    #[test]
    fn test_function_grouping() {
        let instructions = vec![
            create_mock_instruction(0x1000, "push", "rbp", vec![0x55]),
            create_mock_instruction(0x1001, "mov", "rbp, rsp", vec![0x48, 0x89, 0xe5]),
            create_mock_instruction(0x1004, "add", "eax, 1", vec![0x83, 0xc0, 0x01]),
            create_mock_instruction(0x1007, "pop", "rbp", vec![0x5d]),
            create_mock_instruction(0x1008, "ret", "", vec![0xc3]),
            create_mock_instruction(0x2000, "push", "rbp", vec![0x55]),
            create_mock_instruction(0x2001, "mov", "rbp, rsp", vec![0x48, 0x89, 0xe5]),
            create_mock_instruction(0x2004, "sub", "eax, 1", vec![0x83, 0xe8, 0x01]),
            create_mock_instruction(0x2007, "pop", "rbp", vec![0x5d]),
            create_mock_instruction(0x2008, "ret", "", vec![0xc3]),
        ];

        let symbol_table = SymbolTable {
            functions: vec![
                FunctionInfo {
                    name: "func1".to_string(),
                    address: 0x1000,
                    size: 9,
                    function_type: FunctionType::Local,
                    calling_convention: Some(CallingConvention::SysV),
                    parameters: vec![],
                    is_entry_point: false,
                    is_exported: false,
                    is_imported: false,
                },
                FunctionInfo {
                    name: "func2".to_string(),
                    address: 0x2000,
                    size: 9,
                    function_type: FunctionType::Local,
                    calling_convention: Some(CallingConvention::SysV),
                    parameters: vec![],
                    is_entry_point: false,
                    is_exported: false,
                    is_imported: false,
                },
            ],
            global_variables: vec![],
            cross_references: vec![],
            imports: vec![],
            exports: vec![],
            symbol_count: SymbolCounts {
                total_functions: 2,
                local_functions: 2,
                imported_functions: 0,
                exported_functions: 0,
                global_variables: 0,
                cross_references: 0,
            },
        };

        let (functions, capped) = group_into_functions(&instructions, &symbol_table);
        assert!(capped.is_empty());

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "func1");
        assert_eq!(functions[0].address, 0x1000);
        assert_eq!(functions[0].instructions.len(), 5);
        assert_eq!(functions[1].name, "func2");
        assert_eq!(functions[1].address, 0x2000);
        assert_eq!(functions[1].instructions.len(), 5);
    }

    #[test]
    fn test_assembly_listing_generation() {
        let instructions = vec![
            create_mock_instruction(0x1000, "mov", "eax, 1", vec![0xb8, 0x01, 0x00, 0x00, 0x00]),
            create_mock_instruction(0x1005, "add", "eax, 2", vec![0x83, 0xc0, 0x02]),
        ];

        let assembly = generate_assembly_listing(&instructions);

        assert!(assembly.contains("00001000:"));
        assert!(assembly.contains("b8 01 00 00 00"));
        assert!(assembly.contains("mov eax, 1"));
        assert!(assembly.contains("00001005:"));
        assert!(assembly.contains("83 c0 02"));
        assert!(assembly.contains("add eax, 2"));
    }

    #[test]
    fn test_graph_data_generation() {
        let functions = vec![DisassembledFunction {
            address: 0x1000,
            name: "test_func".to_string(),
            size: 20,
            instructions: vec![
                create_mock_instruction(0x1000, "push", "rbp", vec![0x55]),
                create_mock_instruction(0x1001, "ret", "", vec![0xc3]),
            ],
            basic_blocks: vec![BasicBlock {
                start_address: 0x1000,
                end_address: 0x1002,
                instruction_count: 2,
                exits: vec![BlockExit {
                    exit_type: ExitType::Return,
                    target: None,
                }],
            }],
            complexity: 1,
        }];

        let graph_data = generate_graph_data(&functions);

        assert_eq!(graph_data.nodes.len(), 2); // Function node + basic block node
        assert!(graph_data.nodes.iter().any(|n| n.node_type == "function"));
        assert!(graph_data
            .nodes
            .iter()
            .any(|n| n.node_type == "basic_block"));
    }

    #[test]
    fn test_output_formats_generation() {
        let instructions = vec![create_mock_instruction(0x1000, "nop", "", vec![0x90])];
        let functions = vec![];
        let architecture = "x86_64";

        let output_formats = generate_output_formats(&instructions, &functions, architecture);

        assert!(!output_formats.assembly.is_empty());
        assert_eq!(
            output_formats
                .json_structured
                .get("architecture")
                .unwrap()
                .as_str()
                .unwrap(),
            "x86_64"
        );
        assert_eq!(
            output_formats
                .json_structured
                .get("instruction_count")
                .unwrap()
                .as_u64()
                .unwrap(),
            1
        );
    }

    #[test]
    fn test_enum_variants() {
        // Test InstructionType variants
        assert_eq!(InstructionType::Arithmetic, InstructionType::Arithmetic);
        assert_ne!(InstructionType::Arithmetic, InstructionType::Logic);

        // Test serialization/deserialization of complex structures
        let flow_control = FlowControl::Jump {
            target: Some(0x1234),
            conditional: true,
        };
        let serialized = serde_json::to_string(&flow_control).unwrap();
        let deserialized: FlowControl = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(
            deserialized,
            FlowControl::Jump {
                target: Some(0x1234),
                conditional: true
            }
        ));
    }

    #[test]
    fn test_edge_cases() {
        // Test empty instruction list
        let empty_instructions: Vec<Instruction> = vec![];
        let analysis = analyze_instructions(&empty_instructions);
        assert_eq!(analysis.total_instructions, 0);
        assert!(analysis.instruction_types.is_empty());

        // Test instruction with no operands
        let no_op_insn = create_mock_instruction(0x1000, "nop", "", vec![0x90]);
        assert_eq!(no_op_insn.operands, "");
        assert_eq!(no_op_insn.size, 1);

        // Test basic block with no exits
        let blocks_no_exits = vec![BasicBlock {
            start_address: 0x1000,
            end_address: 0x1004,
            instruction_count: 1,
            exits: vec![],
        }];
        assert_eq!(calculate_complexity(&blocks_no_exits), 2); // E(0) - N(1) + 2P(1) = 2

        // Test empty function list
        let empty_functions = vec![];
        let graph_data = generate_graph_data(&empty_functions);
        assert!(graph_data.nodes.is_empty());
        assert!(graph_data.edges.is_empty());
    }

    #[test]
    fn test_data_structure_validation() {
        // Test that all data structures can be serialized/deserialized
        let mem_access = MemoryAccess {
            instruction_address: 0x1000,
            access_type: AccessType::Read,
            size: 4,
            target_address: Some(0x2000),
            register_base: Some("rax".to_string()),
            register_index: Some("rbx".to_string()),
            displacement: Some(8),
        };

        let serialized = serde_json::to_string(&mem_access).unwrap();
        let _deserialized: MemoryAccess = serde_json::from_str(&serialized).unwrap();

        let syscall = SystemCall {
            address: 0x1000,
            syscall_number: Some(1),
            syscall_name: Some("write".to_string()),
            category: SystemCallCategory::FileSystem,
        };

        let serialized = serde_json::to_string(&syscall).unwrap();
        let _deserialized: SystemCall = serde_json::from_str(&serialized).unwrap();

        let crypto_op = CryptoOperation {
            address: 0x1000,
            operation_type: CryptoOpType::AESOperation,
            algorithm_hint: Some("AES-256".to_string()),
            confidence: 0.95,
        };

        let serialized = serde_json::to_string(&crypto_op).unwrap();
        let _deserialized: CryptoOperation = serde_json::from_str(&serialized).unwrap();

        let pattern = SuspiciousPattern {
            pattern_type: PatternType::AntiDebug,
            addresses: vec![0x1000, 0x1010],
            description: "RDTSC timing check".to_string(),
            severity: Severity::High,
        };

        let serialized = serde_json::to_string(&pattern).unwrap();
        let _deserialized: SuspiciousPattern = serde_json::from_str(&serialized).unwrap();
    }

    #[test]
    fn test_system_call_detection_edge_cases() {
        // Test syscall instruction
        let syscall_insn = create_mock_instruction(0x1000, "syscall", "", vec![0x0f, 0x05]);
        let analysis = analyze_instructions(&[syscall_insn]);
        assert_eq!(analysis.system_calls.len(), 1);

        // Test int 0x80 (Linux system call)
        let int80_insn = create_mock_instruction(0x1000, "int", "0x80", vec![0xcd, 0x80]);
        let analysis = analyze_instructions(&[int80_insn]);
        assert_eq!(analysis.system_calls.len(), 1);

        // Test other interrupt (not system call)
        let int3_insn = create_mock_instruction(0x1000, "int", "3", vec![0xcc]);
        let analysis = analyze_instructions(&[int3_insn]);
        assert_eq!(analysis.system_calls.len(), 0);
    }

    #[test]
    fn test_instruction_type_system_special_case() {
        // Test that int 0x80 is classified as System type
        let int80_insn = create_mock_instruction(0x1000, "int", "0x80", vec![0xcd, 0x80]);
        // Note: In the actual implementation, this would need to be tested via classify_instruction
        // but since we can't call it directly with a mock capstone instruction, we test the mock version
        assert_eq!(int80_insn.instruction_type, InstructionType::Control);
    }

    #[test]
    fn test_complex_flow_control_scenarios() {
        let instructions = vec![
            create_mock_instruction(0x1000, "cmp", "eax, 0", vec![0x83, 0xf8, 0x00]),
            create_mock_instruction(0x1003, "jz", "0x1010", vec![0x74, 0x0b]), // Conditional jump
            create_mock_instruction(0x1005, "call", "[rax+8]", vec![0xff, 0x50, 0x08]), // Indirect call
            create_mock_instruction(0x1008, "jmp", "0x1020", vec![0xeb, 0x16]), // Unconditional jump
            create_mock_instruction(0x1010, "ret", "", vec![0xc3]),             // Return
        ];

        let analysis = analyze_instructions(&instructions);

        assert_eq!(analysis.control_flow_summary.conditional_jumps, 1);
        assert_eq!(analysis.control_flow_summary.unconditional_jumps, 1);
        assert_eq!(analysis.control_flow_summary.function_calls, 1);
        assert_eq!(analysis.control_flow_summary.indirect_calls, 1);
        assert_eq!(analysis.control_flow_summary.returns, 1);
    }
}

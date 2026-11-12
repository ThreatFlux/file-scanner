//! Tests for the code-level analyzers: bounds checks on malformed headers,
//! architecture selection, disassembly coverage, call-name resolution in the
//! vulnerability detector, saturating metrics, bounded call graphs and taint
//! reports. Fixtures are built byte by byte so no binary is committed.

use file_scanner::call_graph::{
    call_graph_for_path, call_graph_for_path_with_arch, generate_call_graph, summarize_call_graph,
    CallGraph, CallGraphEdge, CallGraphNode, CallGraphStatistics, CallType, NodeType,
    MAX_REPORT_EDGES, MAX_REPORT_NODES,
};
use file_scanner::control_flow::{
    analyze_control_flow, analyze_control_flow_with_arch, resolve_import_targets,
    resolve_import_targets_noted, BasicBlock, BlockType, ControlFlowAnalyzer, FlowControl,
    Instruction as CfInstruction, InstructionType as CfInstructionType, MAX_CFG_FUNCTIONS,
};
use file_scanner::disassembly::{
    disassemble_binary, disassemble_binary_with_arch, disassemble_binary_with_coverage,
    disassemble_function, disassemble_range, MAX_DISASSEMBLY_INSTRUCTIONS,
};
use file_scanner::function_analysis::{
    analyze_symbols, analyze_symbols_with_arch, FunctionInfo, FunctionType, SymbolCounts,
    SymbolTable,
};
use file_scanner::taint_tracking::{taint_report_for_path, MAX_TAINT_INPUT_BYTES, MAX_TAINT_ITEMS};
use file_scanner::vulnerability_detection::{
    analyze_vulnerabilities, analyze_vulnerabilities_with_arch, VulnerabilityDetector,
    HEURISTIC_NOTICE,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

// ---------------------------------------------------------------- fixtures

/// Minimal ELF64 with a `.text` section. `text_size_override` replaces the
/// section header's size so it can point past the end of the file.
fn elf64(machine: u16, code: &[u8], text_size_override: Option<u64>) -> Vec<u8> {
    let shstrtab = b"\0.text\0.shstrtab\0";
    let code_off = 64u64;
    let strtab_off = code_off + code.len() as u64;
    let shoff = (strtab_off + shstrtab.len() as u64).next_multiple_of(8);

    let mut f = Vec::new();
    f.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    f.extend_from_slice(&[0; 8]);
    f.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    f.extend_from_slice(&machine.to_le_bytes());
    f.extend_from_slice(&1u32.to_le_bytes());
    f.extend_from_slice(&0x1000u64.to_le_bytes()); // entry
    f.extend_from_slice(&0u64.to_le_bytes()); // phoff
    f.extend_from_slice(&shoff.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&64u16.to_le_bytes()); // ehsize
    f.extend_from_slice(&0u16.to_le_bytes()); // phentsize
    f.extend_from_slice(&0u16.to_le_bytes()); // phnum
    f.extend_from_slice(&64u16.to_le_bytes()); // shentsize
    f.extend_from_slice(&3u16.to_le_bytes()); // shnum
    f.extend_from_slice(&2u16.to_le_bytes()); // shstrndx
    assert_eq!(f.len(), 64);
    f.extend_from_slice(code);
    f.extend_from_slice(shstrtab);
    while f.len() < shoff as usize {
        f.push(0);
    }
    let section = |name: u32, kind: u32, addr: u64, off: u64, size: u64| {
        let mut s = Vec::new();
        s.extend_from_slice(&name.to_le_bytes());
        s.extend_from_slice(&kind.to_le_bytes());
        s.extend_from_slice(&6u64.to_le_bytes());
        s.extend_from_slice(&addr.to_le_bytes());
        s.extend_from_slice(&off.to_le_bytes());
        s.extend_from_slice(&size.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());
        s.extend_from_slice(&0u32.to_le_bytes());
        s.extend_from_slice(&1u64.to_le_bytes());
        s.extend_from_slice(&0u64.to_le_bytes());
        s
    };
    f.extend_from_slice(&[0; 64]);
    f.extend_from_slice(&section(
        1,
        1,
        0x1000,
        code_off,
        text_size_override.unwrap_or(code.len() as u64),
    ));
    f.extend_from_slice(&section(7, 3, 0, strtab_off, shstrtab.len() as u64));
    f
}

/// Minimal PE32+ (x86-64) with a `.text` section at RVA 0x1000.
/// `raw_size_override` replaces SizeOfRawData.
fn pe64(code: &[u8], raw_size_override: Option<u32>) -> Vec<u8> {
    let mut f = vec![0u8; 0x200];
    f[0] = b'M';
    f[1] = b'Z';
    f[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    f[0x40..0x44].copy_from_slice(b"PE\0\0");
    f[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    f[0x46..0x48].copy_from_slice(&1u16.to_le_bytes());
    f[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
    f[0x56..0x58].copy_from_slice(&0x22u16.to_le_bytes());
    let opt = 0x58;
    f[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    f[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
    f[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    f[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    f[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    f[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    f[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    f[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
    f[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    f[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
    let sh = opt + 240;
    f[sh..sh + 5].copy_from_slice(b".text");
    f[sh + 8..sh + 12]
        .copy_from_slice(&raw_size_override.unwrap_or(code.len() as u32).to_le_bytes());
    f[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    f[sh + 16..sh + 20]
        .copy_from_slice(&raw_size_override.unwrap_or(code.len() as u32).to_le_bytes());
    f[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes());
    f[sh + 36..sh + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    f.extend_from_slice(code);
    f
}

fn write(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn function(name: &str, address: u64, size: u64) -> FunctionInfo {
    FunctionInfo {
        name: name.to_string(),
        address,
        size,
        function_type: FunctionType::Local,
        calling_convention: None,
        parameters: Vec::new(),
        is_entry_point: false,
        is_exported: false,
        is_imported: false,
    }
}

fn symbols(functions: Vec<FunctionInfo>) -> SymbolTable {
    SymbolTable {
        functions,
        global_variables: Vec::new(),
        cross_references: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        symbol_count: SymbolCounts {
            total_functions: 0,
            local_functions: 0,
            imported_functions: 0,
            exported_functions: 0,
            global_variables: 0,
            cross_references: 0,
        },
    }
}

/// `push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret`
const SIMPLE_FN: &[u8] = &[0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3];

/// A binary tracked in `test_programs/`; a missing one fails the test.
fn repo_binary(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test_programs")
        .join(name);
    assert!(path.exists(), "tracked test binary {name} is missing");
    path
}

// ------------------------------------------------- CB02: malformed headers

#[test]
fn cb02_elf_text_past_end_of_file_is_an_error_not_a_panic() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "bad.elf",
        &elf64(EM_X86_64, SIMPLE_FN, Some(0x1000_0000)),
    );

    let err = disassemble_binary(&path, &symbols(vec![])).unwrap_err();
    assert!(
        err.to_string().contains("Malformed binary"),
        "error should name the problem: {err}"
    );

    // The control-flow path reads the same header.
    let err = analyze_control_flow(&path, &symbols(vec![function("f", 0x1000, 8)])).unwrap_err();
    assert!(err.to_string().contains("Malformed binary"), "{err}");
}

#[test]
fn cb02_elf_text_size_that_overflows_u64_is_an_error() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "huge.elf",
        &elf64(EM_X86_64, SIMPLE_FN, Some(u64::MAX)),
    );
    assert!(disassemble_binary(&path, &symbols(vec![])).is_err());
}

#[test]
fn cb02_pe_text_past_end_of_file_is_an_error_not_a_panic() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "bad.exe", &pe64(SIMPLE_FN, Some(0x0700_0000)));
    let err = disassemble_binary(&path, &symbols(vec![])).unwrap_err();
    assert!(err.to_string().contains("Malformed binary"), "{err}");
}

#[test]
fn cb02_well_formed_fixtures_still_disassemble() {
    let dir = TempDir::new().unwrap();
    let elf = write(&dir, "ok.elf", &elf64(EM_X86_64, SIMPLE_FN, None));
    let pe = write(&dir, "ok.exe", &pe64(SIMPLE_FN, None));
    for path in [elf, pe] {
        let result = disassemble_binary(&path, &symbols(vec![])).unwrap();
        assert_eq!(result.architecture, "x86_64");
        assert_eq!(result.instructions.len(), 5);
    }
}

// ------------------------------------- CB05: skip undecodable bytes, report

#[test]
fn cb05_disassembly_resynchronises_after_undecodable_bytes() {
    // nop; three bytes invalid in 64-bit mode (0x06 is push es); xor eax,eax; ret
    let code = [0x90, 0x06, 0x06, 0x06, 0x31, 0xc0, 0xc3];
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "data.elf", &elf64(EM_X86_64, &code, None));

    let (result, coverage) = disassemble_binary_with_coverage(&path, &symbols(vec![])).unwrap();
    assert_eq!(coverage.section_size, 7);
    assert_eq!(coverage.bytes_skipped, 3);
    assert_eq!(coverage.bytes_decoded, 4);
    assert_eq!(coverage.skipped_runs, 1);
    assert!(!coverage.truncated);
    // The listing continues after the bad bytes.
    let last = result.instructions.last().unwrap();
    assert_eq!(last.mnemonic, "ret");
    assert!(result.instructions.iter().any(|i| i.mnemonic == "xor"));
    // Skipped bytes are not counted as instructions in the analysis.
    assert_eq!(result.analysis.total_instructions, 3);
    // The same figures travel inside the result.
    let cov = &result.output_formats.json_structured["coverage"];
    assert_eq!(cov["bytes_skipped"], 3);
}

#[test]
fn cb05_clean_code_reports_full_coverage() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "ok.elf", &elf64(EM_X86_64, SIMPLE_FN, None));
    let (_, coverage) = disassemble_binary_with_coverage(&path, &symbols(vec![])).unwrap();
    assert_eq!(coverage.bytes_decoded, 8);
    assert_eq!(coverage.bytes_skipped, 0);
    assert!(coverage.notes.is_empty());
}

#[test]
fn cb05_pe_functions_without_symbol_sizes_run_to_the_next_symbol() {
    // Two functions back to back; symbols carry no size (as for PE and Mach-O).
    let mut code = SIMPLE_FN.to_vec();
    code.extend_from_slice(SIMPLE_FN);
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "ok.elf", &elf64(EM_X86_64, &code, None));
    let table = symbols(vec![function("a", 0x1000, 0), function("b", 0x1008, 0)]);
    let result = disassemble_binary(&path, &table).unwrap();
    assert_eq!(result.functions.len(), 2);
    assert_eq!(result.functions[0].instructions.len(), 5);
    assert_eq!(result.functions[1].instructions.len(), 5);
}

#[test]
fn cb05_call_targets_are_decoded() {
    // call +0 (to the next instruction at 0x1005), ret
    let code = [0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3];
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "call.elf", &elf64(EM_X86_64, &code, None));
    let result = disassemble_binary(&path, &symbols(vec![])).unwrap();
    match result.instructions[0].flow_control {
        Some(file_scanner::disassembly::FlowControl::Call {
            target,
            is_indirect,
        }) => {
            assert_eq!(target, Some(0x1005));
            assert!(!is_indirect);
        }
        ref other => panic!("expected a direct call, got {other:?}"),
    }
}

#[test]
fn uc20_disassembly_is_bounded_and_says_so() {
    // More one-byte instructions than the cap.
    let code = vec![0x90u8; MAX_DISASSEMBLY_INSTRUCTIONS + 1000];
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "nops.elf", &elf64(EM_X86_64, &code, None));
    let (result, coverage) = disassemble_binary_with_coverage(&path, &symbols(vec![])).unwrap();
    assert!(coverage.truncated);
    assert_eq!(result.instructions.len(), MAX_DISASSEMBLY_INSTRUCTIONS);
    assert_eq!(coverage.section_size, code.len() as u64);
    assert_eq!(coverage.bytes_examined, MAX_DISASSEMBLY_INSTRUCTIONS as u64);
    assert!(coverage.notes.iter().any(|n| n.contains("stopped after")));
}

// ----------------------------------------- CB04: control-flow engine choice

#[test]
fn cb04_arm64_elf_gets_an_explicit_error_naming_the_architecture() {
    let dir = TempDir::new().unwrap();
    // ret (aarch64)
    let path = write(
        &dir,
        "arm.elf",
        &elf64(EM_AARCH64, &[0xc0, 0x03, 0x5f, 0xd6], None),
    );
    let err = analyze_control_flow(&path, &symbols(vec![function("f", 0x1000, 4)])).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("ARM64"), "{text}");
    assert!(text.contains("x86"), "{text}");
}

#[test]
fn cb04_stripped_binary_says_no_function_boundaries_were_found() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "stripped.elf", &elf64(EM_X86_64, SIMPLE_FN, None));
    let err = analyze_control_flow(&path, &symbols(vec![])).unwrap_err();
    assert!(
        err.to_string()
            .contains("No function boundaries were found"),
        "{err}"
    );
}

#[test]
fn cb04_non_executable_file_is_rejected_by_name() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "notes.txt", b"just some text, not an executable\n");
    let err = analyze_control_flow(&path, &symbols(vec![])).unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("supports ELF, PE and Mach-O executables"),
        "{text}"
    );
}

#[test]
fn cb04_pe_code_is_analyzed_with_symbols_given_as_relative_addresses() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "ok.exe", &pe64(SIMPLE_FN, None));
    // PE symbol tables hold RVAs.
    let table = symbols(vec![function("pe_fn", 0x1000, 0)]);
    let analysis = analyze_control_flow(&path, &table).unwrap();
    assert_eq!(analysis.cfgs.len(), 1);
    assert_eq!(analysis.cfgs[0].function_address, 0x1_4000_1000);
    assert_eq!(analysis.cfgs[0].function_name, "pe_fn");
}

#[test]
fn cb04_unsized_and_local_functions_are_analyzed() {
    // Two functions; neither exported, neither sized.
    let mut code = SIMPLE_FN.to_vec();
    code.extend_from_slice(SIMPLE_FN);
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "two.elf", &elf64(EM_X86_64, &code, None));
    let table = symbols(vec![
        function("local_helper", 0x1000, 0),
        function("other", 0x1008, 0),
    ]);
    let analysis = analyze_control_flow(&path, &table).unwrap();
    assert_eq!(analysis.cfgs.len(), 2);
    assert_eq!(analysis.overall_metrics.total_functions, 2);
}

#[test]
fn cb04_32_bit_engine_decodes_32_bit_registers() {
    let analyzer = ControlFlowAnalyzer::new_x86_32().unwrap();
    let instructions = analyzer.disassemble_function(&[0x53], 0x1000).unwrap(); // push ebx
    assert_eq!(instructions[0].mnemonic, "push");
    assert_eq!(instructions[0].operands, "ebx");
}

#[test]
fn cb04_undecodable_bytes_do_not_abort_function_analysis() {
    let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();
    let instructions = analyzer
        .disassemble_function(&[0x90, 0x06, 0xc3], 0x1000)
        .unwrap();
    assert_eq!(instructions.len(), 3);
    assert_eq!(instructions[2].mnemonic, "ret");
}

// ------------------------------------------------------ CB07: call matching

/// `call rel32` to `target_offset` bytes after the start, then `ret`.
fn call_fixture(target_offset: i32) -> (Vec<u8>, u64) {
    let mut code = vec![0xe8];
    code.extend_from_slice(&(target_offset - 5).to_le_bytes());
    code.push(0xc3);
    (code, 0x1000 + target_offset as u64)
}

#[test]
fn cb07_a_call_to_an_unnamed_target_matches_nothing() {
    let (code, _target) = call_fixture(0x40);
    let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();
    let analysis = analyzer
        .analyze_code(&code, 0x1000, vec![function("caller", 0x1000, 6)])
        .unwrap();
    let result = VulnerabilityDetector::new()
        .analyze(&symbols(vec![]), &analysis)
        .unwrap();
    assert!(
        result.vulnerabilities.is_empty(),
        "an unresolved call must not match any function rule: {:?}",
        result
            .vulnerabilities
            .iter()
            .map(|v| &v.rule_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn cb07_a_call_to_a_local_function_that_is_not_listed_matches_nothing() {
    let (code, target) = call_fixture(0x40);
    let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();
    let analysis = analyzer
        .analyze_code(&code, 0x1000, vec![function("caller", 0x1000, 6)])
        .unwrap();
    let table = symbols(vec![function("local_helper", target, 8)]);
    let result = VulnerabilityDetector::new()
        .analyze(&table, &analysis)
        .unwrap();
    assert!(result.vulnerabilities.is_empty());
}

#[test]
fn cb07_a_call_resolved_to_strcpy_is_reported_once_with_the_name() {
    let (code, target) = call_fixture(0x40);
    let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();
    let analysis = analyzer
        .analyze_code(&code, 0x1000, vec![function("caller", 0x1000, 6)])
        .unwrap();
    let mut imports = HashMap::new();
    imports.insert(target, "strcpy@GLIBC_2.2.5".to_string());
    let result = VulnerabilityDetector::new()
        .analyze_with_imports(&symbols(vec![]), &analysis, &imports)
        .unwrap();
    let ids: Vec<&str> = result
        .vulnerabilities
        .iter()
        .map(|v| v.rule_id.as_str())
        .collect();
    assert_eq!(ids, vec!["BOF001"], "{ids:?}");
    assert!(result.vulnerabilities[0].locations[0]
        .instruction
        .contains("strcpy"));
    assert!(result
        .risk_assessment
        .recommendations
        .iter()
        .any(|r| r == HEURISTIC_NOTICE));
}

#[test]
fn cb07_mnemonic_call_alone_never_matches() {
    // A hand-built call whose operand names nothing dangerous.
    let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();
    let analysis = analyzer
        .analyze_code(
            &[0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3],
            0x1000,
            vec![function("f", 0x1000, 6)],
        )
        .unwrap();
    let result = VulnerabilityDetector::new()
        .analyze(&symbols(vec![]), &analysis)
        .unwrap();
    assert!(result.vulnerabilities.is_empty());
}

#[test]
fn cb07_unimplemented_matchers_match_nothing_so_npd001_never_fires() {
    // `mov` then anything: the old catch-all arm made the Immediate matcher true.
    let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();
    // mov rax, [rbx]; mov rcx, rax; ret
    let code = [0x48, 0x8b, 0x03, 0x48, 0x89, 0xc1, 0xc3];
    let analysis = analyzer
        .analyze_code(&code, 0x1000, vec![function("f", 0x1000, 7)])
        .unwrap();
    let result = VulnerabilityDetector::new()
        .analyze(&symbols(vec![]), &analysis)
        .unwrap();
    assert!(result.vulnerabilities.iter().all(|v| v.rule_id != "NPD001"));
}

#[test]
fn cb07_real_binary_findings_name_the_called_function() {
    let path = repo_binary("c_advanced_binary");
    let table = analyze_symbols(&path).unwrap();
    let cf = analyze_control_flow(&path, &table).unwrap();
    let result = analyze_vulnerabilities(&path, &table, &cf).unwrap();

    let call_rules = ["BOF001", "FMT001", "UAF001", "DBF001"];
    let call_findings: Vec<_> = result
        .vulnerabilities
        .iter()
        .filter(|v| {
            call_rules.contains(&v.rule_id.as_str()) && v.locations[0].function_name != "Imports"
        })
        .collect();
    assert!(!call_findings.is_empty(), "strcpy and printf are called");
    for finding in &call_findings {
        for location in &finding.locations {
            // "<mnemonic> <operand> (<resolved name>)"
            assert!(
                location.instruction.ends_with(')'),
                "location without a resolved name: {}",
                location.instruction
            );
        }
    }
    // vulnerable_strcpy calls strcpy; a function that does not must not get BOF001.
    assert!(call_findings
        .iter()
        .any(|v| v.rule_id == "BOF001" && v.locations[0].function_name == "vulnerable_strcpy"));
    let functions_with_bof: std::collections::HashSet<_> = call_findings
        .iter()
        .filter(|v| v.rule_id == "BOF001")
        .map(|v| v.locations[0].function_name.clone())
        .collect();
    assert!(
        functions_with_bof.len() < cf.cfgs.len() / 2,
        "BOF001 in {} of {} functions",
        functions_with_bof.len(),
        cf.cfgs.len()
    );
}

#[test]
fn cb07_import_stubs_of_a_real_elf_resolve_to_names() {
    let path = repo_binary("c_advanced_binary");
    let names = resolve_import_targets(&std::fs::read(&path).unwrap());
    assert!(names.values().any(|n| n.starts_with("strcpy")), "{names:?}");
}

// ----------------------------------------------- CB17: nesting depth, debt

fn block(id: usize, block_type: BlockType) -> BasicBlock {
    BasicBlock {
        id,
        start_address: id as u64 * 16,
        end_address: id as u64 * 16 + 16,
        instructions: vec![CfInstruction {
            address: id as u64 * 16,
            bytes: vec![0x90],
            mnemonic: "nop".to_string(),
            operands: String::new(),
            instruction_type: CfInstructionType::Nop,
            flow_control: FlowControl::Fall,
            size: 1,
        }],
        successors: Vec::new(),
        predecessors: Vec::new(),
        block_type,
        instruction_count: 1,
    }
}

#[test]
fn cb17_nesting_depth_never_goes_negative() {
    let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();
    // Several return blocks before the first conditional used to push the
    // counter below zero, which wrapped to about 4.29 billion when cast to u32.
    let blocks = vec![
        block(0, BlockType::Return),
        block(1, BlockType::Return),
        block(2, BlockType::Return),
        block(3, BlockType::Conditional),
    ];
    assert_eq!(analyzer.calculate_nesting_depth(&blocks), 1);
}

#[test]
fn cb17_code_quality_survives_go_binaries() {
    let path = repo_binary("crypto_miner_binary");
    let table = analyze_symbols(&path).unwrap();
    let cf = analyze_control_flow(&path, &table).unwrap();
    assert!(cf
        .cfgs
        .iter()
        .all(|g| g.complexity.nesting_depth < 1_000_000));
    let quality = file_scanner::code_metrics::analyze_code_quality(&path, &table, &cf).unwrap();
    assert!(!quality.function_metrics.is_empty());
}

// ------------------------------------------ UC20: bounded control-flow runs

#[test]
fn uc20_control_flow_on_a_large_symbol_table_is_capped_and_says_so() {
    let path = repo_binary("go_test_binary");
    let table = analyze_symbols(&path).unwrap();
    let cf = analyze_control_flow(&path, &table).unwrap();
    assert!(cf.cfgs.len() <= MAX_CFG_FUNCTIONS);
    assert!(cf.overall_metrics.total_functions > cf.cfgs.len());
    assert!(
        cf.analysis_stats
            .errors
            .iter()
            .any(|e| e.starts_with("Limit:")),
        "{:?}",
        cf.analysis_stats.errors
    );
}

// ------------------------------------------------------------ CB08: call graph

#[test]
fn cb08_call_graph_for_path_finds_calls_and_imports() {
    let path = repo_binary("c_advanced_binary");
    let report = call_graph_for_path(&path).unwrap();
    assert!(report.graph.statistics.total_edges > 0);
    let strcpy_node = report
        .graph
        .nodes
        .iter()
        .find(|n| n.function_name == "strcpy@plt")
        .expect("calls to strcpy appear as an external node");
    assert_eq!(strcpy_node.node_type, NodeType::External);
    let caller = report
        .graph
        .nodes
        .iter()
        .find(|n| n.function_name == "vulnerable_strcpy")
        .unwrap();
    assert!(report
        .graph
        .edges
        .iter()
        .any(|e| e.caller == caller.function_address && e.callee == strcpy_node.function_address));
    assert!(!report.truncated);
}

fn big_graph(nodes: usize, edges: usize) -> CallGraph {
    CallGraph {
        nodes: (0..nodes as u64)
            .map(|i| CallGraphNode {
                function_address: i,
                function_name: format!("f{i}"),
                node_type: NodeType::Internal,
                complexity: 0,
                in_degree: (i % 7) as u32,
                out_degree: 0,
                is_recursive: false,
                call_depth: None,
            })
            .collect(),
        edges: (0..edges as u64)
            .map(|i| CallGraphEdge {
                caller: i % nodes as u64,
                callee: (i * 7 + 1) % nodes as u64,
                call_type: CallType::Direct,
                call_sites: (0..20).collect(),
                weight: 20,
            })
            .collect(),
        entry_points: vec![0],
        unreachable_functions: Vec::new(),
        statistics: CallGraphStatistics {
            total_nodes: nodes,
            total_edges: edges,
            max_depth: 0,
            unreachable_count: 0,
            recursive_functions: 0,
            leaf_functions: 0,
            root_functions: 0,
            avg_in_degree: 0.0,
            avg_out_degree: 0.0,
            strongly_connected_components: 0,
        },
    }
}

#[test]
fn cb08_large_call_graphs_are_cut_with_a_note() {
    let report = summarize_call_graph(big_graph(MAX_REPORT_NODES + 500, MAX_REPORT_EDGES + 5000));
    assert!(report.truncated);
    assert_eq!(report.graph.nodes.len(), MAX_REPORT_NODES);
    assert!(report.graph.edges.len() <= MAX_REPORT_EDGES);
    assert_eq!(report.nodes_total, MAX_REPORT_NODES + 500);
    assert!(!report.notes.is_empty());
    // Statistics still describe the whole graph.
    assert_eq!(report.graph.statistics.total_nodes, MAX_REPORT_NODES + 500);
    let kept: std::collections::HashSet<u64> = report
        .graph
        .nodes
        .iter()
        .map(|n| n.function_address)
        .collect();
    assert!(report
        .graph
        .edges
        .iter()
        .all(|e| kept.contains(&e.caller) && kept.contains(&e.callee)));
    assert!(report.graph.edges.iter().all(|e| e.call_sites.len() <= 8));
}

#[test]
fn cb08_small_call_graphs_are_not_marked_truncated() {
    let mut graph = big_graph(10, 5);
    for edge in &mut graph.edges {
        edge.call_sites.truncate(3);
    }
    let report = summarize_call_graph(graph);
    assert!(!report.truncated, "{:?}", report.notes);
    assert!(report.notes.is_empty());
    assert_eq!(report.graph.nodes.len(), 10);
}

// ------------------------------------------------------------- CB19: taint

#[test]
fn cb19_taint_report_for_a_script() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "app.py",
        b"import os\ncmd = request.query['cmd']\nos.system(cmd)\n",
    );
    let report = taint_report_for_path(&path).unwrap();
    assert!(report.totals.sources >= 1, "{:?}", report.totals);
    assert!(report.totals.sinks >= 1, "{:?}", report.totals);
    assert!(report.notes.iter().any(|n| n.contains("heuristic")));
}

#[test]
fn cb19_taint_report_refuses_binaries_with_an_explanation() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "prog.elf", &elf64(EM_X86_64, SIMPLE_FN, None));
    let err = taint_report_for_path(&path).unwrap_err();
    assert!(err.to_string().contains("not UTF-8 text"), "{err}");
}

#[test]
fn cb19_taint_report_lists_are_bounded() {
    let mut text = String::new();
    for i in 0..(MAX_TAINT_ITEMS * 3) {
        text.push_str(&format!("v{i} = request.query['p{i}']\nos.system(v{i})\n"));
    }
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "many.py", text.as_bytes());
    let report = taint_report_for_path(&path).unwrap();
    assert!(report.analysis.sources.len() <= MAX_TAINT_ITEMS);
    assert!(report.analysis.taint_flows.len() <= MAX_TAINT_ITEMS);
    assert!(report.totals.sources > MAX_TAINT_ITEMS);
    assert!(report.truncated);
}

#[test]
fn cb19_taint_report_time_is_linear_in_the_number_of_matches() {
    // Every line matches a source or a sink; the input is cut at the byte cap.
    let mut text = String::new();
    while text.len() < MAX_TAINT_INPUT_BYTES {
        text.push_str("a = sys.argv[1]\nopen(a)\n");
    }
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "dense.py", text.as_bytes());
    let started = std::time::Instant::now();
    let report = taint_report_for_path(&path).unwrap();
    let took = started.elapsed();
    assert!(took.as_secs() < 20, "took {took:?}");
    assert!(report.truncated);
    assert!(report.notes.iter().any(|n| n.contains("flow pairing")));
}

#[test]
fn cb19_taint_report_is_bounded_in_bytes_with_very_long_lines() {
    let line = format!(
        "x=req.query;process.env;sys.argv[1];exec(x);open(x);el.innerHTML=x;{}\n",
        "a=1;".repeat(100_000)
    );
    let text = line.repeat(4);
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "min.js", text.as_bytes());
    let report = taint_report_for_path(&path).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.len() < 1_000_000, "report is {} bytes", json.len());
    assert!(report.truncated);
    assert!(report.notes.iter().any(|n| n.contains("snippets")));
    assert!(report
        .analysis
        .sources
        .iter()
        .all(|s| s.location.code_snippet.chars().count() <= 201));
}

#[test]
fn cb19_function_names_come_from_the_nearest_earlier_declaration() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "f.py",
        b"def first():\n    pass\ndef second():\n    a = request.query['x']\n    os.system(a)\n",
    );
    let report = taint_report_for_path(&path).unwrap();
    assert_eq!(
        report.analysis.sources[0].location.function_name.as_deref(),
        Some("second")
    );
}

#[test]
fn cb08_unsized_symbols_run_to_the_next_symbol_and_get_edges() {
    // a: call b; ret   b: ret   (symbols carry no size, as for PE and Mach-O)
    let code = [0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3];
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "unsized.elf", &elf64(EM_X86_64, &code, None));
    let table = symbols(vec![function("a", 0x1000, 0), function("b", 0x1006, 0)]);
    let dis = disassemble_binary(&path, &table).unwrap();
    let graph = generate_call_graph(&path, &dis, &table).unwrap();
    assert!(
        graph
            .edges
            .iter()
            .any(|e| e.caller == 0x1000 && e.callee == 0x1006),
        "{:?}",
        graph.edges
    );
}

#[test]
fn cb08_calls_without_function_symbols_say_why_there_are_no_edges() {
    let code = [0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3];
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "stripped.elf", &elf64(EM_X86_64, &code, None));
    let report = call_graph_for_path(&path).unwrap();
    assert_eq!(report.edges_total, 0);
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("no function symbols")),
        "{:?}",
        report.notes
    );
}

#[test]
fn cb05_function_cap_is_reported_in_the_coverage_notes() {
    let count = 5_100u64;
    let code = vec![0x90u8; count as usize * 2];
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "many.elf", &elf64(EM_X86_64, &code, None));
    let funcs = (0..count)
        .map(|i| function(&format!("f{i}"), 0x1000 + i * 2, 2))
        .collect();
    let (result, coverage) = disassemble_binary_with_coverage(&path, &symbols(funcs)).unwrap();
    assert_eq!(result.functions.len(), 5_000);
    assert!(coverage.truncated);
    assert!(
        coverage.notes.iter().any(|n| n.contains("grouped")),
        "{:?}",
        coverage.notes
    );
}

#[test]
fn cb05_chunked_decoding_matches_the_instruction_cap_exactly() {
    // Exactly the cap: not truncated. One more: truncated.
    let dir = TempDir::new().unwrap();
    let exact = vec![0x90u8; MAX_DISASSEMBLY_INSTRUCTIONS];
    let path = write(&dir, "exact.elf", &elf64(EM_X86_64, &exact, None));
    let (result, coverage) = disassemble_binary_with_coverage(&path, &symbols(vec![])).unwrap();
    assert_eq!(result.instructions.len(), MAX_DISASSEMBLY_INSTRUCTIONS);
    assert!(!coverage.truncated, "{:?}", coverage.notes);
}

/// 64-bit x86-64 Mach-O with no dyld bind information (as with chained
/// fixups): one `__stubs` entry whose symbol is only named by the indirect
/// symbol table.
fn macho_with_indirect_stub() -> Vec<u8> {
    let u32s = |v: &[u32]| v.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
    let name = |s: &str| {
        let mut b = s.as_bytes().to_vec();
        b.resize(16, 0);
        b
    };
    let mut f = u32s(&[0xfeed_facf, 0x0100_0007, 3, 2, 3, 256, 0, 0]);
    // LC_SEGMENT_64 with one section.
    f.extend(u32s(&[0x19, 152]));
    f.extend(name("__TEXT"));
    for v in [0x1_0000_0000u64, 0x1000, 0, 329] {
        f.extend(v.to_le_bytes());
    }
    f.extend(u32s(&[7, 5, 1, 0]));
    f.extend(name("__stubs"));
    f.extend(name("__TEXT"));
    for v in [0x1_0000_0120u64, 6] {
        f.extend(v.to_le_bytes());
    }
    f.extend(u32s(&[288, 1, 0, 0, 0x8000_0408, 0, 6, 0]));
    // LC_SYMTAB
    f.extend(u32s(&[2, 24, 304, 1, 320, 9]));
    // LC_DYSYMTAB: indirect table at 296 with one entry.
    let mut dys = [0u32; 20];
    dys[0] = 0xb;
    dys[1] = 80;
    dys[7] = 1; // nundefsym
    dys[14] = 296;
    dys[15] = 1;
    f.extend(u32s(&dys));
    assert_eq!(f.len(), 288);
    f.extend([0xff, 0x25, 0, 0, 0, 0, 0, 0]); // stub, padded
    f.extend(u32s(&[0])); // indirect symbol table: symbol 0
    f.extend([0u8; 4]);
    f.extend(u32s(&[1]));
    f.extend([1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // n_type=1 (undef, ext)
    f.extend(b"\0_printf\0");
    f
}

#[test]
fn cb07_macho_imports_resolve_through_the_indirect_symbol_table() {
    let bytes = macho_with_indirect_stub();
    let targets = resolve_import_targets(&bytes);
    assert_eq!(
        targets.get(&0x1_0000_0120).map(String::as_str),
        Some("_printf"),
        "{targets:?}"
    );
}

#[test]
fn cb07_call_presence_rules_are_low_severity_and_risk_never_hides_a_critical() {
    use file_scanner::vulnerability_detection::{RiskLevel, Severity};
    let path = repo_binary("c_advanced_binary");
    let table = analyze_symbols(&path).unwrap();
    let cf = analyze_control_flow(&path, &table).unwrap();
    let result = analyze_vulnerabilities(&path, &table, &cf).unwrap();
    for finding in &result.vulnerabilities {
        if ["UAF001", "DBF001", "FMT001"].contains(&finding.rule_id.as_str()) {
            assert_eq!(
                finding.severity,
                Severity::Low,
                "{} only says the function is called",
                finding.rule_id
            );
        }
    }
    let criticals = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == Severity::Critical)
        .count();
    assert!(criticals > 0, "strcpy is always-unsafe");
    assert!(!matches!(
        result.risk_assessment.risk_level,
        RiskLevel::Minimal | RiskLevel::Low
    ));
}

// ------------------------------------------------------ round 3 fixtures

const CPU_X86_64: u32 = 0x0100_0007;
const CPU_ARM64: u32 = 0x0100_000c;

/// 64-bit Mach-O with one defined symbol `_main` at the start of `code`, whose
/// first section is `sect` (`__text` or `__stubs`). `extra_got` hostile
/// `__got` sections claim a size of almost 2^64 bytes, and
/// `LC_DYSYMTAB.nindirectsyms` is `nindirect`.
fn macho_build(
    cputype: u32,
    sect: &str,
    code: &[u8],
    size_override: Option<u64>,
    off_override: Option<u32>,
    extra_got: usize,
    nindirect: u32,
) -> Vec<u8> {
    let u32s = |v: &[u32]| v.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>();
    let name = |s: &str| {
        let mut b = s.as_bytes().to_vec();
        b.resize(16, 0);
        b
    };
    let nsects = 1 + extra_got;
    let seg_size = 72 + 80 * nsects;
    let data = 32 + seg_size + 24 + 80;
    let code_len = code.len().next_multiple_of(8);
    let ind_off = data + code_len;
    let sym_off = ind_off + 8;
    let str_off = sym_off + 16;
    let strings = b"\0_main\0";
    let total = str_off + strings.len();
    let base = 0x1_0000_0000u64;

    let mut f = u32s(&[
        0xfeed_facf,
        cputype,
        3,
        2,
        3,
        (seg_size + 24 + 80) as u32,
        0,
        0,
    ]);
    f.extend(u32s(&[0x19, seg_size as u32]));
    f.extend(name("__TEXT"));
    for v in [base, 0x4000, 0, total as u64] {
        f.extend(v.to_le_bytes());
    }
    f.extend(u32s(&[7, 5, nsects as u32, 0]));
    let stubs = sect == "__stubs";
    f.extend(name(sect));
    f.extend(name("__TEXT"));
    f.extend((base + data as u64).to_le_bytes());
    f.extend(size_override.unwrap_or(code.len() as u64).to_le_bytes());
    f.extend(u32s(&[
        off_override.unwrap_or(data as u32),
        1,
        0,
        0,
        if stubs { 0x8000_0408 } else { 0x8000_0400 },
        0,
        if stubs { 6 } else { 0 },
        0,
    ]));
    for i in 0..extra_got {
        f.extend(name("__got"));
        f.extend(name("__DATA"));
        f.extend((base + 0x2000 + 0x100 * i as u64).to_le_bytes());
        f.extend(0xFFFF_FFFF_FFFF_FF00u64.to_le_bytes());
        f.extend(u32s(&[0, 3, 0, 0, 6, 0, 0, 0]));
    }
    f.extend(u32s(&[
        2,
        24,
        sym_off as u32,
        1,
        str_off as u32,
        strings.len() as u32,
    ]));
    let mut dys = [0u32; 20];
    dys[0] = 0xb;
    dys[1] = 80;
    dys[7] = 1;
    dys[14] = ind_off as u32;
    dys[15] = nindirect;
    f.extend(u32s(&dys));
    assert_eq!(f.len(), data);
    f.extend(code);
    f.resize(ind_off, 0);
    f.extend(u32s(&[0, 0]));
    // nlist_64: n_strx 1, N_SECT | N_EXT, section 1, value
    f.extend(u32s(&[1]));
    f.extend([0x0f, 1, 0, 0]);
    f.extend((base + data as u64).to_le_bytes());
    f.extend(strings);
    assert_eq!(f.len(), total);
    f
}

/// A universal binary holding `slices` as (cputype, bytes).
fn fat(slices: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(0xCAFE_BABEu32.to_be_bytes());
    f.extend((slices.len() as u32).to_be_bytes());
    let mut offset = 0x1000usize;
    let mut body = Vec::new();
    for (cpu, bytes) in slices {
        f.extend(cpu.to_be_bytes());
        f.extend(0u32.to_be_bytes());
        f.extend((offset as u32).to_be_bytes());
        f.extend((bytes.len() as u32).to_be_bytes());
        f.extend(12u32.to_be_bytes());
        body.push((offset, bytes));
        offset = (offset + bytes.len()).next_multiple_of(0x1000);
    }
    f.resize(0x1000, 0);
    for (off, bytes) in body {
        f.resize(off, 0);
        f.extend(bytes);
    }
    f
}

fn patch_elf_text_addr(elf: &mut [u8], addr: u64) {
    let shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap()) as usize;
    // section 1 (.text): sh_addr is at +16 in its 64-byte header
    let at = shoff + 64 + 16;
    elf[at..at + 8].copy_from_slice(&addr.to_le_bytes());
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, std::time::Duration) {
    let start = std::time::Instant::now();
    let value = f();
    (value, start.elapsed())
}

// ------------------------------- round 3: Mach-O indirect symbol loop

#[test]
fn r3_hostile_indirect_symbol_table_is_bounded() {
    // 40 sections claiming ~2^64 bytes each and nindirectsyms = u32::MAX
    // used to cost about 5 s per section header.
    let bytes = macho_build(
        CPU_X86_64,
        "__stubs",
        &[0xff, 0x25, 0, 0, 0, 0],
        None,
        None,
        40,
        u32::MAX,
    );
    let (targets, took) = timed(|| resolve_import_targets(&bytes));
    assert!(took.as_secs() < 3, "took {took:?}");
    // The walk is cut by the table's real size: few entries, no panic.
    assert!(targets.len() < 1_000, "{}", targets.len());
}

#[test]
fn r3_indirect_table_count_is_checked_against_the_file() {
    let bytes = macho_build(
        CPU_X86_64,
        "__stubs",
        &[0xff, 0x25, 0, 0, 0, 0],
        None,
        None,
        3,
        4,
    );
    let (_, took) = timed(|| resolve_import_targets(&bytes));
    assert!(took.as_secs() < 3, "took {took:?}");
}

// ------------------------------- round 3: function grouping memory

#[test]
fn r3_overlapping_function_symbols_do_not_multiply_the_listing() {
    let count = 3_000usize;
    let code = vec![0x90u8; 6_000];
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "overlap.elf", &elf64(EM_X86_64, &code, None));
    // every symbol claims to run to the end of the code
    let funcs = (0..count)
        .map(|i| function(&format!("f{i}"), 0x1000 + i as u64, 6_000))
        .collect();
    let (result, coverage) = disassemble_binary_with_coverage(&path, &symbols(funcs)).unwrap();
    let copied: usize = result.functions.iter().map(|f| f.instructions.len()).sum();
    assert!(
        copied <= result.instructions.len(),
        "{copied} instructions copied from {}",
        result.instructions.len()
    );
    // functions are disjoint: each ends where the next starts
    for pair in result.functions.windows(2) {
        let last = pair[0].instructions.last().unwrap();
        assert!(last.address < pair[1].address);
    }
    assert!(
        coverage
            .notes
            .iter()
            .any(|n| n.contains("runs into the next function symbol")),
        "{:?}",
        coverage.notes
    );
}

#[test]
fn r3_total_instructions_copied_into_functions_is_bounded_by_the_listing() {
    // 20,000 one-byte instructions, 2,000 symbols of declared size 20,001
    let code = vec![0x90u8; 20_000];
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "overlap2.elf", &elf64(EM_X86_64, &code, None));
    let funcs = (0..2_000u64)
        .map(|i| function(&format!("f{i}"), 0x1000 + i, 20_001))
        .collect();
    let result = disassemble_binary(&path, &symbols(funcs)).unwrap();
    let copied: usize = result.functions.iter().map(|f| f.instructions.len()).sum();
    // 1,999 one-instruction functions, then the last one runs to the end
    assert_eq!(copied, 20_000);
}

// ------------------------------- round 3: address arithmetic

#[test]
fn r3_text_mapped_near_the_top_of_the_address_space_does_not_overflow() {
    // more than one 4,096-instruction chunk, addresses wrap past u64::MAX
    let code = vec![0x90u8; 10_001];
    let mut elf = elf64(EM_X86_64, &code, None);
    patch_elf_text_addr(&mut elf, 0xFFFF_FFFF_FFFF_FF9A);
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "wrap.elf", &elf);
    let (result, coverage) = disassemble_binary_with_coverage(&path, &symbols(vec![])).unwrap();
    assert_eq!(result.instructions.len(), 10_001);
    assert_eq!(coverage.bytes_decoded, 10_001);
}

// ------------------------------- round 3: Mach-O section header past the file

#[test]
fn r3_macho_text_size_past_end_of_file_is_malformed_not_empty() {
    let dir = TempDir::new().unwrap();
    for (name, size, off) in [
        ("size.macho", Some(0x1000_0000u64), None),
        ("off.macho", None, Some(0x7fff_ff00u32)),
    ] {
        let bytes = macho_build(CPU_X86_64, "__text", SIMPLE_FN, size, off, 0, 1);
        let path = write(&dir, name, &bytes);
        let err = disassemble_binary(&path, &symbols(vec![])).unwrap_err();
        assert!(
            err.to_string().contains("Malformed binary"),
            "{name}: {err}"
        );
    }
}

#[test]
fn r3_well_formed_macho_text_disassembles() {
    let dir = TempDir::new().unwrap();
    let path = write(
        &dir,
        "ok.macho",
        &macho_build(CPU_X86_64, "__text", SIMPLE_FN, None, None, 0, 1),
    );
    let table = analyze_symbols(&path).unwrap();
    let result = disassemble_binary(&path, &table).unwrap();
    assert_eq!(result.instructions.len(), 5);
    assert_eq!(result.functions.len(), 1);
    assert_eq!(result.functions[0].name, "_main");
}

// ------------------------------- round 3: universal binaries

fn fat_fixture(dir: &TempDir) -> PathBuf {
    // slice 1 is x86-64 with real code; slice 2 is the same bytes labelled ARM64
    let x86 = macho_build(CPU_X86_64, "__text", SIMPLE_FN, None, None, 0, 1);
    let arm = macho_build(
        CPU_ARM64,
        "__text",
        &[0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6],
        None,
        None,
        0,
        1,
    );
    write(dir, "fat.bin", &fat(&[(CPU_ARM64, arm), (CPU_X86_64, x86)]))
}

#[test]
fn r3_fat_macho_disassembles_the_selected_slice() {
    let dir = TempDir::new().unwrap();
    let path = fat_fixture(&dir);
    let table = analyze_symbols_with_arch(&path, Some("x86_64")).unwrap();
    let (result, _) = disassemble_binary_with_arch(&path, Some("x86_64"), &table).unwrap();
    assert_eq!(result.architecture, "x86_64");
    assert_eq!(result.instructions[0].mnemonic, "push");
    let table = analyze_symbols_with_arch(&path, Some("arm64")).unwrap();
    let (result, _) = disassemble_binary_with_arch(&path, Some("arm64"), &table).unwrap();
    assert_eq!(result.architecture, "ARM64");
    assert_eq!(result.instructions[0].mnemonic, "nop");
    assert_eq!(result.instructions[1].mnemonic, "ret");
}

#[test]
fn r3_fat_macho_control_flow_vulnerabilities_and_call_graph_use_the_slice() {
    let dir = TempDir::new().unwrap();
    let path = fat_fixture(&dir);
    let table = analyze_symbols_with_arch(&path, Some("x86_64")).unwrap();
    let cf = analyze_control_flow_with_arch(&path, Some("x86_64"), &table).unwrap();
    assert_eq!(cf.cfgs.len(), 1);
    assert_eq!(cf.cfgs[0].function_name, "_main");
    let vulns = analyze_vulnerabilities_with_arch(&path, Some("x86_64"), &table, &cf).unwrap();
    assert_eq!(vulns.risk_assessment.total_vulnerabilities, 0);
    let graph = call_graph_for_path_with_arch(&path, Some("x86_64")).unwrap();
    assert!(!graph.graph.nodes.is_empty());
    // the ARM64 slice is named, not decoded as x86
    let arm_table = analyze_symbols_with_arch(&path, Some("arm64")).unwrap();
    let err = analyze_control_flow_with_arch(&path, Some("arm64"), &arm_table).unwrap_err();
    assert!(err.to_string().contains("ARM64"), "{err}");
}

// ------------------------------- round 3: branch targets

#[test]
fn r3_arm64_branch_targets_are_decoded() {
    // cbz x0, #8 ; bl #8 ; b #4
    let code = [
        0x40, 0x00, 0x00, 0xb4, // cbz x0, +8
        0x02, 0x00, 0x00, 0x94, // bl +8
        0x01, 0x00, 0x00, 0x14, // b +4
    ];
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "branches.elf", &elf64(EM_AARCH64, &code, None));
    let result = disassemble_binary(&path, &symbols(vec![])).unwrap();
    use file_scanner::disassembly::FlowControl as Fc;
    assert!(
        matches!(
            result.instructions[0].flow_control,
            Some(Fc::Jump {
                target: Some(0x1008),
                conditional: true
            })
        ),
        "{:?}",
        result.instructions[0]
    );
    assert!(
        matches!(
            result.instructions[1].flow_control,
            Some(Fc::Call {
                target: Some(0x100c),
                is_indirect: false
            })
        ),
        "{:?}",
        result.instructions[1]
    );
    assert!(
        matches!(
            result.instructions[2].flow_control,
            Some(Fc::Jump {
                target: Some(0x100c),
                conditional: false
            })
        ),
        "{:?}",
        result.instructions[2]
    );
}

// ------------------------------- round 3: whole-file coverage and ranges

/// 1.2 M one-byte nops, then a small function at the end.
fn long_elf(dir: &TempDir) -> (PathBuf, u64) {
    let mut code = vec![0x90u8; MAX_DISASSEMBLY_INSTRUCTIONS + 200_000];
    let tail = code.len() as u64;
    code.extend_from_slice(SIMPLE_FN);
    (
        write(dir, "long.elf", &elf64(EM_X86_64, &code, None)),
        0x1000 + tail,
    )
}

#[test]
fn r3_truncated_coverage_says_which_addresses_were_decoded() {
    let dir = TempDir::new().unwrap();
    let (path, _) = long_elf(&dir);
    let (_, coverage) = disassemble_binary_with_coverage(&path, &symbols(vec![])).unwrap();
    assert!(coverage.truncated);
    assert_eq!(coverage.start_address, 0x1000);
    assert_eq!(
        coverage.end_address,
        0x1000 + MAX_DISASSEMBLY_INSTRUCTIONS as u64
    );
    assert_eq!(coverage.bytes_not_decoded, 200_000 + SIMPLE_FN.len() as u64);
    let expected = format!(
        "decoded 0x1000 to 0x{:x}; {} of {} bytes not decoded",
        coverage.end_address, coverage.bytes_not_decoded, coverage.section_size
    );
    assert!(coverage.notes.contains(&expected), "{:?}", coverage.notes);
}

#[test]
fn r3_code_past_the_whole_file_cap_can_be_listed_by_range() {
    let dir = TempDir::new().unwrap();
    let (path, tail) = long_elf(&dir);
    let (whole, _) = disassemble_binary_with_coverage(&path, &symbols(vec![])).unwrap();
    assert!(whole.instructions.last().unwrap().address < tail);
    let range = disassemble_range(&path, None, tail, 100).unwrap();
    assert_eq!(range.instructions.len(), 5);
    assert_eq!(range.instructions[0].address, tail);
    assert_eq!(range.instructions[0].mnemonic, "push");
    assert_eq!(range.instructions[4].mnemonic, "ret");
    assert!(!range.more);
    // a function by name
    let table = symbols(vec![function("tail_fn", tail, SIMPLE_FN.len() as u64)]);
    let listing = disassemble_function(&path, None, &table, "tail_fn", 100).unwrap();
    assert_eq!(listing.instructions.len(), 5);
    assert!(disassemble_function(&path, None, &table, "nope", 100).is_err());
}

#[test]
fn r3_range_limits_are_reported() {
    let dir = TempDir::new().unwrap();
    let (path, _) = long_elf(&dir);
    let range = disassemble_range(&path, None, 0x1000, 10).unwrap();
    assert_eq!(range.instructions.len(), 10);
    assert!(range.more);
    assert!(range
        .notes
        .iter()
        .any(|n| n.contains("stopped after 10 instructions")));
    // outside the section
    let err = disassemble_range(&path, None, 0x10, 10).unwrap_err();
    assert!(
        err.to_string().contains("outside the code section"),
        "{err}"
    );
}

#[test]
fn r3_go_main_main_is_reachable_by_name() {
    let path = repo_binary("go_test_binary");
    let table = analyze_symbols(&path).unwrap();
    let main = table
        .functions
        .iter()
        .find(|f| f.name == "main.main")
        .expect("main.main symbol");
    let (whole, coverage) = disassemble_binary_with_coverage(&path, &table).unwrap();
    // the grouping cap (5,000 functions) leaves main.main out of the listing
    assert!(whole.functions.iter().all(|f| f.name != "main.main"));
    assert!(coverage
        .notes
        .iter()
        .any(|n| n.contains("later functions are not listed")));
    let listing = disassemble_function(&path, None, &table, "main.main", 50).unwrap();
    assert_eq!(listing.instructions[0].address, main.address);
    assert!(listing.instructions.len() > 5);
}

#[test]
fn r3_real_binary_call_targets_are_filled() {
    let path = repo_binary("c_advanced_binary");
    let table = analyze_symbols(&path).unwrap();
    let result = disassemble_binary(&path, &table).unwrap();
    let direct = result
        .instructions
        .iter()
        .filter(|i| {
            matches!(
                i.flow_control,
                Some(file_scanner::disassembly::FlowControl::Call {
                    target: Some(_),
                    ..
                })
            )
        })
        .count();
    assert!(direct > 10, "{direct} direct calls with a target");
}

// ------------------------------- round 3: control-flow instruction budget

#[test]
fn r3_control_flow_instruction_budget_is_enforced_and_noted() {
    use file_scanner::control_flow::MAX_CFG_TOTAL_INSTRUCTIONS;
    // 24 functions of 60,000 one-byte instructions: 1.44 M instructions in
    // 1.44 MB, well inside the byte budget
    let per = 60_000u64;
    let count = 24u64;
    let code = vec![0x90u8; (per * count) as usize];
    let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();
    let candidates = (0..count)
        .map(|i| function(&format!("f{i}"), 0x1000 + i * per, per))
        .collect();
    let analysis = analyzer.analyze_code(&code, 0x1000, candidates).unwrap();
    let kept = analysis.analysis_stats.instructions_analyzed;
    assert!(kept <= MAX_CFG_TOTAL_INSTRUCTIONS + per as usize, "{kept}");
    assert!(analysis.cfgs.len() < count as usize);
    assert!(
        analysis
            .analysis_stats
            .errors
            .iter()
            .any(|e| e.contains("instruction analysis budget")),
        "{:?}",
        analysis.analysis_stats.errors
    );
}

// ------------------------------- round 3: vulnerability rules

#[test]
fn r3_weak_rules_are_counts_not_findings() {
    let path = repo_binary("go_test_binary");
    let table = analyze_symbols(&path).unwrap();
    let cf = analyze_control_flow(&path, &table).unwrap();
    let result = analyze_vulnerabilities(&path, &table, &cf).unwrap();
    for finding in &result.vulnerabilities {
        assert!(
            !["INT001", "BOF002", "DIV001", "REC001", "UAF001", "DBF001"]
                .contains(&finding.rule_id.as_str()),
            "{} is a count, not a finding",
            finding.rule_id
        );
    }
    assert!(
        result.vulnerabilities.len() < 100,
        "{}",
        result.vulnerabilities.len()
    );
    assert_eq!(
        result.risk_assessment.total_vulnerabilities as usize,
        result.vulnerabilities.len()
    );
    let int001 = result
        .pattern_counts
        .iter()
        .find(|c| c.rule_id == "INT001")
        .expect("INT001 counted");
    assert!(int001.matches >= int001.functions && int001.functions > 0);
}

#[test]
fn r3_risk_summary_agrees_with_the_findings_shown() {
    use file_scanner::vulnerability_detection::{RiskLevel, Severity};
    for name in [
        "go_test_binary",
        "c_advanced_binary",
        "packed_rust_binary",
        "crypto_miner_binary",
    ] {
        let path = repo_binary(name);
        let table = analyze_symbols(&path).unwrap();
        let Ok(cf) = analyze_control_flow(&path, &table) else {
            continue;
        };
        let r = analyze_vulnerabilities(&path, &table, &cf).unwrap();
        let worst_medium_or_more = r.vulnerabilities.iter().any(|v| {
            matches!(
                v.severity,
                Severity::Critical | Severity::High | Severity::Medium
            )
        });
        if matches!(r.risk_assessment.risk_level, RiskLevel::Minimal) {
            assert!(
                !worst_medium_or_more,
                "{name}: Minimal with a Medium+ finding"
            );
            assert!(
                !r.risk_assessment
                    .recommendations
                    .iter()
                    .any(|m| m.contains("Plan remediation") || m.contains("Immediate")),
                "{name}: {:?}",
                r.risk_assessment.recommendations
            );
        }
        if worst_medium_or_more {
            assert!(
                !matches!(r.risk_assessment.risk_level, RiskLevel::Minimal),
                "{name}"
            );
        }
    }
}

#[test]
fn r3_a_tail_call_to_an_unsafe_import_is_a_finding() {
    // jmp rel32 to the import stub at 0x1040: a tail call to strcpy
    let mut code = vec![0xe9];
    code.extend_from_slice(&(0x40i32 - 5).to_le_bytes());
    let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();
    let analysis = analyzer
        .analyze_code(&code, 0x1000, vec![function("copy_it", 0x1000, 5)])
        .unwrap();
    let mut imports = HashMap::new();
    imports.insert(0x1040u64, "strcpy".to_string());
    let result = VulnerabilityDetector::new()
        .analyze_with_imports(&symbols(vec![]), &analysis, &imports)
        .unwrap();
    let ids: Vec<&str> = result
        .vulnerabilities
        .iter()
        .map(|v| v.rule_id.as_str())
        .collect();
    assert_eq!(ids, vec!["BOF001"], "{ids:?}");
}

#[test]
fn r3_a_jump_inside_the_function_is_not_a_call() {
    // jmp +0 (next instruction), ret
    let code = [0xeb, 0x00, 0xc3];
    let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();
    let analysis = analyzer
        .analyze_code(&code, 0x1000, vec![function("f", 0x1000, 3)])
        .unwrap();
    let mut imports = HashMap::new();
    imports.insert(0x1002u64, "strcpy".to_string());
    let result = VulnerabilityDetector::new()
        .analyze_with_imports(&symbols(vec![]), &analysis, &imports)
        .unwrap();
    // 0x1002 is inside this function: a jump there is not a call to the import
    // named at that address, so nothing is reported.
    let ids: Vec<&str> = result
        .vulnerabilities
        .iter()
        .map(|v| v.rule_id.as_str())
        .collect();
    assert!(ids.is_empty(), "{ids:?}");
}

// ------------------------------- round 3: taint report lists

#[test]
fn r3_taint_vulnerability_flow_id_lists_are_cut() {
    let mut text = String::new();
    for i in 0..1_500 {
        text.push_str(&format!("v{i} = request.query['p{i}']\nos.system(v{i})\n"));
    }
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "flows.py", text.as_bytes());
    let report = taint_report_for_path(&path).unwrap();
    assert!(!report.analysis.vulnerabilities.is_empty());
    for v in &report.analysis.vulnerabilities {
        assert!(
            v.affected_flows.len() <= MAX_TAINT_ITEMS,
            "{}",
            v.affected_flows.len()
        );
    }
    assert!(
        report.notes.iter().any(|n| n.contains("affected flow ids")),
        "{:?}",
        report.notes
    );
}

#[test]
fn r3_partial_control_flow_is_not_reported_as_a_clean_scan() {
    let path = repo_binary("go_test_binary");
    let table = analyze_symbols(&path).unwrap();
    let cf = analyze_control_flow(&path, &table).unwrap();
    assert!(cf.overall_metrics.analyzed_functions < cf.overall_metrics.total_functions);
    let result = analyze_vulnerabilities(&path, &table, &cf).unwrap();
    let joined = result.risk_assessment.recommendations.join(" | ");
    assert!(
        joined.contains(&format!(
            "Only {} of {} functions were analyzed",
            cf.overall_metrics.analyzed_functions, cf.overall_metrics.total_functions
        )),
        "{joined}"
    );
    assert!(!joined.contains("No vulnerabilities detected"), "{joined}");
}

// ------------------------------- round 3b: bind-opcode repeat counts

/// A Mach-O (from `macho_build`) with an `LC_DYLD_INFO_ONLY` command whose bind
/// stream binds `_x` `count` times. Section offsets are shifted by the new
/// command; only the load commands and the bind stream matter here.
fn macho_with_bind_count(count: u64) -> Vec<u8> {
    macho_with_bind_count_sized(count, None)
}

/// As `macho_with_bind_count`, with the declared `bind_size` overridden (a size
/// that ends inside the repeat count, as a hostile file can do).
fn macho_with_bind_count_sized(count: u64, declared: Option<u32>) -> Vec<u8> {
    let mut uleb = Vec::new();
    let mut v = count;
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            uleb.push(b);
            break;
        }
        uleb.push(b | 0x80);
    }
    let mut stream = vec![0x11, 0x40];
    stream.extend(b"_x\0");
    stream.extend([0x51, 0x72, 0x00, 0xC0]);
    stream.extend(&uleb);
    stream.extend([0x00, 0x00]);
    macho_with_stream(stream, declared)
}

/// The Mach-O of `macho_with_bind_count`, with `stream` as its bind stream.
fn macho_with_stream(stream: Vec<u8>, declared: Option<u32>) -> Vec<u8> {
    let base = macho_build(CPU_X86_64, "__text", SIMPLE_FN, None, None, 0, 1);
    let hdr_end = 32 + (u32::from_le_bytes(base[20..24].try_into().unwrap()) as usize);
    let bind_off = (base.len() + 48) as u32;
    let mut cmd = Vec::new();
    for v in [
        0x8000_0022u32,
        48,
        0,
        0,
        bind_off,
        declared.unwrap_or(stream.len() as u32),
        0,
        0,
        0,
        0,
        0,
        0,
    ] {
        cmd.extend(v.to_le_bytes());
    }
    let mut f = base[..hdr_end].to_vec();
    f.extend(cmd);
    f.extend(&base[hdr_end..]);
    let ncmds = u32::from_le_bytes(f[16..20].try_into().unwrap()) + 1;
    let size = u32::from_le_bytes(f[20..24].try_into().unwrap()) + 48;
    f[16..20].copy_from_slice(&ncmds.to_le_bytes());
    f[20..24].copy_from_slice(&size.to_le_bytes());
    f.extend(stream);
    f
}

#[test]
fn r3b_a_huge_bind_repeat_count_does_not_expand_into_imports() {
    for count in [20_000_000u64, 0xFFFF_FFFF] {
        let bytes = macho_with_bind_count(count);
        let macho = match goblin::mach::Mach::parse(&bytes) {
            Ok(goblin::mach::Mach::Binary(m)) => m,
            other => panic!("fixture does not parse: {other:?}"),
        };
        assert!(!file_scanner::control_flow::macho_bind_count_within_cap(
            &macho, &bytes
        ));
        // Bounded work: the interpreter stops at its entry cap, says so, and
        // the map stays small.
        let (map, note) = resolve_import_targets_noted(&bytes, None);
        assert!(map.len() < 1000);
        assert!(note.is_some(), "the cut is not reported");
    }
    // a small repeat count is expanded as before
    let bytes = macho_with_bind_count(3);
    let Ok(goblin::mach::Mach::Binary(m)) = goblin::mach::Mach::parse(&bytes) else {
        panic!("fixture does not parse");
    };
    assert!(file_scanner::control_flow::macho_bind_count_within_cap(
        &m, &bytes
    ));
}

#[test]
fn r3c_a_bind_size_that_ends_inside_the_repeat_count_is_still_bounded() {
    // stream: 11 40 "_x\0" 51 72 00 C0 <count>: the count starts at index 9
    for count in [20_000_000u64, 0xFFFF_FFFF] {
        let bytes = macho_with_bind_count_sized(count, Some(10));
        let (map, note) = resolve_import_targets_noted(&bytes, None);
        // (the count is cut off by the stream's end, so the walk may end without a cap)
        let _ = note;
        assert!(map.len() < 1000, "{}", map.len());
    }
}

#[test]
fn r3c_a_bad_segment_index_or_address_does_not_panic() {
    for tail in [
        vec![0x7F, 0x00, 0x90],
        vec![
            0x72, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x90, 0x90,
        ],
    ] {
        let mut bytes = macho_with_bind_count(1);
        let start = bytes.len() - 14;
        let mut stream = vec![0x11, 0x40, b'_', b'x', 0];
        stream.extend(&tail);
        stream.resize(14, 0);
        bytes[start..].copy_from_slice(&stream);
        let _ = resolve_import_targets(&bytes);
    }
}

#[test]
fn r3c_many_dyld_info_commands_sharing_one_stream_stay_linear() {
    let base = macho_with_bind_count(1);
    let hdr_end = 32 + (u32::from_le_bytes(base[20..24].try_into().unwrap()) as usize);
    let stream_len: u32 = 1_000_000;
    let extra = 3000usize;
    let added = (extra * 48) as u32;
    let stream_off = base.len() as u32 + added;
    let mut cmds = Vec::new();
    for _ in 0..extra {
        for v in [
            0x8000_0022u32,
            48,
            0,
            0,
            stream_off,
            stream_len,
            stream_off,
            stream_len,
            stream_off,
            stream_len,
            0,
            0,
        ] {
            cmds.extend(v.to_le_bytes());
        }
    }
    let mut f = base[..hdr_end].to_vec();
    f.extend(cmds);
    f.extend(&base[hdr_end..]);
    let ncmds = u32::from_le_bytes(f[16..20].try_into().unwrap()) + extra as u32;
    let size = u32::from_le_bytes(f[20..24].try_into().unwrap()) + added;
    f[16..20].copy_from_slice(&ncmds.to_le_bytes());
    f[20..24].copy_from_slice(&size.to_le_bytes());
    f.resize(f.len() + stream_len as usize, 0);
    // Only the last command is read and the stream holds no binds: nothing is
    // named and nothing is cut. A bound generous by a factor of twenty guards
    // against reading the stream once per command (3000 x 1 MB).
    let started = std::time::Instant::now();
    let (map, note) = resolve_import_targets_noted(&f, None);
    assert!(map.is_empty() && note.is_none());
    assert!(started.elapsed().as_secs() < 40, "{:?}", started.elapsed());
}

fn uleb_bytes(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

#[test]
fn r4_one_long_symbol_name_bound_many_times_is_not_copied_per_bind() {
    // 10,000-byte name x 199,999 binds would be 2 GB of names if copied per bind.
    for name_len in [10_000usize, 100_000] {
        let mut stream = vec![0x11, 0x40];
        stream.extend(std::iter::repeat_n(b'a', name_len));
        stream.extend([0, 0x51, 0x70, 0x00, 0xC0]);
        stream.extend(uleb_bytes(199_999));
        stream.extend([0x00, 0x00]);
        let bytes = macho_with_stream(stream, None);
        let Ok(goblin::mach::Mach::Binary(m)) = goblin::mach::Mach::parse(&bytes) else {
            panic!("fixture does not parse");
        };
        assert!(!file_scanner::control_flow::macho_bind_count_within_cap(
            &m, &bytes
        ));
        let (map, note) = resolve_import_targets_noted(&bytes, None);
        assert!(note.is_some(), "the cut is not reported");
        let total: usize = map.values().map(String::len).sum();
        assert!(total < 1_000_000, "{total} bytes of names");
    }
    // an ordinary long-named bind is still resolved
    let mut stream = vec![0x11, 0x40];
    stream.extend(std::iter::repeat_n(b'a', 300));
    stream.extend([0, 0x51, 0x70, 0x00, 0xC0]);
    stream.extend(uleb_bytes(50));
    stream.extend([0x00, 0x00]);
    let bytes = macho_with_stream(stream, None);
    let map = resolve_import_targets(&bytes);
    assert!(map.values().any(|n| n.len() == 300 && n.starts_with("aaa")));
}

#[test]
fn r4_binds_with_an_out_of_range_segment_still_count_against_the_cap() {
    // 20,000 x DO_BIND_ULEB_TIMES 200000 on a segment that does not exist
    let mut stream = vec![0x11, 0x40, b'_', b'x', 0, 0x51, 0x7F, 0x00];
    for _ in 0..20_000 {
        stream.push(0xC0);
        stream.extend(uleb_bytes(200_000));
        stream.push(0x00);
    }
    let bytes = macho_with_stream(stream, None);
    let Ok(goblin::mach::Mach::Binary(m)) = goblin::mach::Mach::parse(&bytes) else {
        panic!("fixture does not parse");
    };
    // Bounded work: the attempts are counted against the cap, which ends the walk.
    assert!(!file_scanner::control_flow::macho_bind_count_within_cap(
        &m, &bytes
    ));
    let (map, note) = resolve_import_targets_noted(&bytes, None);
    assert!(map.is_empty(), "{}", map.len());
    assert!(note.is_some(), "the cut is not reported");
}

#[test]
fn r4_loop_exit_and_unreachable_lists_share_one_budget_and_say_so() {
    use file_scanner::control_flow::{MAX_CFG_LISTED_ITEMS, MIN_CFG_LISTED_ITEMS};
    // 8 functions of 64 KiB: self-jumping blocks (a loop per 2 bytes) and ret-filled ones
    // (an exit block per byte, all but the first unreachable).
    for (fill, label) in [(vec![0x75u8, 0xfe], "selfloop"), (vec![0xc3u8], "ret")] {
        let mut code = Vec::new();
        let mut functions = Vec::new();
        for i in 0..8u64 {
            functions.push(function(&format!("f{i}"), 0x1000 + i * 0x10000, 0x10000));
            code.extend(fill.iter().cycle().take(0x10000));
        }
        let analyzer = ControlFlowAnalyzer::new_x86_64().unwrap();
        let cf = analyzer.analyze_code(&code, 0x1000, functions).unwrap();
        let listed: usize = cf
            .cfgs
            .iter()
            .map(|c| c.loops.len() + c.exit_blocks.len() + c.complexity.unreachable_blocks.len())
            .sum();
        assert!(
            listed <= MAX_CFG_LISTED_ITEMS + 3 * MIN_CFG_LISTED_ITEMS * cf.cfgs.len(),
            "{label}: {listed} entries listed"
        );
        let note = cf
            .analysis_stats
            .errors
            .iter()
            .find(|e| e.starts_with("Limit: the lists of loops"))
            .unwrap_or_else(|| panic!("{label}: no note in {:?}", cf.analysis_stats.errors));
        assert!(note.contains(" of "), "{note}");
        // counts stay true
        if label == "selfloop" {
            for cfg in &cf.cfgs {
                assert_eq!(cfg.complexity.loop_count, cfg.complexity.basic_block_count);
            }
        }
    }
    // a small function keeps every entry and adds no note
    let code = [0x75u8, 0xfe, 0xc3];
    let cf = ControlFlowAnalyzer::new_x86_64()
        .unwrap()
        .analyze_code(&code, 0x1000, vec![function("f", 0x1000, 3)])
        .unwrap();
    assert_eq!(cf.cfgs[0].loops.len(), 1);
    assert!(!cf
        .analysis_stats
        .errors
        .iter()
        .any(|e| e.contains("lists of loops")));
}

// ------------------------------- round 4: one long name, many references

/// Offset of the first load command with command number `cmd` in a 64-bit Mach-O.
fn macho_command_offset(bytes: &[u8], cmd: u32) -> usize {
    let ncmds = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let mut at = 32usize;
    for _ in 0..ncmds {
        let c = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let size = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
        if c == cmd {
            return at;
        }
        at += size;
    }
    panic!("no load command {cmd:#x}");
}

fn name_bytes_total(map: &std::collections::HashMap<u64, String>) -> usize {
    map.values().map(String::len).sum()
}

#[test]
fn r4_one_long_bind_name_read_by_many_stubs_stays_within_the_name_budget() {
    const NAME: usize = 100_000;
    const STUBS: usize = 20_000;
    // `__stubs` section at file offset 288 + 48 (the bind command is inserted
    // before it), address base + 288; every stub is `jmp [rip+rel]` to the slot
    // at segment 0 offset 0 (the base address).
    let base = 0x1_0000_0000u64;
    let stub_addr = base + 288;
    let mut stubs = Vec::new();
    for i in 0..STUBS {
        let rel = base.wrapping_sub(stub_addr + 6 * i as u64 + 6) as u32;
        stubs.extend([0xff, 0x25]);
        stubs.extend(rel.to_le_bytes());
    }
    let built = macho_build(CPU_X86_64, "__stubs", &stubs, None, Some(288 + 48), 0, 1);
    let mut stream = vec![0x11, 0x40, b'_'];
    stream.extend(std::iter::repeat_n(b'A', NAME - 1));
    stream.extend([0, 0x51, 0x70, 0x00, 0x90, 0x00]);
    // macho_with_stream rebuilds its own base: insert the command by hand here.
    let hdr_end = 32 + (u32::from_le_bytes(built[20..24].try_into().unwrap()) as usize);
    let bind_off = (built.len() + 48) as u32;
    let mut cmd = Vec::new();
    for v in [
        0x8000_0022u32,
        48,
        0,
        0,
        bind_off,
        stream.len() as u32,
        0,
        0,
        0,
        0,
        0,
        0,
    ] {
        cmd.extend(v.to_le_bytes());
    }
    let mut f = built[..hdr_end].to_vec();
    f.extend(cmd);
    f.extend(&built[hdr_end..]);
    let ncmds = u32::from_le_bytes(f[16..20].try_into().unwrap()) + 1;
    let size = u32::from_le_bytes(f[20..24].try_into().unwrap()) + 48;
    f[16..20].copy_from_slice(&ncmds.to_le_bytes());
    f[20..24].copy_from_slice(&size.to_le_bytes());
    f.extend(stream);

    let map = resolve_import_targets(&f);
    let total = name_bytes_total(&map);
    assert!(total <= 16 * 1024 * 1024, "{total} name bytes in the map");
    assert!(map.contains_key(&base), "the slot itself is still named");
    assert!(map.len() < STUBS, "{} entries", map.len());
}

#[test]
fn r4_one_long_symbol_named_by_many_indirect_entries_stays_within_the_name_budget() {
    const NAME: usize = 100_000;
    const ENTRIES: usize = 20_000;
    let mut f = macho_build(CPU_X86_64, "__la_symbol_ptr", SIMPLE_FN, None, None, 0, 1);
    let sym = macho_command_offset(&f, 0x2);
    let dys = macho_command_offset(&f, 0xb);
    let symoff = u32::from_le_bytes(f[sym + 8..sym + 12].try_into().unwrap()) as usize;
    // the first section's size claims ENTRIES pointers, reserved1 = 0
    let sect = 32 + 72;
    f[sect + 40..sect + 48].copy_from_slice(&(8 * ENTRIES as u64).to_le_bytes());
    // new string table: one long name, referred to by symbol 0
    let str_at = f.len();
    f.push(0);
    f.push(b'_');
    f.extend(std::iter::repeat_n(b'A', NAME - 1));
    f.push(0);
    f[sym + 16..sym + 20].copy_from_slice(&(str_at as u32).to_le_bytes());
    f[sym + 20..sym + 24].copy_from_slice(&((NAME + 2) as u32).to_le_bytes());
    f[symoff..symoff + 4].copy_from_slice(&1u32.to_le_bytes());
    // indirect table: ENTRIES entries, all symbol 0
    let ind_at = f.len();
    f.extend(std::iter::repeat_n(0u8, 4 * ENTRIES));
    f[dys + 56..dys + 60].copy_from_slice(&(ind_at as u32).to_le_bytes());
    f[dys + 60..dys + 64].copy_from_slice(&(ENTRIES as u32).to_le_bytes());

    let map = resolve_import_targets(&f);
    assert!(!map.is_empty(), "the fallback names its first entries");
    let total = name_bytes_total(&map);
    assert!(total <= 16 * 1024 * 1024, "{total} name bytes in the map");
    assert!(map.len() < ENTRIES, "{} entries", map.len());
}

// ------------------------------- round 5

#[test]
fn r5_never_bound_symbol_names_are_dropped_from_the_bind_table() {
    // 3,000 SET_SYMBOL names of 1,000 bytes that no bind uses, then one bound name.
    let mut stream = vec![0x11];
    for _ in 0..3_000 {
        stream.push(0x40);
        stream.extend(std::iter::repeat_n(b'z', 1_000));
        stream.push(0);
    }
    stream.extend([0x40, b'_', b'y', 0, 0x51, 0x70, 0x08, 0x90, 0x00]);
    let bytes = macho_with_stream(stream, None);
    let Ok(goblin::mach::Mach::Binary(m)) = goblin::mach::Mach::parse(&bytes) else {
        panic!("fixture does not parse");
    };
    let kept = file_scanner::control_flow::macho_bind_name_table_len(&m, &bytes).unwrap();
    assert!(kept <= 2, "{kept} names kept");
    // the bound name is still the one resolved
    let map = resolve_import_targets(&bytes);
    assert!(map.values().any(|n| n == "_y"), "{map:?}");
}

#[test]
fn r5_a_cut_import_map_is_reported_and_reaches_the_vulnerability_notes() {
    // One 1 MiB name bound 20 times: the 16 MiB name budget is not enough once
    // the name is also charged for the slot table and the map.
    let mut stream = vec![0x11, 0x40];
    stream.extend(std::iter::repeat_n(b'a', 1 << 20));
    stream.extend([0, 0x51, 0x72, 0x00, 0xC0]);
    stream.extend(uleb_bytes(20));
    stream.extend([0x00, 0x00]);
    let bytes = macho_with_stream(stream, None);
    let (_, note) = resolve_import_targets_noted(&bytes, None);
    let note = note.expect("the cut is not reported");
    assert!(note.contains("left unnamed"), "{note}");
    // an ordinary file has no such note
    let small = macho_with_stream(
        vec![0x11, 0x40, b'_', b'x', 0, 0x51, 0x72, 0x00, 0x90, 0x00],
        None,
    );
    assert!(resolve_import_targets_noted(&small, None).1.is_none());
    // and the detector puts a given note first in its recommendations
    let analysis = ControlFlowAnalyzer::new_x86_64()
        .unwrap()
        .analyze_code(&[0xc3], 0x1000, vec![function("f", 0x1000, 1)])
        .unwrap();
    let result = VulnerabilityDetector::new()
        .analyze_with_imports_and_notes(
            &symbols(vec![]),
            &analysis,
            &HashMap::new(),
            std::slice::from_ref(&note),
        )
        .unwrap();
    assert_eq!(result.risk_assessment.recommendations[0], note);
}

#[test]
fn r5_a_named_architecture_that_is_absent_is_an_error_naming_the_slices() {
    let slice = macho_build(CPU_X86_64, "__text", SIMPLE_FN, None, None, 0, 1);
    let mut fat = Vec::new();
    fat.extend(0xcafe_babeu32.to_be_bytes());
    fat.extend(1u32.to_be_bytes());
    let offset = 4096u32;
    for v in [CPU_X86_64, 3, offset, slice.len() as u32, 12] {
        fat.extend(v.to_be_bytes());
    }
    fat.resize(offset as usize, 0);
    fat.extend(&slice);
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "one_slice_fat", &fat);
    let table = symbols(vec![]);
    let err = analyze_control_flow_with_arch(&path, Some("arm64"), &table)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("no 'arm64' slice") && err.contains("x86_64"),
        "{err}"
    );
    let err = file_scanner::disassembly::disassemble_binary_with_arch(&path, Some("arm64"), &table)
        .unwrap_err()
        .to_string();
    assert!(err.contains("slices present"), "{err}");
    // the present slice is still accepted, by name and by default
    // (the fixture has no function symbols, so these end in another error)
    for arch in [Some("x86_64"), Some("X86-64"), None] {
        let message = analyze_control_flow_with_arch(&path, arch, &table)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(!message.contains("slice"), "{arch:?}: {message}");
    }
}

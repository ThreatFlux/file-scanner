//! Tests for the code-level analyzers: bounds checks on malformed headers,
//! architecture selection, disassembly coverage, call-name resolution in the
//! vulnerability detector, saturating metrics, bounded call graphs and taint
//! reports. Fixtures are built byte by byte so no binary is committed.

use file_scanner::call_graph::{
    call_graph_for_path, generate_call_graph, summarize_call_graph, CallGraph, CallGraphEdge,
    CallGraphNode, CallGraphStatistics, CallType, NodeType, MAX_REPORT_EDGES, MAX_REPORT_NODES,
};
use file_scanner::control_flow::{
    analyze_control_flow, resolve_import_targets, BasicBlock, BlockType, ControlFlowAnalyzer,
    FlowControl, Instruction as CfInstruction, InstructionType as CfInstructionType,
    MAX_CFG_FUNCTIONS,
};
use file_scanner::disassembly::{
    disassemble_binary, disassemble_binary_with_coverage, MAX_DISASSEMBLY_INSTRUCTIONS,
};
use file_scanner::function_analysis::{
    analyze_symbols, FunctionInfo, FunctionType, SymbolCounts, SymbolTable,
};
use file_scanner::taint_tracking::{taint_report_for_path, MAX_TAINT_INPUT_BYTES, MAX_TAINT_ITEMS};
use file_scanner::vulnerability_detection::{
    analyze_vulnerabilities, VulnerabilityDetector, HEURISTIC_NOTICE,
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

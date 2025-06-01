#\!/bin/bash

# Fix default for unit struct
sed -i 's/Self::default()/Self/g' src/code_metrics.rs

# Fix needless borrows
sed -i 's/classify_instruction(&insn)/classify_instruction(insn)/g' src/control_flow.rs
sed -i 's/analyze_flow_control(&insn)/analyze_flow_control(insn)/g' src/control_flow.rs
sed -i 's/detect_flow_control(&insn)/detect_flow_control(insn)/g' src/disassembly.rs
sed -i 's/classify_instruction(&insn)/classify_instruction(insn)/g' src/disassembly.rs

# Fix strip_suffix
sed -i 's/if import_name.ends_with(".dll") {/if let Some(base_name) = import_name.strip_suffix(".dll") {/g' src/dependency_analysis.rs
sed -i 's/import_name\[..import_name.len() - 4\]/base_name/g' src/dependency_analysis.rs

# Fix map_or
sed -i "s/insn.op_str().map_or(false,  < /dev/null | ops| ops.contains('\['))/insn.op_str().is_some_and(|ops| ops.contains('['))/g" src/disassembly.rs

# Fix manual range contains
sed -i 's/entropy > 6.5 || entropy < 4.0/\!(4.0..=6.5).contains(\&entropy)/g' src/entropy_analysis.rs

# Fix len_zero
sed -i 's/section.name.len() == 0/section.name.is_empty()/g' src/entropy_analysis.rs

echo "Additional clippy fixes applied"

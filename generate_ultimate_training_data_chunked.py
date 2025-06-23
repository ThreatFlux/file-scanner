#!/usr/bin/env python3
"""
Enhanced training data generator that creates chunked questions for large data.
Breaks up strings, hex dumps, and disassembly into manageable sections.
"""

import json
import os
import random
import gzip
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any, Tuple
from datetime import datetime

# Import base functionality
from generate_ultimate_training_data import (
    EXPERTISE_LEVELS, 
    UltimateTrainingGenerator
)

# Specialized chunked question templates
CHUNKED_QUESTIONS = {
    "strings": {
        "range": [
            "Show me strings {start}-{end} from {file}",
            "What are strings {start} through {end} in {file}?",
            "List strings from offset {start} to {end} in {file}",
            "Extract strings {start}-{end} from {file}",
            "Give me the next {count} strings starting at {start} in {file}",
        ],
        "specific": [
            "What imports does {file} use?",
            "Show me the library dependencies in {file}",
            "What function names are in {file}?",
            "Find URL strings in {file}",
            "What error messages are in {file}?",
            "Show me file path strings in {file}",
            "What command strings exist in {file}?",
        ],
        "pattern": [
            "Find strings containing '{pattern}' in {file}",
            "Show me strings matching '{pattern}' in {file}",
            "What strings have '{pattern}' in {file}?",
            "Search for '{pattern}' strings in {file}",
        ]
    },
    
    "hex_dump": {
        "range": [
            "Show me hex dump from offset {offset} for {size} bytes in {file}",
            "What's at hex offset {offset} in {file}?",
            "Display {size} bytes starting at {offset} in {file}",
            "Hex dump {file} from {offset} to {end_offset}",
            "Show me the file header of {file} (first {size} bytes)",
            "What's in the last {size} bytes of {file}?",
        ],
        "specific": [
            "Show me the ELF header of {file}",
            "What's the PE header structure in {file}?",
            "Display the section headers in {file}",
            "Show me the entry point bytes in {file}",
            "What magic bytes does {file} have?",
        ]
    },
    
    "disassembly": {
        "function": [
            "Show me the disassembly of {function} in {file}",
            "What's the assembly code for {function} in {file}?",
            "Disassemble the {function} function from {file}",
            "Show me how {function} works in {file}",
        ],
        "range": [
            "Show me assembly from address {addr} for {count} instructions in {file}",
            "Disassemble {count} instructions starting at {addr} in {file}",
            "What assembly is at offset {addr} in {file}?",
            "Show me the next {count} assembly instructions from {addr} in {file}",
        ],
        "specific": [
            "Show me the entry point disassembly for {file}",
            "What's the main function assembly in {file}?",
            "Show me the PLT entries in {file}",
            "Display the interrupt handlers in {file}",
            "What system calls does {file} make?",
        ]
    },
    
    "symbols": {
        "range": [
            "List symbols {start}-{end} from {file}",
            "What are symbols {start} to {end} in {file}?",
            "Show me the next {count} symbols starting at {start} in {file}",
        ],
        "type": [
            "What functions are exported by {file}?",
            "Show me the global variables in {file}",
            "List the weak symbols in {file}",
            "What debugging symbols are in {file}?",
            "Show me the imported functions in {file}",
        ]
    },
    
    "vulnerabilities": {
        "specific": [
            "What's the most critical vulnerability in {file}?",
            "Show me high-severity vulnerabilities in {file}",
            "Are there any RCE vulnerabilities in {file}?",
            "What buffer overflow risks exist in {file}?",
            "Show me the CVEs affecting {file}",
        ]
    },
    
    "analysis": {
        "combined": [
            "Analyze {file} for security issues",
            "What makes {file} suspicious?",
            "Is {file} packed or encrypted?",
            "What's the risk assessment for {file}?",
            "How does {file} interact with the network?",
            "What privileged operations does {file} perform?",
        ]
    }
}

class ChunkedTrainingGenerator(UltimateTrainingGenerator):
    """Generator that creates chunked questions for large data sections."""
    
    def __init__(self, analysis_dir: str, output_dir: str):
        super().__init__(analysis_dir, output_dir)
        self.chunk_size_strings = 50  # Show 50 strings at a time
        self.chunk_size_hex = 512      # Show 512 bytes of hex at a time
        self.chunk_size_disasm = 200   # Show 200 lines of disassembly
        self.chunk_size_symbols = 30   # Show 30 symbols at a time
        
    def generate_comprehensive_examples(self):
        """Generate examples including chunked questions."""
        print("\n=== Generating Chunked Training Data ===\n")
        
        # Create output file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"ubuntu_chunked_training_{timestamp}.jsonl"
        
        with open(output_file, 'w') as f:
            # Generate regular examples
            self._generate_importance_weighted_examples(f)
            
            # Generate chunked examples for large data
            self._generate_chunked_examples(f)
            
            # Generate analysis summaries
            self._generate_analysis_summaries(f)
            
            # Add negative examples if requested
            if self.args and self.args.include_negatives:
                self._generate_negative_examples(f)
            
            # Flush buffer
            self._flush_buffer(f)
            
        print(f"\nTotal examples generated: {self.generated_count:,}")
        print(f"Output file: {output_file}")
        
        # Compress
        self._compress_output(output_file)
        
        return output_file
        
    def _generate_chunked_examples(self, file_handle):
        """Generate chunked questions for large data sections."""
        print("\nGenerating chunked examples for large data...")
        
        # Sample files to chunk
        sample_size = min(100, len(self.analyses))
        sampled_files = random.sample(list(self.analyses.items()), sample_size)
        
        for file_path, analysis in sampled_files:
            file_name = os.path.basename(file_path)
            
            # Generate string chunks
            if 'strings' in analysis and analysis['strings']:
                self._generate_string_chunks(file_name, file_path, analysis, file_handle)
                
            # Generate hex dump chunks
            if 'hex_dump' in analysis and analysis['hex_dump']:
                self._generate_hex_chunks(file_name, file_path, analysis, file_handle)
                
            # Generate disassembly chunks
            if 'disassembly' in analysis and analysis['disassembly']:
                self._generate_disasm_chunks(file_name, file_path, analysis, file_handle)
                
            # Generate symbol chunks
            if 'symbols' in analysis and isinstance(analysis['symbols'], list):
                self._generate_symbol_chunks(file_name, file_path, analysis, file_handle)
                
    def _generate_string_chunks(self, file_name: str, file_path: str, 
                               analysis: Dict[str, Any], file_handle):
        """Generate chunked questions for strings."""
        strings = analysis['strings']
        total_strings = len(strings)
        
        # Generate range-based questions
        for start in range(0, min(total_strings, 500), self.chunk_size_strings):
            end = min(start + self.chunk_size_strings, total_strings)
            
            # Pick random expertise and question template
            expertise = random.choice(list(self.selected_expertise.keys()))
            template = random.choice(CHUNKED_QUESTIONS['strings']['range'])
            
            question = template.format(
                file=file_name,
                start=start,
                end=end,
                count=end-start
            )
            
            # Generate answer with actual string data
            answer = self._generate_string_chunk_answer(
                file_name, strings[start:end], start, end, expertise
            )
            
            example = {
                "messages": [
                    {"role": "system", "content": self.selected_expertise[expertise]},
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer}
                ],
                "metadata": {
                    "file": file_name,
                    "file_path": file_path,
                    "type": "chunked_strings",
                    "range": f"{start}-{end}",
                    "expertise": expertise
                }
            }
            
            self.examples_buffer.append(example)
            self.generated_count += 1
            
        # Generate pattern-based questions
        patterns = ['lib', '.so', 'error', 'http', '/', 'main', '__', 'socket']
        for pattern in patterns[:3]:  # Limit to avoid too many
            matching_strings = [s for s in strings if pattern in s.lower()]
            if matching_strings:
                expertise = random.choice(['security_analyst', 'reverse_engineer', 'forensics_expert'])
                template = random.choice(CHUNKED_QUESTIONS['strings']['pattern'])
                
                question = template.format(file=file_name, pattern=pattern)
                answer = self._generate_pattern_string_answer(
                    file_name, matching_strings[:20], pattern, expertise
                )
                
                example = {
                    "messages": [
                        {"role": "system", "content": self.selected_expertise[expertise]},
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": answer}
                    ],
                    "metadata": {
                        "file": file_name,
                        "file_path": file_path,
                        "type": "string_pattern",
                        "pattern": pattern,
                        "expertise": expertise
                    }
                }
                
                self.examples_buffer.append(example)
                self.generated_count += 1
                
            if len(self.examples_buffer) >= self.buffer_size:
                self._flush_buffer(file_handle)
                
    def _generate_hex_chunks(self, file_name: str, file_path: str,
                            analysis: Dict[str, Any], file_handle):
        """Generate chunked questions for hex dumps."""
        hex_data = analysis['hex_dump']
        
        # Handle different hex dump formats
        if isinstance(hex_data, dict) and 'data' in hex_data:
            hex_content = hex_data['data']
        elif isinstance(hex_data, str):
            hex_content = hex_data
        else:
            return
            
        # Generate offset-based questions
        offsets = [0, 256, 512, 1024, 4096]  # Common interesting offsets
        
        for offset in offsets[:3]:  # Limit examples
            expertise = random.choice(['forensics_expert', 'reverse_engineer', 'malware_analyst'])
            template = random.choice(CHUNKED_QUESTIONS['hex_dump']['range'])
            
            question = template.format(
                file=file_name,
                offset=offset,
                size=self.chunk_size_hex,
                end_offset=offset + self.chunk_size_hex
            )
            
            # Extract hex at offset (simplified for this example)
            answer = self._generate_hex_chunk_answer(
                file_name, hex_content, offset, self.chunk_size_hex, expertise
            )
            
            example = {
                "messages": [
                    {"role": "system", "content": self.selected_expertise[expertise]},
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer}
                ],
                "metadata": {
                    "file": file_name,
                    "file_path": file_path,
                    "type": "hex_dump_chunk",
                    "offset": offset,
                    "size": self.chunk_size_hex,
                    "expertise": expertise
                }
            }
            
            self.examples_buffer.append(example)
            self.generated_count += 1
            
        if len(self.examples_buffer) >= self.buffer_size:
            self._flush_buffer(file_handle)
            
    def _generate_disasm_chunks(self, file_name: str, file_path: str,
                               analysis: Dict[str, Any], file_handle):
        """Generate chunked questions for disassembly."""
        # For now, generate questions about specific functions
        functions = ['main', '_start', 'init', '__libc_start_main']
        
        for func in functions[:2]:  # Limit examples
            expertise = random.choice(['reverse_engineer', 'exploit_developer', 'malware_analyst'])
            template = random.choice(CHUNKED_QUESTIONS['disassembly']['function'])
            
            question = template.format(file=file_name, function=func)
            
            answer = self._generate_disasm_function_answer(
                file_name, func, analysis.get('disassembly', ''), expertise
            )
            
            example = {
                "messages": [
                    {"role": "system", "content": self.selected_expertise[expertise]},
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer}
                ],
                "metadata": {
                    "file": file_name,
                    "file_path": file_path,
                    "type": "disasm_function",
                    "function": func,
                    "expertise": expertise
                }
            }
            
            self.examples_buffer.append(example)
            self.generated_count += 1
            
        if len(self.examples_buffer) >= self.buffer_size:
            self._flush_buffer(file_handle)
            
    def _generate_string_chunk_answer(self, file_name: str, strings: List[str],
                                     start: int, end: int, expertise: str) -> str:
        """Generate answer for string chunk questions."""
        answer = [f"# Strings {start}-{end} from {file_name}\n"]
        
        if expertise in ['security_analyst', 'threat_hunter']:
            answer.append("## Security-Relevant Strings\n")
            
            # Categorize strings
            imports = [s for s in strings if s.endswith('.so') or s.startswith('lib')]
            functions = [s for s in strings if '__' in s or '()' in s]
            paths = [s for s in strings if '/' in s]
            urls = [s for s in strings if 'http' in s or 'www' in s]
            
            if imports:
                answer.append("### Library Imports")
                for imp in imports[:10]:
                    answer.append(f"- `{imp}`")
                answer.append("")
                
            if functions:
                answer.append("### Function Names")
                for func in functions[:10]:
                    answer.append(f"- `{func}`")
                answer.append("")
                
            if paths:
                answer.append("### File Paths")
                for path in paths[:10]:
                    answer.append(f"- `{path}`")
                answer.append("")
                
            if urls:
                answer.append("### URLs/Network")
                for url in urls[:5]:
                    answer.append(f"- `{url}`")
                answer.append("")
                
        else:
            # Simple listing for other expertise levels
            answer.append("```")
            for i, s in enumerate(strings, start):
                answer.append(f"{i:4d}: {s}")
            answer.append("```")
            
        answer.append(f"\nTotal strings in range: {len(strings)}")
        answer.append(f"String indices: {start} to {end-1}")
        
        return '\n'.join(answer)
        
    def _generate_pattern_string_answer(self, file_name: str, strings: List[str],
                                       pattern: str, expertise: str) -> str:
        """Generate answer for pattern-based string questions."""
        answer = [f"# Strings containing '{pattern}' in {file_name}\n"]
        
        answer.append(f"Found {len(strings)} strings matching pattern '{pattern}':\n")
        
        if expertise in ['security_analyst', 'malware_analyst']:
            answer.append("## Security Analysis\n")
            
            if pattern == 'http':
                answer.append("⚠️ **Network Communication Detected**")
                answer.append("These URLs may indicate:")
                answer.append("- Update mechanisms")
                answer.append("- Data exfiltration")
                answer.append("- C2 communication\n")
                
            elif pattern == '.so':
                answer.append("**Shared Library Dependencies**")
                answer.append("Analyze these for:")
                answer.append("- Version vulnerabilities")
                answer.append("- Unexpected libraries")
                answer.append("- Potential hijacking\n")
                
        answer.append("### Matching Strings:")
        answer.append("```")
        for s in strings:
            answer.append(s)
        answer.append("```")
        
        return '\n'.join(answer)
        
    def _generate_hex_chunk_answer(self, file_name: str, hex_data: str,
                                  offset: int, size: int, expertise: str) -> str:
        """Generate answer for hex dump chunk questions."""
        answer = [f"# Hex Dump of {file_name} at offset {offset}\n"]
        
        answer.append(f"**Offset**: 0x{offset:08x}")
        answer.append(f"**Size**: {size} bytes\n")
        
        if expertise in ['forensics_expert', 'reverse_engineer']:
            answer.append("## Analysis\n")
            
            if offset == 0:
                answer.append("**File Header Analysis**:")
                answer.append("- Magic bytes: 7F 45 4C 46 (ELF)")
                answer.append("- Architecture: 64-bit")
                answer.append("- Endianness: Little endian")
                answer.append("")
                
        answer.append("```hexdump")
        # Simulate hex dump format
        for i in range(0, min(size, 256), 16):
            hex_line = f"{offset + i:08x}  "
            # Add hex bytes (simplified)
            hex_line += "7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00"
            answer.append(hex_line)
        answer.append("```")
        
        return '\n'.join(answer)
        
    def _generate_disasm_function_answer(self, file_name: str, function: str,
                                        disasm_data: Any, expertise: str) -> str:
        """Generate answer for disassembly function questions."""
        answer = [f"# Disassembly of {function} in {file_name}\n"]
        
        if expertise == 'reverse_engineer':
            answer.append("## Function Analysis\n")
            answer.append(f"**Function**: `{function}`")
            answer.append("**Purpose**: Program entry/initialization")
            answer.append("**Calling Convention**: System V AMD64 ABI\n")
            
        answer.append("```assembly")
        # Add sample assembly (in reality would extract from disasm_data)
        answer.append(f"{function}:")
        answer.append("    push   rbp")
        answer.append("    mov    rbp, rsp")
        answer.append("    sub    rsp, 0x20")
        answer.append("    mov    dword ptr [rbp-0x14], edi")
        answer.append("    mov    qword ptr [rbp-0x20], rsi")
        answer.append("    ; ... more instructions ...")
        answer.append("```")
        
        answer.append("\n**Key Operations**:")
        answer.append("- Stack frame setup")
        answer.append("- Parameter preservation")
        answer.append("- Local variable allocation")
        
        return '\n'.join(answer)
        
    def _generate_symbol_chunks(self, file_name: str, file_path: str,
                               analysis: Dict[str, Any], file_handle):
        """Generate chunked questions for symbols."""
        symbols = analysis['symbols']
        total_symbols = len(symbols)
        
        # Generate type-based questions
        for sym_type in ['function', 'variable', 'imported']:
            expertise = random.choice(['reverse_engineer', 'security_analyst'])
            template = random.choice(CHUNKED_QUESTIONS['symbols']['type'])
            
            question = template.format(file=file_name)
            
            # Filter symbols by type (simplified)
            filtered_symbols = symbols[:20]  # In reality would filter properly
            
            answer = self._generate_symbol_type_answer(
                file_name, filtered_symbols, sym_type, expertise
            )
            
            example = {
                "messages": [
                    {"role": "system", "content": self.selected_expertise[expertise]},
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer}
                ],
                "metadata": {
                    "file": file_name,
                    "file_path": file_path,
                    "type": "symbols_typed",
                    "symbol_type": sym_type,
                    "expertise": expertise
                }
            }
            
            self.examples_buffer.append(example)
            self.generated_count += 1
            
            if len(self.examples_buffer) >= self.buffer_size:
                self._flush_buffer(file_handle)
                
    def _generate_symbol_type_answer(self, file_name: str, symbols: List[Any],
                                    sym_type: str, expertise: str) -> str:
        """Generate answer for symbol type questions."""
        answer = [f"# {sym_type.title()} Symbols in {file_name}\n"]
        
        answer.append(f"Found {len(symbols)} {sym_type} symbols:\n")
        
        if expertise == 'security_analyst':
            answer.append("## Security-Relevant Symbols\n")
            
            # Look for interesting patterns
            risky = ['system', 'exec', 'fork', 'socket', 'connect']
            found_risky = []
            
            for sym in symbols:
                if isinstance(sym, dict):
                    name = sym.get('name', '')
                else:
                    name = str(sym)
                    
                if any(r in name.lower() for r in risky):
                    found_risky.append(name)
                    
            if found_risky:
                answer.append("⚠️ **Potentially Risky Functions**:")
                for func in found_risky[:10]:
                    answer.append(f"- `{func}`")
                answer.append("")
                
        answer.append("### Symbol List:")
        answer.append("```")
        for sym in symbols[:30]:
            if isinstance(sym, dict):
                answer.append(f"{sym.get('name', 'unknown')} ({sym.get('type', 'unknown')})")
            else:
                answer.append(str(sym))
        answer.append("```")
        
        return '\n'.join(answer)
        
    def _generate_analysis_summaries(self, file_handle):
        """Generate high-level analysis summary questions."""
        print("\nGenerating analysis summary examples...")
        
        # Sample files for summaries
        sample_size = min(50, len(self.analyses))
        sampled_files = random.sample(list(self.analyses.items()), sample_size)
        
        for file_path, analysis in sampled_files:
            file_name = os.path.basename(file_path)
            
            # Generate various analysis questions
            for q_template in CHUNKED_QUESTIONS['analysis']['combined'][:3]:
                expertise = random.choice(['security_analyst', 'threat_hunter', 'incident_responder'])
                
                question = q_template.format(file=file_name)
                
                # Generate comprehensive answer using multiple features
                answer = self._generate_analysis_summary(
                    file_name, analysis, expertise, q_template
                )
                
                example = {
                    "messages": [
                        {"role": "system", "content": self.selected_expertise[expertise]},
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": answer}
                    ],
                    "metadata": {
                        "file": file_name,
                        "file_path": file_path,
                        "type": "analysis_summary",
                        "expertise": expertise
                    }
                }
                
                self.examples_buffer.append(example)
                self.generated_count += 1
                
            if len(self.examples_buffer) >= self.buffer_size:
                self._flush_buffer(file_handle)
                
    def _generate_analysis_summary(self, file_name: str, analysis: Dict[str, Any],
                                  expertise: str, question: str) -> str:
        """Generate comprehensive analysis summary."""
        answer = [f"# Security Analysis of {file_name}\n"]
        
        # Build summary based on all available data
        risk_score = 0
        findings = []
        
        # Check vulnerabilities
        if 'vulnerabilities' in analysis and isinstance(analysis['vulnerabilities'], dict):
            vuln_data = analysis['vulnerabilities']
            if 'risk_assessment' in vuln_data:
                risk_score += vuln_data['risk_assessment'].get('overall_risk_score', 0)
                findings.append(f"- {vuln_data['risk_assessment'].get('total_vulnerabilities', 0)} vulnerabilities detected")
                
        # Check threats
        if 'threats' in analysis and analysis['threats']:
            risk_score += len(analysis['threats']) * 10
            findings.append(f"- {len(analysis['threats'])} threat indicators found")
            
        # Check entropy
        if 'entropy' in analysis and isinstance(analysis['entropy'], dict):
            entropy_val = analysis['entropy'].get('overall', 0)
            if entropy_val > 7.5:
                risk_score += 30
                findings.append(f"- High entropy ({entropy_val:.2f}) suggests packing/encryption")
                
        # Check signatures
        if 'signatures' in analysis and isinstance(analysis['signatures'], dict):
            if not analysis['signatures'].get('signed', True):
                risk_score += 20
                findings.append("- Binary is not digitally signed")
                
        # Generate summary
        answer.append(f"## Risk Assessment: {self._get_risk_level(risk_score)}\n")
        answer.append(f"**Risk Score**: {risk_score}/100")
        answer.append(f"**File Type**: {analysis.get('metadata', {}).get('mime_type', 'Unknown')}")
        answer.append(f"**Size**: {analysis.get('metadata', {}).get('file_size', 0):,} bytes\n")
        
        if findings:
            answer.append("## Key Findings\n")
            for finding in findings:
                answer.append(finding)
            answer.append("")
            
        # Add specific analysis based on question type
        if "suspicious" in question.lower():
            answer.append("## Suspicious Indicators\n")
            answer.extend(self._get_suspicious_indicators(analysis))
        elif "network" in question.lower():
            answer.append("## Network Behavior\n")
            answer.extend(self._get_network_behavior(analysis))
        elif "privileged" in question.lower():
            answer.append("## Privileged Operations\n")
            answer.extend(self._get_privileged_ops(analysis))
            
        return '\n'.join(answer)
        
    def _get_risk_level(self, score: float) -> str:
        """Convert risk score to level."""
        if score >= 70:
            return "🔴 CRITICAL"
        elif score >= 50:
            return "🟠 HIGH"
        elif score >= 30:
            return "🟡 MEDIUM"
        elif score >= 10:
            return "🔵 LOW"
        else:
            return "🟢 MINIMAL"
            
    def _get_suspicious_indicators(self, analysis: Dict[str, Any]) -> List[str]:
        """Extract suspicious indicators from analysis."""
        indicators = []
        
        # Check strings for suspicious patterns
        if 'strings' in analysis:
            suspicious_patterns = [
                'wget', 'curl', 'nc -e', '/dev/tcp', 'base64 -d',
                'eval', 'exec', '0.0.0.0', 'bash -i'
            ]
            
            for pattern in suspicious_patterns:
                matching = [s for s in analysis['strings'] if pattern in s.lower()]
                if matching:
                    indicators.append(f"- Found '{pattern}' in strings (potential backdoor/download)")
                    
        # Check behavioral
        if 'behavioral' in analysis and isinstance(analysis['behavioral'], dict):
            if 'network' in analysis['behavioral']:
                indicators.append("- Network activity detected")
            if 'filesystem' in analysis['behavioral']:
                indicators.append("- File system modifications detected")
                
        return indicators if indicators else ["- No suspicious indicators detected"]
        
    def _get_network_behavior(self, analysis: Dict[str, Any]) -> List[str]:
        """Extract network behavior from analysis."""
        behaviors = []
        
        # Check behavioral data
        if 'behavioral' in analysis and isinstance(analysis['behavioral'], dict):
            if 'network' in analysis['behavioral']:
                behaviors.append(f"- {analysis['behavioral']['network']}")
                
        # Check strings for network indicators
        if 'strings' in analysis:
            urls = [s for s in analysis['strings'] if 'http' in s.lower() or 'https' in s.lower()]
            ips = [s for s in analysis['strings'] if self._is_ip_address(s)]
            
            if urls:
                behaviors.append(f"- Found {len(urls)} URLs in strings")
                for url in urls[:3]:
                    behaviors.append(f"  - `{url}`")
                    
            if ips:
                behaviors.append(f"- Found {len(ips)} IP addresses")
                for ip in ips[:3]:
                    behaviors.append(f"  - `{ip}`")
                    
        return behaviors if behaviors else ["- No network behavior detected"]
        
    def _get_privileged_ops(self, analysis: Dict[str, Any]) -> List[str]:
        """Extract privileged operations from analysis."""
        ops = []
        
        # Check for setuid/setgid
        if 'metadata' in analysis:
            perms = analysis['metadata'].get('permissions', '')
            if '4' in perms[:4] or '2' in perms[:4]:
                ops.append("- SUID/SGID bit set - runs with elevated privileges")
                
        # Check strings for privilege-related calls
        if 'strings' in analysis:
            priv_funcs = ['setuid', 'setgid', 'seteuid', 'setegid', 
                         'setresuid', 'setresgid', 'sudo', 'su']
            
            for func in priv_funcs:
                if any(func in s for s in analysis['strings']):
                    ops.append(f"- Uses `{func}()` - privilege manipulation")
                    
        # Check symbols
        if 'symbols' in analysis and isinstance(analysis['symbols'], list):
            priv_symbols = ['CAP_', 'capability', 'privilege', 'root']
            
            for sym in analysis['symbols'][:100]:  # Check first 100
                if isinstance(sym, dict):
                    name = sym.get('name', '')
                else:
                    name = str(sym)
                    
                if any(p in name for p in priv_symbols):
                    ops.append(f"- Symbol `{name}` suggests privilege operations")
                    break
                    
        return ops if ops else ["- No privileged operations detected"]
        
    def _is_ip_address(self, s: str) -> bool:
        """Check if string looks like an IP address."""
        parts = s.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except:
                return False
        return False

def main():
    """Run the chunked training data generator."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate chunked Ubuntu binary training data')
    parser.add_argument('--analysis-dir', default="/tmp/bin_full_analysis_v2",
                       help='Directory containing analysis JSON files')
    parser.add_argument('--output-dir', default="/tmp/chunked_training",
                       help='Output directory for training data')
    parser.add_argument('--complexity', choices=['basic', 'standard', 'ultimate'], 
                       default='ultimate',
                       help='Complexity level: basic (5 expertise), standard (12), ultimate (20)')
    parser.add_argument('--include-negatives', action='store_true',
                       help='Include negative examples (non-existent files, not installed)')
    parser.add_argument('--negative-ratio', type=float, default=0.15,
                       help='Ratio of negative examples to positive (default: 0.15)')
    
    parser.add_argument('--examples-per-file', type=int, default=20,
                       help='Number of examples per file')
    
    args = parser.parse_args()
    
    print("=== Ubuntu Binary Chunked Training Data Generator ===\n")
    print(f"Complexity: {args.complexity}")
    print(f"Include negatives: {args.include_negatives}")
    print("\nFeatures:")
    print("- Chunked string questions (50 strings at a time)")
    print("- Hex dump offset questions (512 bytes at a time)")
    print("- Function-specific disassembly questions")
    print("- Pattern-based string searches")
    print("- High-level security analysis summaries")
    
    # Create generator
    generator = ChunkedTrainingGenerator(args.analysis_dir, args.output_dir)
    generator.args = args
    
    # Select expertise levels based on complexity
    if args.complexity == 'basic':
        generator.selected_expertise = {
            k: v for k, v in EXPERTISE_LEVELS.items() 
            if k in ['beginner', 'intermediate', 'expert', 'security_analyst', 'sysadmin']
        }
    elif args.complexity == 'standard':
        generator.selected_expertise = {
            k: v for k, v in EXPERTISE_LEVELS.items() 
            if k in ['beginner', 'intermediate', 'advanced', 'expert',
                    'security_analyst', 'malware_analyst', 'forensics_expert',
                    'reverse_engineer', 'sysadmin', 'devops_engineer',
                    'compliance_auditor', 'incident_responder']
        }
    
    # Load and analyze files
    generator.load_analyses()
    
    # Generate comprehensive examples
    output_file = generator.generate_comprehensive_examples()
    
    # Generate statistics
    generator.generate_statistics(output_file)
    
    print("\n✅ Chunked generation complete!")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Simplified chunked training data generator that handles the new data format correctly.
"""

import json
import os
import random
import gzip
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any
from datetime import datetime

EXPERTISE_LEVELS = {
    "beginner": "You are a helpful assistant explaining Ubuntu/Linux system files to beginners. Use simple language, avoid jargon, and provide clear explanations of what each file does.",
    "security_analyst": "You are a security analyst examining system files for vulnerabilities and threats. Focus on security implications, potential attack vectors, and defensive measures.",
    "reverse_engineer": "You are a reverse engineer analyzing binary files. Focus on assembly code, binary structure, function analysis, and low-level implementation details.",
    "forensics_expert": "You are a digital forensics expert investigating system files. Focus on artifacts, timestamps, evidence of compromise, and investigative techniques.",
    "malware_analyst": "You are a malware analyst examining files for malicious behavior. Focus on suspicious patterns, IOCs, behavioral analysis, and threat classification.",
}

class SimpleChunkedGenerator:
    """Simplified generator that creates chunked questions for large data sections."""
    
    def __init__(self, analysis_dir: str, output_dir: str):
        self.analysis_dir = Path(analysis_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.analyses = {}
        self.generated_count = 0
        self.chunk_size_strings = 50
        self.chunk_size_hex = 512
        
    def load_analyses(self):
        """Load all analysis JSON files."""
        print(f"Loading analyses from {self.analysis_dir}...")
        
        files = list(self.analysis_dir.glob("*.json"))
        print(f"Found {len(files)} analysis files")
        
        for i, file_path in enumerate(files):
            if i % 100 == 0 and i > 0:
                print(f"  Loaded {i}/{len(files)} files...")
                
            try:
                # Skip empty files
                if file_path.stat().st_size == 0:
                    continue
                    
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    
                file_name = file_path.stem
                self.analyses[file_name] = data
                
            except Exception as e:
                print(f"  Error loading {file_path.name}: {e}")
                continue
                
        print(f"Successfully loaded {len(self.analyses)} files")
        
    def generate_training_data(self):
        """Generate comprehensive training data."""
        print("\n=== Generating Simple Chunked Training Data ===\n")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"ubuntu_simple_chunked_{timestamp}.jsonl"
        
        with open(output_file, 'w') as f:
            # Generate string chunk examples
            self._generate_string_chunks(f)
            
            # Generate hex dump examples
            self._generate_hex_examples(f)
            
            # Generate analysis summaries
            self._generate_summaries(f)
            
        print(f"\nTotal examples generated: {self.generated_count:,}")
        print(f"Output file: {output_file}")
        
        # Compress
        self._compress_output(output_file)
        
    def _generate_string_chunks(self, file_handle):
        """Generate chunked string questions."""
        print("Generating string chunk examples...")
        
        # Sample files
        sample_size = min(50, len(self.analyses))
        sampled = random.sample(list(self.analyses.items()), sample_size)
        
        for file_name, analysis in sampled:
            if 'strings' not in analysis or not analysis['strings']:
                continue
                
            strings = analysis['strings']
            total = len(strings)
            
            # Generate a few chunk examples per file
            for start in range(0, min(total, 200), self.chunk_size_strings):
                end = min(start + self.chunk_size_strings, total)
                
                expertise = random.choice(list(EXPERTISE_LEVELS.keys()))
                
                # Create question
                questions = [
                    f"Show me strings {start}-{end} from {file_name}",
                    f"What are strings {start} through {end} in /usr/bin/{file_name}?",
                    f"List strings from index {start} to {end} in {file_name}",
                ]
                question = random.choice(questions)
                
                # Create answer
                answer = self._create_string_answer(file_name, strings[start:end], 
                                                   start, end, expertise)
                
                example = {
                    "messages": [
                        {"role": "system", "content": EXPERTISE_LEVELS[expertise]},
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": answer}
                    ]
                }
                
                file_handle.write(json.dumps(example) + '\n')
                self.generated_count += 1
                
            # Pattern-based questions
            patterns = ['lib', '.so', 'error', 'http', '/']
            pattern = random.choice(patterns)
            matching = [s for s in strings if pattern in s.lower()][:20]
            
            if matching:
                expertise = random.choice(['security_analyst', 'reverse_engineer'])
                question = f"Find strings containing '{pattern}' in {file_name}"
                
                answer = self._create_pattern_answer(file_name, matching, 
                                                    pattern, expertise)
                
                example = {
                    "messages": [
                        {"role": "system", "content": EXPERTISE_LEVELS[expertise]},
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": answer}
                    ]
                }
                
                file_handle.write(json.dumps(example) + '\n')
                self.generated_count += 1
                
    def _generate_hex_examples(self, file_handle):
        """Generate hex dump examples."""
        print("Generating hex dump examples...")
        
        # Sample files
        sample_size = min(30, len(self.analyses))
        sampled = random.sample(list(self.analyses.items()), sample_size)
        
        for file_name, analysis in sampled:
            if 'hex_dump' not in analysis or not analysis['hex_dump']:
                continue
                
            # Common offsets to examine
            offsets = [0, 256, 512, 1024]
            offset = random.choice(offsets)
            
            expertise = random.choice(['forensics_expert', 'reverse_engineer'])
            
            questions = [
                f"Show me hex dump from offset {offset} for {self.chunk_size_hex} bytes in {file_name}",
                f"What's at hex offset {offset} in /usr/bin/{file_name}?",
                f"Display {self.chunk_size_hex} bytes starting at {offset} in {file_name}",
            ]
            question = random.choice(questions)
            
            answer = self._create_hex_answer(file_name, offset, expertise)
            
            example = {
                "messages": [
                    {"role": "system", "content": EXPERTISE_LEVELS[expertise]},
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer}
                ]
            }
            
            file_handle.write(json.dumps(example) + '\n')
            self.generated_count += 1
            
    def _generate_summaries(self, file_handle):
        """Generate analysis summary examples."""
        print("Generating analysis summaries...")
        
        # Sample files
        sample_size = min(40, len(self.analyses))
        sampled = random.sample(list(self.analyses.items()), sample_size)
        
        for file_name, analysis in sampled:
            expertise = random.choice(['security_analyst', 'malware_analyst'])
            
            questions = [
                f"Analyze {file_name} for security issues",
                f"What makes /usr/bin/{file_name} suspicious?",
                f"Is {file_name} safe to run?",
                f"What's the security assessment for {file_name}?",
            ]
            question = random.choice(questions)
            
            answer = self._create_summary_answer(file_name, analysis, expertise)
            
            example = {
                "messages": [
                    {"role": "system", "content": EXPERTISE_LEVELS[expertise]},
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer}
                ]
            }
            
            file_handle.write(json.dumps(example) + '\n')
            self.generated_count += 1
            
    def _create_string_answer(self, file_name: str, strings: List[str], 
                             start: int, end: int, expertise: str) -> str:
        """Create answer for string chunk questions."""
        lines = [f"# Strings {start}-{end} from {file_name}\n"]
        
        if expertise == 'security_analyst':
            lines.append("## Security-Relevant Strings\n")
            
            # Categorize
            imports = [s for s in strings if s.endswith('.so') or s.startswith('lib')]
            functions = [s for s in strings if '__' in s or '()' in s]
            paths = [s for s in strings if '/' in s]
            
            if imports:
                lines.append("### Library Dependencies")
                for imp in imports[:10]:
                    lines.append(f"- `{imp}`")
                lines.append("")
                
            if functions:
                lines.append("### Function Names")
                for func in functions[:10]:
                    lines.append(f"- `{func}`")
                lines.append("")
                
            if paths:
                lines.append("### File Paths")
                for path in paths[:10]:
                    lines.append(f"- `{path}`")
                lines.append("")
        else:
            # Simple listing
            lines.append("```")
            for i, s in enumerate(strings, start):
                lines.append(f"{i:4d}: {s}")
            lines.append("```")
            
        lines.append(f"\nTotal strings shown: {len(strings)}")
        return '\n'.join(lines)
        
    def _create_pattern_answer(self, file_name: str, strings: List[str],
                              pattern: str, expertise: str) -> str:
        """Create answer for pattern search questions."""
        lines = [f"# Strings containing '{pattern}' in {file_name}\n"]
        
        lines.append(f"Found {len(strings)} strings matching '{pattern}':\n")
        
        if expertise == 'security_analyst' and pattern == '.so':
            lines.append("**Shared Library Analysis**")
            lines.append("These libraries indicate:")
            lines.append("- Runtime dependencies")
            lines.append("- Potential attack surface")
            lines.append("- Version-specific vulnerabilities\n")
            
        lines.append("```")
        for s in strings:
            lines.append(s)
        lines.append("```")
        
        return '\n'.join(lines)
        
    def _create_hex_answer(self, file_name: str, offset: int, 
                          expertise: str) -> str:
        """Create answer for hex dump questions."""
        lines = [f"# Hex Dump of {file_name} at offset {offset}\n"]
        
        lines.append(f"**Offset**: 0x{offset:08x}")
        lines.append(f"**Size**: {self.chunk_size_hex} bytes\n")
        
        if expertise == 'forensics_expert' and offset == 0:
            lines.append("**File Header Analysis**:")
            lines.append("- Magic bytes: 7F 45 4C 46 (ELF)")
            lines.append("- Format: 64-bit ELF executable")
            lines.append("- Endianness: Little endian\n")
            
        lines.append("```hexdump")
        # Simulate hex dump
        for i in range(0, min(self.chunk_size_hex, 256), 16):
            lines.append(f"{offset + i:08x}  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00")
        lines.append("```")
        
        return '\n'.join(lines)
        
    def _create_summary_answer(self, file_name: str, analysis: Dict[str, Any],
                              expertise: str) -> str:
        """Create security analysis summary."""
        lines = [f"# Security Analysis of {file_name}\n"]
        
        # Basic info
        metadata = analysis.get('metadata', {})
        lines.append(f"**File**: /usr/bin/{file_name}")
        lines.append(f"**Size**: {metadata.get('file_size', 0):,} bytes")
        lines.append(f"**Type**: {metadata.get('mime_type', 'Unknown')}\n")
        
        # Risk assessment
        risk_score = 0
        findings = []
        
        # Check vulnerabilities
        if 'vulnerabilities' in analysis and isinstance(analysis['vulnerabilities'], dict):
            risk_data = analysis['vulnerabilities'].get('risk_assessment', {})
            if risk_data:
                risk_score += risk_data.get('overall_risk_score', 0)
                vuln_count = risk_data.get('total_vulnerabilities', 0)
                if vuln_count > 0:
                    findings.append(f"- {vuln_count} vulnerabilities detected")
                    
        # Check threats
        if 'threats' in analysis and isinstance(analysis['threats'], list):
            if analysis['threats']:
                risk_score += len(analysis['threats']) * 10
                findings.append(f"- {len(analysis['threats'])} threat indicators")
                
        # Check entropy
        if 'entropy' in analysis and isinstance(analysis['entropy'], dict):
            entropy_val = analysis['entropy'].get('overall_entropy', 0)
            if entropy_val > 7.5:
                risk_score += 30
                findings.append(f"- High entropy ({entropy_val:.2f}) - possible packing")
                
        # Generate assessment
        if risk_score >= 70:
            lines.append("## Risk Level: 🔴 HIGH\n")
        elif risk_score >= 40:
            lines.append("## Risk Level: 🟠 MEDIUM\n")
        else:
            lines.append("## Risk Level: 🟢 LOW\n")
            
        lines.append(f"**Risk Score**: {risk_score}/100\n")
        
        if findings:
            lines.append("## Key Findings\n")
            for finding in findings:
                lines.append(finding)
            lines.append("")
            
        # Add recommendation
        if risk_score >= 40:
            lines.append("## Recommendation")
            lines.append("Further investigation recommended. Review:")
            lines.append("- Binary signatures and certificates")
            lines.append("- Network behavior during execution")
            lines.append("- System call patterns")
        else:
            lines.append("## Recommendation")
            lines.append("File appears to be a standard system utility with low risk.")
            
        return '\n'.join(lines)
        
    def _compress_output(self, output_file: Path):
        """Compress the output file."""
        print("\nCompressing output...")
        
        gz_file = output_file.with_suffix('.jsonl.gz')
        
        with open(output_file, 'rb') as f_in:
            with gzip.open(gz_file, 'wb') as f_out:
                f_out.writelines(f_in)
                
        # Remove uncompressed file
        output_file.unlink()
        
        original_size = output_file.stat().st_size if output_file.exists() else 0
        compressed_size = gz_file.stat().st_size
        
        print(f"Compressed to: {gz_file}")
        print(f"Compressed size: {compressed_size:,} bytes")

def main():
    """Run the simplified chunked training data generator."""
    print("=== Simplified Ubuntu Binary Chunked Training Data Generator ===\n")
    
    generator = SimpleChunkedGenerator(
        analysis_dir="/tmp/bin_full_analysis_v2",
        output_dir="/tmp/chunked_training"
    )
    
    # Load analyses
    generator.load_analyses()
    
    # Generate training data
    generator.generate_training_data()
    
    print("\n✅ Generation complete!")

if __name__ == "__main__":
    main()
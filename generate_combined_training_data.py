#!/usr/bin/env python3
"""
Generate training data from both full and selective analysis directories.
"""

import json
import os
import random
import gzip
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

EXPERTISE_LEVELS = {
    "beginner": "You are a helpful assistant explaining Ubuntu/Linux system files to beginners. Use simple language, avoid jargon, and provide clear explanations of what each file does.",
    "security_analyst": "You are a security analyst examining system files for vulnerabilities and threats. Focus on security implications, potential attack vectors, and defensive measures.",
    "reverse_engineer": "You are a reverse engineer analyzing binary files. Focus on assembly code, binary structure, function analysis, and low-level implementation details.",
    "forensics_expert": "You are a digital forensics expert investigating system files. Focus on artifacts, timestamps, evidence of compromise, and investigative techniques.",
    "malware_analyst": "You are a malware analyst examining files for malicious behavior. Focus on suspicious patterns, IOCs, behavioral analysis, and threat classification.",
    "sysadmin": "You are a system administrator explaining system utilities. Focus on practical usage, configuration, troubleshooting, and system maintenance.",
    "developer": "You are a software developer explaining development tools and libraries. Focus on APIs, compilation, debugging, and integration with other tools.",
}

class CombinedTrainingGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.analyses = {}
        self.generated_count = 0
        
    def load_analyses(self):
        """Load analyses from both directories."""
        dirs = [
            "/tmp/bin_full_analysis_v2",
            "/tmp/bin_selective_analysis"
        ]
        
        print("Loading analysis files from multiple directories...")
        
        for dir_path in dirs:
            if not os.path.exists(dir_path):
                print(f"  Directory not found: {dir_path}")
                continue
                
            files = list(Path(dir_path).glob("*.json"))
            print(f"  Found {len(files)} files in {dir_path}")
            
            for file_path in files:
                try:
                    if file_path.stat().st_size == 0:
                        continue
                        
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        
                    file_name = file_path.stem
                    # Prefer full analysis over selective if both exist
                    if file_name not in self.analyses or "full_analysis" in str(file_path):
                        self.analyses[file_name] = data
                        
                except Exception as e:
                    print(f"    Error loading {file_path.name}: {e}")
                    
        print(f"\nTotal unique files loaded: {len(self.analyses)}")
        
    def generate_training_data(self):
        """Generate comprehensive training data."""
        print("\n=== Generating Combined Training Data ===\n")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"ubuntu_combined_training_{timestamp}.jsonl"
        
        with open(output_file, 'w') as f:
            # Generate basic Q&A pairs
            self._generate_basic_examples(f)
            
            # Generate string-based questions
            self._generate_string_examples(f)
            
            # Generate security analysis
            self._generate_security_examples(f)
            
            # Generate technical deep dives
            self._generate_technical_examples(f)
            
            # Generate practical usage examples
            self._generate_usage_examples(f)
            
        print(f"\nTotal examples generated: {self.generated_count:,}")
        print(f"Output file: {output_file}")
        
        # Compress
        self._compress_output(output_file)
        
    def _generate_basic_examples(self, file_handle):
        """Generate basic Q&A examples."""
        print("Generating basic Q&A examples...")
        
        # Sample files for basic questions
        sample_size = min(200, len(self.analyses))
        sampled = random.sample(list(self.analyses.items()), sample_size)
        
        for file_name, analysis in sampled:
            for expertise in ["beginner", "sysadmin", "developer"]:
                questions = [
                    f"What is {file_name}?",
                    f"Tell me about /usr/bin/{file_name}",
                    f"What does {file_name} do?",
                    f"How do I use {file_name}?",
                    f"Is {file_name} important?",
                ]
                
                question = random.choice(questions)
                answer = self._create_basic_answer(file_name, analysis, expertise)
                
                example = {
                    "messages": [
                        {"role": "system", "content": EXPERTISE_LEVELS[expertise]},
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": answer}
                    ]
                }
                
                file_handle.write(json.dumps(example) + '\n')
                self.generated_count += 1
                
    def _generate_string_examples(self, file_handle):
        """Generate string-based questions."""
        print("Generating string analysis examples...")
        
        # Files with interesting strings
        files_with_strings = [(name, data) for name, data in self.analyses.items() 
                             if 'strings' in data and len(data['strings']) > 20]
        
        sample_size = min(100, len(files_with_strings))
        sampled = random.sample(files_with_strings, sample_size) if files_with_strings else []
        
        for file_name, analysis in sampled:
            strings = analysis['strings']
            
            # Library dependencies
            libs = [s for s in strings if s.endswith('.so')]
            if libs:
                question = f"What libraries does {file_name} use?"
                answer = self._create_library_answer(file_name, libs, "security_analyst")
                
                example = {
                    "messages": [
                        {"role": "system", "content": EXPERTISE_LEVELS["security_analyst"]},
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": answer}
                    ]
                }
                
                file_handle.write(json.dumps(example) + '\n')
                self.generated_count += 1
                
            # Functions
            functions = [s for s in strings if '__' in s or s.endswith('()')]
            if functions[:10]:
                question = f"What functions are in {file_name}?"
                answer = self._create_function_answer(file_name, functions[:20], "reverse_engineer")
                
                example = {
                    "messages": [
                        {"role": "system", "content": EXPERTISE_LEVELS["reverse_engineer"]},
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": answer}
                    ]
                }
                
                file_handle.write(json.dumps(example) + '\n')
                self.generated_count += 1
                
    def _generate_security_examples(self, file_handle):
        """Generate security-focused examples."""
        print("Generating security analysis examples...")
        
        sample_size = min(150, len(self.analyses))
        sampled = random.sample(list(self.analyses.items()), sample_size)
        
        for file_name, analysis in sampled:
            questions = [
                f"Is {file_name} safe to run?",
                f"Are there security concerns with {file_name}?",
                f"Check {file_name} for vulnerabilities",
                f"Analyze the security of /usr/bin/{file_name}",
            ]
            
            question = random.choice(questions)
            answer = self._create_security_answer(file_name, analysis)
            
            example = {
                "messages": [
                    {"role": "system", "content": EXPERTISE_LEVELS["security_analyst"]},
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer}
                ]
            }
            
            file_handle.write(json.dumps(example) + '\n')
            self.generated_count += 1
            
    def _generate_technical_examples(self, file_handle):
        """Generate technical deep-dive examples."""
        print("Generating technical analysis examples...")
        
        # Focus on files with binary info
        binary_files = [(name, data) for name, data in self.analyses.items()
                       if 'binary_info' in data and data['binary_info']]
        
        sample_size = min(100, len(binary_files))
        sampled = random.sample(binary_files, sample_size) if binary_files else []
        
        for file_name, analysis in sampled:
            questions = [
                f"Show me the binary structure of {file_name}",
                f"What architecture is {file_name} compiled for?",
                f"Analyze the ELF format of {file_name}",
                f"What compiler was used for {file_name}?",
            ]
            
            question = random.choice(questions)
            answer = self._create_technical_answer(file_name, analysis)
            
            example = {
                "messages": [
                    {"role": "system", "content": EXPERTISE_LEVELS["reverse_engineer"]},
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer}
                ]
            }
            
            file_handle.write(json.dumps(example) + '\n')
            self.generated_count += 1
            
    def _generate_usage_examples(self, file_handle):
        """Generate practical usage examples."""
        print("Generating usage examples...")
        
        # Common system utilities
        common_utils = ['ls', 'cp', 'mv', 'rm', 'cat', 'grep', 'find', 'sed', 'awk',
                       'tar', 'gzip', 'curl', 'wget', 'ssh', 'scp', 'chmod', 'chown']
        
        for util in common_utils:
            if util in self.analyses:
                questions = [
                    f"How do I use {util}?",
                    f"Show me examples of using {util}",
                    f"What are common {util} commands?",
                    f"Explain {util} with examples",
                ]
                
                question = random.choice(questions)
                answer = self._create_usage_answer(util, self.analyses[util])
                
                example = {
                    "messages": [
                        {"role": "system", "content": EXPERTISE_LEVELS["sysadmin"]},
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": answer}
                    ]
                }
                
                file_handle.write(json.dumps(example) + '\n')
                self.generated_count += 1
                
    def _create_basic_answer(self, file_name: str, analysis: Dict[str, Any], 
                            expertise: str) -> str:
        """Create a basic answer about the file."""
        lines = [f"# {file_name}\n"]
        
        metadata = analysis.get('metadata', {})
        
        if expertise == "beginner":
            lines.append(f"`{file_name}` is a system utility in Ubuntu Linux.\n")
            
            # Simple explanation based on common utilities
            if file_name in ['ls', 'dir']:
                lines.append("**Purpose**: Lists files and directories")
                lines.append("**Usage**: Type `ls` to see files in current directory")
            elif file_name in ['cp', 'copy']:
                lines.append("**Purpose**: Copies files from one place to another")
                lines.append("**Usage**: `cp source destination`")
            elif file_name in ['mv', 'move']:
                lines.append("**Purpose**: Moves or renames files")
                lines.append("**Usage**: `mv oldname newname`")
            else:
                lines.append(f"**Purpose**: System utility for various tasks")
                lines.append(f"**Usage**: Run `{file_name} --help` for options")
                
        else:
            # More technical details
            lines.append(f"**Path**: /usr/bin/{file_name}")
            lines.append(f"**Size**: {metadata.get('file_size', 0):,} bytes")
            lines.append(f"**Type**: {metadata.get('mime_type', 'Unknown')}")
            
            if 'binary_info' in analysis and analysis['binary_info']:
                bi = analysis['binary_info']
                if 'format' in bi:
                    lines.append(f"**Format**: {bi['format']}")
                if 'arch' in bi:
                    lines.append(f"**Architecture**: {bi['arch']}")
                    
        return '\n'.join(lines)
        
    def _create_library_answer(self, file_name: str, libs: List[str], 
                              expertise: str) -> str:
        """Create answer about library dependencies."""
        lines = [f"# Library Dependencies of {file_name}\n"]
        
        lines.append(f"The binary uses {len(libs)} shared libraries:\n")
        
        # Group common libraries
        system_libs = [l for l in libs if 'libc.so' in l or 'libpthread' in l]
        security_libs = [l for l in libs if 'libssl' in l or 'libcrypto' in l]
        
        if system_libs:
            lines.append("## System Libraries")
            for lib in system_libs[:5]:
                lines.append(f"- `{lib}` - Core system functionality")
                
        if security_libs:
            lines.append("\n## Security Libraries")
            for lib in security_libs:
                lines.append(f"- `{lib}` - Cryptographic operations")
                
        # Other libraries
        other_libs = [l for l in libs if l not in system_libs + security_libs]
        if other_libs:
            lines.append("\n## Additional Libraries")
            for lib in other_libs[:10]:
                lines.append(f"- `{lib}`")
                
        return '\n'.join(lines)
        
    def _create_function_answer(self, file_name: str, functions: List[str],
                               expertise: str) -> str:
        """Create answer about functions."""
        lines = [f"# Functions in {file_name}\n"]
        
        lines.append("Key functions found in the binary:\n")
        
        # Categorize functions
        main_funcs = [f for f in functions if 'main' in f.lower()]
        init_funcs = [f for f in functions if 'init' in f or '_start' in f]
        
        if main_funcs:
            lines.append("## Entry Points")
            for func in main_funcs[:5]:
                lines.append(f"- `{func}`")
                
        if init_funcs:
            lines.append("\n## Initialization")
            for func in init_funcs[:5]:
                lines.append(f"- `{func}`")
                
        # Other functions
        other_funcs = [f for f in functions if f not in main_funcs + init_funcs]
        if other_funcs:
            lines.append("\n## Other Functions")
            for func in other_funcs[:15]:
                lines.append(f"- `{func}`")
                
        return '\n'.join(lines)
        
    def _create_security_answer(self, file_name: str, analysis: Dict[str, Any]) -> str:
        """Create security-focused answer."""
        lines = [f"# Security Analysis of {file_name}\n"]
        
        risk_score = 0
        findings = []
        
        # Check vulnerabilities
        if 'vulnerabilities' in analysis and isinstance(analysis['vulnerabilities'], dict):
            risk_data = analysis['vulnerabilities'].get('risk_assessment', {})
            if risk_data:
                vuln_count = risk_data.get('total_vulnerabilities', 0)
                if vuln_count > 0:
                    risk_score += 30
                    findings.append(f"⚠️ {vuln_count} known vulnerabilities")
                    
        # Check signatures
        if 'signatures' in analysis and isinstance(analysis['signatures'], dict):
            if not analysis['signatures'].get('signed', True):
                risk_score += 20
                findings.append("❌ Binary is not digitally signed")
                
        # Check entropy (potential packing)
        if 'entropy' in analysis and isinstance(analysis['entropy'], dict):
            entropy_val = analysis['entropy'].get('overall_entropy', 0)
            if entropy_val > 7.5:
                risk_score += 30
                findings.append(f"🔍 High entropy ({entropy_val:.2f}) - possible packing")
                
        # Generate assessment
        if risk_score >= 50:
            lines.append("## Risk Level: 🔴 HIGH\n")
        elif risk_score >= 20:
            lines.append("## Risk Level: 🟠 MEDIUM\n")
        else:
            lines.append("## Risk Level: 🟢 LOW\n")
            
        lines.append(f"**Overall Risk Score**: {risk_score}/100\n")
        
        if findings:
            lines.append("## Security Findings\n")
            for finding in findings:
                lines.append(finding)
        else:
            lines.append("✅ No significant security concerns detected")
            
        # Add recommendations
        lines.append("\n## Recommendations\n")
        if risk_score >= 50:
            lines.append("- Review file permissions and access controls")
            lines.append("- Monitor execution with system call tracing")
            lines.append("- Consider running in isolated environment")
        else:
            lines.append("- Standard system utility with normal risk profile")
            lines.append("- Keep system updated for security patches")
            
        return '\n'.join(lines)
        
    def _create_technical_answer(self, file_name: str, analysis: Dict[str, Any]) -> str:
        """Create technical deep-dive answer."""
        lines = [f"# Binary Analysis of {file_name}\n"]
        
        if 'binary_info' in analysis and analysis['binary_info']:
            bi = analysis['binary_info']
            
            lines.append("## Binary Format\n")
            lines.append(f"**Type**: {bi.get('format', 'Unknown')}")
            lines.append(f"**Architecture**: {bi.get('arch', 'Unknown')}")
            
            if 'machine' in bi:
                lines.append(f"**Machine**: {bi['machine']}")
            if 'entry_point' in bi:
                lines.append(f"**Entry Point**: 0x{bi['entry_point']:x}")
            if 'compiler' in bi:
                lines.append(f"**Compiler**: {bi['compiler']}")
                
            if 'sections' in bi and bi['sections']:
                lines.append("\n## Sections\n")
                for section in bi['sections'][:8]:
                    if isinstance(section, dict):
                        name = section.get('name', 'Unknown')
                        size = section.get('size', 0)
                        lines.append(f"- `{name}`: {size:,} bytes")
                        
        # Add hash information
        if 'hashes' in analysis and analysis['hashes']:
            lines.append("\n## File Hashes\n")
            hashes = analysis['hashes']
            if 'md5' in hashes:
                lines.append(f"**MD5**: `{hashes['md5']}`")
            if 'sha256' in hashes:
                lines.append(f"**SHA256**: `{hashes['sha256']}`")
                
        return '\n'.join(lines)
        
    def _create_usage_answer(self, util: str, analysis: Dict[str, Any]) -> str:
        """Create practical usage answer."""
        lines = [f"# Using {util}\n"]
        
        # Common utilities with examples
        examples = {
            'ls': [
                "`ls` - List files in current directory",
                "`ls -la` - List all files with details",
                "`ls -lh` - Human-readable file sizes",
                "`ls *.txt` - List only .txt files"
            ],
            'cp': [
                "`cp file1 file2` - Copy file1 to file2",
                "`cp -r dir1 dir2` - Copy directory recursively",
                "`cp -i file1 file2` - Interactive mode (confirm overwrite)",
                "`cp -p file1 file2` - Preserve permissions"
            ],
            'grep': [
                "`grep 'pattern' file` - Search for pattern in file",
                "`grep -i 'pattern' file` - Case-insensitive search",
                "`grep -r 'pattern' dir/` - Recursive search in directory",
                "`grep -n 'pattern' file` - Show line numbers"
            ],
            'find': [
                "`find . -name '*.txt'` - Find all .txt files",
                "`find /home -size +10M` - Find files larger than 10MB",
                "`find . -mtime -7` - Files modified in last 7 days",
                "`find . -type d` - Find only directories"
            ]
        }
        
        if util in examples:
            lines.append("## Common Examples\n")
            for example in examples[util]:
                lines.append(example)
        else:
            lines.append(f"**Basic Usage**: `{util} [options] [arguments]`")
            lines.append(f"\nFor detailed options, run: `{util} --help`")
            
        # Add general info
        metadata = analysis.get('metadata', {})
        lines.append(f"\n## File Information\n")
        lines.append(f"**Size**: {metadata.get('file_size', 0):,} bytes")
        lines.append(f"**Type**: {metadata.get('mime_type', 'Unknown')}")
        
        return '\n'.join(lines)
        
    def _compress_output(self, output_file: Path):
        """Compress the output file."""
        print("\nCompressing output...")
        
        gz_file = output_file.with_suffix('.jsonl.gz')
        
        with open(output_file, 'rb') as f_in:
            with gzip.open(gz_file, 'wb') as f_out:
                f_out.writelines(f_in)
                
        # Remove uncompressed
        output_file.unlink()
        
        compressed_size = gz_file.stat().st_size
        print(f"Compressed to: {gz_file}")
        print(f"Size: {compressed_size:,} bytes")
        
    def generate_statistics(self):
        """Generate statistics about the training data."""
        print("\n=== Training Data Statistics ===\n")
        
        print(f"Total analysis files: {len(self.analyses)}")
        print(f"Total training examples: {self.generated_count}")
        print(f"Examples per file: {self.generated_count / len(self.analyses):.1f}")
        
        # File type distribution
        mime_types = {}
        for analysis in self.analyses.values():
            mime_type = analysis.get('metadata', {}).get('mime_type', 'Unknown')
            mime_types[mime_type] = mime_types.get(mime_type, 0) + 1
            
        print("\nFile type distribution:")
        for mime_type, count in sorted(mime_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {mime_type}: {count}")

def main():
    """Run the combined training data generator."""
    print("=== Combined Ubuntu Binary Training Data Generator ===\n")
    
    generator = CombinedTrainingGenerator("/tmp/combined_training")
    
    # Load all analyses
    generator.load_analyses()
    
    if not generator.analyses:
        print("No analysis files found. Exiting.")
        return
        
    # Generate training data
    generator.generate_training_data()
    
    # Show statistics
    generator.generate_statistics()
    
    print("\n✅ Training data generation complete!")

if __name__ == "__main__":
    main()
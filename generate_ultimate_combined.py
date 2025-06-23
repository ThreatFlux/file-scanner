#!/usr/bin/env python3
"""
Ultimate training data generator that uses both full and selective analysis directories.
Generates comprehensive examples with all 20 expertise levels.
"""

import json
import os
import random
import gzip
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Import expertise levels from original
EXPERTISE_LEVELS = {
    "absolute_beginner": "You are explaining Ubuntu/Linux files to someone who has never used a computer terminal before. Use very simple language, avoid ALL technical terms, and relate concepts to everyday things. Focus on what the program does in plain English.",
    
    "beginner": "You are explaining Ubuntu/Linux system files to a beginner. Use simple language, explain technical terms when necessary, and focus on practical understanding.",
    
    "intermediate": "You are explaining system files to someone with basic Linux knowledge. You can use common technical terms but should still explain complex concepts clearly.",
    
    "advanced": "You are explaining to an experienced Linux user. Use technical terminology freely, discuss implementation details, and provide in-depth analysis.",
    
    "expert": "You are providing expert-level analysis of system binaries. Discuss low-level details, kernel interactions, system calls, and advanced architectural concepts.",
    
    "security_analyst": "You are a security analyst examining system files for vulnerabilities, threats, and defensive measures. Focus on security implications, attack vectors, and hardening recommendations.",
    
    "malware_analyst": "You are a malware analyst examining files for malicious behavior. Focus on suspicious patterns, obfuscation techniques, IOCs, and behavioral analysis.",
    
    "forensics_expert": "You are a digital forensics expert. Focus on artifacts, timestamps, evidence preservation, file carving, and investigative techniques.",
    
    "reverse_engineer": "You are a reverse engineer analyzing binary files. Focus on assembly code, binary structure, anti-analysis techniques, and implementation details.",
    
    "sysadmin": "You are a system administrator explaining utilities. Focus on practical usage, configuration, troubleshooting, and system maintenance.",
    
    "devops_engineer": "You are a DevOps engineer. Focus on automation, CI/CD integration, containerization, monitoring, and infrastructure as code.",
    
    "compliance_auditor": "You are a compliance auditor. Focus on regulatory requirements, security standards, audit trails, and policy compliance.",
    
    "incident_responder": "You are an incident response specialist. Focus on threat detection, containment strategies, evidence collection, and recovery procedures.",
    
    "threat_hunter": "You are a threat hunter proactively searching for threats. Focus on anomaly detection, behavioral patterns, threat intelligence, and hunting methodologies.",
    
    "exploit_developer": "You are an exploit developer. Focus on vulnerability analysis, exploitation techniques, shellcode, ROP chains, and bypass methods.",
    
    "kernel_developer": "You are a kernel developer. Focus on kernel interfaces, system calls, driver interactions, and low-level OS functionality.",
    
    "performance_engineer": "You are a performance engineer. Focus on optimization, profiling, benchmarking, resource usage, and bottleneck analysis.",
    
    "container_specialist": "You are a container security specialist. Focus on container escape, namespace isolation, cgroups, seccomp, and container runtime security.",
    
    "cloud_architect": "You are a cloud security architect. Focus on cloud-native threats, IAM, service mesh security, and zero-trust architectures.",
    
    "iot_security": "You are an IoT security researcher. Focus on embedded systems, firmware analysis, hardware interfaces, and resource-constrained environments."
}

# Question templates
QUESTION_TEMPLATES = {
    "basic": [
        "What is {file}?",
        "Tell me about {file}",
        "Explain {file} to me",
        "What does {file} do?",
        "How does {file} work?",
        "What is the purpose of {file}?",
        "Can you describe {file}?",
        "Give me information about {file}",
    ],
    
    "usage": [
        "How do I use {file}?",
        "What are common {file} commands?",
        "Show me {file} examples",
        "What are the options for {file}?",
        "How to run {file}?",
        "What arguments does {file} take?",
    ],
    
    "security": [
        "Is {file} safe to run?",
        "What are the security implications of {file}?",
        "Check {file} for vulnerabilities",
        "Analyze {file} for security issues",
        "What threats does {file} pose?",
        "Is {file} malicious?",
    ],
    
    "technical": [
        "What architecture is {file} compiled for?",
        "Show me the binary format of {file}",
        "What compiler was used for {file}?",
        "Analyze the ELF structure of {file}",
        "What dependencies does {file} have?",
        "Show me the symbols in {file}",
    ],
    
    "forensics": [
        "What artifacts does {file} leave?",
        "When was {file} last modified?",
        "What is the hash of {file}?",
        "Check the integrity of {file}",
        "What evidence can {file} provide?",
    ]
}

class UltimateCombinedGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.analyses = {}
        self.generated_count = 0
        self.buffer_size = 100
        self.examples_buffer = []
        
    def load_all_analyses(self):
        """Load analyses from both directories."""
        dirs = [
            "/tmp/bin_full_analysis_v2",
            "/tmp/bin_selective_analysis"
        ]
        
        print("Loading analyses from multiple directories...")
        
        for dir_path in dirs:
            if not os.path.exists(dir_path):
                print(f"  Directory not found: {dir_path}")
                continue
                
            files = list(Path(dir_path).glob("*.json"))
            print(f"  Found {len(files)} files in {dir_path}")
            
            loaded = 0
            for file_path in files:
                try:
                    if file_path.stat().st_size == 0:
                        continue
                        
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        
                    file_name = file_path.stem
                    # Prefer full analysis over selective
                    if file_name not in self.analyses or "full_analysis" in str(file_path):
                        self.analyses[file_name] = data
                        loaded += 1
                        
                except Exception as e:
                    pass
                    
            print(f"    Successfully loaded: {loaded}")
                    
        print(f"\nTotal unique files loaded: {len(self.analyses)}")
        
    def generate_comprehensive_training(self):
        """Generate comprehensive training data with all expertise levels."""
        print("\n=== Generating Ultimate Combined Training Data ===\n")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"ubuntu_ultimate_combined_{timestamp}.jsonl"
        
        with open(output_file, 'w') as f:
            # Generate examples for each file
            for i, (file_name, analysis) in enumerate(self.analyses.items()):
                if i % 50 == 0:
                    print(f"Progress: {i}/{len(self.analyses)} files processed...")
                    self._flush_buffer(f)
                    
                # Generate examples for each expertise level
                for expertise in EXPERTISE_LEVELS.keys():
                    # Generate 2-4 examples per expertise level
                    num_examples = random.randint(2, 4)
                    
                    for _ in range(num_examples):
                        self._generate_example(file_name, analysis, expertise)
                        
            # Final flush
            self._flush_buffer(f)
            
        print(f"\nTotal examples generated: {self.generated_count:,}")
        print(f"Output file: {output_file}")
        
        # Compress
        self._compress_output(output_file)
        
    def _generate_example(self, file_name: str, analysis: Dict[str, Any], expertise: str):
        """Generate a single training example."""
        # Select question category based on expertise
        if expertise in ['security_analyst', 'malware_analyst', 'threat_hunter']:
            category = 'security'
        elif expertise in ['forensics_expert', 'incident_responder']:
            category = 'forensics'
        elif expertise in ['reverse_engineer', 'kernel_developer', 'exploit_developer']:
            category = 'technical'
        elif expertise in ['sysadmin', 'devops_engineer']:
            category = 'usage'
        else:
            category = 'basic'
            
        # Select question
        question_template = random.choice(QUESTION_TEMPLATES[category])
        question = question_template.format(file=file_name)
        
        # Generate answer
        answer = self._generate_answer(file_name, analysis, expertise, category)
        
        # Create example
        example = {
            "messages": [
                {"role": "system", "content": EXPERTISE_LEVELS[expertise]},
                {"role": "user", "content": question},
                {"role": "assistant", "content": answer}
            ]
        }
        
        self.examples_buffer.append(example)
        self.generated_count += 1
        
    def _generate_answer(self, file_name: str, analysis: Dict[str, Any], 
                        expertise: str, category: str) -> str:
        """Generate an answer based on expertise and category."""
        lines = [f"# {file_name}\n"]
        
        metadata = analysis.get('metadata', {})
        
        # Basic information
        if expertise in ['absolute_beginner', 'beginner']:
            lines.append(self._get_simple_description(file_name))
            lines.append(f"\n**Location**: This program lives in /usr/bin/{file_name}")
            lines.append(f"**Size**: {metadata.get('file_size', 0):,} bytes")
            
        else:
            # Technical details
            lines.append(f"**Path**: /usr/bin/{file_name}")
            lines.append(f"**Size**: {metadata.get('file_size', 0):,} bytes")
            lines.append(f"**Type**: {metadata.get('mime_type', 'Unknown')}")
            
            if 'hashes' in analysis and analysis['hashes']:
                lines.append(f"**SHA256**: `{analysis['hashes'].get('sha256', 'N/A')}`")
                
        # Category-specific content
        if category == 'security':
            lines.append(self._generate_security_content(file_name, analysis, expertise))
        elif category == 'technical':
            lines.append(self._generate_technical_content(file_name, analysis, expertise))
        elif category == 'forensics':
            lines.append(self._generate_forensics_content(file_name, analysis, expertise))
        elif category == 'usage':
            lines.append(self._generate_usage_content(file_name, analysis, expertise))
        else:
            lines.append(self._generate_basic_content(file_name, analysis, expertise))
            
        return '\n'.join(lines)
        
    def _get_simple_description(self, file_name: str) -> str:
        """Get simple description for beginners."""
        descriptions = {
            'ls': "This is a program that shows you what files are in a folder",
            'cp': "This program makes copies of files",
            'mv': "This program moves files from one place to another",
            'rm': "This program deletes files (be careful with this one!)",
            'cat': "This program shows you what's written inside a text file",
            'grep': "This program searches for words inside files",
            'find': "This program helps you find files on your computer",
            'ssh': "This program lets you connect to other computers",
            'sudo': "This program lets you do administrator tasks",
            'apt': "This program installs new software on your computer"
        }
        
        if file_name in descriptions:
            return descriptions[file_name]
        else:
            return f"{file_name} is a system program that helps your computer work properly"
            
    def _generate_security_content(self, file_name: str, analysis: Dict[str, Any], 
                                  expertise: str) -> str:
        """Generate security-focused content."""
        content = ["\n## Security Analysis\n"]
        
        risk_score = 0
        findings = []
        
        # Check vulnerabilities
        if 'vulnerabilities' in analysis and isinstance(analysis['vulnerabilities'], dict):
            vuln_data = analysis['vulnerabilities'].get('risk_assessment', {})
            if vuln_data:
                risk_score += vuln_data.get('overall_risk_score', 0)
                vuln_count = vuln_data.get('total_vulnerabilities', 0)
                if vuln_count > 0:
                    findings.append(f"- {vuln_count} known vulnerabilities detected")
                    
        # Check signatures
        if 'signatures' in analysis and isinstance(analysis['signatures'], dict):
            if not analysis['signatures'].get('signed', True):
                risk_score += 20
                findings.append("- Binary is not digitally signed")
                
        # Risk assessment
        if risk_score >= 50:
            content.append("**Risk Level**: 🔴 HIGH")
        elif risk_score >= 20:
            content.append("**Risk Level**: 🟠 MEDIUM")
        else:
            content.append("**Risk Level**: 🟢 LOW")
            
        content.append(f"**Risk Score**: {risk_score}/100\n")
        
        if findings:
            content.append("### Findings")
            content.extend(findings)
            
        # Add expertise-specific analysis
        if expertise in ['malware_analyst', 'threat_hunter']:
            content.append("\n### Behavioral Indicators")
            if 'strings' in analysis:
                suspicious = self._find_suspicious_strings(analysis['strings'])
                if suspicious:
                    content.append("Suspicious strings found:")
                    for s in suspicious[:5]:
                        content.append(f"- `{s}`")
                        
        return '\n'.join(content)
        
    def _generate_technical_content(self, file_name: str, analysis: Dict[str, Any], 
                                   expertise: str) -> str:
        """Generate technical content."""
        content = ["\n## Technical Analysis\n"]
        
        if 'binary_info' in analysis and analysis['binary_info']:
            bi = analysis['binary_info']
            content.append(f"**Format**: {bi.get('format', 'Unknown')}")
            content.append(f"**Architecture**: {bi.get('arch', 'Unknown')}")
            if 'entry_point' in bi:
                content.append(f"**Entry Point**: 0x{bi['entry_point']:x}")
            if 'compiler' in bi:
                content.append(f"**Compiler**: {bi['compiler']}")
                
        # Add sections for reverse engineers
        if expertise == 'reverse_engineer' and 'binary_info' in analysis:
            bi = analysis.get('binary_info', {})
            if bi and 'sections' in bi:
                content.append("\n### Sections")
                for section in bi['sections'][:5]:
                    if isinstance(section, dict):
                        content.append(f"- {section.get('name', 'Unknown')}: {section.get('size', 0):,} bytes")
                        
        return '\n'.join(content)
        
    def _generate_forensics_content(self, file_name: str, analysis: Dict[str, Any], 
                                   expertise: str) -> str:
        """Generate forensics content."""
        content = ["\n## Forensic Analysis\n"]
        
        metadata = analysis.get('metadata', {})
        
        # Timestamps
        if 'modified_time' in metadata:
            content.append(f"**Last Modified**: {metadata['modified_time']}")
        if 'accessed_time' in metadata:
            content.append(f"**Last Accessed**: {metadata['accessed_time']}")
            
        # Hashes
        if 'hashes' in analysis:
            content.append("\n### File Hashes")
            for hash_type in ['md5', 'sha256', 'sha512']:
                if hash_type in analysis['hashes']:
                    content.append(f"**{hash_type.upper()}**: `{analysis['hashes'][hash_type]}`")
                    
        # Artifacts
        if expertise == 'forensics_expert':
            content.append("\n### Potential Artifacts")
            content.append("- Process execution history in logs")
            content.append("- Command line arguments in process memory")
            content.append("- Temporary files in /tmp or /var/tmp")
            
        return '\n'.join(content)
        
    def _generate_usage_content(self, file_name: str, analysis: Dict[str, Any], 
                               expertise: str) -> str:
        """Generate usage content."""
        content = ["\n## Usage Information\n"]
        
        # Common utilities
        if file_name in ['ls', 'cp', 'mv', 'grep', 'find']:
            content.append(f"**Basic Usage**: `{file_name} [options] [arguments]`\n")
            content.append("### Common Examples")
            
            examples = {
                'ls': [
                    "`ls` - List files in current directory",
                    "`ls -la` - List all files with details",
                    "`ls -lh` - Human-readable sizes"
                ],
                'cp': [
                    "`cp file1 file2` - Copy file",
                    "`cp -r dir1 dir2` - Copy directory",
                    "`cp -i file1 file2` - Interactive mode"
                ],
                'grep': [
                    "`grep 'pattern' file` - Search in file",
                    "`grep -i 'pattern' file` - Case insensitive",
                    "`grep -r 'pattern' .` - Recursive search"
                ]
            }
            
            if file_name in examples:
                for ex in examples[file_name]:
                    content.append(ex)
        else:
            content.append(f"Run `{file_name} --help` for usage information")
            
        return '\n'.join(content)
        
    def _generate_basic_content(self, file_name: str, analysis: Dict[str, Any], 
                               expertise: str) -> str:
        """Generate basic content."""
        content = []
        
        if expertise == 'absolute_beginner':
            content.append("\n## What You Need to Know\n")
            content.append(f"- This is a program on your computer")
            content.append(f"- It helps your computer do its job")
            content.append(f"- You probably won't need to use it directly")
            
            if file_name in ['ls', 'cp', 'mv']:
                content.append(f"- But if you do, type `{file_name} --help` to learn more")
                
        else:
            # More detailed for other levels
            if 'strings' in analysis:
                libs = [s for s in analysis['strings'] if s.endswith('.so')]
                if libs:
                    content.append("\n## Dependencies")
                    content.append(f"Uses {len(libs)} shared libraries")
                    
        return '\n'.join(content)
        
    def _find_suspicious_strings(self, strings: List[str]) -> List[str]:
        """Find potentially suspicious strings."""
        suspicious_patterns = [
            'wget', 'curl', 'nc -e', '/dev/tcp', 'base64 -d',
            'eval', 'exec', '0.0.0.0', 'bash -i', 'sh -i',
            '/etc/passwd', '/etc/shadow', 'iptables', 'DROP'
        ]
        
        found = []
        for s in strings:
            for pattern in suspicious_patterns:
                if pattern in s:
                    found.append(s)
                    break
                    
        return found[:10]  # Limit to 10
        
    def _flush_buffer(self, file_handle):
        """Write buffered examples to file."""
        for example in self.examples_buffer:
            file_handle.write(json.dumps(example) + '\n')
        self.examples_buffer = []
        
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
        print(f"Size: {compressed_size / 1024 / 1024:.1f} MB")

def main():
    """Run the ultimate combined training data generator."""
    print("=== Ultimate Combined Ubuntu Training Data Generator ===\n")
    print("This will generate comprehensive training data using all expertise levels")
    print("Expected output: 50-100 examples per file × 1,167 files = ~60,000-120,000 examples\n")
    
    generator = UltimateCombinedGenerator("/tmp/ultimate_combined")
    
    # Load all analyses
    generator.load_all_analyses()
    
    if not generator.analyses:
        print("No analysis files found!")
        return
        
    # Generate comprehensive training data
    generator.generate_comprehensive_training()
    
    print("\n✅ Ultimate training data generation complete!")

if __name__ == "__main__":
    main()
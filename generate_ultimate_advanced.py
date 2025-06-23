#!/usr/bin/env python3
"""
Advanced ultimate training data generator that creates rich, detailed answers.
"""

import json
import os
import random
import gzip
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from generate_ultimate_training_data import EXPERTISE_LEVELS

class AdvancedUltimateGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.analyses = {}
        self.generated_count = 0
        self.buffer_size = 100
        self.examples_buffer = []
        
    def load_all_analyses(self):
        """Load analyses from both directories."""
        dirs = ["/tmp/bin_full_analysis_v2", "/tmp/bin_selective_analysis"]
        
        print("Loading analyses from multiple directories...")
        
        for dir_path in dirs:
            if not os.path.exists(dir_path):
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
                    # Prefer full analysis
                    if file_name not in self.analyses or "full_analysis" in str(file_path):
                        self.analyses[file_name] = data
                        
                except Exception:
                    pass
                    
        print(f"\nTotal unique files loaded: {len(self.analyses)}")
        
    def generate_advanced_training(self):
        """Generate training data with rich, detailed content."""
        print("\n=== Generating Advanced Ultimate Training Data ===\n")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"ubuntu_ultimate_advanced_{timestamp}.jsonl"
        
        with open(output_file, 'w') as f:
            for i, (file_name, analysis) in enumerate(self.analyses.items()):
                if i % 50 == 0:
                    print(f"Progress: {i}/{len(self.analyses)} files...")
                    self._flush_buffer(f)
                    
                # Generate 40-80 examples per file with varied expertise
                for expertise in EXPERTISE_LEVELS.keys():
                    num_examples = random.randint(2, 4)
                    for _ in range(num_examples):
                        self._generate_rich_example(file_name, analysis, expertise)
                        
            self._flush_buffer(f)
            
        print(f"\nTotal examples generated: {self.generated_count:,}")
        print(f"Output file: {output_file}")
        
        self._compress_output(output_file)
        
    def _generate_rich_example(self, file_name: str, analysis: Dict[str, Any], expertise: str):
        """Generate example with rich, detailed content."""
        # Question selection based on expertise
        questions = {
            'absolute_beginner': [
                f"What is {file_name}?",
                f"What does {file_name} do?",
                f"How do I use {file_name}?"
            ],
            'security_analyst': [
                f"Analyze {file_name} for security vulnerabilities",
                f"What are the security implications of running {file_name}?",
                f"Check {file_name} for malicious behavior",
                f"Is {file_name} safe to execute?"
            ],
            'reverse_engineer': [
                f"Show me the binary structure of {file_name}",
                f"Analyze the assembly code of {file_name}",
                f"What compiler optimizations were used in {file_name}?",
                f"Explain the entry point of {file_name}"
            ],
            'malware_analyst': [
                f"Check {file_name} for malware indicators",
                f"Analyze the behavioral patterns of {file_name}",
                f"What IOCs are present in {file_name}?",
                f"Is {file_name} packed or obfuscated?"
            ],
            'forensics_expert': [
                f"What forensic artifacts does {file_name} leave?",
                f"Show me the timeline analysis for {file_name}",
                f"What evidence can {file_name} provide?",
                f"Analyze the metadata of {file_name}"
            ]
        }
        
        # Get appropriate questions
        question_list = questions.get(expertise, questions['absolute_beginner'])
        question = random.choice(question_list)
        
        # Generate comprehensive answer
        answer = self._create_comprehensive_answer(file_name, analysis, expertise)
        
        example = {
            "messages": [
                {"role": "system", "content": EXPERTISE_LEVELS[expertise]},
                {"role": "user", "content": question},
                {"role": "assistant", "content": answer}
            ]
        }
        
        self.examples_buffer.append(example)
        self.generated_count += 1
        
    def _create_comprehensive_answer(self, file_name: str, analysis: Dict[str, Any], 
                                    expertise: str) -> str:
        """Create a comprehensive answer using all available data."""
        sections = []
        
        # Header
        sections.append(f"# {file_name}")
        
        # Basic metadata (always include)
        metadata = analysis.get('metadata', {})
        basic_info = [
            f"**Path**: /usr/bin/{file_name}",
            f"**Size**: {metadata.get('file_size', 0):,} bytes",
            f"**Type**: {metadata.get('mime_type', 'Unknown')}"
        ]
        
        # Add permissions for security roles
        if expertise in ['security_analyst', 'forensics_expert'] and 'permissions' in metadata:
            basic_info.append(f"**Permissions**: {metadata.get('permissions', 'Unknown')}")
            
        sections.append('\n'.join(basic_info))
        
        # Hashes for verification
        if 'hashes' in analysis and analysis['hashes']:
            if expertise != 'absolute_beginner':
                hash_section = ["\n## File Hashes"]
                for hash_type in ['md5', 'sha256', 'sha512']:
                    if hash_type in analysis['hashes']:
                        hash_section.append(f"**{hash_type.upper()}**: `{analysis['hashes'][hash_type]}`")
                sections.append('\n'.join(hash_section))
                
        # Binary information for technical roles
        if expertise in ['reverse_engineer', 'malware_analyst', 'exploit_developer'] and 'binary_info' in analysis:
            bi = analysis['binary_info']
            if bi:
                binary_section = ["\n## Binary Analysis"]
                if 'format' in bi:
                    binary_section.append(f"**Format**: {bi['format']}")
                if 'arch' in bi:
                    binary_section.append(f"**Architecture**: {bi['arch']}")
                if 'machine' in bi:
                    binary_section.append(f"**Machine**: {bi['machine']}")
                if 'entry_point' in bi:
                    binary_section.append(f"**Entry Point**: 0x{bi['entry_point']:x}")
                if 'compiler' in bi:
                    binary_section.append(f"**Compiler**: {bi['compiler']}")
                    
                # Add sections
                if 'sections' in bi and bi['sections']:
                    binary_section.append("\n### Sections")
                    for section in bi['sections'][:8]:
                        if isinstance(section, dict):
                            name = section.get('name', 'Unknown')
                            size = section.get('size', 0)
                            perms = section.get('permissions', '')
                            binary_section.append(f"- `{name}`: {size:,} bytes {perms}")
                            
                sections.append('\n'.join(binary_section))
                
        # Vulnerability analysis
        if expertise in ['security_analyst', 'threat_hunter', 'incident_responder']:
            vuln_section = self._generate_vulnerability_section(analysis)
            if vuln_section:
                sections.append(vuln_section)
                
        # String analysis for various roles
        if 'strings' in analysis and analysis['strings']:
            string_section = self._generate_string_section(analysis['strings'], expertise)
            if string_section:
                sections.append(string_section)
                
        # Behavioral analysis
        if 'behavioral' in analysis and analysis['behavioral']:
            behav_section = self._generate_behavioral_section(analysis['behavioral'], expertise)
            if behav_section:
                sections.append(behav_section)
                
        # Threat analysis
        if 'threats' in analysis and analysis['threats'] and isinstance(analysis['threats'], list):
            threat_section = self._generate_threat_section(analysis['threats'], expertise)
            if threat_section:
                sections.append(threat_section)
                
        # Entropy analysis for packing detection
        if expertise in ['malware_analyst', 'reverse_engineer'] and 'entropy' in analysis:
            entropy_section = self._generate_entropy_section(analysis['entropy'])
            if entropy_section:
                sections.append(entropy_section)
                
        # Recommendations based on expertise
        recommendations = self._generate_recommendations(file_name, analysis, expertise)
        if recommendations:
            sections.append(recommendations)
            
        return '\n\n'.join(sections)
        
    def _generate_vulnerability_section(self, analysis: Dict[str, Any]) -> str:
        """Generate vulnerability analysis section."""
        if 'vulnerabilities' not in analysis:
            return ""
            
        vuln_data = analysis['vulnerabilities']
        if isinstance(vuln_data, dict) and 'risk_assessment' in vuln_data:
            risk = vuln_data['risk_assessment']
            vuln_list = vuln_data.get('vulnerabilities', [])
            
            section = ["## Security Analysis"]
            
            # Risk score
            score = risk.get('overall_risk_score', 0)
            if score >= 70:
                section.append(f"**Risk Level**: 🔴 CRITICAL ({score}/100)")
            elif score >= 50:
                section.append(f"**Risk Level**: 🟠 HIGH ({score}/100)")
            elif score >= 30:
                section.append(f"**Risk Level**: 🟡 MEDIUM ({score}/100)")
            else:
                section.append(f"**Risk Level**: 🟢 LOW ({score}/100)")
                
            # Vulnerability count
            if risk.get('total_vulnerabilities', 0) > 0:
                section.append(f"**Vulnerabilities Found**: {risk['total_vulnerabilities']}")
                
            # List specific vulnerabilities
            if vuln_list:
                section.append("\n### Known Vulnerabilities")
                for vuln in vuln_list[:5]:
                    if isinstance(vuln, dict):
                        cve = vuln.get('cve', 'Unknown')
                        severity = vuln.get('severity', 'Unknown')
                        desc = vuln.get('description', 'No description')
                        section.append(f"- **{cve}** ({severity}): {desc}")
                        
            return '\n'.join(section)
            
        return ""
        
    def _generate_string_section(self, strings: List[str], expertise: str) -> str:
        """Generate string analysis section."""
        if not strings:
            return ""
            
        section = ["## String Analysis"]
        
        # Different analysis based on expertise
        if expertise in ['security_analyst', 'malware_analyst', 'threat_hunter']:
            # Look for suspicious strings
            suspicious = []
            network = []
            system = []
            
            for s in strings:
                s_lower = s.lower()
                if any(x in s_lower for x in ['wget', 'curl', 'nc -e', 'bash -i', 'sh -i']):
                    suspicious.append(s)
                elif any(x in s_lower for x in ['http://', 'https://', 'ftp://', 'tcp://']):
                    network.append(s)
                elif any(x in s_lower for x in ['/etc/passwd', '/etc/shadow', 'sudo', 'setuid']):
                    system.append(s)
                    
            if suspicious:
                section.append("\n### ⚠️ Suspicious Strings")
                for s in suspicious[:5]:
                    section.append(f"- `{s}`")
                    
            if network:
                section.append("\n### 🌐 Network Indicators")
                for s in network[:5]:
                    section.append(f"- `{s}`")
                    
            if system:
                section.append("\n### 🔧 System Access")
                for s in system[:5]:
                    section.append(f"- `{s}`")
                    
        elif expertise == 'reverse_engineer':
            # Functions and symbols
            functions = [s for s in strings if '__' in s or s.endswith('()')]
            imports = [s for s in strings if s.endswith('.so')]
            
            if functions:
                section.append("\n### Function Names")
                for f in functions[:10]:
                    section.append(f"- `{f}`")
                    
            if imports:
                section.append("\n### Library Dependencies")
                for i in imports[:10]:
                    section.append(f"- `{i}`")
                    
        else:
            # Basic string stats
            section.append(f"**Total Strings**: {len(strings)}")
            section.append(f"**Unique Strings**: {len(set(strings))}")
            
        return '\n'.join(section) if len(section) > 1 else ""
        
    def _generate_behavioral_section(self, behavioral: Dict[str, Any], expertise: str) -> str:
        """Generate behavioral analysis section."""
        section = ["## Behavioral Analysis"]
        
        for key, value in behavioral.items():
            if value:
                section.append(f"**{key.replace('_', ' ').title()}**: {value}")
                
        return '\n'.join(section) if len(section) > 1 else ""
        
    def _generate_threat_section(self, threats: List[Any], expertise: str) -> str:
        """Generate threat analysis section."""
        if not threats:
            return ""
            
        section = ["## Threat Indicators"]
        section.append(f"**Threats Detected**: {len(threats)}")
        
        for threat in threats[:5]:
            if isinstance(threat, dict):
                section.append(f"- {threat.get('type', 'Unknown')}: {threat.get('description', '')}")
            else:
                section.append(f"- {threat}")
                
        return '\n'.join(section)
        
    def _generate_entropy_section(self, entropy: Dict[str, Any]) -> str:
        """Generate entropy analysis section."""
        if not entropy:
            return ""
            
        section = ["## Entropy Analysis"]
        
        overall = entropy.get('overall_entropy', 0)
        section.append(f"**Overall Entropy**: {overall:.2f}/8.0")
        
        if overall > 7.5:
            section.append("⚠️ **High entropy detected** - Possible packing or encryption")
        elif overall > 6.5:
            section.append("📊 **Moderate entropy** - Some compressed or encrypted sections")
        else:
            section.append("✅ **Normal entropy** - Typical compiled binary")
            
        # Section entropy if available
        if 'sections' in entropy and isinstance(entropy['sections'], dict):
            section.append("\n### Section Entropy")
            for sec_name, sec_entropy in entropy['sections'].items():
                section.append(f"- `{sec_name}`: {sec_entropy:.2f}")
                
        return '\n'.join(section)
        
    def _generate_recommendations(self, file_name: str, analysis: Dict[str, Any], 
                                 expertise: str) -> str:
        """Generate recommendations based on analysis."""
        recs = ["## Recommendations"]
        
        # Calculate overall risk
        risk_score = 0
        if 'vulnerabilities' in analysis and isinstance(analysis['vulnerabilities'], dict):
            risk_score += analysis['vulnerabilities'].get('risk_assessment', {}).get('overall_risk_score', 0)
        if 'threats' in analysis and analysis['threats']:
            risk_score += len(analysis['threats']) * 10
        if 'entropy' in analysis and analysis['entropy'].get('overall_entropy', 0) > 7.5:
            risk_score += 30
            
        if expertise == 'security_analyst':
            if risk_score >= 50:
                recs.extend([
                    "1. **Isolate**: Run in sandboxed environment",
                    "2. **Monitor**: Use process monitoring tools",
                    "3. **Verify**: Check file integrity against known good hashes",
                    "4. **Update**: Ensure latest security patches are applied"
                ])
            else:
                recs.extend([
                    "1. **Standard Precautions**: Follow normal security practices",
                    "2. **Updates**: Keep system and binary updated",
                    "3. **Monitoring**: Include in regular security scans"
                ])
                
        elif expertise == 'malware_analyst':
            recs.extend([
                "1. **Static Analysis**: Complete disassembly recommended",
                "2. **Dynamic Analysis**: Monitor in controlled environment",
                "3. **Network**: Capture all network traffic",
                "4. **Memory**: Dump process memory for analysis"
            ])
            
        elif expertise == 'sysadmin':
            recs.extend([
                f"1. **Usage**: Run `{file_name} --help` for options",
                "2. **Permissions**: Verify file permissions are correct",
                "3. **Logging**: Enable logging for audit trail"
            ])
            
        return '\n'.join(recs) if len(recs) > 1 else ""
        
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
                
        output_file.unlink()
        
        uncompressed = output_file.stat().st_size if output_file.exists() else 0
        compressed = gz_file.stat().st_size
        
        print(f"Compressed to: {gz_file}")
        print(f"Uncompressed: {uncompressed/1024/1024:.1f} MB")
        print(f"Compressed: {compressed/1024/1024:.1f} MB")
        print(f"Compression ratio: {uncompressed/compressed:.1f}x")

def main():
    print("=== Advanced Ultimate Training Data Generator ===\n")
    print("This generates comprehensive training data with rich, detailed content")
    print("Using all available analysis features for maximum value\n")
    
    generator = AdvancedUltimateGenerator("/tmp/ultimate_advanced")
    generator.load_all_analyses()
    
    if not generator.analyses:
        print("No analysis files found!")
        return
        
    generator.generate_advanced_training()
    print("\n✅ Advanced training data generation complete!")

if __name__ == "__main__":
    main()
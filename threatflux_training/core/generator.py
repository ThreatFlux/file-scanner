"""Main training data generator with comprehensive answer generation."""

import json
import gzip
import random
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import logging
from collections import defaultdict

from .expertise import ExpertiseManager
from .tokenizer import TokenCounter
from .analyzer import AnalysisLoader
from .multiprocess import MultiProcessTrainingGenerator

logger = logging.getLogger(__name__)

class AnswerBuilder:
    """Builds comprehensive answers from analysis data."""
    
    def __init__(self, max_tokens: int = 2000):
        self.max_tokens = max_tokens
        self.tokenizer = TokenCounter()
        
    def build_answer(self, file_name: str, analysis: Dict[str, Any], 
                    expertise: str, question: str) -> str:
        """Build a comprehensive answer based on the question and expertise."""
        sections = []
        current_tokens = 0
        
        # Always start with file identification
        header = f"# Analysis of {file_name}\n"
        sections.append(header)
        current_tokens += self.tokenizer.estimate_tokens(header)
        
        # Determine what to include based on question
        question_lower = question.lower()
        
        # Question-specific content selection
        if any(word in question_lower for word in ['vulnerability', 'cve', 'security', 'vulnerable']):
            content = self._build_vulnerability_section(analysis, expertise)
            if content:
                sections.append(content)
                
        elif any(word in question_lower for word in ['string', 'text', 'embedded']):
            content = self._build_strings_section(analysis, expertise, question)
            if content:
                sections.append(content)
                
        elif any(word in question_lower for word in ['hex', 'dump', 'bytes', 'binary']):
            content = self._build_hex_section(analysis, expertise, question)
            if content:
                sections.append(content)
                
        elif any(word in question_lower for word in ['disassembly', 'assembly', 'asm', 'instructions']):
            content = self._build_disassembly_section(analysis, expertise, question)
            if content:
                sections.append(content)
                
        elif any(word in question_lower for word in ['behavior', 'runtime', 'execute', 'run']):
            content = self._build_behavioral_section(analysis, expertise)
            if content:
                sections.append(content)
                
        elif any(word in question_lower for word in ['threat', 'malicious', 'malware', 'suspicious']):
            content = self._build_threat_section(analysis, expertise)
            if content:
                sections.append(content)
                
        elif any(word in question_lower for word in ['metadata', 'timestamp', 'permission', 'forensic']):
            content = self._build_metadata_section(analysis, expertise)
            if content:
                sections.append(content)
                
        elif any(word in question_lower for word in ['hash', 'md5', 'sha256', 'integrity']):
            content = self._build_hash_section(analysis)
            if content:
                sections.append(content)
                
        elif any(word in question_lower for word in ['structure', 'format', 'elf', 'architecture']):
            content = self._build_binary_structure_section(analysis, expertise)
            if content:
                sections.append(content)
                
        elif any(word in question_lower for word in ['dependency', 'library', 'import', 'symbol']):
            content = self._build_dependencies_section(analysis, expertise)
            if content:
                sections.append(content)
                
        else:
            # General comprehensive answer
            content = self._build_comprehensive_answer(file_name, analysis, expertise)
            sections.append(content)
            
        # Add recommendations if appropriate
        if expertise != 'absolute_beginner':
            recommendations = self._build_recommendations(file_name, analysis, expertise, question)
            if recommendations:
                sections.append(recommendations)
                
        # Join sections and check token limit
        full_answer = '\n\n'.join(sections)
        estimated_tokens = self.tokenizer.estimate_tokens(full_answer)
        
        if estimated_tokens > self.max_tokens:
            # Truncate intelligently
            return self.tokenizer.truncate_to_tokens(full_answer, self.max_tokens)
            
        return full_answer
        
    def _build_comprehensive_answer(self, file_name: str, analysis: Dict[str, Any], 
                                   expertise: str) -> str:
        """Build a comprehensive general answer."""
        sections = []
        
        # Basic information
        metadata = analysis.get('metadata', {})
        basic_info = [
            f"**File**: `/usr/bin/{file_name}`",
            f"**Size**: {metadata.get('file_size', 0):,} bytes",
            f"**Type**: {metadata.get('mime_type', 'Unknown')}",
            f"**Permissions**: {metadata.get('permissions', 'Unknown')}"
        ]
        
        if 'owner' in metadata:
            basic_info.append(f"**Owner**: {metadata['owner']}:{metadata.get('group', 'unknown')}")
            
        sections.append('\n'.join(basic_info))
        
        # Purpose and functionality
        sections.append(self._generate_purpose_description(file_name, analysis, expertise))
        
        # Technical details for appropriate expertise levels
        if expertise not in ['absolute_beginner', 'beginner', 'casual_user']:
            # Binary information
            if 'binary_info' in analysis and analysis['binary_info']:
                sections.append(self._build_binary_structure_section(analysis, expertise))
                
            # Security assessment
            security_content = []
            if 'vulnerabilities' in analysis:
                vuln_section = self._build_vulnerability_section(analysis, expertise)
                if vuln_section:
                    security_content.append(vuln_section)
                    
            if 'threats' in analysis:
                threat_section = self._build_threat_section(analysis, expertise)
                if threat_section:
                    security_content.append(threat_section)
                    
            if security_content:
                sections.append("## Security Assessment\n" + '\n'.join(security_content))
                
        # Key features based on analysis
        if 'strings' in analysis and analysis['strings']:
            key_strings = self._extract_key_strings(analysis['strings'], expertise)
            if key_strings:
                sections.append(f"## Key Features\n\n{key_strings}")
                
        return '\n\n'.join(sections)
        
    def _build_vulnerability_section(self, analysis: Dict[str, Any], expertise: str) -> str:
        """Build vulnerability analysis section."""
        if 'vulnerabilities' not in analysis:
            return ""
            
        vuln_data = analysis['vulnerabilities']
        if isinstance(vuln_data, dict) and 'risk_assessment' in vuln_data:
            sections = []
            risk = vuln_data['risk_assessment']
            vuln_list = vuln_data.get('vulnerabilities', [])
            
            # Risk score with visual indicator
            score = risk.get('overall_risk_score', 0)
            if score >= 70:
                risk_level = "🔴 **CRITICAL**"
            elif score >= 50:
                risk_level = "🟠 **HIGH**"
            elif score >= 30:
                risk_level = "🟡 **MEDIUM**"
            else:
                risk_level = "🟢 **LOW**"
                
            sections.append(f"### Vulnerability Assessment\n\n**Risk Level**: {risk_level} ({score}/100)")
            
            # Vulnerability details
            if vuln_list:
                sections.append(f"**Vulnerabilities Found**: {len(vuln_list)}\n")
                
                if expertise in ['security_analyst', 'incident_responder', 'exploit_developer']:
                    # Detailed view for security professionals
                    for vuln in vuln_list[:10]:
                        if isinstance(vuln, dict):
                            cve = vuln.get('cve', 'Unknown')
                            severity = vuln.get('severity', 'Unknown')
                            cvss = vuln.get('cvss_score', 'N/A')
                            desc = vuln.get('description', 'No description')
                            
                            sections.append(f"#### {cve}")
                            sections.append(f"- **Severity**: {severity}")
                            sections.append(f"- **CVSS Score**: {cvss}")
                            sections.append(f"- **Description**: {desc}")
                            
                            if 'affected_versions' in vuln:
                                sections.append(f"- **Affected Versions**: {vuln['affected_versions']}")
                            if 'fixed_in' in vuln:
                                sections.append(f"- **Fixed In**: {vuln['fixed_in']}")
                            sections.append("")
                else:
                    # Summary view for others
                    severity_counts = defaultdict(int)
                    for vuln in vuln_list:
                        if isinstance(vuln, dict):
                            severity_counts[vuln.get('severity', 'Unknown')] += 1
                            
                    sections.append("**Severity Distribution**:")
                    for severity, count in sorted(severity_counts.items()):
                        sections.append(f"- {severity}: {count}")
                        
            return '\n'.join(sections)
            
        return ""
        
    def _build_strings_section(self, analysis: Dict[str, Any], expertise: str, 
                              question: str) -> str:
        """Build strings analysis section."""
        if 'strings' not in analysis or not analysis['strings']:
            return "No strings found in this binary."
            
        strings = analysis['strings']
        sections = ["## String Analysis\n"]
        
        # Check for range-based questions
        import re
        range_match = re.search(r'(\d+)-(\d+)', question)
        offset_match = re.search(r'offset\s+(\d+)', question)
        pattern_match = re.search(r"'([^']+)'", question)
        
        if range_match:
            # Range-based string extraction
            start = int(range_match.group(1))
            end = int(range_match.group(2))
            selected_strings = strings[start:end]
            
            sections.append(f"**Strings {start}-{end}** (of {len(strings)} total):\n")
            for i, s in enumerate(selected_strings, start):
                sections.append(f"{i:4d}: `{s}`")
                
        elif offset_match:
            # Offset-based (approximate)
            offset = int(offset_match.group(1))
            window = 10
            start = max(0, offset - window)
            end = min(len(strings), offset + window)
            
            sections.append(f"**Strings around index {offset}**:\n")
            for i in range(start, end):
                marker = " <--" if i == offset else ""
                sections.append(f"{i:4d}: `{strings[i]}`{marker}")
                
        elif pattern_match:
            # Pattern matching
            pattern = pattern_match.group(1).lower()
            matching = [s for s in strings if pattern in s.lower()]
            
            sections.append(f"**Strings containing '{pattern}'** ({len(matching)} found):\n")
            for s in matching[:50]:
                sections.append(f"- `{s}`")
                
        else:
            # General string analysis based on expertise
            categorized = self._categorize_strings(strings)
            
            if expertise in ['security_analyst', 'malware_analyst', 'threat_hunter']:
                # Security-focused analysis
                if categorized['suspicious']:
                    sections.append("### ⚠️ Suspicious Strings\n")
                    for s in categorized['suspicious'][:20]:
                        sections.append(f"- `{s}`")
                        
                if categorized['network']:
                    sections.append("\n### 🌐 Network Indicators\n")
                    for s in categorized['network'][:20]:
                        sections.append(f"- `{s}`")
                        
                if categorized['system']:
                    sections.append("\n### 🔧 System Access\n")
                    for s in categorized['system'][:20]:
                        sections.append(f"- `{s}`")
                        
            elif expertise == 'reverse_engineer':
                # Technical analysis
                if categorized['functions']:
                    sections.append("### Function Names\n")
                    for s in categorized['functions'][:30]:
                        sections.append(f"- `{s}`")
                        
                if categorized['libraries']:
                    sections.append("\n### Library Dependencies\n")
                    for s in categorized['libraries'][:20]:
                        sections.append(f"- `{s}`")
                        
            else:
                # General statistics
                sections.append(f"**Total Strings**: {len(strings)}")
                sections.append(f"**Unique Strings**: {len(set(strings))}")
                sections.append(f"**Average Length**: {sum(len(s) for s in strings) / len(strings):.1f} characters")
                
                # Show some interesting strings
                interesting = categorized['commands'] + categorized['paths'] + categorized['configs']
                if interesting:
                    sections.append("\n### Notable Strings\n")
                    for s in interesting[:20]:
                        sections.append(f"- `{s}`")
                        
        return '\n'.join(sections)
        
    def _build_hex_section(self, analysis: Dict[str, Any], expertise: str, 
                          question: str) -> str:
        """Build hex dump section."""
        if 'hex_dump' not in analysis or not analysis['hex_dump']:
            return "No hex dump data available."
            
        hex_data = analysis['hex_dump']
        sections = ["## Hex Dump Analysis\n"]
        
        # Parse question for specific requirements
        import re
        offset_match = re.search(r'offset\s+(\d+)', question)
        size_match = re.search(r'(\d+)\s+bytes', question)
        
        if isinstance(hex_data, str):
            # Simple hex string
            lines = hex_data.strip().split('\n')
            
            if offset_match:
                offset = int(offset_match.group(1))
                # Show hex around the offset (simplified)
                sections.append(f"**Hex dump at offset {offset}**:\n")
                sections.append("```")
                sections.extend(lines[:20])  # Show first 20 lines
                sections.append("```")
            else:
                # Show header by default
                sections.append("**File Header**:\n```")
                sections.extend(lines[:16])  # First 256 bytes typically
                sections.append("```")
                
                # File signature analysis
                if expertise != 'absolute_beginner':
                    sig_analysis = self._analyze_file_signature(lines[0] if lines else "")
                    if sig_analysis:
                        sections.append(f"\n**File Signature**: {sig_analysis}")
                        
        elif isinstance(hex_data, dict):
            # Structured hex data
            if 'header' in hex_data:
                sections.append("**File Header**:\n```")
                sections.append(hex_data['header'])
                sections.append("```")
                
            if 'sections' in hex_data:
                sections.append("\n**Section Headers**:")
                for section in hex_data['sections'][:5]:
                    if isinstance(section, dict):
                        sections.append(f"\n`{section.get('name', 'Unknown')}`:")
                        sections.append("```")
                        sections.append(section.get('hex', ''))
                        sections.append("```")
                        
        return '\n'.join(sections)
        
    def _build_disassembly_section(self, analysis: Dict[str, Any], expertise: str,
                                  question: str) -> str:
        """Build disassembly section."""
        if 'disassembly' not in analysis or not analysis['disassembly']:
            return "No disassembly data available."
            
        disasm = analysis['disassembly']
        sections = ["## Disassembly Analysis\n"]
        
        # Check for specific function requests
        import re
        func_match = re.search(r'(main|_start|init|entry)', question.lower())
        
        if isinstance(disasm, dict):
            if func_match:
                func_name = func_match.group(1)
                if func_name in disasm:
                    sections.append(f"### Function: {func_name}\n```asm")
                    sections.append(disasm[func_name])
                    sections.append("```")
                else:
                    sections.append(f"Function '{func_name}' not found in disassembly.")
            else:
                # Show available functions
                functions = list(disasm.keys())[:10]
                sections.append(f"**Available Functions** ({len(disasm)} total):")
                for func in functions:
                    sections.append(f"- `{func}`")
                    
                # Show main or _start if available
                for preferred in ['main', '_start', 'entry_point']:
                    if preferred in disasm:
                        sections.append(f"\n### {preferred}\n```asm")
                        # Show first 50 lines
                        lines = disasm[preferred].split('\n')[:50]
                        sections.extend(lines)
                        if len(disasm[preferred].split('\n')) > 50:
                            sections.append("... (truncated)")
                        sections.append("```")
                        break
                        
        elif isinstance(disasm, list):
            # List of instructions
            sections.append("### Assembly Instructions\n```asm")
            for inst in disasm[:100]:
                if isinstance(inst, dict):
                    addr = inst.get('address', '0x0')
                    mnemonic = inst.get('mnemonic', '')
                    operands = inst.get('operands', '')
                    sections.append(f"{addr}: {mnemonic} {operands}")
                else:
                    sections.append(str(inst))
            sections.append("```")
            
        else:
            # Raw disassembly text
            sections.append("```asm")
            lines = str(disasm).split('\n')[:100]
            sections.extend(lines)
            if len(str(disasm).split('\n')) > 100:
                sections.append("... (truncated)")
            sections.append("```")
            
        # Add analysis for security experts
        if expertise in ['reverse_engineer', 'exploit_developer', 'malware_analyst']:
            patterns = self._analyze_assembly_patterns(str(disasm))
            if patterns:
                sections.append("\n### Assembly Pattern Analysis")
                sections.append(patterns)
                
        return '\n'.join(sections)
        
    def _build_behavioral_section(self, analysis: Dict[str, Any], expertise: str) -> str:
        """Build behavioral analysis section."""
        if 'behavioral' not in analysis or not analysis['behavioral']:
            return ""
            
        behavioral = analysis['behavioral']
        sections = ["### Behavioral Analysis\n"]
        
        if isinstance(behavioral, dict):
            # Categorize behaviors
            categories = {
                'Network': ['network_activity', 'opens_sockets', 'dns_queries'],
                'File System': ['file_operations', 'creates_files', 'modifies_files'],
                'Process': ['process_creation', 'thread_creation', 'memory_allocation'],
                'System': ['registry_access', 'system_calls', 'privilege_escalation']
            }
            
            for cat_name, keys in categories.items():
                cat_items = []
                for key in keys:
                    if key in behavioral and behavioral[key]:
                        cat_items.append(f"- **{key.replace('_', ' ').title()}**: {behavioral[key]}")
                        
                if cat_items:
                    sections.append(f"**{cat_name} Activity**:")
                    sections.extend(cat_items)
                    sections.append("")
                    
            # Risk indicators
            risk_indicators = []
            if behavioral.get('suspicious_behavior'):
                risk_indicators.append("⚠️ Suspicious behavior detected")
            if behavioral.get('anti_debugging'):
                risk_indicators.append("🔍 Anti-debugging techniques present")
            if behavioral.get('obfuscation'):
                risk_indicators.append("🔐 Code obfuscation detected")
                
            if risk_indicators:
                sections.append("**Risk Indicators**:")
                sections.extend(risk_indicators)
                
        return '\n'.join(sections)
        
    def _build_threat_section(self, analysis: Dict[str, Any], expertise: str) -> str:
        """Build threat analysis section."""
        if 'threats' not in analysis or not analysis['threats']:
            return ""
            
        threats = analysis['threats']
        sections = ["### Threat Analysis\n"]
        
        if isinstance(threats, list) and threats:
            sections.append(f"**Threats Detected**: {len(threats)}\n")
            
            # Group by severity
            by_severity = defaultdict(list)
            for threat in threats:
                if isinstance(threat, dict):
                    severity = threat.get('severity', 'Unknown')
                    by_severity[severity].append(threat)
                    
            # Show threats by severity
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                if severity in by_severity:
                    sections.append(f"**{severity} Severity**:")
                    for threat in by_severity[severity][:5]:
                        threat_type = threat.get('type', 'Unknown')
                        desc = threat.get('description', 'No description')
                        sections.append(f"- **{threat_type}**: {desc}")
                        
                        if expertise in ['malware_analyst', 'threat_hunter']:
                            # Add IOCs if available
                            if 'iocs' in threat:
                                sections.append(f"  - IOCs: {', '.join(threat['iocs'][:5])}")
                            if 'mitre_attack' in threat:
                                sections.append(f"  - MITRE ATT&CK: {threat['mitre_attack']}")
                    sections.append("")
                    
        elif isinstance(threats, dict):
            # Structured threat data
            if 'malware_indicators' in threats:
                sections.append("**Malware Indicators**:")
                for indicator in threats['malware_indicators'][:10]:
                    sections.append(f"- {indicator}")
                    
        return '\n'.join(sections)
        
    def _build_metadata_section(self, analysis: Dict[str, Any], expertise: str) -> str:
        """Build metadata section for forensic analysis."""
        if 'metadata' not in analysis:
            return ""
            
        metadata = analysis['metadata']
        sections = ["### File Metadata\n"]
        
        # Timestamps
        if any(key.endswith('_time') for key in metadata.keys()):
            sections.append("**Timestamps**:")
            for key in ['creation_time', 'modification_time', 'access_time', 'change_time']:
                if key in metadata:
                    sections.append(f"- **{key.replace('_', ' ').title()}**: {metadata[key]}")
            sections.append("")
            
        # Ownership and permissions
        sections.append("**Ownership & Permissions**:")
        sections.append(f"- **Owner**: {metadata.get('owner', 'Unknown')}")
        sections.append(f"- **Group**: {metadata.get('group', 'Unknown')}")
        sections.append(f"- **Permissions**: {metadata.get('permissions', 'Unknown')}")
        
        if 'selinux_context' in metadata:
            sections.append(f"- **SELinux Context**: {metadata['selinux_context']}")
            
        # File attributes
        if expertise != 'absolute_beginner':
            sections.append("\n**File Attributes**:")
            sections.append(f"- **Inode**: {metadata.get('inode', 'Unknown')}")
            sections.append(f"- **Hard Links**: {metadata.get('hard_links', 'Unknown')}")
            sections.append(f"- **Block Size**: {metadata.get('block_size', 'Unknown')}")
            
        return '\n'.join(sections)
        
    def _build_hash_section(self, analysis: Dict[str, Any]) -> str:
        """Build hash verification section."""
        if 'hashes' not in analysis or not analysis['hashes']:
            return ""
            
        hashes = analysis['hashes']
        sections = ["### Cryptographic Hashes\n"]
        
        sections.append("Use these hashes to verify file integrity:\n")
        
        hash_order = ['md5', 'sha1', 'sha256', 'sha512', 'blake3']
        for hash_type in hash_order:
            if hash_type in hashes:
                sections.append(f"**{hash_type.upper()}**:")
                sections.append(f"```\n{hashes[hash_type]}\n```")
                
        # Verification command
        if 'sha256' in hashes:
            sections.append("\n**Verification Command**:")
            sections.append(f"```bash\necho '{hashes['sha256']}  /usr/bin/{analysis.get('file_name', 'file')}' | sha256sum -c\n```")
            
        return '\n'.join(sections)
        
    def _build_binary_structure_section(self, analysis: Dict[str, Any], expertise: str) -> str:
        """Build binary structure analysis section."""
        if 'binary_info' not in analysis or not analysis['binary_info']:
            return ""
            
        bi = analysis['binary_info']
        sections = ["### Binary Structure\n"]
        
        # Basic info
        info_items = []
        if 'format' in bi:
            info_items.append(f"**Format**: {bi['format']}")
        if 'arch' in bi:
            info_items.append(f"**Architecture**: {bi['arch']}")
        if 'machine' in bi:
            info_items.append(f"**Machine**: {bi['machine']}")
        if 'class' in bi:
            info_items.append(f"**Class**: {bi['class']}")
        if 'endianness' in bi:
            info_items.append(f"**Endianness**: {bi['endianness']}")
            
        sections.extend(info_items)
        
        # Entry point and linking
        if expertise != 'absolute_beginner':
            if 'entry_point' in bi:
                sections.append(f"\n**Entry Point**: `0x{bi['entry_point']:x}`")
            if 'interpreter' in bi:
                sections.append(f"**Interpreter**: `{bi['interpreter']}`")
            if 'is_stripped' in bi:
                sections.append(f"**Stripped**: {'Yes' if bi['is_stripped'] else 'No'}")
                
        # Compiler detection
        if 'compiler' in bi and bi['compiler']:
            sections.append(f"\n**Compiler**: {bi['compiler']}")
            
        # Sections
        if 'sections' in bi and bi['sections'] and expertise != 'absolute_beginner':
            sections.append("\n**Sections**:")
            
            # Group sections by type
            text_sections = []
            data_sections = []
            other_sections = []
            
            for section in bi['sections']:
                if isinstance(section, dict):
                    name = section.get('name', 'Unknown')
                    size = section.get('size', 0)
                    perms = section.get('permissions', '')
                    
                    section_str = f"- `{name}`: {size:,} bytes"
                    if perms:
                        section_str += f" ({perms})"
                        
                    if name in ['.text', '.init', '.fini', '.plt']:
                        text_sections.append(section_str)
                    elif name in ['.data', '.rodata', '.bss', '.got']:
                        data_sections.append(section_str)
                    else:
                        other_sections.append(section_str)
                        
            if text_sections:
                sections.append("\n*Code Sections:*")
                sections.extend(text_sections)
            if data_sections:
                sections.append("\n*Data Sections:*")
                sections.extend(data_sections)
            if other_sections and len(other_sections) < 10:
                sections.append("\n*Other Sections:*")
                sections.extend(other_sections)
                
        return '\n'.join(sections)
        
    def _build_dependencies_section(self, analysis: Dict[str, Any], expertise: str) -> str:
        """Build dependencies and imports section."""
        sections = ["### Dependencies Analysis\n"]
        
        # From binary info
        if 'binary_info' in analysis and analysis['binary_info']:
            bi = analysis['binary_info']
            if 'needed_libs' in bi and bi['needed_libs']:
                sections.append("**Required Libraries**:")
                for lib in bi['needed_libs']:
                    sections.append(f"- `{lib}`")
                sections.append("")
                
        # From dependencies analysis
        if 'dependencies' in analysis and analysis['dependencies']:
            deps = analysis['dependencies']
            
            if isinstance(deps, dict):
                if 'libraries' in deps:
                    sections.append("**Shared Library Dependencies**:")
                    for lib in deps['libraries'][:20]:
                        if isinstance(lib, dict):
                            name = lib.get('name', 'Unknown')
                            version = lib.get('version', '')
                            path = lib.get('path', '')
                            
                            lib_str = f"- `{name}`"
                            if version:
                                lib_str += f" (version: {version})"
                            if path and expertise != 'absolute_beginner':
                                lib_str += f"\n  Path: `{path}`"
                            sections.append(lib_str)
                        else:
                            sections.append(f"- `{lib}`")
                            
                if 'symbols' in deps and expertise != 'absolute_beginner':
                    sections.append("\n**Imported Symbols** (sample):")
                    symbols = deps['symbols']
                    if isinstance(symbols, list):
                        for sym in symbols[:15]:
                            sections.append(f"- `{sym}`")
                            
        # From symbols analysis
        if 'symbols' in analysis and analysis['symbols'] and expertise == 'reverse_engineer':
            sections.append("\n**Symbol Table Analysis**:")
            symbols = analysis['symbols']
            
            if isinstance(symbols, dict):
                if 'exported' in symbols:
                    sections.append(f"- Exported symbols: {len(symbols['exported'])}")
                if 'imported' in symbols:
                    sections.append(f"- Imported symbols: {len(symbols['imported'])}")
                if 'undefined' in symbols:
                    sections.append(f"- Undefined symbols: {len(symbols['undefined'])}")
                    
        return '\n'.join(sections)
        
    def _build_recommendations(self, file_name: str, analysis: Dict[str, Any],
                             expertise: str, question: str) -> str:
        """Build recommendations based on analysis and expertise."""
        recommendations = []
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(analysis)
        
        # Expertise-specific recommendations
        if expertise == 'security_analyst':
            recommendations.append("## Security Recommendations\n")
            
            if risk_score >= 70:
                recommendations.extend([
                    "1. **CRITICAL**: Isolate this binary immediately",
                    "2. **Analyze**: Perform deep malware analysis in sandbox",
                    "3. **Hunt**: Search for this binary across infrastructure",
                    "4. **Block**: Add to security tool blocklists"
                ])
            elif risk_score >= 40:
                recommendations.extend([
                    "1. **Monitor**: Enable enhanced monitoring for this binary",
                    "2. **Restrict**: Apply application control policies",
                    "3. **Audit**: Review execution logs regularly",
                    "4. **Update**: Ensure latest security patches"
                ])
            else:
                recommendations.extend([
                    "1. **Standard**: Apply baseline security controls",
                    "2. **Update**: Keep binary and dependencies updated",
                    "3. **Monitor**: Include in regular security scans"
                ])
                
        elif expertise == 'sysadmin':
            recommendations.append("## Operational Recommendations\n")
            recommendations.extend([
                f"1. **Usage**: Run `{file_name} --help` for available options",
                "2. **Permissions**: Verify correct file permissions (755 for executables)",
                "3. **Logging**: Enable audit logging for sensitive operations",
                "4. **Backup**: Include in system backup procedures"
            ])
            
        elif expertise == 'developer':
            recommendations.append("## Development Recommendations\n")
            
            if 'dependencies' in analysis:
                recommendations.append("1. **Dependencies**: Review and update library versions")
            if 'compiler' in analysis.get('binary_info', {}):
                recommendations.append("2. **Optimization**: Consider compiler optimization flags")
            recommendations.extend([
                "3. **Integration**: Use proper error handling when calling this binary",
                "4. **Testing**: Include in integration test suites"
            ])
            
        elif expertise == 'forensics_expert':
            recommendations.append("## Forensic Recommendations\n")
            recommendations.extend([
                "1. **Preserve**: Create forensic copy with dd or similar",
                "2. **Timeline**: Correlate timestamps with system events",
                "3. **Context**: Check process execution artifacts",
                "4. **Compare**: Verify against known good hashes"
            ])
            
        return '\n'.join(recommendations) if recommendations else ""
        
    def _generate_purpose_description(self, file_name: str, analysis: Dict[str, Any],
                                    expertise: str) -> str:
        """Generate a description of the file's purpose."""
        # This would ideally use a more sophisticated approach
        # For now, use simple heuristics
        
        sections = ["\n## Purpose and Functionality\n"]
        
        # Common utilities with known purposes
        known_purposes = {
            'ls': "Lists directory contents, showing files and subdirectories with various formatting options.",
            'cp': "Copies files and directories from source to destination locations.",
            'mv': "Moves or renames files and directories.",
            'rm': "Removes files and directories from the filesystem.",
            'grep': "Searches for patterns in text files using regular expressions.",
            'find': "Searches for files and directories based on various criteria.",
            'chmod': "Changes file permissions and access modes.",
            'chown': "Changes file ownership and group assignments.",
            'tar': "Archives and extracts files using the TAR format.",
            'gzip': "Compresses and decompresses files using GZIP compression.",
            'curl': "Transfers data from or to servers using various protocols.",
            'wget': "Downloads files from the web via HTTP, HTTPS, and FTP.",
            'ssh': "Provides secure shell access to remote systems.",
            'git': "Version control system for tracking changes in source code.",
            'python3': "Python programming language interpreter version 3."
        }
        
        base_name = file_name.replace('3', '').replace('2', '')  # Handle python3, etc.
        
        if base_name in known_purposes:
            sections.append(known_purposes[base_name])
        else:
            # Generic description based on analysis
            if 'strings' in analysis and analysis['strings']:
                # Look for usage strings
                usage_strings = [s for s in analysis['strings'] if 'usage:' in s.lower() or 'help' in s.lower()]
                if usage_strings:
                    sections.append(f"Based on embedded strings, this appears to be a utility that {usage_strings[0].lower()}")
                else:
                    sections.append(f"This is a binary executable that performs system operations.")
            else:
                sections.append(f"This is a system binary file.")
                
        # Add technical details for appropriate expertise
        if expertise not in ['absolute_beginner', 'beginner']:
            if 'binary_info' in analysis and analysis['binary_info']:
                bi = analysis['binary_info']
                if bi.get('format') == 'ELF':
                    sections.append(f"\nThis is an ELF (Executable and Linkable Format) binary compiled for {bi.get('arch', 'unknown architecture')}.")
                    
        return '\n'.join(sections)
        
    def _categorize_strings(self, strings: List[str]) -> Dict[str, List[str]]:
        """Categorize strings by type."""
        categories = {
            'suspicious': [],
            'network': [],
            'system': [],
            'functions': [],
            'libraries': [],
            'commands': [],
            'paths': [],
            'configs': [],
            'errors': []
        }
        
        for s in strings:
            s_lower = s.lower()
            
            # Suspicious patterns
            if any(p in s_lower for p in ['wget', 'curl', 'nc -e', 'bash -i', '/dev/tcp',
                                          'base64', 'eval', 'exec', 'system(']):
                categories['suspicious'].append(s)
                
            # Network related
            if any(p in s for p in ['http://', 'https://', 'ftp://', 'tcp://', 'udp://',
                                   '.com', '.org', '.net', ':80', ':443', ':22']):
                categories['network'].append(s)
                
            # System access
            if any(p in s for p in ['/etc/passwd', '/etc/shadow', 'sudo', 'root',
                                   '/proc/', '/sys/', '/dev/']):
                categories['system'].append(s)
                
            # Functions (heuristic)
            if (s.startswith('_') or s.endswith('()') or 
                ('_' in s and len(s) > 5 and s.replace('_', '').isalnum())):
                categories['functions'].append(s)
                
            # Libraries
            if s.endswith('.so') or s.endswith('.so.1') or s.endswith('.so.2'):
                categories['libraries'].append(s)
                
            # Commands
            if s in ['ls', 'cp', 'mv', 'rm', 'cat', 'grep', 'find', 'chmod', 'chown']:
                categories['commands'].append(s)
                
            # Paths
            if s.startswith('/') and '/' in s[1:]:
                categories['paths'].append(s)
                
            # Config files
            if s.endswith('.conf') or s.endswith('.cfg') or s.endswith('.ini'):
                categories['configs'].append(s)
                
            # Error messages
            if any(p in s_lower for p in ['error', 'fail', 'unable', 'cannot', 'denied']):
                categories['errors'].append(s)
                
        return categories
        
    def _extract_key_strings(self, strings: List[str], expertise: str) -> str:
        """Extract and format key strings based on expertise."""
        categorized = self._categorize_strings(strings)
        sections = []
        
        if expertise in ['security_analyst', 'malware_analyst']:
            if categorized['suspicious']:
                sections.append("**Security-Relevant Strings**:")
                for s in categorized['suspicious'][:10]:
                    sections.append(f"- `{s}`")
                    
        elif expertise == 'sysadmin':
            if categorized['commands'] or categorized['paths']:
                sections.append("**System Integration**:")
                for s in (categorized['commands'] + categorized['paths'])[:10]:
                    sections.append(f"- `{s}`")
                    
        elif expertise == 'developer':
            if categorized['functions'] or categorized['libraries']:
                sections.append("**API/Library Usage**:")
                for s in (categorized['functions'] + categorized['libraries'])[:10]:
                    sections.append(f"- `{s}`")
                    
        else:
            # General interesting strings
            interesting = (categorized['commands'] + categorized['network'] + 
                          categorized['errors'])[:10]
            if interesting:
                sections.append("**Notable Strings**:")
                for s in interesting:
                    sections.append(f"- `{s}`")
                    
        return '\n'.join(sections)
        
    def _analyze_file_signature(self, hex_line: str) -> str:
        """Analyze file signature from hex dump."""
        # Common file signatures
        signatures = {
            '7f454c46': 'ELF executable',
            '4d5a': 'DOS/Windows executable',
            '504b0304': 'ZIP archive',
            '1f8b': 'GZIP compressed',
            '425a68': 'BZIP2 compressed',
            '526172': 'RAR archive',
            'cafebabe': 'Java class file',
            'feedface': 'Mach-O 32-bit',
            'feedfacf': 'Mach-O 64-bit',
            'cefaedfe': 'Mach-O 32-bit (swapped)',
            'cffaedfe': 'Mach-O 64-bit (swapped)'
        }
        
        # Extract just hex values
        hex_only = ''.join(c for c in hex_line if c in '0123456789abcdefABCDEF').lower()
        
        for sig, desc in signatures.items():
            if hex_only.startswith(sig):
                return desc
                
        return "Unknown file type"
        
    def _analyze_assembly_patterns(self, disasm_text: str) -> str:
        """Analyze assembly code for patterns."""
        patterns = []
        
        # Security-relevant patterns
        security_patterns = {
            'int 0x80': 'System call (32-bit Linux)',
            'syscall': 'System call (64-bit)',
            'call.*ptrace': 'Anti-debugging (ptrace)',
            'rdtsc': 'Timing checks (anti-debugging)',
            'cpuid': 'CPU identification',
            'int3': 'Breakpoint/debugging',
            'push.*call': 'Possible code injection',
            'xor.*,.*': 'Possible encoding/encryption',
            'jmp.*esp': 'Stack pivot',
            'ret.*': 'Return instruction'
        }
        
        import re
        found_patterns = []
        
        for pattern, description in security_patterns.items():
            if re.search(pattern, disasm_text, re.IGNORECASE):
                found_patterns.append(f"- **{description}**: Pattern `{pattern}` detected")
                
        if found_patterns:
            patterns.extend(found_patterns[:10])
            
        return '\n'.join(patterns)
        
    def _calculate_risk_score(self, analysis: Dict[str, Any]) -> float:
        """Calculate overall risk score from analysis."""
        score = 0.0
        
        # Vulnerability score
        if 'vulnerabilities' in analysis and isinstance(analysis['vulnerabilities'], dict):
            risk_data = analysis['vulnerabilities'].get('risk_assessment', {})
            score += risk_data.get('overall_risk_score', 0) * 0.4
            
        # Threat score
        if 'threats' in analysis and analysis['threats']:
            if isinstance(analysis['threats'], list):
                score += min(len(analysis['threats']) * 10, 50) * 0.3
                
        # Behavioral score
        if 'behavioral' in analysis and analysis['behavioral']:
            if isinstance(analysis['behavioral'], dict):
                risky_behaviors = ['suspicious_behavior', 'anti_debugging', 'obfuscation',
                                 'privilege_escalation', 'persistence']
                behavior_count = sum(1 for b in risky_behaviors 
                                   if analysis['behavioral'].get(b))
                score += (behavior_count / len(risky_behaviors)) * 100 * 0.2
                
        # Entropy score (packing indicator)
        if 'entropy' in analysis and isinstance(analysis['entropy'], dict):
            overall_entropy = analysis['entropy'].get('overall_entropy', 0)
            if overall_entropy > 7.5:
                score += 30 * 0.1
            elif overall_entropy > 6.5:
                score += 15 * 0.1
                
        return min(score, 100)  # Cap at 100


class ChunkedQuestionGenerator:
    """Generates chunked questions for large data sections."""
    
    def __init__(self, chunk_sizes: Dict[str, int] = None):
        self.chunk_sizes = chunk_sizes or {
            'strings': 50,
            'hex': 512,
            'disassembly': 200,
            'symbols': 100
        }
        
    def generate_chunked_questions(self, file_name: str, analysis: Dict[str, Any],
                                  expertise: str) -> List[Tuple[str, str]]:
        """Generate questions that request specific chunks of data."""
        questions = []
        
        # String chunks
        if 'strings' in analysis and analysis['strings']:
            strings = analysis['strings']
            num_strings = len(strings)
            chunk_size = self.chunk_sizes['strings']
            
            for i in range(0, min(num_strings, 500), chunk_size):
                end = min(i + chunk_size, num_strings)
                questions.append((
                    f"Show me strings {i}-{end} from {file_name}",
                    f"strings_chunk_{i}_{end}"
                ))
                
            # Pattern-based string questions
            patterns = ['lib', 'error', 'http', 'config', 'socket', 'proc']
            for pattern in patterns:
                questions.append((
                    f"Extract strings containing '{pattern}' from {file_name}",
                    f"strings_pattern_{pattern}"
                ))
                
        # Hex dump chunks
        if 'hex_dump' in analysis and analysis['hex_dump']:
            offsets = [0, 256, 512, 1024, 2048, 4096, 8192]
            for offset in offsets:
                questions.append((
                    f"Show me hex dump at offset {offset} from {file_name}",
                    f"hex_offset_{offset}"
                ))
                
        # Disassembly chunks
        if 'disassembly' in analysis and analysis['disassembly']:
            functions = ['main', '_start', 'entry_point', '_init']
            for func in functions:
                questions.append((
                    f"Show me the {func} function disassembly from {file_name}",
                    f"disasm_function_{func}"
                ))
                
        return questions


class TrainingGenerator:
    """Main training data generator that orchestrates the generation process."""
    
    def __init__(self, output_dir: str = "/tmp/training_output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.analyzer = AnalysisLoader()
        self.expertise_mgr = ExpertiseManager()
        self.tokenizer = TokenCounter()
        self.answer_builder = AnswerBuilder()
        self.chunk_gen = ChunkedQuestionGenerator()
        
        self.config = {
            'examples_per_file': 50,
            'max_answer_tokens': 2000,
            'enable_chunking': True,
            'enable_negative_examples': True,
            'buffer_size': 100,
            'compression': True
        }
        
        self.stats = {
            'files_processed': 0,
            'examples_generated': 0,
            'expertise_distribution': defaultdict(int),
            'question_types': defaultdict(int)
        }
        
    def configure(self, **kwargs):
        """Update configuration."""
        self.config.update(kwargs)
        
    def load_analyses(self, directories: List[Tuple[str, int]]) -> int:
        """Load analysis data from directories with priorities."""
        total = self.analyzer.load_multiple_directories(directories)
        logger.info(f"Loaded {total} analysis files")
        return total
        
    def generate_dataset_parallel(self, dataset_name: str = "comprehensive", 
                                 num_processes: int = None) -> Path:
        """Generate dataset using multiprocessing for speed."""
        # Get file importance scores
        importance_scores = self.analyzer.get_importance_scores()
        all_analyses = self.analyzer.get_all_analyses()
        
        # Create multiprocess generator
        mp_generator = MultiProcessTrainingGenerator(
            str(self.output_dir), 
            num_processes=num_processes
        )
        
        # Configure with same settings
        mp_generator.configure(**self.config)
        
        logger.info(f"Starting parallel generation with {mp_generator.num_processes} processes")
        
        # Generate dataset
        output_path = mp_generator.generate_dataset_parallel(
            all_analyses, importance_scores, dataset_name
        )
        
        # Update our statistics
        mp_stats = mp_generator.get_statistics()
        self.stats.update(mp_stats)
        
        return output_path
        
    def generate_dataset(self, dataset_name: str = "comprehensive") -> Path:
        """Generate a complete training dataset."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"threatflux_{dataset_name}_{timestamp}.jsonl"
        
        # Get file importance scores
        importance_scores = self.analyzer.get_importance_scores()
        sorted_files = sorted(importance_scores.items(), key=lambda x: x[1], reverse=True)
        
        logger.info(f"Generating dataset for {len(sorted_files)} files")
        
        with open(output_file, 'w') as f:
            buffer = []
            
            for i, (file_name, score) in enumerate(sorted_files):
                if i % 10 == 0:
                    logger.info(f"Progress: {i}/{len(sorted_files)} files")
                    # Flush buffer
                    for example in buffer:
                        f.write(json.dumps(example) + '\n')
                    buffer = []
                    
                analysis = self.analyzer.get_analysis(file_name)
                if not analysis:
                    continue
                    
                # Generate examples for this file
                examples = self._generate_file_examples(file_name, analysis, score)
                buffer.extend(examples)
                
                self.stats['files_processed'] += 1
                
            # Final flush
            for example in buffer:
                f.write(json.dumps(example) + '\n')
                
        # Compress if enabled
        if self.config['compression']:
            compressed = self._compress_file(output_file)
            return compressed
            
        return output_file
        
    def _generate_file_examples(self, file_name: str, analysis: Dict[str, Any],
                               importance_score: float) -> List[Dict[str, Any]]:
        """Generate all examples for a single file."""
        examples = []
        
        # Adjust example count based on importance
        base_count = self.config['examples_per_file']
        example_count = int(base_count * (importance_score / 2.0))  # Scale by importance
        
        # Get all expertise levels
        expertise_levels = self.expertise_mgr.get_all_expertise_levels()
        
        # Distribute examples across expertise levels
        examples_per_expertise = max(1, example_count // len(expertise_levels))
        
        for expertise in expertise_levels:
            # Get questions for this expertise
            questions = self.expertise_mgr.get_questions_for_expertise(
                file_name, expertise, analysis, examples_per_expertise * 2
            )
            
            for question in questions[:examples_per_expertise]:
                # Generate answer
                answer = self.answer_builder.build_answer(
                    file_name, analysis, expertise, question
                )
                
                # Create example
                example = {
                    "messages": [
                        {
                            "role": "system",
                            "content": self.expertise_mgr.get_expertise_prompt(expertise)
                        },
                        {
                            "role": "user",
                            "content": question
                        },
                        {
                            "role": "assistant",
                            "content": answer
                        }
                    ]
                }
                
                # Count tokens
                token_info = self.tokenizer.count_example(example, file_name, expertise)
                
                # Track statistics
                self.stats['examples_generated'] += 1
                self.stats['expertise_distribution'][expertise] += 1
                
                examples.append(example)
                
        # Add chunked questions if enabled
        if self.config['enable_chunking'] and len(analysis.get('strings', [])) > 100:
            chunked_questions = self.chunk_gen.generate_chunked_questions(
                file_name, analysis, random.choice(expertise_levels)
            )
            
            for question, question_type in chunked_questions[:10]:
                expertise = random.choice(['reverse_engineer', 'security_analyst', 'malware_analyst'])
                answer = self.answer_builder.build_answer(
                    file_name, analysis, expertise, question
                )
                
                example = {
                    "messages": [
                        {
                            "role": "system",
                            "content": self.expertise_mgr.get_expertise_prompt(expertise)
                        },
                        {
                            "role": "user",
                            "content": question
                        },
                        {
                            "role": "assistant",
                            "content": answer
                        }
                    ]
                }
                
                self.tokenizer.count_example(example, file_name, expertise)
                self.stats['question_types'][question_type] += 1
                examples.append(example)
                
        # Add negative examples if enabled
        if self.config['enable_negative_examples'] and random.random() < 0.1:
            fake_file = f"non_existent_{random.randint(1000, 9999)}.exe"
            question = f"Tell me about {fake_file}"
            
            answer = (f"I cannot find the file `{fake_file}` in the system. "
                     "This file does not exist in the standard Ubuntu installation. "
                     "Please verify the file name and path.")
            
            example = {
                "messages": [
                    {
                        "role": "system",
                        "content": self.expertise_mgr.get_expertise_prompt('casual_user')
                    },
                    {
                        "role": "user",
                        "content": question
                    },
                    {
                        "role": "assistant",
                        "content": answer
                    }
                ]
            }
            
            examples.append(example)
            
        return examples
        
    def _compress_file(self, file_path: Path) -> Path:
        """Compress the output file."""
        gz_path = file_path.with_suffix('.jsonl.gz')
        
        with open(file_path, 'rb') as f_in:
            with gzip.open(gz_path, 'wb') as f_out:
                f_out.writelines(f_in)
                
        # Remove uncompressed file
        file_path.unlink()
        
        logger.info(f"Compressed output to {gz_path}")
        return gz_path
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get generation statistics."""
        token_stats = self.tokenizer.get_statistics()
        analysis_stats = self.analyzer.get_statistics()
        
        return {
            "generation": self.stats,
            "tokens": token_stats,
            "analyses": analysis_stats
        }
        
    def print_report(self):
        """Print comprehensive generation report."""
        print("\n" + "="*80)
        print("TRAINING DATA GENERATION REPORT")
        print("="*80 + "\n")
        
        # Generation stats
        print(f"Files Processed: {self.stats['files_processed']:,}")
        print(f"Examples Generated: {self.stats['examples_generated']:,}")
        print(f"Average Examples/File: {self.stats['examples_generated'] / max(1, self.stats['files_processed']):.1f}\n")
        
        # Token report
        print(self.tokenizer.format_report())
        
        # Feature usage
        analysis_stats = self.analyzer.get_statistics()
        if 'feature_usage' in analysis_stats:
            print("\nFeature Usage:")
            for feature, usage in sorted(analysis_stats['feature_usage'].items(), 
                                       key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {feature}: {usage:.1f}%")
                
        print("\n" + "="*80)
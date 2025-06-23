#!/usr/bin/env python3
"""
Enhanced ultimate comprehensive training data generator for Ubuntu binaries.
Better utilizes all the new analysis features from the file scanner.
"""

import json
import os
import random
import hashlib
import gzip
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any, Tuple, Set, Optional
import concurrent.futures
from datetime import datetime
import itertools

# Import the original expertise levels and question categories
from generate_ultimate_training_data import (
    EXPERTISE_LEVELS, 
    QUESTION_CATEGORIES,
    UltimateTrainingGenerator
)

class EnhancedUltimateTrainingGenerator(UltimateTrainingGenerator):
    """Enhanced generator that better utilizes new analysis features."""
    
    def __init__(self, analysis_dir: str, output_dir: str):
        super().__init__(analysis_dir, output_dir)
        self.feature_usage_stats = defaultdict(int)
        
    def _load_and_score_file(self, file_path: Path) -> Tuple[str, Dict, float]:
        """Enhanced file loading with better importance scoring using new features."""
        result = super()._load_and_score_file(file_path)
        if not result:
            return None
            
        file_path_str, data, base_importance = result
        
        # Enhanced importance scoring using new features
        enhanced_importance = base_importance
        
        # Vulnerability risk assessment boosts importance
        if 'vulnerabilities' in data and data['vulnerabilities']:
            for vuln in data['vulnerabilities']:
                if isinstance(vuln, dict) and 'risk_assessment' in vuln:
                    risk = vuln['risk_assessment']
                    if isinstance(risk, dict):
                        enhanced_importance += risk.get('score', 0) / 10
                    
        # Threat indicators increase importance
        if 'threats' in data and data['threats']:
            enhanced_importance += min(len(data['threats']) * 2, 10)
            
        # High entropy suggests packing/encryption (interesting)
        if 'entropy' in data and isinstance(data['entropy'], dict):
            overall_entropy = data['entropy'].get('overall', 0)
            if overall_entropy > 7.5:
                enhanced_importance += 5  # Packed/encrypted binaries are interesting
                
        # Unsigned binaries in sensitive locations
        if 'signatures' in data:
            sigs = data['signatures']
            if isinstance(sigs, dict) and not sigs.get('signed', True):
                if '/sbin/' in file_path_str or '/bin/' in file_path_str:
                    enhanced_importance += 3
                    
        # Complex control flow suggests interesting functionality
        if 'control_flow' in data and data['control_flow']:
            enhanced_importance += 2
            
        # Many symbols suggest rich functionality
        if 'symbols' in data and isinstance(data['symbols'], list):
            enhanced_importance += min(len(data['symbols']) / 50, 5)
            
        return file_path_str, data, enhanced_importance
        
    def _generate_rich_answer(self, file_path: str, analysis: Dict[str, Any],
                             expertise: str, q_category: str, q_subcategory: str) -> str:
        """Enhanced answer generation using new features."""
        # Track feature usage
        for feature in ['vulnerabilities', 'threats', 'behavioral', 'entropy', 
                       'signatures', 'hex_dump', 'symbols', 'disassembly', 
                       'control_flow', 'code_quality', 'dependencies', 'yara_indicators']:
            if feature in analysis and analysis[feature]:
                self.feature_usage_stats[feature] += 1
                
        # Call parent method for base content
        base_content = super()._generate_rich_answer(
            file_path, analysis, expertise, q_category, q_subcategory
        )
        
        # Add enhanced content based on expertise and category
        enhanced_parts = []
        
        if q_category == 'security' and expertise in ['security_analyst', 'threat_hunter', 'malware_analyst']:
            enhanced_parts.extend(self._generate_enhanced_security_content(
                file_path, analysis, expertise, q_subcategory
            ))
            
        elif q_category == 'technical' and expertise in ['reverse_engineer', 'exploit_developer']:
            enhanced_parts.extend(self._generate_enhanced_technical_content(
                file_path, analysis, expertise, q_subcategory
            ))
            
        elif expertise in ['forensics_expert', 'incident_responder']:
            enhanced_parts.extend(self._generate_enhanced_forensics_content(
                file_path, analysis, expertise
            ))
            
        # Combine base and enhanced content
        if enhanced_parts:
            return base_content + '\n\n' + '\n'.join(enhanced_parts)
        return base_content
        
    def _generate_enhanced_security_content(self, file_path: str, analysis: Dict[str, Any],
                                          expertise: str, subcategory: str) -> List[str]:
        """Generate enhanced security content using new features."""
        content = []
        
        # Enhanced vulnerability analysis with risk assessment
        if subcategory == 'vulnerability' and 'vulnerabilities' in analysis:
            content.append("## Enhanced Vulnerability Assessment\n")
            
            vulnerabilities = analysis['vulnerabilities']
            if vulnerabilities:
                # Group by risk level
                risk_groups = defaultdict(list)
                for vuln in vulnerabilities:
                    if isinstance(vuln, dict) and 'risk_assessment' in vuln:
                        risk = vuln['risk_assessment']
                        if isinstance(risk, dict):
                            level = risk.get('level', 'Unknown')
                            risk_groups[level].append(vuln)
                        else:
                            risk_groups['Unknown'].append(vuln)
                    else:
                        risk_groups['Unknown'].append(vuln)
                        
                # Report by risk level
                for level in ['Critical', 'High', 'Medium', 'Low', 'Unknown']:
                    if level in risk_groups:
                        content.append(f"\n### {level} Risk Vulnerabilities")
                        for vuln in risk_groups[level][:5]:
                            if isinstance(vuln, dict):
                                content.append(f"- **{vuln.get('type', 'Unknown')}**: {vuln.get('description', '')}")
                                if 'risk_assessment' in vuln:
                                    risk = vuln['risk_assessment']
                                    if isinstance(risk, dict):
                                        content.append(f"  - Impact: {risk.get('impact', 'N/A')}")
                                        content.append(f"  - Exploitability: {risk.get('exploitability', 'N/A')}")
                                        content.append(f"  - CVSS Score: {risk.get('score', 'N/A')}")
                                if 'mitigation' in vuln:
                                    content.append(f"  - Mitigation: {vuln['mitigation']}")
                            else:
                                content.append(f"- {vuln}")
                                
        # Enhanced threat analysis
        if 'threats' in analysis and analysis['threats']:
            content.append("\n## Threat Intelligence\n")
            threats = analysis['threats']
            
            # Categorize threats
            threat_categories = defaultdict(list)
            for threat in threats:
                if isinstance(threat, dict):
                    category = threat.get('category', 'Unknown')
                    threat_categories[category].append(threat)
                else:
                    threat_categories['Unknown'].append(threat)
                    
            for category, threats_list in threat_categories.items():
                content.append(f"\n### {category} Threats")
                for threat in threats_list[:3]:
                    if isinstance(threat, dict):
                        content.append(f"- **{threat.get('name', 'Unknown')}**")
                        content.append(f"  - Description: {threat.get('description', 'N/A')}")
                        content.append(f"  - Severity: {threat.get('severity', 'N/A')}")
                        if 'indicators' in threat:
                            content.append(f"  - Indicators: {', '.join(threat['indicators'][:3])}")
                        if 'mitre_attack' in threat:
                            content.append(f"  - MITRE ATT&CK: {threat['mitre_attack']}")
                    else:
                        content.append(f"- {threat}")
                        
        # Behavioral analysis for runtime threats
        if 'behavioral' in analysis and analysis['behavioral']:
            content.append("\n## Behavioral Analysis\n")
            behavioral = analysis['behavioral']
            
            if isinstance(behavioral, dict):
                # System calls analysis
                if 'syscalls' in behavioral and isinstance(behavioral['syscalls'], list):
                    suspicious_syscalls = ['ptrace', 'execve', 'fork', 'clone', 'mmap', 
                                         'mprotect', 'connect', 'socket', 'bind']
                    found_suspicious = [s for s in behavioral['syscalls'] 
                                      if any(susp in s for susp in suspicious_syscalls)]
                    if found_suspicious:
                        content.append("### Suspicious System Calls Detected")
                        for syscall in found_suspicious[:5]:
                            content.append(f"- `{syscall}` - Potential security concern")
                            
                # Network behavior
                if 'network' in behavioral:
                    content.append("\n### Network Behavior")
                    content.append(f"- {behavioral['network']}")
                    
                # File operations
                if 'filesystem' in behavioral:
                    content.append("\n### File System Operations")
                    content.append(f"- {behavioral['filesystem']}")
                    
                # Process behavior
                if 'processes' in behavioral:
                    content.append("\n### Process Behavior")
                    content.append(f"- {behavioral['processes']}")
                    
        # Entropy-based packing/encryption detection
        if 'entropy' in analysis and isinstance(analysis['entropy'], dict):
            content.append("\n## Entropy Analysis\n")
            entropy_data = analysis['entropy']
            
            overall = entropy_data.get('overall', 0)
            content.append(f"- **Overall Entropy**: {overall:.2f}/8.0")
            
            if overall > 7.5:
                content.append("- ⚠️ **Very High Entropy** - Likely packed or encrypted")
                content.append("  - May be using UPX, custom packer, or encryption")
                content.append("  - Requires dynamic analysis for full inspection")
            elif overall > 6.5:
                content.append("- **High Entropy** - Possibly compressed or optimized")
                
            # Section-level entropy
            if 'sections' in entropy_data and isinstance(entropy_data['sections'], dict):
                content.append("\n### Section Entropy")
                for section, entropy in entropy_data['sections'].items():
                    if entropy > 7.0:
                        content.append(f"- **{section}**: {entropy:.2f} (suspicious)")
                    else:
                        content.append(f"- **{section}**: {entropy:.2f}")
                        
        return content
        
    def _generate_enhanced_technical_content(self, file_path: str, analysis: Dict[str, Any],
                                           expertise: str, subcategory: str) -> List[str]:
        """Generate enhanced technical content using new features."""
        content = []
        
        # Enhanced disassembly analysis
        if 'disassembly' in analysis and analysis['disassembly']:
            content.append("## Disassembly Analysis\n")
            
            disasm = analysis['disassembly']
            if isinstance(disasm, dict):
                # Function analysis
                if 'functions' in disasm:
                    content.append("### Key Functions")
                    for func in disasm['functions'][:5]:
                        if isinstance(func, dict):
                            content.append(f"- **{func.get('name', 'Unknown')}**")
                            content.append(f"  - Address: {func.get('address', 'N/A')}")
                            content.append(f"  - Size: {func.get('size', 0)} bytes")
                            if 'calls' in func:
                                content.append(f"  - Calls: {', '.join(func['calls'][:3])}")
                                
                # Instruction patterns
                if 'patterns' in disasm:
                    content.append("\n### Instruction Patterns")
                    for pattern in disasm['patterns'][:5]:
                        content.append(f"- {pattern}")
                        
            elif isinstance(disasm, str):
                # Show snippet of disassembly
                content.append("### Disassembly Snippet")
                content.append("```assembly")
                lines = disasm.split('\n')[:20]
                for line in lines:
                    content.append(line)
                content.append("```")
                
        # Enhanced symbol analysis
        if 'symbols' in analysis and isinstance(analysis['symbols'], list):
            content.append("\n## Symbol Analysis\n")
            
            # Categorize symbols
            symbol_types = defaultdict(list)
            for sym in analysis['symbols']:
                if isinstance(sym, dict):
                    sym_type = sym.get('type', 'Unknown')
                    symbol_types[sym_type].append(sym)
                else:
                    symbol_types['Unknown'].append(sym)
                    
            # Report interesting symbols
            if 'FUNC' in symbol_types:
                content.append("### Exported Functions")
                for func in symbol_types['FUNC'][:10]:
                    if isinstance(func, dict):
                        name = func.get('name', 'Unknown')
                        # Flag interesting functions
                        if any(pattern in name for pattern in ['crypt', 'hash', 'encode', 
                                                               'decode', 'compress', 'exec']):
                            content.append(f"- **{name}** ⚠️ (security-relevant)")
                        else:
                            content.append(f"- {name}")
                            
            # Look for debug symbols
            debug_symbols = [s for s in analysis['symbols'] 
                           if isinstance(s, dict) and 'debug' in s.get('name', '').lower()]
            if debug_symbols:
                content.append("\n### Debug Information Present")
                content.append("- Binary contains debug symbols")
                content.append("- Easier to reverse engineer")
                
        # Control flow analysis
        if 'control_flow' in analysis and analysis['control_flow']:
            content.append("\n## Control Flow Analysis\n")
            
            cf = analysis['control_flow']
            if isinstance(cf, dict):
                # Basic blocks
                if 'basic_blocks' in cf:
                    content.append(f"- **Basic Blocks**: {cf['basic_blocks']}")
                    
                # Complexity metrics
                if 'cyclomatic_complexity' in cf:
                    complexity = cf['cyclomatic_complexity']
                    content.append(f"- **Cyclomatic Complexity**: {complexity}")
                    if complexity > 50:
                        content.append("  - Very high complexity - difficult to analyze")
                    elif complexity > 20:
                        content.append("  - High complexity - moderately difficult")
                        
                # Call graph
                if 'call_graph' in cf:
                    content.append("\n### Call Graph Insights")
                    cg = cf['call_graph']
                    if isinstance(cg, dict):
                        if 'nodes' in cg:
                            content.append(f"- Total functions: {cg['nodes']}")
                        if 'edges' in cg:
                            content.append(f"- Function calls: {cg['edges']}")
                        if 'max_depth' in cg:
                            content.append(f"- Max call depth: {cg['max_depth']}")
                            
                # Control flow patterns
                if 'patterns' in cf:
                    content.append("\n### Control Flow Patterns")
                    for pattern in cf['patterns'][:5]:
                        content.append(f"- {pattern}")
                        
        # Code quality metrics
        if 'code_quality' in analysis and analysis['code_quality']:
            content.append("\n## Code Quality Analysis\n")
            
            cq = analysis['code_quality']
            if isinstance(cq, dict):
                # Performance metrics
                if 'performance' in cq:
                    content.append("### Performance Characteristics")
                    perf = cq['performance']
                    if isinstance(perf, dict):
                        for metric, value in perf.items():
                            content.append(f"- **{metric}**: {value}")
                            
                # Security metrics
                if 'security' in cq:
                    content.append("\n### Security Quality")
                    sec = cq['security']
                    if isinstance(sec, dict):
                        for metric, value in sec.items():
                            content.append(f"- **{metric}**: {value}")
                            
                # Maintainability
                if 'maintainability' in cq:
                    content.append(f"\n- **Maintainability Score**: {cq['maintainability']}")
                    
        return content
        
    def _generate_enhanced_forensics_content(self, file_path: str, analysis: Dict[str, Any],
                                           expertise: str) -> List[str]:
        """Generate enhanced forensics content using new features."""
        content = []
        
        content.append("## Digital Forensics Analysis\n")
        
        # Digital signature verification
        if 'signatures' in analysis and analysis['signatures']:
            content.append("### Digital Signature Analysis")
            sigs = analysis['signatures']
            
            if isinstance(sigs, dict):
                if sigs.get('signed', False):
                    content.append("✅ **Binary is digitally signed**")
                    content.append("\n#### Signature Details:")
                    
                    # Certificate chain
                    if 'certificates' in sigs:
                        content.append("- **Certificate Chain**:")
                        for cert in sigs['certificates']:
                            if isinstance(cert, dict):
                                content.append(f"  - Subject: {cert.get('subject', 'N/A')}")
                                content.append(f"    - Issuer: {cert.get('issuer', 'N/A')}")
                                content.append(f"    - Valid from: {cert.get('not_before', 'N/A')}")
                                content.append(f"    - Valid to: {cert.get('not_after', 'N/A')}")
                                content.append(f"    - Serial: {cert.get('serial', 'N/A')}")
                                
                    # Timestamp
                    if 'timestamp' in sigs:
                        content.append(f"\n- **Signing Timestamp**: {sigs['timestamp']}")
                        content.append("  - Important for establishing timeline")
                        
                    # Verification status
                    if 'verified' in sigs:
                        if sigs['verified']:
                            content.append("\n- **Verification**: ✅ Signature valid")
                        else:
                            content.append("\n- **Verification**: ❌ Signature invalid!")
                            content.append("  - Binary may have been tampered with")
                            
                else:
                    content.append("❌ **Binary is not signed**")
                    content.append("- Cannot verify authenticity")
                    content.append("- Higher risk of tampering")
                    
        # Hex dump analysis for magic bytes and patterns
        if 'hex_dump' in analysis and analysis['hex_dump']:
            content.append("\n### Binary Pattern Analysis")
            
            hex_data = analysis['hex_dump']
            if isinstance(hex_data, dict) and 'data' in hex_data:
                # Extract header bytes
                header = hex_data['data'][:64]  # First line of hex
                content.append("- **File Header**: `" + header + "`")
                
                # Check for known patterns
                if '4D 5A' in header:
                    content.append("  - PE executable header detected")
                elif '7F 45 4C 46' in header:
                    content.append("  - ELF executable header detected")
                elif '50 4B' in header:
                    content.append("  - ZIP/JAR archive header detected")
                    
                # Look for embedded content
                full_hex = hex_data.get('data', '')
                if 'MZ' in full_hex[100:]:  # Embedded PE
                    content.append("  - ⚠️ Possible embedded PE executable detected")
                if 'PK' in full_hex[100:]:  # Embedded archive
                    content.append("  - ⚠️ Possible embedded archive detected")
                    
        # YARA rule generation for detection
        if 'yara_indicators' in analysis and analysis['yara_indicators']:
            content.append("\n### YARA Detection Rule")
            
            yara = analysis['yara_indicators']
            if isinstance(yara, dict):
                content.append("```yara")
                content.append(f"rule detect_{os.path.basename(file_path).replace('.', '_')}")
                content.append("{")
                content.append("    meta:")
                content.append(f'        description = "Detect {os.path.basename(file_path)}"')
                content.append(f'        author = "Forensics Analysis"')
                content.append(f'        date = "{datetime.now().strftime("%Y-%m-%d")}"')
                
                if 'hashes' in analysis:
                    content.append(f'        md5 = "{analysis["hashes"].get("md5", "")}"')
                    content.append(f'        sha256 = "{analysis["hashes"].get("sha256", "")}"')
                    
                if 'strings' in yara:
                    content.append("    strings:")
                    for string in yara['strings'][:10]:
                        if isinstance(string, dict):
                            content.append(f'        ${string.get("name", "str")} = "{string.get("value", "")}"')
                        else:
                            content.append(f'        $str = "{string}"')
                            
                if 'condition' in yara:
                    content.append("    condition:")
                    content.append(f"        {yara['condition']}")
                else:
                    content.append("    condition:")
                    content.append("        all of them")
                    
                content.append("}")
                content.append("```")
            elif isinstance(yara, str):
                content.append("```yara")
                content.append(yara)
                content.append("```")
                
        # Dependency analysis for supply chain
        if 'dependencies' in analysis and analysis['dependencies']:
            content.append("\n### Supply Chain Analysis")
            
            deps = analysis['dependencies']
            vulnerable_deps = []
            suspicious_deps = []
            
            for dep in deps:
                if isinstance(dep, dict):
                    name = dep.get('name', 'Unknown')
                    version = dep.get('version', 'Unknown')
                    
                    # Check for known vulnerable versions
                    if 'vulnerable' in dep and dep['vulnerable']:
                        vulnerable_deps.append(f"{name} {version}")
                        
                    # Check for suspicious names
                    suspicious_patterns = ['hack', 'exploit', 'backdoor', 'rootkit']
                    if any(pattern in name.lower() for pattern in suspicious_patterns):
                        suspicious_deps.append(f"{name} {version}")
                        
            if vulnerable_deps:
                content.append("\n#### ⚠️ Vulnerable Dependencies Detected")
                for dep in vulnerable_deps:
                    content.append(f"- {dep}")
                    
            if suspicious_deps:
                content.append("\n#### ⚠️ Suspicious Dependencies")
                for dep in suspicious_deps:
                    content.append(f"- {dep}")
                    
        return content
        
    def generate_feature_usage_report(self):
        """Generate a report on which new features were used."""
        report_file = self.output_dir / "feature_usage_report.json"
        
        total_examples = self.generated_count
        usage_percentages = {}
        
        for feature, count in self.feature_usage_stats.items():
            percentage = (count / total_examples * 100) if total_examples > 0 else 0
            usage_percentages[feature] = {
                "count": count,
                "percentage": round(percentage, 2)
            }
            
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_examples": total_examples,
            "feature_usage": usage_percentages,
            "sorted_by_usage": sorted(
                usage_percentages.items(), 
                key=lambda x: x[1]['percentage'], 
                reverse=True
            )
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\nFeature usage report saved to: {report_file}")
        
        # Print summary
        print("\n=== Feature Usage Summary ===")
        for feature, stats in report['sorted_by_usage'][:10]:
            print(f"{feature}: {stats['percentage']}% ({stats['count']} examples)")
            
    def _generate_thematic_answer(self, theme: str, expertise: str) -> str:
        """Enhanced thematic answer generation."""
        if theme == "security_hardening":
            return self._generate_enhanced_security_hardening_guide()
        elif theme == "incident_response":
            return self._generate_enhanced_incident_response_guide()
        elif theme == "malware_analysis":
            return self._generate_enhanced_malware_analysis_guide()
        elif theme == "vulnerability_assessment":
            return self._generate_enhanced_vulnerability_assessment_guide()
        elif theme == "forensics_investigation":
            return self._generate_enhanced_forensics_guide()
        else:
            # Fall back to parent implementation
            return super()._generate_thematic_answer(theme, expertise)
            
    def _generate_enhanced_security_hardening_guide(self) -> str:
        """Generate enhanced security hardening guide using new features."""
        return """# Advanced Ubuntu Binary Security Hardening Guide

## 1. Binary Integrity Verification

### Digital Signature Verification
```bash
# Check if binaries are signed
for binary in /usr/bin/*; do
    if file "$binary" | grep -q "ELF"; then
        # Check for signatures using our scanner
        ./file-scanner "$binary" --signatures --format json | \
            jq -r '.signatures.signed // false'
    fi
done
```

### Entropy-Based Packing Detection
```bash
# Detect packed/encrypted binaries
find /usr/bin -type f -executable | while read binary; do
    entropy=$(./file-scanner "$binary" --entropy --format json | \
              jq -r '.entropy.overall // 0')
    if (( $(echo "$entropy > 7.5" | bc -l) )); then
        echo "WARNING: $binary has high entropy ($entropy) - possibly packed"
    fi
done
```

## 2. Vulnerability Assessment

### Risk-Based Vulnerability Scanning
```bash
# Scan for vulnerabilities with risk assessment
./file-scanner /usr/bin/* --vulnerabilities --format json | \
    jq -r '.vulnerabilities[] | 
           select(.risk_assessment.level == "Critical" or 
                  .risk_assessment.level == "High") | 
           "\(.type): \(.description) (Score: \(.risk_assessment.score))"'
```

### Behavioral Analysis for Runtime Threats
```bash
# Analyze behavioral patterns
./file-scanner /usr/sbin/* --behavioral --format json | \
    jq -r 'select(.behavioral.syscalls[] | 
           contains("ptrace") or contains("execve")) | 
           .file_path'
```

## 3. Advanced Threat Detection

### YARA Rule Generation and Scanning
```bash
# Generate YARA rules for system binaries
for binary in /bin/* /sbin/*; do
    ./file-scanner "$binary" --yara-indicators --format json | \
        jq -r '.yara_indicators' > "/tmp/yara/$(basename $binary).yara"
done

# Scan for modifications
yara -r /tmp/yara/*.yara /usr/bin/
```

### Symbol-Based Backdoor Detection
```bash
# Look for suspicious function symbols
./file-scanner /usr/bin/* --symbols --format json | \
    jq -r '.symbols[] | 
           select(.name | test("backdoor|rootkit|hide|inject"; "i")) | 
           "\(.file_path): \(.name)"'
```

## 4. Control Flow Integrity

### Complexity Analysis
```bash
# Identify overly complex binaries (potential obfuscation)
./file-scanner /usr/bin/* --control-flow --format json | \
    jq -r 'select(.control_flow.cyclomatic_complexity > 100) | 
           "\(.file_path): Complexity \(.control_flow.cyclomatic_complexity)"'
```

## 5. Supply Chain Security

### Dependency Vulnerability Scanning
```bash
# Check for vulnerable dependencies
./file-scanner /usr/bin/* --dependencies --format json | \
    jq -r '.dependencies[] | 
           select(.vulnerable == true) | 
           "\(.name) \(.version): \(.vulnerabilities[])"'
```

## 6. Automated Hardening Script
```bash
#!/bin/bash
# comprehensive_hardening.sh

echo "Starting comprehensive binary hardening..."

# Create audit directory
mkdir -p /var/audit/binaries

# Scan all system binaries
for dir in /bin /sbin /usr/bin /usr/sbin; do
    echo "Scanning $dir..."
    
    find "$dir" -type f -executable | while read binary; do
        # Full analysis
        ./file-scanner "$binary" --all --format json > \
            "/var/audit/binaries/$(basename $binary).json"
        
        # Check critical issues
        critical_issues=$(jq -r '
            (.vulnerabilities[] | select(.risk_assessment.level == "Critical")) // 
            (.threats[] | select(.severity == "Critical")) // 
            (if .entropy.overall > 7.8 then "Highly packed/encrypted" else empty end) //
            (if .signatures.signed == false then "Unsigned binary" else empty end)
        ' "/var/audit/binaries/$(basename $binary).json" 2>/dev/null)
        
        if [ -n "$critical_issues" ]; then
            echo "CRITICAL: $binary has issues:"
            echo "$critical_issues"
            
            # Take action
            chmod 700 "$binary"  # Restrict permissions
            echo "$binary" >> /var/audit/high_risk_binaries.txt
        fi
    done
done

echo "Hardening complete. Check /var/audit/ for results."
```"""

    def _generate_enhanced_incident_response_guide(self) -> str:
        """Generate enhanced incident response guide."""
        return """# Advanced Binary Incident Response Guide

## Phase 1: Rapid Triage Using Enhanced Analysis

### Immediate Binary Analysis
```bash
# Suspected binary rapid analysis
SUSPICIOUS_BINARY="/usr/bin/suspicious_process"

# Comprehensive scan with all features
./file-scanner "$SUSPICIOUS_BINARY" --all --format json > /incident/binary_analysis.json

# Quick risk assessment
risk_score=$(jq -r '
    ((.vulnerabilities[] | .risk_assessment.score) // 0) +
    ((.threats | length) * 10) +
    (if .entropy.overall > 7.5 then 50 else 0 end) +
    (if .signatures.signed == false then 30 else 0 end) +
    ((.behavioral.syscalls | map(select(. == "ptrace" or . == "execve")) | length) * 20)
' /incident/binary_analysis.json | awk '{s+=$1} END {print s}')

echo "Risk Score: $risk_score"
```

### Behavioral Pattern Matching
```bash
# Extract behavioral indicators
jq -r '.behavioral' /incident/binary_analysis.json > /incident/behavior.json

# Check for known malicious patterns
MALICIOUS_PATTERNS=(
    "socket.*connect.*exec"
    "fork.*dup2.*/bin/sh"
    "mmap.*PROT_EXEC.*memcpy"
)

for pattern in "${MALICIOUS_PATTERNS[@]}"; do
    if grep -qE "$pattern" /incident/behavior.json; then
        echo "ALERT: Malicious pattern detected: $pattern"
    fi
done
```

## Phase 2: Deep Forensic Analysis

### Disassembly Analysis
```bash
# Extract and analyze disassembly
jq -r '.disassembly' /incident/binary_analysis.json > /incident/disasm.txt

# Look for anti-forensics techniques
grep -E "ptrace|prctl|PR_SET_DUMPABLE" /incident/disasm.txt

# Identify crypto/encoding functions
grep -E "AES|RC4|base64|xor" /incident/disasm.txt
```

### Control Flow Reconstruction
```bash
# Analyze control flow for obfuscation
jq -r '.control_flow' /incident/binary_analysis.json

# Generate call graph
echo "digraph G {" > /incident/callgraph.dot
jq -r '.control_flow.call_graph.edges[] | 
       "\"\(.from)\" -> \"\(.to)\";"' /incident/binary_analysis.json >> /incident/callgraph.dot
echo "}" >> /incident/callgraph.dot

# Visualize
dot -Tpng /incident/callgraph.dot -o /incident/callgraph.png
```

## Phase 3: Threat Intelligence Integration

### YARA Rule Creation and Hunting
```bash
# Generate YARA rule from malicious binary
jq -r '.yara_indicators' /incident/binary_analysis.json > /incident/malware.yara

# Hunt across system
yara -r /incident/malware.yara / 2>/dev/null | tee /incident/yara_matches.txt

# Create enhanced YARA rule with behavioral patterns
cat > /incident/enhanced_malware.yara << 'EOF'
rule Enhanced_Malware_Detection {
    meta:
        description = "Enhanced detection based on static and behavioral analysis"
        severity = "critical"
        
    strings:
        $hex_pattern = { [hex_dump.data first 32 bytes] }
        $import1 = "ptrace"
        $import2 = "dlopen"
        $string1 = [unique string from analysis]
        
    condition:
        uint32(0) == 0x464c457f and
        ($hex_pattern at 0) and
        2 of ($import*, $string*)
}
EOF
```

### Timeline Reconstruction
```bash
# Build timeline from binary metadata
echo "=== Binary Timeline ===" > /incident/timeline.txt

# Binary creation/modification times
jq -r '.metadata | 
       "Created: \(.created)\nModified: \(.modified)\nAccessed: \(.accessed)"' \
       /incident/binary_analysis.json >> /incident/timeline.txt

# Check against system logs
grep -h "$SUSPICIOUS_BINARY" /var/log/auth.log /var/log/syslog | 
    sort -k1,2 >> /incident/timeline.txt
```

## Phase 4: Automated Response Actions

### Containment Script
```bash
#!/bin/bash
# contain_malicious_binary.sh

BINARY_PATH="$1"
ANALYSIS_FILE="$2"

# Calculate threat level
THREAT_LEVEL=$(jq -r '
    if (.threats | length) > 5 or 
       (.vulnerabilities[] | select(.risk_assessment.level == "Critical") | length) > 0 or
       .entropy.overall > 7.8
    then "CRITICAL"
    elif (.threats | length) > 2 or
         .entropy.overall > 7.0
    then "HIGH"
    else "MEDIUM"
    end
' "$ANALYSIS_FILE")

case $THREAT_LEVEL in
    CRITICAL)
        echo "CRITICAL threat detected - immediate containment"
        # Kill all instances
        pkill -9 -f "$BINARY_PATH"
        # Quarantine binary
        mv "$BINARY_PATH" "/quarantine/$(basename $BINARY_PATH).$(date +%s)"
        # Block with AppArmor
        aa-complain "$BINARY_PATH"
        ;;
    HIGH)
        echo "HIGH threat detected - restricting execution"
        chmod 000 "$BINARY_PATH"
        # Add to audit watch
        auditctl -w "$BINARY_PATH" -p x -k malware_exec
        ;;
    MEDIUM)
        echo "MEDIUM threat - monitoring enabled"
        auditctl -w "$BINARY_PATH" -p rwxa -k suspicious_binary
        ;;
esac

# Generate IoCs
jq -r '{
    md5: .hashes.md5,
    sha256: .hashes.sha256,
    size: .metadata.file_size,
    entropy: .entropy.overall,
    imports: .symbols[] | select(.type == "FUNC") | .name,
    strings: .strings[:20]
}' "$ANALYSIS_FILE" > "/incident/iocs_$(basename $BINARY_PATH).json"
```"""

    def _generate_enhanced_malware_analysis_guide(self) -> str:
        """Generate enhanced malware analysis guide."""
        return """# Advanced Malware Analysis Using Enhanced Features

## Static Analysis Workflow

### 1. Initial Triage with Entropy Analysis
```bash
# Quick entropy check for packing/encryption
SAMPLE="/samples/malware.bin"
entropy=$(./file-scanner "$SAMPLE" --entropy --format json | jq -r '.entropy.overall')

if (( $(echo "$entropy > 7.5" | bc -l) )); then
    echo "Sample is likely packed/encrypted (entropy: $entropy)"
    echo "Attempting to identify packer..."
    
    # Check section entropy
    ./file-scanner "$SAMPLE" --entropy --format json | \
        jq -r '.entropy.sections | to_entries[] | 
               "\(.key): \(.value)"' | \
        while read section entropy; do
            if (( $(echo "$entropy > 7.8" | bc -l) )); then
                echo "  High entropy section: $section ($entropy)"
            fi
        done
fi
```

### 2. Symbol and Import Analysis
```bash
# Extract and categorize symbols
./file-scanner "$SAMPLE" --symbols --format json | jq -r '
    .symbols[] | 
    select(.type == "FUNC") | 
    .name' > /tmp/imports.txt

# Categorize imports by functionality
declare -A IMPORT_CATEGORIES=(
    ["process"]="CreateProcess|fork|execve|system"
    ["network"]="socket|connect|send|recv|inet_"
    ["file"]="fopen|CreateFile|write|read"
    ["registry"]="RegOpenKey|RegSetValue|RegQuery"
    ["injection"]="VirtualAlloc|WriteProcessMemory|SetThreadContext"
    ["evasion"]="IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformation"
)

for category in "${!IMPORT_CATEGORIES[@]}"; do
    echo "=== $category APIs ==="
    grep -E "${IMPORT_CATEGORIES[$category]}" /tmp/imports.txt || echo "None found"
    echo
done
```

### 3. Disassembly Pattern Recognition
```bash
# Extract disassembly and look for patterns
./file-scanner "$SAMPLE" --disassembly --format json | \
    jq -r '.disassembly' > /tmp/disasm.txt

# Anti-analysis techniques
echo "=== Anti-Analysis Techniques ==="
grep -n -E "int3|ud2|cpuid|rdtsc" /tmp/disasm.txt | head -20

# Encryption/encoding routines
echo -e "\n=== Possible Crypto/Encoding ==="
grep -n -E "xor|rol|ror|rc4|aes" /tmp/disasm.txt | head -20

# Dynamic API resolution
echo -e "\n=== Dynamic API Loading ==="
grep -n -E "GetProcAddress|dlsym|LoadLibrary" /tmp/disasm.txt | head -20
```

### 4. Control Flow Deobfuscation
```bash
# Analyze control flow complexity
cf_analysis=$(./file-scanner "$SAMPLE" --control-flow --format json | jq -r '.control_flow')

complexity=$(echo "$cf_analysis" | jq -r '.cyclomatic_complexity // 0')
if [ "$complexity" -gt 100 ]; then
    echo "WARNING: Very high complexity ($complexity) - likely obfuscated"
fi

# Identify control flow flattening
if echo "$cf_analysis" | jq -e '.patterns[] | contains("flattening")' >/dev/null 2>&1; then
    echo "Control flow flattening detected!"
fi
```

### 5. Behavioral Prediction
```bash
# Predict runtime behavior from static analysis
./file-scanner "$SAMPLE" --behavioral --format json | jq -r '
    .behavioral | {
        "Predicted Behaviors": [
            if .syscalls[] | contains("socket") then "Network communication" else empty end,
            if .syscalls[] | contains("fork") then "Process creation" else empty end,
            if .syscalls[] | contains("ptrace") then "Anti-debugging" else empty end,
            if .filesystem | contains("write") then "File system modification" else empty end,
            if .processes | contains("inject") then "Process injection" else empty end
        ]
    }'
```

## Advanced YARA Rule Generation

```bash
# Generate comprehensive YARA rule
cat > /tmp/generate_yara.py << 'EOF'
import json
import sys

with open(sys.argv[1]) as f:
    analysis = json.load(f)

rule_name = "Malware_" + analysis['hashes']['md5'][:8]

print(f"""rule {rule_name} {{
    meta:
        description = "Auto-generated rule for malware sample"
        md5 = "{analysis['hashes']['md5']}"
        sha256 = "{analysis['hashes']['sha256']}"
        entropy = "{analysis.get('entropy', {}).get('overall', 0)}"
        
    strings:""")

# Add hex patterns from header
if 'hex_dump' in analysis:
    hex_data = analysis['hex_dump']['data'][:64].replace(' ', ' ')
    print(f'        $header = {{ {hex_data} }}')

# Add unique strings
if 'strings' in analysis:
    for i, s in enumerate(analysis['strings'][:10]):
        if len(s) > 6 and s.isprintable():
            print(f'        $str{i} = "{s}"')

# Add import names
if 'symbols' in analysis:
    imports = [s['name'] for s in analysis['symbols'] if s.get('type') == 'FUNC']
    for i, imp in enumerate(imports[:5]):
        print(f'        $imp{i} = "{imp}"')

print("""
    condition:
        uint32(0) == 0x464c457f and  // ELF header
        $header at 0 and
        4 of them
}""")
EOF

./file-scanner "$SAMPLE" --all --format json | python3 /tmp/generate_yara.py -
```

## Automated Malware Classification

```bash
# Classify malware based on characteristics
cat > /tmp/classify_malware.sh << 'EOF'
#!/bin/bash
ANALYSIS_FILE="$1"

# Initialize scores
ransomware_score=0
backdoor_score=0
miner_score=0
trojan_score=0

# Check for ransomware indicators
if jq -e '.strings[] | select(contains("encrypt") or contains("bitcoin") or contains("decrypt"))' "$ANALYSIS_FILE" >/dev/null 2>&1; then
    ((ransomware_score+=30))
fi

if jq -e '.symbols[] | select(.name | contains("crypto") or contains("AES") or contains("RSA"))' "$ANALYSIS_FILE" >/dev/null 2>&1; then
    ((ransomware_score+=20))
fi

# Check for backdoor indicators
if jq -e '.behavioral.network | contains("listen") or contains("bind")' "$ANALYSIS_FILE" >/dev/null 2>&1; then
    ((backdoor_score+=40))
fi

if jq -e '.symbols[] | select(.name | contains("shell") or contains("cmd"))' "$ANALYSIS_FILE" >/dev/null 2>&1; then
    ((backdoor_score+=20))
fi

# Check for miner indicators
if jq -e '.strings[] | select(contains("stratum") or contains("mining") or contains("pool"))' "$ANALYSIS_FILE" >/dev/null 2>&1; then
    ((miner_score+=50))
fi

# Output classification
echo "=== Malware Classification Scores ==="
echo "Ransomware: $ransomware_score"
echo "Backdoor: $backdoor_score"
echo "Cryptominer: $miner_score"
echo "Generic Trojan: $trojan_score"

# Determine primary classification
max_score=0
classification="Unknown"
for type in ransomware:$ransomware_score backdoor:$backdoor_score miner:$miner_score; do
    name=${type%:*}
    score=${type#*:}
    if [ $score -gt $max_score ]; then
        max_score=$score
        classification=$name
    fi
done

echo -e "\nPrimary Classification: $classification (confidence: $max_score%)"
EOF

chmod +x /tmp/classify_malware.sh
./file-scanner "$SAMPLE" --all --format json > /tmp/analysis.json
/tmp/classify_malware.sh /tmp/analysis.json
```"""

    def _generate_enhanced_vulnerability_assessment_guide(self) -> str:
        """Generate enhanced vulnerability assessment guide."""
        return """# Comprehensive Vulnerability Assessment Guide

## Automated Vulnerability Scanning with Risk Scoring

### 1. System-Wide Vulnerability Assessment
```bash
#!/bin/bash
# comprehensive_vuln_scan.sh

echo "Starting comprehensive vulnerability assessment..."

# Create results directory
SCAN_DIR="/var/security/vuln_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$SCAN_DIR"

# Scan all executable files
find /bin /sbin /usr/bin /usr/sbin -type f -executable | while read binary; do
    echo "Scanning: $binary"
    
    # Full vulnerability analysis
    ./file-scanner "$binary" --vulnerabilities --format json > \
        "$SCAN_DIR/$(basename $binary).json"
    
    # Extract high-risk vulnerabilities
    jq -r '
        .vulnerabilities[] | 
        select(.risk_assessment.level == "Critical" or 
               .risk_assessment.level == "High") |
        {
            binary: .file_path,
            type: .type,
            description: .description,
            score: .risk_assessment.score,
            impact: .risk_assessment.impact,
            exploitability: .risk_assessment.exploitability,
            mitigation: .mitigation
        }' "$SCAN_DIR/$(basename $binary).json" >> "$SCAN_DIR/high_risk_vulns.jsonl" 2>/dev/null
done

# Generate summary report
echo "Generating vulnerability summary..."
cat > "$SCAN_DIR/summary.txt" << EOF
Vulnerability Assessment Summary
================================
Date: $(date)
Files Scanned: $(find "$SCAN_DIR" -name "*.json" | wc -l)

Critical Vulnerabilities: $(grep -c '"level":"Critical"' "$SCAN_DIR"/*.json 2>/dev/null || echo 0)
High Vulnerabilities: $(grep -c '"level":"High"' "$SCAN_DIR"/*.json 2>/dev/null || echo 0)
Medium Vulnerabilities: $(grep -c '"level":"Medium"' "$SCAN_DIR"/*.json 2>/dev/null || echo 0)
Low Vulnerabilities: $(grep -c '"level":"Low"' "$SCAN_DIR"/*.json 2>/dev/null || echo 0)

Top Vulnerable Binaries:
EOF

# List top vulnerable binaries
jq -s 'group_by(.binary) | 
       map({binary: .[0].binary, count: length, max_score: (map(.score) | max)}) | 
       sort_by(.max_score) | 
       reverse | 
       .[:10]' "$SCAN_DIR/high_risk_vulns.jsonl" >> "$SCAN_DIR/summary.txt" 2>/dev/null

echo "Assessment complete. Results in: $SCAN_DIR"
```

### 2. Vulnerability Risk Matrix
```bash
# Generate risk matrix visualization
cat > /tmp/risk_matrix.py << 'EOF'
import json
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

# Read vulnerability data
vulns = defaultdict(list)
with open('high_risk_vulns.jsonl') as f:
    for line in f:
        vuln = json.loads(line)
        impact = vuln.get('impact', 'Unknown')
        exploitability = vuln.get('exploitability', 'Unknown')
        vulns[(impact, exploitability)].append(vuln)

# Create risk matrix
impact_levels = ['Low', 'Medium', 'High', 'Critical']
exploit_levels = ['Low', 'Medium', 'High', 'Critical']

matrix = np.zeros((len(impact_levels), len(exploit_levels)))
for i, impact in enumerate(impact_levels):
    for j, exploit in enumerate(exploit_levels):
        matrix[i, j] = len(vulns.get((impact, exploit), []))

# Plot
fig, ax = plt.subplots(figsize=(10, 8))
im = ax.imshow(matrix, cmap='YlOrRd')

ax.set_xticks(np.arange(len(exploit_levels)))
ax.set_yticks(np.arange(len(impact_levels)))
ax.set_xticklabels(exploit_levels)
ax.set_yticklabels(impact_levels)
ax.set_xlabel('Exploitability')
ax.set_ylabel('Impact')
ax.set_title('Vulnerability Risk Matrix')

# Add text annotations
for i in range(len(impact_levels)):
    for j in range(len(exploit_levels)):
        text = ax.text(j, i, int(matrix[i, j]),
                      ha="center", va="center", color="black")

plt.colorbar(im)
plt.tight_layout()
plt.savefig('risk_matrix.png')
print("Risk matrix saved to risk_matrix.png")
EOF

python3 /tmp/risk_matrix.py
```

### 3. Exploit Prediction Analysis
```bash
# Predict exploitability based on vulnerability characteristics
cat > /tmp/exploit_predictor.sh << 'EOF'
#!/bin/bash
VULN_FILE="$1"

# Extract vulnerability characteristics
exploit_score=0
exploit_factors=""

# Check for memory corruption
if jq -e '.type | contains("buffer overflow") or contains("heap overflow")' "$VULN_FILE" >/dev/null 2>&1; then
    ((exploit_score+=30))
    exploit_factors+="Memory corruption vulnerability; "
fi

# Check for code execution
if jq -e '.description | contains("code execution") or contains("RCE")' "$VULN_FILE" >/dev/null 2>&1; then
    ((exploit_score+=40))
    exploit_factors+="Remote code execution possible; "
fi

# Check for authentication bypass
if jq -e '.type | contains("authentication") or contains("bypass")' "$VULN_FILE" >/dev/null 2>&1; then
    ((exploit_score+=25))
    exploit_factors+="Authentication bypass; "
fi

# Check for privilege escalation
if jq -e '.description | contains("privilege") or contains("escalation")' "$VULN_FILE" >/dev/null 2>&1; then
    ((exploit_score+=35))
    exploit_factors+="Privilege escalation vector; "
fi

# Check if SUID/SGID binary
if jq -e '.metadata.permissions | startswith("4") or startswith("2")' "$VULN_FILE" >/dev/null 2>&1; then
    ((exploit_score+=20))
    exploit_factors+="SUID/SGID binary; "
fi

# Output prediction
echo "Exploit Likelihood Score: $exploit_score/100"
echo "Risk Factors: $exploit_factors"

if [ $exploit_score -gt 80 ]; then
    echo "CRITICAL: Very high likelihood of exploitation"
elif [ $exploit_score -gt 60 ]; then
    echo "HIGH: Likely to be exploited"
elif [ $exploit_score -gt 40 ]; then
    echo "MEDIUM: Moderate exploitation risk"
else
    echo "LOW: Less likely to be exploited"
fi
EOF

chmod +x /tmp/exploit_predictor.sh
```

### 4. Patch Priority Matrix
```bash
# Generate patch priority recommendations
cat > /tmp/patch_priority.py << 'EOF'
import json
from datetime import datetime

class PatchPrioritizer:
    def __init__(self):
        self.vulnerabilities = []
    
    def add_vulnerability(self, vuln):
        priority_score = self.calculate_priority(vuln)
        vuln['priority_score'] = priority_score
        self.vulnerabilities.append(vuln)
    
    def calculate_priority(self, vuln):
        score = 0
        
        # Base score from risk assessment
        risk_score = vuln.get('risk_assessment', {}).get('score', 0)
        score += risk_score * 10
        
        # Exploitability factor
        exploitability = vuln.get('risk_assessment', {}).get('exploitability', 'Low')
        exploit_multipliers = {
            'Critical': 2.0,
            'High': 1.5,
            'Medium': 1.0,
            'Low': 0.5
        }
        score *= exploit_multipliers.get(exploitability, 1.0)
        
        # Internet-facing services get higher priority
        if 'network' in vuln.get('description', '').lower():
            score *= 1.5
        
        # Privilege escalation vulnerabilities
        if 'privilege' in vuln.get('type', '').lower():
            score *= 1.3
        
        # Actively exploited in the wild
        if vuln.get('exploited_in_wild', False):
            score *= 2.0
        
        return round(score, 2)
    
    def get_priority_list(self):
        return sorted(self.vulnerabilities, 
                     key=lambda x: x['priority_score'], 
                     reverse=True)

# Usage
prioritizer = PatchPrioritizer()

# Read vulnerabilities
with open('high_risk_vulns.jsonl') as f:
    for line in f:
        vuln = json.loads(line)
        prioritizer.add_vulnerability(vuln)

# Output priority list
print("Patch Priority List")
print("=" * 50)
for i, vuln in enumerate(prioritizer.get_priority_list()[:20], 1):
    print(f"{i}. {vuln['binary']}")
    print(f"   Type: {vuln['type']}")
    print(f"   Priority Score: {vuln['priority_score']}")
    print(f"   Mitigation: {vuln.get('mitigation', 'Update to latest version')}")
    print()
EOF

python3 /tmp/patch_priority.py
```

### 5. Continuous Vulnerability Monitoring
```bash
# Set up continuous monitoring
cat > /usr/local/bin/vuln_monitor.sh << 'EOF'
#!/bin/bash
# Continuous vulnerability monitoring daemon

BASELINE_DIR="/var/security/baseline"
MONITOR_LOG="/var/log/vuln_monitor.log"

# Create baseline if doesn't exist
if [ ! -d "$BASELINE_DIR" ]; then
    echo "Creating vulnerability baseline..."
    mkdir -p "$BASELINE_DIR"
    
    find /bin /sbin /usr/bin /usr/sbin -type f -executable | while read binary; do
        ./file-scanner "$binary" --vulnerabilities --hashes --format json > \
            "$BASELINE_DIR/$(basename $binary).json" 2>/dev/null
    done
fi

# Monitor for changes
while true; do
    echo "[$(date)] Starting vulnerability scan cycle" >> "$MONITOR_LOG"
    
    find /bin /sbin /usr/bin /usr/sbin -type f -executable | while read binary; do
        current_hash=$(sha256sum "$binary" | awk '{print $1}')
        baseline_file="$BASELINE_DIR/$(basename $binary).json"
        
        if [ -f "$baseline_file" ]; then
            baseline_hash=$(jq -r '.hashes.sha256' "$baseline_file" 2>/dev/null)
            
            if [ "$current_hash" != "$baseline_hash" ]; then
                echo "[$(date)] ALERT: Binary modified: $binary" >> "$MONITOR_LOG"
                
                # Re-scan for vulnerabilities
                ./file-scanner "$binary" --vulnerabilities --format json > \
                    "/tmp/vuln_check_$(basename $binary).json"
                
                # Check for new vulnerabilities
                new_vulns=$(jq -r '.vulnerabilities | length' "/tmp/vuln_check_$(basename $binary).json")
                old_vulns=$(jq -r '.vulnerabilities | length' "$baseline_file")
                
                if [ "$new_vulns" -gt "$old_vulns" ]; then
                    echo "[$(date)] NEW VULNERABILITIES in $binary!" >> "$MONITOR_LOG"
                    # Send alert
                    mail -s "New vulnerabilities detected in $binary" admin@example.com < \
                        "/tmp/vuln_check_$(basename $binary).json"
                fi
                
                # Update baseline
                cp "/tmp/vuln_check_$(basename $binary).json" "$baseline_file"
            fi
        fi
    done
    
    # Sleep for 1 hour
    sleep 3600
done
EOF

chmod +x /usr/local/bin/vuln_monitor.sh

# Create systemd service
cat > /etc/systemd/system/vuln-monitor.service << EOF
[Unit]
Description=Continuous Vulnerability Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vuln_monitor.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl enable vuln-monitor.service
systemctl start vuln-monitor.service
```"""

    def _generate_enhanced_forensics_guide(self) -> str:
        """Generate enhanced forensics investigation guide."""
        return """# Advanced Digital Forensics Investigation Guide

## Evidence Collection and Preservation

### 1. Binary Evidence Acquisition
```bash
#!/bin/bash
# forensic_acquisition.sh

CASE_ID="CASE_$(date +%Y%m%d_%H%M%S)"
EVIDENCE_DIR="/forensics/$CASE_ID"
mkdir -p "$EVIDENCE_DIR"/{binaries,analysis,timeline,artifacts}

echo "Starting forensic acquisition for case: $CASE_ID"

# Acquire binary evidence with metadata preservation
find / -type f -executable -mtime -7 2>/dev/null | while read binary; do
    echo "Acquiring: $binary"
    
    # Preserve timestamps
    cp -p "$binary" "$EVIDENCE_DIR/binaries/$(basename $binary).$(stat -c %Y $binary)"
    
    # Calculate hashes immediately
    md5sum "$binary" >> "$EVIDENCE_DIR/hashes.md5"
    sha256sum "$binary" >> "$EVIDENCE_DIR/hashes.sha256"
    
    # Capture extended attributes
    getfattr -d "$binary" > "$EVIDENCE_DIR/artifacts/$(basename $binary).xattrs" 2>/dev/null
    
    # Full analysis with all features
    ./file-scanner "$binary" --all --format json > \
        "$EVIDENCE_DIR/analysis/$(basename $binary).json"
done

# Create evidence manifest
cat > "$EVIDENCE_DIR/manifest.txt" << EOF
Case ID: $CASE_ID
Acquisition Date: $(date)
Investigator: $(whoami)
System: $(hostname)
Kernel: $(uname -r)

Files Acquired: $(ls "$EVIDENCE_DIR/binaries" | wc -l)
Total Size: $(du -sh "$EVIDENCE_DIR" | cut -f1)

Hash Verification:
MD5: $(md5sum "$EVIDENCE_DIR/hashes.md5" | awk '{print $1}')
SHA256: $(sha256sum "$EVIDENCE_DIR/hashes.sha256" | awk '{print $1}')
EOF

echo "Acquisition complete. Evidence in: $EVIDENCE_DIR"
```

### 2. Timeline Analysis with Enhanced Features
```bash
# Build comprehensive timeline
cat > /tmp/build_timeline.py << 'EOF'
import json
import os
from datetime import datetime
from pathlib import Path

class ForensicTimeline:
    def __init__(self, evidence_dir):
        self.evidence_dir = Path(evidence_dir)
        self.events = []
    
    def add_binary_events(self, analysis_file):
        with open(analysis_file) as f:
            data = json.load(f)
        
        metadata = data.get('metadata', {})
        file_path = data.get('file_path', 'Unknown')
        
        # File system timestamps
        for event_type, timestamp_key in [
            ('Created', 'created'),
            ('Modified', 'modified'),
            ('Accessed', 'accessed')
        ]:
            if timestamp_key in metadata:
                self.events.append({
                    'timestamp': metadata[timestamp_key],
                    'type': event_type,
                    'source': 'filesystem',
                    'file': file_path,
                    'details': f"File {event_type.lower()}"
                })
        
        # Digital signature timestamp
        if 'signatures' in data and isinstance(data['signatures'], dict):
            if 'timestamp' in data['signatures']:
                self.events.append({
                    'timestamp': data['signatures']['timestamp'],
                    'type': 'Signed',
                    'source': 'signature',
                    'file': file_path,
                    'details': f"Binary digitally signed"
                })
        
        # Compilation timestamp (if available from binary info)
        if 'binary_info' in data and 'compile_time' in data['binary_info']:
            self.events.append({
                'timestamp': data['binary_info']['compile_time'],
                'type': 'Compiled',
                'source': 'binary',
                'file': file_path,
                'details': f"Binary compiled"
            })
    
    def correlate_with_logs(self, log_file):
        # Add system log events
        pass
    
    def generate_timeline(self, output_file):
        # Sort events by timestamp
        sorted_events = sorted(self.events, key=lambda x: x['timestamp'])
        
        with open(output_file, 'w') as f:
            f.write("Forensic Timeline\n")
            f.write("=" * 80 + "\n\n")
            
            for event in sorted_events:
                f.write(f"{event['timestamp']} | {event['type']:10} | "
                       f"{event['source']:10} | {os.path.basename(event['file']):20} | "
                       f"{event['details']}\n")

# Usage
timeline = ForensicTimeline('/forensics/CASE_XXX')
for analysis_file in Path('/forensics/CASE_XXX/analysis').glob('*.json'):
    timeline.add_binary_events(analysis_file)
timeline.generate_timeline('/forensics/CASE_XXX/timeline/master_timeline.txt')
EOF

python3 /tmp/build_timeline.py
```

### 3. Artifact Correlation and Analysis
```bash
# Correlate artifacts across multiple binaries
cat > /tmp/correlate_artifacts.sh << 'EOF'
#!/bin/bash
EVIDENCE_DIR="$1"

echo "Correlating forensic artifacts..."

# Find binaries with matching hashes (possible copies)
echo "=== Duplicate Binaries ===" > "$EVIDENCE_DIR/correlation_report.txt"
sort "$EVIDENCE_DIR/hashes.sha256" | uniq -d >> "$EVIDENCE_DIR/correlation_report.txt"

# Find binaries with similar entropy (possibly same packer)
echo -e "\n=== Similar Entropy Patterns ===" >> "$EVIDENCE_DIR/correlation_report.txt"
for json in "$EVIDENCE_DIR/analysis"/*.json; do
    entropy=$(jq -r '.entropy.overall // 0' "$json" 2>/dev/null)
    if (( $(echo "$entropy > 7.5" | bc -l) )); then
        echo "$(basename $json): $entropy" >> "$EVIDENCE_DIR/correlation_report.txt"
    fi
done | sort -k2 -nr

# Find binaries with common strings (possible same family)
echo -e "\n=== Common Unique Strings ===" >> "$EVIDENCE_DIR/correlation_report.txt"
> /tmp/all_strings.txt
for json in "$EVIDENCE_DIR/analysis"/*.json; do
    jq -r '.strings[]' "$json" 2>/dev/null | 
        grep -E '^[A-Za-z0-9]{8,}$' >> /tmp/all_strings.txt
done
sort /tmp/all_strings.txt | uniq -c | sort -nr | 
    awk '$1 > 2 && $1 < 10 {print $2}' | head -20 >> "$EVIDENCE_DIR/correlation_report.txt"

# Find binaries signed by same certificate
echo -e "\n=== Digital Signature Correlation ===" >> "$EVIDENCE_DIR/correlation_report.txt"
for json in "$EVIDENCE_DIR/analysis"/*.json; do
    signer=$(jq -r '.signatures.signer // "unsigned"' "$json" 2>/dev/null)
    if [ "$signer" != "unsigned" ]; then
        echo "$(basename $json): $signer"
    fi
done | sort -k2 >> "$EVIDENCE_DIR/correlation_report.txt"

# Network indicators correlation
echo -e "\n=== Network Indicators ===" >> "$EVIDENCE_DIR/correlation_report.txt"
grep -h -E '([0-9]{1,3}\.){3}[0-9]{1,3}|https?://[^\s]+' "$EVIDENCE_DIR/analysis"/*.json | 
    sort | uniq -c | sort -nr | head -20 >> "$EVIDENCE_DIR/correlation_report.txt"
EOF

chmod +x /tmp/correlate_artifacts.sh
/tmp/correlate_artifacts.sh "$EVIDENCE_DIR"
```

### 4. Advanced Memory Forensics Integration
```bash
# Extract and analyze memory artifacts related to binaries
cat > /tmp/memory_binary_analysis.sh << 'EOF'
#!/bin/bash
MEMORY_DUMP="$1"
BINARY_PATH="$2"
OUTPUT_DIR="$3"

echo "Analyzing binary artifacts in memory dump..."

# Extract process list
volatility -f "$MEMORY_DUMP" --profile=LinuxUbuntu20x64 pslist > "$OUTPUT_DIR/pslist.txt"

# Find process using the binary
BINARY_NAME=$(basename "$BINARY_PATH")
PID=$(grep "$BINARY_NAME" "$OUTPUT_DIR/pslist.txt" | awk '{print $3}')

if [ -n "$PID" ]; then
    echo "Found process $PID running $BINARY_NAME"
    
    # Dump process memory
    volatility -f "$MEMORY_DUMP" --profile=LinuxUbuntu20x64 memdump -p "$PID" -D "$OUTPUT_DIR"
    
    # Extract process maps
    volatility -f "$MEMORY_DUMP" --profile=LinuxUbuntu20x64 maps -p "$PID" > "$OUTPUT_DIR/maps_$PID.txt"
    
    # Look for injected code
    echo "Checking for code injection..."
    volatility -f "$MEMORY_DUMP" --profile=LinuxUbuntu20x64 malfind -p "$PID" > "$OUTPUT_DIR/malfind_$PID.txt"
    
    # Extract network connections
    volatility -f "$MEMORY_DUMP" --profile=LinuxUbuntu20x64 netscan | grep "$PID" > "$OUTPUT_DIR/netconn_$PID.txt"
    
    # Compare binary on disk vs in memory
    echo "Comparing disk vs memory image..."
    ./file-scanner "$OUTPUT_DIR/$PID.dmp" --hashes --entropy --format json > "$OUTPUT_DIR/memory_analysis.json"
    ./file-scanner "$BINARY_PATH" --hashes --entropy --format json > "$OUTPUT_DIR/disk_analysis.json"
    
    # Check for modifications
    DISK_HASH=$(jq -r '.hashes.sha256' "$OUTPUT_DIR/disk_analysis.json")
    MEM_HASH=$(jq -r '.hashes.sha256' "$OUTPUT_DIR/memory_analysis.json")
    
    if [ "$DISK_HASH" != "$MEM_HASH" ]; then
        echo "WARNING: Binary modified in memory!"
        echo "Disk SHA256: $DISK_HASH"
        echo "Memory SHA256: $MEM_HASH"
    fi
fi
EOF

chmod +x /tmp/memory_binary_analysis.sh
```

### 5. Automated Forensic Reporting
```bash
# Generate comprehensive forensic report
cat > /tmp/generate_forensic_report.py << 'EOF'
import json
import os
from datetime import datetime
from pathlib import Path
import matplotlib.pyplot as plt
from collections import Counter, defaultdict

class ForensicReporter:
    def __init__(self, case_dir):
        self.case_dir = Path(case_dir)
        self.report_data = {
            'case_info': {},
            'executive_summary': {},
            'findings': [],
            'artifacts': [],
            'recommendations': []
        }
    
    def analyze_case(self):
        # Analyze all evidence
        analysis_files = list(self.case_dir.glob('analysis/*.json'))
        
        risk_scores = []
        malicious_binaries = []
        unsigned_binaries = []
        high_entropy_binaries = []
        vulnerable_binaries = []
        
        for analysis_file in analysis_files:
            with open(analysis_file) as f:
                data = json.load(f)
            
            file_name = os.path.basename(data.get('file_path', 'Unknown'))
            
            # Calculate risk score
            risk_score = 0
            
            # Check vulnerabilities
            if 'vulnerabilities' in data:
                vulns = data['vulnerabilities']
                risk_score += len(vulns) * 10
                if vulns:
                    vulnerable_binaries.append(file_name)
            
            # Check threats
            if 'threats' in data and data['threats']:
                risk_score += len(data['threats']) * 15
                malicious_binaries.append(file_name)
            
            # Check signatures
            if 'signatures' in data:
                if not data['signatures'].get('signed', True):
                    risk_score += 20
                    unsigned_binaries.append(file_name)
            
            # Check entropy
            if 'entropy' in data:
                entropy = data['entropy'].get('overall', 0)
                if entropy > 7.5:
                    risk_score += 30
                    high_entropy_binaries.append(file_name)
            
            risk_scores.append((file_name, risk_score))
        
        # Sort by risk
        risk_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Update report data
        self.report_data['executive_summary'] = {
            'total_binaries_analyzed': len(analysis_files),
            'high_risk_binaries': len([s for f, s in risk_scores if s > 50]),
            'malicious_indicators_found': len(malicious_binaries),
            'unsigned_binaries': len(unsigned_binaries),
            'packed_binaries': len(high_entropy_binaries),
            'vulnerable_binaries': len(vulnerable_binaries)
        }
        
        # Top findings
        self.report_data['findings'] = [
            {
                'severity': 'Critical' if score > 80 else 'High' if score > 50 else 'Medium',
                'binary': binary,
                'risk_score': score,
                'details': self._get_binary_details(binary)
            }
            for binary, score in risk_scores[:10]
        ]
    
    def _get_binary_details(self, binary_name):
        # Get detailed findings for a binary
        details = []
        analysis_file = self.case_dir / f'analysis/{binary_name}.json'
        
        if analysis_file.exists():
            with open(analysis_file) as f:
                data = json.load(f)
            
            if 'threats' in data and data['threats']:
                details.append(f"Threat indicators: {len(data['threats'])}")
            
            if 'vulnerabilities' in data and data['vulnerabilities']:
                details.append(f"Vulnerabilities: {len(data['vulnerabilities'])}")
            
            if 'entropy' in data and data['entropy'].get('overall', 0) > 7.5:
                details.append("High entropy (packed/encrypted)")
            
            if 'signatures' in data and not data['signatures'].get('signed', True):
                details.append("Unsigned binary")
        
        return '; '.join(details)
    
    def generate_report(self, output_file):
        # Generate HTML report
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Analysis Report - {self.case_dir.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; }}
        .summary {{ background-color: #ecf0f1; padding: 20px; margin: 20px 0; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #34495e; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Digital Forensics Analysis Report</h1>
        <p>Case: {self.case_dir.name}</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <ul>
            <li>Total binaries analyzed: {self.report_data['executive_summary']['total_binaries_analyzed']}</li>
            <li class="critical">High-risk binaries: {self.report_data['executive_summary']['high_risk_binaries']}</li>
            <li class="high">Malicious indicators: {self.report_data['executive_summary']['malicious_indicators_found']}</li>
            <li>Unsigned binaries: {self.report_data['executive_summary']['unsigned_binaries']}</li>
            <li>Packed/encrypted binaries: {self.report_data['executive_summary']['packed_binaries']}</li>
            <li>Vulnerable binaries: {self.report_data['executive_summary']['vulnerable_binaries']}</li>
        </ul>
    </div>
    
    <h2>Key Findings</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Binary</th>
            <th>Risk Score</th>
            <th>Details</th>
        </tr>
"""
        
        for finding in self.report_data['findings']:
            severity_class = finding['severity'].lower()
            html += f"""
        <tr>
            <td class="{severity_class}">{finding['severity']}</td>
            <td>{finding['binary']}</td>
            <td>{finding['risk_score']}</td>
            <td>{finding['details']}</td>
        </tr>
"""
        
        html += """
    </table>
    
    <h2>Recommendations</h2>
    <ol>
        <li>Immediately quarantine and analyze high-risk binaries</li>
        <li>Update vulnerable binaries to latest versions</li>
        <li>Implement code signing requirements for system binaries</li>
        <li>Deploy runtime monitoring for suspicious behaviors</li>
        <li>Conduct regular binary integrity checks</li>
    </ol>
    
    <h2>Technical Details</h2>
    <p>Full technical analysis available in: {case_dir}/analysis/</p>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        print(f"Report generated: {output_file}")

# Usage
reporter = ForensicReporter('/forensics/CASE_XXX')
reporter.analyze_case()
reporter.generate_report('/forensics/CASE_XXX/forensic_report.html')
EOF

python3 /tmp/generate_forensic_report.py
```"""

def main():
    """Run the enhanced ultimate training data generator."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate enhanced Ubuntu binary training data')
    parser.add_argument('--analysis-dir', default="/tmp/bin_full_analysis_v2",
                       help='Directory containing analysis JSON files')
    parser.add_argument('--output-dir', default="/tmp/ultimate_training_enhanced",
                       help='Output directory for training data')
    parser.add_argument('--complexity', choices=['basic', 'standard', 'ultimate'], 
                       default='ultimate',
                       help='Complexity level: basic (5 expertise), standard (12), ultimate (20)')
    parser.add_argument('--examples-per-file', type=int, default=None,
                       help='Override examples per file (default: importance-based)')
    parser.add_argument('--include-negatives', action='store_true',
                       help='Include negative examples (non-existent files, not installed)')
    parser.add_argument('--negative-ratio', type=float, default=0.15,
                       help='Ratio of negative examples to positive (default: 0.15)')
    
    args = parser.parse_args()
    
    print("=== Enhanced Ubuntu Binary Ultimate Training Data Generator ===\n")
    print(f"Complexity: {args.complexity}")
    print(f"Include negatives: {args.include_negatives}")
    print("Enhanced features: Better utilizing all new analysis capabilities")
    
    # Select expertise levels based on complexity
    if args.complexity == 'basic':
        selected_expertise = {
            k: v for k, v in EXPERTISE_LEVELS.items() 
            if k in ['beginner', 'intermediate', 'expert', 'security_analyst', 'sysadmin']
        }
    elif args.complexity == 'standard':
        selected_expertise = {
            k: v for k, v in EXPERTISE_LEVELS.items() 
            if k in ['beginner', 'intermediate', 'advanced', 'expert',
                    'security_analyst', 'malware_analyst', 'forensics_expert',
                    'reverse_engineer', 'sysadmin', 'devops_engineer',
                    'compliance_auditor', 'incident_responder']
        }
    else:
        selected_expertise = EXPERTISE_LEVELS
    
    # Create enhanced generator
    generator = EnhancedUltimateTrainingGenerator(args.analysis_dir, args.output_dir)
    generator.selected_expertise = selected_expertise
    generator.args = args
    
    # Load and analyze files
    generator.load_analyses()
    
    # Generate comprehensive examples
    output_file = generator.generate_comprehensive_examples()
    
    # Generate statistics
    generator.generate_statistics(output_file)
    
    # Generate feature usage report
    generator.generate_feature_usage_report()
    
    print("\n✅ Enhanced generation complete!")
    print("   - Better vulnerability risk assessment integration")
    print("   - Enhanced threat indicator analysis")
    print("   - Improved behavioral pattern detection")
    print("   - Advanced entropy-based packing detection")
    print("   - Comprehensive signature verification")
    print("   - Deep disassembly and symbol analysis")
    print("   - Control flow complexity assessment")
    print("   - Dependency vulnerability tracking")

if __name__ == "__main__":
    main()
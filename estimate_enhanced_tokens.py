#!/usr/bin/env python3
"""
Estimate token counts for enhanced training data based on new analysis features.
"""

import json
import random
from pathlib import Path

def estimate_tokens(text):
    """Estimate token count using 1 token ≈ 4 characters approximation."""
    return len(text) / 4

def analyze_enhanced_content():
    """Estimate token counts for enhanced training data."""
    
    # Sample analysis files to get real data
    analysis_files = list(Path("/tmp/bin_full_analysis_v2").glob("*.json"))[:10]
    
    if not analysis_files:
        print("No analysis files found")
        return
    
    print("=== Enhanced Training Data Token Estimates ===\n")
    
    estimates = []
    
    for file_path in analysis_files:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        file_name = file_path.stem
        print(f"\n📄 Analyzing: {file_name}")
        
        # Estimate tokens for different expertise levels
        token_estimates = {}
        
        # Basic answer (similar to current)
        basic_content = f"""# {file_name} Analysis

## File Information
- Path: {data.get('file_path', '')}
- Size: {data.get('metadata', {}).get('file_size', 0):,} bytes
- Type: {data.get('metadata', {}).get('mime_type', 'Unknown')}

## Purpose
This is a system utility that performs specific tasks.

## Basic Usage
Run `{file_name} --help` for options."""
        
        token_estimates['basic'] = estimate_tokens(basic_content)
        
        # Enhanced answer with new features
        enhanced_parts = [basic_content]
        
        # Add vulnerability data if present
        if 'vulnerabilities' in data and isinstance(data['vulnerabilities'], dict):
            vuln_data = data['vulnerabilities']
            if 'vulnerabilities' in vuln_data and vuln_data['vulnerabilities']:
                vuln_content = "\n## Security Vulnerabilities\n"
                for vuln in vuln_data['vulnerabilities'][:3]:
                    if isinstance(vuln, dict):
                        vuln_content += f"- **{vuln.get('cve', 'CVE-Unknown')}**: {vuln.get('description', 'N/A')}\n"
                        vuln_content += f"  - Severity: {vuln.get('severity', 'Unknown')}\n"
                        vuln_content += f"  - CVSS Score: {vuln.get('cvss_score', 'N/A')}\n"
                enhanced_parts.append(vuln_content)
        
        # Add threat data
        if 'threats' in data and data['threats']:
            threat_content = "\n## Threat Analysis\n"
            threat_content += f"Detected {len(data['threats'])} potential threats\n"
            enhanced_parts.append(threat_content)
        
        # Add behavioral analysis
        if 'behavioral' in data and data['behavioral']:
            behav_content = "\n## Behavioral Analysis\n"
            behav_content += "- System calls detected\n"
            behav_content += "- Network activity monitored\n"
            behav_content += "- File system operations tracked\n"
            enhanced_parts.append(behav_content)
        
        # Add entropy analysis
        if 'entropy' in data and data['entropy']:
            entropy_content = "\n## Entropy Analysis\n"
            entropy_content += f"- Overall entropy: {data['entropy'].get('overall', 0):.2f}/8.0\n"
            if data['entropy'].get('overall', 0) > 7.5:
                entropy_content += "- ⚠️ High entropy detected - possible packing/encryption\n"
            enhanced_parts.append(entropy_content)
        
        # Add disassembly snippet
        if 'disassembly' in data and data['disassembly']:
            disasm_content = "\n## Disassembly Analysis\n```assembly\n"
            # Simulate 20 lines of assembly
            disasm_content += "push   rbp\nmov    rbp,rsp\nsub    rsp,0x20\n" * 7
            disasm_content += "```\n"
            enhanced_parts.append(disasm_content)
        
        # Add hex dump
        if 'hex_dump' in data and data['hex_dump']:
            hex_content = "\n## Binary Header\n```\n"
            hex_content += "00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00\n" * 8
            hex_content += "```\n"
            enhanced_parts.append(hex_content)
        
        enhanced_content = '\n'.join(enhanced_parts)
        token_estimates['enhanced'] = estimate_tokens(enhanced_content)
        
        # Expert level with all features
        expert_content = enhanced_content + """
## Advanced Analysis

### Symbol Table
- main: Function at 0x1040
- init: Function at 0x1000
- fini: Function at 0x2000

### Control Flow Complexity
- Cyclomatic complexity: 15
- Basic blocks: 42
- Call sites: 18

### Dependencies
- libc.so.6 (GLIBC_2.34)
- libpthread.so.0
- libdl.so.2

### YARA Rule
```yara
rule detect_binary {
    meta:
        description = "Detection rule"
    strings:
        $a = {7F 45 4C 46}
        $b = "main"
    condition:
        $a at 0 and $b
}
```

### Incident Response
1. Verify binary integrity
2. Check process behavior
3. Monitor network connections
4. Review file access patterns
"""
        
        token_estimates['expert'] = estimate_tokens(expert_content)
        
        print(f"  Basic level: {token_estimates['basic']:,.0f} tokens")
        print(f"  Enhanced level: {token_estimates['enhanced']:,.0f} tokens")
        print(f"  Expert level: {token_estimates['expert']:,.0f} tokens")
        
        estimates.append({
            'file': file_name,
            'basic': token_estimates['basic'],
            'enhanced': token_estimates['enhanced'],
            'expert': token_estimates['expert']
        })
    
    # Calculate overall statistics
    print("\n" + "="*50)
    print("\n📊 Overall Token Estimates for Enhanced Training Data:\n")
    
    avg_basic = sum(e['basic'] for e in estimates) / len(estimates)
    avg_enhanced = sum(e['enhanced'] for e in estimates) / len(estimates)
    avg_expert = sum(e['expert'] for e in estimates) / len(estimates)
    
    print(f"Average tokens per conversation pair:")
    print(f"  Basic answers: {avg_basic:,.0f} tokens")
    print(f"  Enhanced answers: {avg_enhanced:,.0f} tokens")
    print(f"  Expert answers: {avg_expert:,.0f} tokens")
    
    print(f"\nEstimated ranges (including system + user messages):")
    print(f"  Minimum: {avg_basic + 50:,.0f} tokens (basic + minimal features)")
    print(f"  Average: {avg_enhanced + 50:,.0f} tokens (enhanced with most features)")
    print(f"  Maximum: {avg_expert + 50:,.0f} tokens (expert with all features)")
    
    print(f"\nIncrease from current data:")
    current_avg = 180  # From previous analysis
    print(f"  Current average: {current_avg:,.0f} tokens")
    print(f"  Enhanced average: {avg_enhanced + 50:,.0f} tokens")
    print(f"  Increase: {((avg_enhanced + 50) / current_avg - 1) * 100:,.1f}%")

if __name__ == "__main__":
    analyze_enhanced_content()
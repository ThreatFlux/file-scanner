#!/usr/bin/env python3
"""
Ultimate comprehensive training data generator for Ubuntu binaries.
Generates rich, multi-perspective training data covering all possible angles.
"""

import json
import os
import random
import hashlib
import gzip
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any, Tuple, Set
import concurrent.futures
from datetime import datetime
import itertools

# Extended expertise levels covering specialized roles
EXPERTISE_LEVELS = {
    # Basic levels
    "absolute_beginner": "You are a patient Linux teacher for complete beginners. Use analogies, avoid jargon, and explain everything in simple terms. Compare technical concepts to everyday things people understand.",
    
    "beginner": "You are a helpful Linux educator. Explain Ubuntu system files clearly, focusing on what they do rather than how they work internally. Use simple language but maintain accuracy.",
    
    "intermediate": "You are a Linux systems analyst. Provide detailed explanations balancing technical accuracy with clarity. Include practical examples and common use cases.",
    
    "advanced": "You are an experienced Linux professional. Provide comprehensive technical details while maintaining readability. Include best practices and optimization tips.",
    
    "expert": "You are a Linux internals expert. Provide deep technical analysis including kernel interactions, system calls, and low-level implementation details.",
    
    # Security specializations
    "security_analyst": "You are a security analyst focusing on defensive security. Analyze files for vulnerabilities, misconfigurations, and security best practices. Provide actionable recommendations.",
    
    "threat_hunter": "You are a threat hunter searching for adversary techniques. Focus on behavioral analysis, anomaly detection, and identifying potential attack vectors. Map findings to MITRE ATT&CK.",
    
    "malware_analyst": "You are a malware analyst examining binaries for malicious indicators. Look for obfuscation, anti-analysis techniques, and suspicious behaviors. Provide detailed technical indicators.",
    
    "forensics_expert": "You are a digital forensics expert. Focus on evidence preservation, timeline analysis, and artifact extraction. Document findings in a legally defensible manner.",
    
    "incident_responder": "You are responding to an active security incident. Provide rapid triage, containment strategies, and remediation steps. Focus on minimizing damage and collecting evidence.",
    
    # Development and operations
    "reverse_engineer": "You are a reverse engineer analyzing binary internals. Focus on disassembly, control flow, algorithm reconstruction, and vulnerability discovery. Provide IDA Pro/Ghidra-style analysis.",
    
    "exploit_developer": "You are an ethical exploit developer. Analyze binaries for vulnerabilities, explain exploitation techniques, and provide proof-of-concept code. Always emphasize responsible disclosure.",
    
    "sysadmin": "You are a senior system administrator. Focus on operational aspects, troubleshooting, performance tuning, and maintenance. Provide practical solutions to real-world problems.",
    
    "devops_engineer": "You are a DevOps engineer. Focus on automation, CI/CD integration, containerization, and infrastructure as code. Explain how binaries fit into modern deployment pipelines.",
    
    "performance_engineer": "You are a performance engineer. Analyze binaries for optimization opportunities, resource usage, and bottlenecks. Provide profiling insights and tuning recommendations.",
    
    # Compliance and governance
    "compliance_auditor": "You are a compliance auditor. Evaluate files against standards like CIS, NIST, PCI-DSS, and GDPR. Document findings and remediation requirements.",
    
    "risk_assessor": "You are a risk assessment specialist. Evaluate the potential business impact of file compromises. Provide risk ratings and mitigation strategies.",
    
    # Specialized roles
    "kernel_developer": "You are a Linux kernel developer. Explain how user-space binaries interact with kernel subsystems. Include syscall analysis and kernel module interactions.",
    
    "container_specialist": "You are a container security specialist. Analyze binaries in the context of Docker/Kubernetes deployments. Focus on container escape risks and isolation.",
    
    "iot_security": "You are an IoT security researcher. Consider how binaries might behave in embedded/IoT contexts. Focus on resource constraints and attack surfaces.",
}

# Comprehensive question templates with multiple variations
QUESTION_CATEGORIES = {
    "identification": {
        "basic": [
            "What is {file}?",
            "Tell me about {file}",
            "Explain what {file} does",
            "I found {file} on my system - what is it?",
            "Can you describe the purpose of {file}?",
        ],
        "detailed": [
            "Provide a comprehensive overview of {file}",
            "Give me an in-depth analysis of {file}",
            "What are all the capabilities of {file}?",
            "Explain {file} in detail including its internals",
        ],
        "comparative": [
            "How does {file} compare to similar tools?",
            "What makes {file} unique among Ubuntu binaries?",
            "Compare {file} to its alternatives",
            "Why would I use {file} instead of other options?",
        ],
    },
    
    "security": {
        "vulnerability": [
            "What vulnerabilities might {file} have?",
            "Analyze {file} for security weaknesses",
            "Could {file} be exploited? How?",
            "What are the attack vectors for {file}?",
            "Check {file} for common vulnerabilities",
        ],
        "hardening": [
            "How do I secure {file}?",
            "What hardening steps should I apply to {file}?",
            "Provide security best practices for {file}",
            "How can I reduce the attack surface of {file}?",
        ],
        "detection": [
            "How do I detect if {file} is compromised?",
            "Create detection rules for malicious use of {file}",
            "What are the IoCs for {file} abuse?",
            "Build a YARA rule for {file}",
            "How would {file} appear in logs if misused?",
        ],
        "incident": [
            "I think {file} was compromised - what do I do?",
            "{file} is behaving strangely - investigate",
            "Perform incident response on {file}",
            "How do I contain a compromised {file}?",
            "What forensic artifacts does {file} leave?",
        ],
    },
    
    "technical": {
        "binary": [
            "Analyze the binary structure of {file}",
            "What are the ELF headers of {file}?",
            "Show me the sections and segments of {file}",
            "What compiler/linker flags were used for {file}?",
            "Explain the memory layout of {file}",
        ],
        "runtime": [
            "How does {file} behave at runtime?",
            "What system calls does {file} make?",
            "Trace the execution flow of {file}",
            "What signals does {file} handle?",
            "How does {file} interact with the kernel?",
        ],
        "dependencies": [
            "What libraries does {file} depend on?",
            "Show me the dependency tree for {file}",
            "What happens if {file}'s dependencies are missing?",
            "How do I resolve dependency issues with {file}?",
        ],
        "internals": [
            "Reverse engineer {file}",
            "What algorithms does {file} implement?",
            "Show me the key functions in {file}",
            "How is {file} implemented internally?",
            "Disassemble the main logic of {file}",
        ],
    },
    
    "operational": {
        "usage": [
            "How do I use {file}?",
            "What are the command line options for {file}?",
            "Show me examples of {file} usage",
            "What's the proper syntax for {file}?",
            "When should I use {file}?",
        ],
        "troubleshooting": [
            "{file} is not working - help!",
            "Debug why {file} is failing",
            "Common problems with {file} and solutions",
            "Why does {file} give permission denied?",
            "{file} crashes - how do I fix it?",
        ],
        "performance": [
            "How do I optimize {file} performance?",
            "Why is {file} running slowly?",
            "Profile the resource usage of {file}",
            "What are the performance characteristics of {file}?",
            "How do I tune {file} for my workload?",
        ],
        "monitoring": [
            "How do I monitor {file}?",
            "Set up logging for {file}",
            "What metrics should I track for {file}?",
            "How do I know if {file} is healthy?",
            "Create alerts for {file} issues",
        ],
    },
    
    "compliance": {
        "standards": [
            "Does {file} meet CIS benchmark requirements?",
            "Evaluate {file} against NIST controls",
            "Is {file} PCI-DSS compliant?",
            "Check {file} for GDPR implications",
            "Audit {file} against security standards",
        ],
        "policies": [
            "What policies should govern {file} usage?",
            "Create security policies for {file}",
            "Document acceptable use of {file}",
            "What restrictions should apply to {file}?",
        ],
    },
    
    "development": {
        "integration": [
            "How do I integrate {file} into my application?",
            "Can I call {file} from Python/Java/etc?",
            "What's the API for {file}?",
            "How do I script {file}?",
            "Best practices for using {file} programmatically",
        ],
        "modification": [
            "Can I modify {file}? How?",
            "How do I patch {file}?",
            "Explain how to rebuild {file} from source",
            "What would happen if I changed {file}?",
        ],
    },
    
    "learning": {
        "educational": [
            "Teach me about {file} from scratch",
            "I'm learning Linux - explain {file}",
            "What can {file} teach me about Linux?",
            "Use {file} to explain Linux concepts",
            "What's a good exercise using {file}?",
        ],
        "historical": [
            "What's the history of {file}?",
            "How has {file} evolved over time?",
            "Why was {file} created?",
            "What problem does {file} solve?",
        ],
    },
}

class UltimateTrainingGenerator:
    def __init__(self, analysis_dir: str, output_dir: str):
        self.analysis_dir = Path(analysis_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.analyses = {}
        self.file_importance = {}  # Score files by importance
        self.string_patterns = defaultdict(set)
        self.selected_expertise = EXPERTISE_LEVELS  # Default to all
        self.args = None  # Will be set by main()
        self.generated_count = 0
        self.examples_buffer = []
        self.buffer_size = 1000  # Write in chunks
        
    def load_analyses(self):
        """Load all analysis files with importance scoring."""
        print(f"Loading analyses from {self.analysis_dir}...")
        
        json_files = list(self.analysis_dir.glob("*.json"))
        total_files = len(json_files)
        print(f"Found {total_files} analysis files")
        
        # Load files and calculate importance
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._load_and_score_file, f): f 
                      for f in json_files}
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                if completed % 100 == 0:
                    print(f"  Loaded {completed}/{total_files} files...")
                    
                try:
                    result = future.result()
                    if result:
                        file_path, analysis, importance = result
                        self.analyses[file_path] = analysis
                        self.file_importance[file_path] = importance
                except Exception as e:
                    print(f"Error: {e}")
        
        print(f"Successfully loaded {len(self.analyses)} files")
        
        # Sort files by importance
        self.sorted_files = sorted(self.file_importance.items(), 
                                 key=lambda x: x[1], reverse=True)
        
    def _load_and_score_file(self, file_path: Path) -> Tuple[str, Dict, float]:
        """Load file and calculate importance score."""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            if not isinstance(data, dict) or 'file_path' not in data:
                return None
                
            file_path_str = data['file_path']
            
            # Calculate importance score
            importance = 0.0
            basename = os.path.basename(file_path_str)
            
            # Core utilities get highest scores
            core_utils = ['ls', 'cat', 'grep', 'find', 'bash', 'sh', 'cp', 'mv', 
                         'rm', 'chmod', 'chown', 'ps', 'kill', 'top', 'df', 'du']
            if any(basename == util for util in core_utils):
                importance += 10.0
                
            # Security tools
            security_tools = ['sudo', 'su', 'passwd', 'gpg', 'ssh', 'openssl', 
                            'iptables', 'ufw', 'fail2ban', 'aide']
            if any(tool in basename for tool in security_tools):
                importance += 8.0
                
            # Development tools
            dev_tools = ['gcc', 'g++', 'make', 'git', 'python', 'perl', 'ruby', 
                        'node', 'java', 'cargo', 'go']
            if any(tool in basename for tool in dev_tools):
                importance += 7.0
                
            # System management
            if 'systemd' in basename or 'systemctl' in basename:
                importance += 6.0
                
            # Network tools
            if any(net in basename for net in ['curl', 'wget', 'nc', 'netstat', 
                                               'ss', 'ip', 'ifconfig']):
                importance += 6.0
                
            # File size factor (larger binaries often more complex)
            if 'metadata' in data:
                size = data['metadata'].get('file_size', 0)
                importance += min(size / 1000000, 5.0)  # Max 5 points for size
                
            # String complexity factor
            if 'strings' in data:
                importance += min(len(data['strings']) / 100, 5.0)
                
            return file_path_str, data, importance
            
        except Exception:
            return None
            
    def generate_comprehensive_examples(self):
        """Generate comprehensive examples with intelligent distribution."""
        print("\n=== Generating Comprehensive Training Data ===")
        
        # Open output file for streaming
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"ubuntu_ultimate_training_{timestamp}.jsonl"
        
        with open(output_file, 'w') as f:
            # Generate examples with importance-based distribution
            self._generate_importance_weighted_examples(f)
            
            # Generate negative examples if requested
            if self.args and self.args.include_negatives:
                self._generate_negative_examples(f)
            
            # Generate cross-cutting examples
            self._generate_thematic_examples(f)
            
            # Generate comparative examples
            self._generate_comparative_examples(f)
            
            # Generate scenario-based examples
            self._generate_scenario_examples(f)
            
            # Flush any remaining buffer
            self._flush_buffer(f)
            
        print(f"\nTotal examples generated: {self.generated_count:,}")
        print(f"Output file: {output_file}")
        
        # Generate compressed version
        self._compress_output(output_file)
        
        return output_file
        
    def _generate_importance_weighted_examples(self, file_handle):
        """Generate examples with more for important files."""
        print("\nGenerating importance-weighted examples...")
        
        for file_path, importance in self.sorted_files:
            analysis = self.analyses[file_path]
            
            # Calculate examples based on importance
            if importance >= 10:
                num_examples = 200  # Maximum for most important
            elif importance >= 8:
                num_examples = 150
            elif importance >= 6:
                num_examples = 100
            elif importance >= 4:
                num_examples = 50
            else:
                num_examples = 25  # Minimum
            
            # Override if specified
            if self.args and self.args.examples_per_file:
                num_examples = self.args.examples_per_file
                
            self._generate_file_examples(file_path, analysis, num_examples, file_handle)
            
            # Progress
            if self.generated_count % 1000 == 0:
                print(f"  Generated {self.generated_count:,} examples...")
                
    def _generate_file_examples(self, file_path: str, analysis: Dict[str, Any], 
                               num_examples: int, file_handle):
        """Generate all examples for a single file."""
        file_name = os.path.basename(file_path)
        
        # Get all combinations of expertise and question types
        all_combinations = list(itertools.product(
            self.selected_expertise.keys(),
            QUESTION_CATEGORIES.keys()
        ))
        
        # If we need more examples than combinations, add variations
        if num_examples > len(all_combinations):
            # Repeat important combinations
            important_expertise = ['security_analyst', 'threat_hunter', 'sysadmin', 
                                 'incident_responder', 'expert']
            important_questions = ['security', 'technical', 'operational']
            
            for exp in important_expertise:
                for q_cat in important_questions:
                    all_combinations.append((exp, q_cat))
                    
        # Shuffle for variety
        random.shuffle(all_combinations)
        
        # Generate examples
        for i in range(min(num_examples, len(all_combinations))):
            expertise, q_category = all_combinations[i]
            
            # Get question subcategory and template
            q_subcategories = list(QUESTION_CATEGORIES[q_category].keys())
            q_subcategory = random.choice(q_subcategories)
            q_templates = QUESTION_CATEGORIES[q_category][q_subcategory]
            question = random.choice(q_templates).format(file=file_name)
            
            # Generate rich answer
            answer = self._generate_rich_answer(
                file_path, analysis, expertise, q_category, q_subcategory
            )
            
            example = {
                "messages": [
                    {"role": "system", "content": EXPERTISE_LEVELS[expertise]},
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer}
                ],
                "metadata": {
                    "file": file_name,
                    "file_path": file_path,
                    "importance_score": self.file_importance.get(file_path, 0),
                    "expertise": expertise,
                    "question_category": q_category,
                    "question_subcategory": q_subcategory
                }
            }
            
            self.examples_buffer.append(example)
            self.generated_count += 1
            
            # Write buffer if full
            if len(self.examples_buffer) >= self.buffer_size:
                self._flush_buffer(file_handle)
                
    def _generate_rich_answer(self, file_path: str, analysis: Dict[str, Any],
                             expertise: str, q_category: str, q_subcategory: str) -> str:
        """Generate a rich, detailed answer based on all parameters."""
        parts = []
        file_name = os.path.basename(file_path)
        
        # Expertise-appropriate header
        if expertise in ['absolute_beginner', 'beginner']:
            parts.append(f"# Understanding {file_name}\n")
        elif expertise in ['security_analyst', 'threat_hunter', 'malware_analyst']:
            parts.append(f"# Security Analysis: {file_name}\n")
        elif expertise in ['reverse_engineer', 'exploit_developer']:
            parts.append(f"# Technical Deep Dive: {file_name}\n")
        else:
            parts.append(f"# {file_name} Analysis\n")
            
        # Core information adapted to expertise
        if expertise == 'absolute_beginner':
            parts.append(self._generate_beginner_explanation(file_name, analysis))
        else:
            parts.append(self._generate_technical_overview(file_name, analysis, expertise))
            
        # Category-specific content
        if q_category == 'security':
            parts.extend(self._generate_security_content(
                file_name, analysis, expertise, q_subcategory
            ))
        elif q_category == 'technical':
            parts.extend(self._generate_technical_content(
                file_name, analysis, expertise, q_subcategory
            ))
        elif q_category == 'operational':
            parts.extend(self._generate_operational_content(
                file_name, analysis, expertise, q_subcategory
            ))
        elif q_category == 'compliance':
            parts.extend(self._generate_compliance_content(
                file_name, analysis, expertise
            ))
            
        # Add code examples for technical roles
        if expertise in ['reverse_engineer', 'exploit_developer', 'kernel_developer']:
            parts.extend(self._generate_code_examples(file_name, analysis))
            
        # Add practical recommendations
        if expertise in ['sysadmin', 'devops_engineer', 'incident_responder']:
            parts.extend(self._generate_practical_recommendations(
                file_name, analysis, expertise
            ))
            
        return '\n'.join(parts)
        
    def _generate_beginner_explanation(self, file_name: str, analysis: Dict[str, Any]) -> str:
        """Generate explanation for absolute beginners."""
        explanation = []
        
        # Use analogies
        if 'ls' in file_name:
            explanation.append("Think of `ls` like opening a folder on your desktop - "
                             "it shows you what's inside a directory.")
        elif 'cat' in file_name:
            explanation.append("`cat` is like opening a text file to read it - "
                             "it displays the contents on your screen.")
        elif 'grep' in file_name:
            explanation.append("`grep` is like using Ctrl+F to search for text - "
                             "it finds specific words or patterns in files.")
        else:
            # Use actual metadata to provide context
            if 'metadata' in analysis:
                mime_type = analysis['metadata'].get('mime_type', '')
                if 'shell' in mime_type or 'script' in mime_type:
                    explanation.append(f"`{file_name}` is a script that automates tasks on your computer.")
                elif 'executable' in mime_type or 'elf' in mime_type.lower():
                    explanation.append(f"`{file_name}` is a program that runs directly on your computer.")
                else:
                    explanation.append(f"`{file_name}` is a file that your computer uses.")
            else:
                explanation.append(f"`{file_name}` is part of your Ubuntu system.")
            
        # Add simple metadata
        if 'metadata' in analysis:
            size = analysis['metadata'].get('file_size', 0)
            size_mb = size / 1024 / 1024
            explanation.append(f"\nℹ️ **File size**: {size_mb:.1f} MB")
            explanation.append("📍 **Location**: " + analysis.get('file_path', ''))
            
        return '\n'.join(explanation)
        
    def _generate_technical_overview(self, file_name: str, analysis: Dict[str, Any], 
                                   expertise: str) -> str:
        """Generate technical overview adapted to expertise level."""
        overview = []
        
        # File information
        if 'metadata' in analysis:
            meta = analysis['metadata']
            overview.append("## File Information\n")
            overview.append(f"- **Path**: `{analysis.get('file_path', '')}`")
            overview.append(f"- **Type**: {meta.get('mime_type', 'Unknown')}")
            overview.append(f"- **Size**: {meta.get('file_size', 0):,} bytes")
            overview.append(f"- **Permissions**: {meta.get('permissions', 'Unknown')}")
            
            if expertise in ['forensics_expert', 'incident_responder']:
                overview.append(f"- **Created**: {meta.get('created', 'Unknown')}")
                overview.append(f"- **Modified**: {meta.get('modified', 'Unknown')}")
                overview.append(f"- **Accessed**: {meta.get('accessed', 'Unknown')}")
                
            overview.append("")
            
        # Hashes for security roles
        if expertise in ['security_analyst', 'malware_analyst', 'forensics_expert']:
            if 'hashes' in analysis:
                overview.append("## Cryptographic Hashes\n")
                overview.append("```")
                for algo, hash_val in analysis['hashes'].items():
                    overview.append(f"{algo.upper():8}: {hash_val}")
                overview.append("```\n")
                
        # Entropy analysis for malware/forensics
        if expertise in ['malware_analyst', 'forensics_expert', 'threat_hunter']:
            if 'entropy' in analysis and analysis['entropy']:
                overview.append("## Entropy Analysis\n")
                entropy_val = analysis['entropy'].get('overall', 0)
                overview.append(f"- **Overall Entropy**: {entropy_val:.2f}/8.0")
                if entropy_val > 7.5:
                    overview.append("- ⚠️ **High entropy detected** - Possible encryption/packing")
                elif entropy_val > 6.5:
                    overview.append("- **Moderate entropy** - Compressed or optimized binary")
                else:
                    overview.append("- **Normal entropy** - Standard binary")
                overview.append("")
                
        # Digital signatures for trust verification
        if expertise in ['security_analyst', 'compliance_auditor', 'forensics_expert']:
            if 'signatures' in analysis and analysis['signatures']:
                overview.append("## Digital Signatures\n")
                sigs = analysis['signatures']
                if isinstance(sigs, dict):
                    if sigs.get('signed', False):
                        overview.append("✅ **Binary is digitally signed**")
                        if 'signer' in sigs:
                            overview.append(f"- Signer: {sigs['signer']}")
                        if 'timestamp' in sigs:
                            overview.append(f"- Timestamp: {sigs['timestamp']}")
                    else:
                        overview.append("❌ **Binary is not signed**")
                elif isinstance(sigs, list):
                    for sig in sigs:
                        overview.append(f"- {sig}")
                overview.append("")
                
        return '\n'.join(overview)
        
    def _generate_security_content(self, file_name: str, analysis: Dict[str, Any],
                                 expertise: str, subcategory: str) -> List[str]:
        """Generate security-focused content."""
        content = []
        
        if subcategory == 'vulnerability':
            content.append("\n## Vulnerability Analysis\n")
            content.append(self._analyze_vulnerabilities(file_name, analysis))
            
        elif subcategory == 'detection':
            content.append("\n## Detection Rules\n")
            content.append(self._generate_detection_rules(file_name, analysis))
            
        elif subcategory == 'hardening':
            content.append("\n## Security Hardening\n")
            content.append(self._generate_hardening_steps(file_name, analysis))
            
        elif subcategory == 'incident':
            content.append("\n## Incident Response\n")
            content.append(self._generate_incident_response(file_name, analysis))
            
        return content
        
    def _analyze_vulnerabilities(self, file_name: str, analysis: Dict[str, Any]) -> str:
        """Analyze potential vulnerabilities."""
        vulns = []
        
        # Use actual vulnerability analysis if available
        if 'vulnerabilities' in analysis and analysis['vulnerabilities']:
            vulns.append("### Detected Vulnerabilities")
            
            # Handle dict format with nested vulnerabilities
            if isinstance(analysis['vulnerabilities'], dict):
                vuln_list = analysis['vulnerabilities'].get('vulnerabilities', [])
                if vuln_list:
                    for vuln in vuln_list[:10]:
                        if isinstance(vuln, dict):
                            vulns.append(f"- **{vuln.get('type', 'Unknown')}**: {vuln.get('description', '')}")
                            if 'severity' in vuln:
                                vulns.append(f"  - Severity: {vuln['severity']}")
                            if 'cve' in vuln:
                                vulns.append(f"  - CVE: {vuln['cve']}")
                        else:
                            vulns.append(f"- {vuln}")
            # Handle list format (legacy)
            elif isinstance(analysis['vulnerabilities'], list):
                for vuln in analysis['vulnerabilities'][:10]:
                    if isinstance(vuln, dict):
                        vulns.append(f"- **{vuln.get('type', 'Unknown')}**: {vuln.get('description', '')}")
                        if 'severity' in vuln:
                            vulns.append(f"  - Severity: {vuln['severity']}")
                        if 'cve' in vuln:
                            vulns.append(f"  - CVE: {vuln['cve']}")
                    else:
                        vulns.append(f"- {vuln}")
            vulns.append("")
        
        # Check for risky functions in strings
        if 'strings' in analysis:
            risky_functions = ['system', 'exec', 'popen', 'strcpy', 'strcat', 
                             'sprintf', 'gets', 'scanf']
            found_risky = [s for s in analysis['strings'] 
                          if any(risk in s for risk in risky_functions)]
            
            if found_risky:
                vulns.append("### Potentially Risky Functions")
                for func in found_risky[:5]:
                    vulns.append(f"- `{func}` - May be vulnerable to injection/overflow")
                    
        # Check for setuid/setgid
        if 'metadata' in analysis:
            perms = analysis['metadata'].get('permissions', '')
            if '4' in perms[0] or '2' in perms[0]:
                vulns.append("\n### Privilege Escalation Risk")
                vulns.append("- File has SUID/SGID bit set")
                vulns.append("- Can be exploited for privilege escalation if vulnerable")
        
        # Add threat analysis if available
        if 'threats' in analysis and analysis['threats']:
            vulns.append("\n### Threat Indicators")
            for threat in analysis['threats'][:5]:
                if isinstance(threat, dict):
                    vulns.append(f"- **{threat.get('name', 'Unknown')}**: {threat.get('description', '')}")
                else:
                    vulns.append(f"- {threat}")
                
        if not vulns:
            vulns.append("No obvious vulnerabilities detected in static analysis.")
            vulns.append("Dynamic analysis recommended for comprehensive assessment.")
            
        return '\n'.join(vulns)
        
    def _generate_detection_rules(self, file_name: str, analysis: Dict[str, Any]) -> str:
        """Generate detection rules."""
        rules = []
        
        # Use actual YARA indicators if available
        if 'yara_indicators' in analysis and analysis['yara_indicators']:
            rules.append("### Generated YARA Rule\n")
            rules.append("```yara")
            rules.append(analysis['yara_indicators'])
            rules.append("```")
        else:
            # Generate YARA rule manually
            rules.append("### YARA Rule\n")
            rules.append("```yara")
            rules.append(f"rule detect_{file_name.replace('-', '_').replace('.', '_')}")
            rules.append("{")
            rules.append("    meta:")
            rules.append(f'        description = "Detect {file_name} binary"')
            rules.append(f'        author = "Ubuntu Binary Analysis"')
            
            # Add hash from new location
            if 'hashes' in analysis:
                rules.append(f'        md5 = "{analysis["hashes"].get("md5", "")}"')
                rules.append(f'        sha256 = "{analysis["hashes"].get("sha256", "")}"')
                
            rules.append("    strings:")
            
            # Add hex patterns if available
            if 'hex_dump' in analysis and analysis['hex_dump']:
                hex_data = analysis['hex_dump'].get('data', '')
                if hex_data:
                    # Extract first 16 bytes as pattern
                    hex_pattern = hex_data[:47].replace(' ', ' ').strip()
                    rules.append(f'        $hex_pattern = {{ {hex_pattern} }}')
                    
            if 'strings' in analysis:
                # Add unique strings
                unique_strings = [s for s in analysis['strings'] 
                                if len(s) > 10 and s.isprintable()][:3]
                for i, s in enumerate(unique_strings):
                    rules.append(f'        $str{i} = "{s}"')
                    
            rules.append("    condition:")
            rules.append("        uint32(0) == 0x464c457f and")  # ELF header
            rules.append("        any of them")
            rules.append("}")
            rules.append("```")
        
        # Sigma rule for logging
        rules.append("\n### Sigma Rule\n")
        rules.append("```yaml")
        rules.append(f"title: Suspicious Execution of {file_name}")
        rules.append("description: Detects potentially malicious use")
        rules.append("logsource:")
        rules.append("    product: linux")
        rules.append("    service: syslog")
        rules.append("detection:")
        rules.append("    selection:")
        rules.append(f"        - CommandLine|contains: '{file_name}'")
        rules.append("    suspicious_params:")
        rules.append("        - CommandLine|contains:")
        rules.append("            - '/dev/tcp/'")
        rules.append("            - 'bash -i'")
        rules.append("            - 'nc -e'")
        rules.append("    condition: selection and suspicious_params")
        rules.append("```")
        
        return '\n'.join(rules)
        
    def _generate_hardening_steps(self, file_name: str, analysis: Dict[str, Any]) -> str:
        """Generate security hardening recommendations."""
        steps = []
        
        steps.append("### Security Hardening Steps")
        steps.append("1. **Verify Binary Integrity**")
        steps.append("   ```bash")
        steps.append(f"   debsums -c | grep {file_name}")
        steps.append("   ```")
        steps.append("")
        steps.append("2. **Restrict Permissions**")
        steps.append("   ```bash")
        steps.append(f"   chmod 755 {analysis.get('file_path', '/usr/bin/' + file_name)}")
        steps.append(f"   chown root:root {analysis.get('file_path', '/usr/bin/' + file_name)}")
        steps.append("   ```")
        steps.append("")
        steps.append("3. **Create AppArmor Profile**")
        steps.append("   ```bash")
        steps.append(f"   aa-genprof {file_name}")
        steps.append("   ```")
        steps.append("")
        steps.append("4. **Monitor with auditd**")
        steps.append("   ```bash")
        steps.append(f"   auditctl -w {analysis.get('file_path', '/usr/bin/' + file_name)} -p x -k {file_name}_exec")
        steps.append("   ```")
        
        return '\n'.join(steps)
        
    def _generate_incident_response(self, file_name: str, analysis: Dict[str, Any]) -> str:
        """Generate incident response steps."""
        steps = []
        
        steps.append("### Incident Response Procedures")
        steps.append("")
        steps.append("#### 1. Initial Triage")
        steps.append(f"- Check if {file_name} is currently running: `ps aux | grep {file_name}`")
        steps.append(f"- Verify file hash against known-good: `sha256sum {analysis.get('file_path', '/usr/bin/' + file_name)}`")
        steps.append("")
        steps.append("#### 2. Evidence Collection")
        steps.append("```bash")
        steps.append("# Capture process memory")
        steps.append(f"gcore $(pgrep {file_name})")
        steps.append("# Save file for analysis")
        steps.append(f"cp {analysis.get('file_path', '/usr/bin/' + file_name)} /evidence/")
        steps.append("```")
        steps.append("")
        steps.append("#### 3. Containment")
        steps.append(f"- Kill suspicious processes: `pkill -9 {file_name}`")
        steps.append(f"- Quarantine file: `chmod 000 {analysis.get('file_path', '/usr/bin/' + file_name)}`")
        steps.append("")
        steps.append("#### 4. Recovery")
        steps.append(f"- Reinstall from package: `apt-get install --reinstall $(dpkg -S {file_name} | cut -d: -f1)`")
        
        return '\n'.join(steps)
        
    def _generate_technical_content(self, file_name: str, analysis: Dict[str, Any],
                                  expertise: str, subcategory: str) -> List[str]:
        """Generate technical analysis content."""
        content = []
        
        if subcategory == 'binary':
            content.append("\n## Binary Structure Analysis\n")
            if 'binary_info' in analysis and analysis['binary_info']:
                bi = analysis['binary_info']
                content.append(f"- **Format**: {bi.get('format', 'Unknown')}")
                content.append(f"- **Architecture**: {bi.get('arch', 'Unknown')}")
                content.append(f"- **Entry Point**: {bi.get('entry_point', 'N/A')}")
                if 'compiler' in bi:
                    content.append(f"- **Compiler**: {bi['compiler']}")
                if 'sections' in bi:
                    content.append("\n### Sections")
                    for section in bi['sections'][:5]:
                        content.append(f"- {section.get('name', 'Unknown')}: {section.get('size', 0)} bytes")
                        
            # Add hex dump if available
            if 'hex_dump' in analysis and analysis['hex_dump']:
                content.append("\n### Header Hex Dump")
                content.append("```")
                # Handle both string and dict formats
                if isinstance(analysis['hex_dump'], str):
                    hex_data = analysis['hex_dump'][:256]
                else:
                    hex_data = analysis['hex_dump'].get('data', '')[:256]
                content.append(hex_data)
                content.append("```")
                
        elif subcategory == 'dependencies':
            content.append("\n## Dependency Analysis\n")
            
            # Use actual dependency analysis if available
            if 'dependencies' in analysis and analysis['dependencies']:
                content.append("### Detected Dependencies")
                for dep in analysis['dependencies'][:10]:
                    if isinstance(dep, dict):
                        content.append(f"- **{dep.get('name', 'Unknown')}**: {dep.get('version', 'N/A')}")
                    else:
                        content.append(f"- {dep}")
            else:
                # Fall back to string analysis
                if 'strings' in analysis:
                    libs = [s for s in analysis['strings'] if s.endswith('.so')]
                    if libs:
                        content.append("### Shared Libraries (from strings)")
                        for lib in sorted(set(libs))[:10]:
                            content.append(f"- `{lib}`")
                            
        elif subcategory == 'internals' and expertise == 'reverse_engineer':
            content.append("\n## Reverse Engineering Analysis\n")
            
            # Use actual disassembly if available
            if 'disassembly' in analysis and analysis['disassembly']:
                content.append("### Disassembly")
                content.append("```assembly")
                # Show first 20 lines of disassembly
                disasm_lines = str(analysis['disassembly']).split('\n')[:20]
                for line in disasm_lines:
                    content.append(line)
                content.append("```")
                
            # Add symbol analysis
            if 'symbols' in analysis and analysis['symbols']:
                content.append("\n### Symbol Table")
                for sym in analysis['symbols'][:10]:
                    if isinstance(sym, dict):
                        content.append(f"- {sym.get('name', 'Unknown')}: {sym.get('type', 'N/A')}")
                    else:
                        content.append(f"- {sym}")
                        
            # Add control flow if available
            if 'control_flow' in analysis and analysis['control_flow']:
                content.append("\n### Control Flow Analysis")
                content.append("- Basic blocks detected")
                content.append("- Call graph available for analysis")
            
        elif subcategory == 'performance' and expertise in ['performance_engineer', 'devops_engineer']:
            content.append("\n## Performance Analysis\n")
            
            # Code quality metrics
            if 'code_quality' in analysis and analysis['code_quality']:
                content.append("### Code Quality Metrics")
                cq = analysis['code_quality']
                if isinstance(cq, dict):
                    for metric, value in cq.items():
                        content.append(f"- **{metric}**: {value}")
                else:
                    content.append(str(cq))
                    
            # Behavioral analysis for performance
            if 'behavioral' in analysis and analysis['behavioral']:
                content.append("\n### Behavioral Patterns")
                behavioral = analysis['behavioral']
                if isinstance(behavioral, dict):
                    if 'syscalls' in behavioral:
                        content.append("- **System Calls**: " + ", ".join(behavioral['syscalls'][:5]))
                    if 'network' in behavioral:
                        content.append("- **Network Activity**: " + behavioral['network'])
                    if 'filesystem' in behavioral:
                        content.append("- **File Operations**: " + behavioral['filesystem'])
            
        return content
        
    def _generate_operational_content(self, file_name: str, analysis: Dict[str, Any],
                                    expertise: str, subcategory: str) -> List[str]:
        """Generate operational content."""
        content = []
        
        if subcategory == 'troubleshooting':
            content.append("\n## Troubleshooting Guide\n")
            content.append("### Common Issues")
            content.append("1. **Permission Denied**")
            content.append("   - Check file permissions: `ls -l " + analysis.get('file_path', file_name) + "`")
            content.append("   - Ensure executable bit: `chmod +x " + file_name + "`")
            content.append("2. **Command Not Found**")
            content.append("   - Verify PATH: `echo $PATH`")
            content.append("   - Use full path: `" + analysis.get('file_path', '/usr/bin/' + file_name) + "`")
            
        elif subcategory == 'performance':
            content.append("\n## Performance Optimization\n")
            content.append("### Profiling")
            content.append(f"1. CPU profiling: `perf record -g {file_name} <args>`")
            content.append(f"2. Memory profiling: `valgrind --tool=massif {file_name}`")
            content.append(f"3. System calls: `strace -c {file_name}`")
            
        elif subcategory == 'monitoring':
            content.append("\n## Monitoring Setup\n")
            content.append("### Key Metrics")
            content.append(f"- Process count: `pgrep -c {file_name}`")
            content.append(f"- CPU usage: `top -b -n 1 | grep {file_name}`")
            content.append(f"- Memory usage: `ps aux | grep {file_name}`")
            content.append("### Logging")
            content.append(f"- Enable audit logging: `auditctl -w {analysis.get('file_path', '/usr/bin/' + file_name)} -p rwxa`")
            
        return content
        
    def _generate_compliance_content(self, file_name: str, analysis: Dict[str, Any],
                                   expertise: str) -> List[str]:
        """Generate compliance-focused content."""
        content = ["\n## Compliance Assessment\n"]
        
        content.append("### CIS Ubuntu Linux Benchmark")
        content.append("- Ensure proper file permissions (0755 or more restrictive)")
        content.append("- Verify file ownership (root:root for system binaries)")
        content.append("- Check for unnecessary SUID/SGID bits")
        
        content.append("\n### NIST SP 800-53 Controls")
        content.append("- **AC-3**: Access Enforcement")
        content.append("  - Implement least privilege for binary execution")
        content.append("- **AU-2**: Audit Events")
        content.append("  - Log all executions of sensitive binaries")
        content.append("- **CM-7**: Least Functionality")
        content.append("  - Remove if not required for system operation")
        
        return content
        
    def _generate_code_examples(self, file_name: str, analysis: Dict[str, Any]) -> List[str]:
        """Generate code examples for technical roles."""
        examples = ["\n## Code Examples\n"]
        
        # Python wrapper
        examples.append("### Python Wrapper")
        examples.append("```python")
        examples.append("import subprocess")
        examples.append("import shlex")
        examples.append("")
        examples.append(f"def run_{file_name.replace('-', '_')}(args):")
        examples.append(f'    """Wrapper for {file_name}"""')
        examples.append(f"    cmd = ['{file_name}'] + shlex.split(args)")
        examples.append("    result = subprocess.run(cmd, capture_output=True, text=True)")
        examples.append("    return result.stdout, result.stderr, result.returncode")
        examples.append("```")
        
        # C example
        examples.append("\n### C Integration")
        examples.append("```c")
        examples.append("#include <stdlib.h>")
        examples.append("#include <unistd.h>")
        examples.append("")
        examples.append(f"int execute_{file_name.replace('-', '_')}(char *args[]) {{")
        examples.append(f'    return execvp("{file_name}", args);')
        examples.append("}")
        examples.append("```")
        
        return examples
        
    def _generate_practical_recommendations(self, file_name: str, analysis: Dict[str, Any],
                                          expertise: str) -> List[str]:
        """Generate practical recommendations."""
        recs = ["\n## Recommendations\n"]
        
        if expertise == 'sysadmin':
            recs.append("### System Administration")
            recs.append("1. Regular integrity checks: `aide --check`")
            recs.append("2. Monitor for unauthorized changes: `auditd` rules")
            recs.append("3. Restrict access with AppArmor/SELinux profiles")
            recs.append("4. Keep updated via package manager")
            
        elif expertise == 'incident_responder':
            recs.append("### Incident Response Actions")
            recs.append("1. **Immediate**: Check process list for anomalies")
            recs.append("2. **Containment**: Restrict network access if compromised")
            recs.append("3. **Investigation**: Compare hashes with known-good")
            recs.append("4. **Recovery**: Reinstall from trusted source")
            
        elif expertise == 'devops_engineer':
            recs.append("### DevOps Integration")
            recs.append("1. Include in container minimal base images")
            recs.append("2. Version pin in Dockerfiles")
            recs.append("3. Scan with Trivy/Grype in CI/CD")
            recs.append("4. Monitor with Prometheus/Grafana")
            
        return recs
        
    def _generate_thematic_examples(self, file_handle):
        """Generate examples around themes."""
        print("\nGenerating thematic examples...")
        
        themes = {
            "security_hardening": "How do I harden Ubuntu system binaries?",
            "incident_response": "I've been compromised - how do I check system binaries?",
            "performance_tuning": "How do I optimize Ubuntu binary performance?",
            "container_security": "What binaries are safe to include in containers?",
            "compliance_audit": "How do I audit Ubuntu binaries for compliance?",
        }
        
        for theme, question in themes.items():
            for expertise in ['expert', 'security_analyst', 'sysadmin']:
                answer = self._generate_thematic_answer(theme, expertise)
                
                example = {
                    "messages": [
                        {"role": "system", "content": EXPERTISE_LEVELS[expertise]},
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": answer}
                    ],
                    "metadata": {
                        "type": "thematic",
                        "theme": theme,
                        "expertise": expertise
                    }
                }
                
                self.examples_buffer.append(example)
                self.generated_count += 1
                
        self._flush_buffer(file_handle)
        
    def _generate_thematic_answer(self, theme: str, expertise: str) -> str:
        """Generate answer for thematic questions."""
        if theme == "security_hardening":
            return """# Ubuntu Binary Security Hardening Guide

## 1. File Permissions
```bash
# Find files with excessive permissions
find /usr/bin -perm -4000 -o -perm -2000 | xargs ls -l

# Remove unnecessary SUID/SGID
chmod u-s /path/to/binary
```

## 2. Integrity Monitoring
```bash
# Generate baseline
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Regular checks
aide --check
```

## 3. Access Controls
- Implement AppArmor profiles
- Use SELinux contexts
- Apply ACLs for granular control

## 4. Binary Allowlisting
- Use fapolicyd for application control
- Implement executable restrictions
- Monitor with auditd"""
        
        elif theme == "incident_response":
            return """# Binary Compromise Investigation

## Immediate Actions
1. **Isolate System** - Disconnect network if possible
2. **Preserve Evidence** - Create memory dump and disk image
3. **Document Everything** - Start incident log

## Binary Verification
```bash
# Compare hashes with known-good
debsums -c
rpm -Va  # For RPM-based systems

# Check for modified binaries
find /usr/bin -type f -mtime -7 | while read f; do
    dpkg -S "$f" && md5sum "$f"
done
```

## Detection Techniques
- Check for unusual process arguments
- Look for hidden processes
- Verify library injections
- Analyze network connections

## Recovery Steps
1. Boot from trusted media
2. Mount filesystem read-only
3. Extract evidence
4. Reinstall affected binaries"""
        
        # Add more themes...
        return f"# {theme.replace('_', ' ').title()}\n\nDetailed guidance..."
        
    def _generate_comparative_examples(self, file_handle):
        """Generate comparative analysis examples."""
        print("\nGenerating comparative examples...")
        
        # Find groups of similar binaries
        groups = {
            "shells": ["bash", "sh", "dash", "zsh"],
            "editors": ["vim", "nano", "ed", "emacs"],
            "compilers": ["gcc", "g++", "clang", "rustc"],
            "interpreters": ["python", "python3", "perl", "ruby"],
        }
        
        for group_name, binaries in groups.items():
            # Find matching files in our analyses
            matching = []
            for binary in binaries:
                for file_path in self.analyses:
                    if binary in os.path.basename(file_path):
                        matching.append((binary, file_path))
                        break
                        
            if len(matching) >= 2:
                question = f"Compare {group_name} in Ubuntu"
                answer = self._generate_comparison(group_name, matching)
                
                example = {
                    "messages": [
                        {"role": "system", "content": EXPERTISE_LEVELS["expert"]},
                        {"role": "user", "content": question},
                        {"role": "assistant", "content": answer}
                    ],
                    "metadata": {
                        "type": "comparative",
                        "group": group_name,
                        "binaries": [m[0] for m in matching]
                    }
                }
                
                self.examples_buffer.append(example)
                self.generated_count += 1
                
        self._flush_buffer(file_handle)
    
    def _generate_negative_examples(self, file_handle):
        """Generate examples for non-existent files and not-installed packages."""
        print("\nGenerating negative examples...")
        
        # Calculate number of negative examples
        num_negatives = int(self.generated_count * self.args.negative_ratio)
        print(f"Generating {num_negatives} negative examples ({self.args.negative_ratio*100:.0f}% ratio)")
        
        # Non-existent binaries (typos, common mistakes)
        non_existent_binaries = [
            # Common typos
            ("systemd", "systemctl"),  # (wrong, correct)
            ("aptget", "apt-get"),
            ("ifconfig", "ip"),  # deprecated
            ("service", "systemctl"),
            ("yum", "apt"),  # wrong distro
            ("pacman", "apt"),  # wrong distro
            ("emerge", "apt"),  # wrong distro
            
            # Common tools not in base Ubuntu
            ("htop", "top"),
            ("tree", "ls"),
            ("ncdu", "du"),
            ("tmux", "screen"),
            ("zsh", "bash"),
            ("fish", "bash"),
            ("nvim", "vim"),
            ("emacs", "nano"),
            ("docker", None),
            ("kubectl", None),
            ("terraform", None),
            ("ansible", None),
            ("vagrant", None),
            ("virtualbox", None),
            
            # Development tools not always installed
            ("node", None),
            ("npm", None),
            ("yarn", None),
            ("cargo", None),
            ("rustc", None),
            ("go", None),
            ("java", None),
            ("javac", None),
            ("mvn", None),
            ("gradle", None),
            
            # Security tools
            ("nmap", None),
            ("wireshark", None),
            ("metasploit", None),
            ("burpsuite", None),
            ("nikto", None),
            ("hydra", None),
            ("john", None),
            ("hashcat", None),
            
            # Made-up/fake binaries
            ("hack-system", None),
            ("linux-exploit", None),
            ("root-shell", None),
            ("password-cracker", None),
            ("system-backdoor", None),
            ("kernel-rootkit", None),
        ]
        
        # Generate examples for non-existent binaries
        for i in range(min(num_negatives, len(non_existent_binaries) * 5)):
            # Pick a non-existent binary
            wrong_name, correct_name = random.choice(non_existent_binaries)
            
            # Pick expertise and question type
            expertise = random.choice(list(self.selected_expertise.keys()))
            q_category = random.choice(list(QUESTION_CATEGORIES.keys()))
            q_subcategory = random.choice(list(QUESTION_CATEGORIES[q_category].keys()))
            q_template = random.choice(QUESTION_CATEGORIES[q_category][q_subcategory])
            
            question = q_template.format(file=wrong_name)
            answer = self._generate_negative_answer(
                wrong_name, correct_name, expertise, q_category, q_subcategory
            )
            
            example = {
                "messages": [
                    {"role": "system", "content": self.selected_expertise[expertise]},
                    {"role": "user", "content": question},
                    {"role": "assistant", "content": answer}
                ],
                "metadata": {
                    "file": wrong_name,
                    "type": "negative",
                    "reason": "not_installed" if correct_name is None else "typo/mistake",
                    "correct_alternative": correct_name,
                    "expertise": expertise,
                    "question_category": q_category,
                    "question_subcategory": q_subcategory
                }
            }
            
            self.examples_buffer.append(example)
            self.generated_count += 1
            
            if len(self.examples_buffer) >= self.buffer_size:
                self._flush_buffer(file_handle)
        
        self._flush_buffer(file_handle)
    
    def _generate_negative_answer(self, wrong_name: str, correct_name: str, 
                                 expertise: str, q_category: str, q_subcategory: str) -> str:
        """Generate answer for non-existent binary."""
        parts = []
        
        # Header based on expertise
        if expertise in ['absolute_beginner', 'beginner']:
            parts.append(f"# About {wrong_name}\n")
            parts.append(f"❌ **{wrong_name}** is not found in the standard Ubuntu installation.\n")
        else:
            parts.append(f"# {wrong_name} - Not Found\n")
            parts.append(f"The binary `{wrong_name}` is not present in the default Ubuntu system PATH.\n")
        
        # Explain based on type
        if correct_name:
            # It's a typo or wrong command
            parts.append(f"## Did you mean `{correct_name}`?\n")
            if expertise in ['absolute_beginner', 'beginner']:
                parts.append(f"It looks like you might be looking for **{correct_name}** instead.")
                parts.append(f"This is a common mistake!\n")
            else:
                parts.append(f"You may be looking for `{correct_name}`, which is the correct command.")
                parts.append(f"Common confusion: {wrong_name} → {correct_name}\n")
        else:
            # It's not installed by default
            parts.append("## Installation Required\n")
            if wrong_name in ['docker', 'kubectl', 'terraform', 'ansible']:
                parts.append(f"`{wrong_name}` is a popular tool but not included in Ubuntu by default.")
                parts.append("\n### How to install:")
                parts.append("```bash")
                
                if wrong_name == 'docker':
                    parts.append("# Install Docker")
                    parts.append("curl -fsSL https://get.docker.com | sh")
                    parts.append("sudo usermod -aG docker $USER")
                elif wrong_name == 'kubectl':
                    parts.append("# Install kubectl")
                    parts.append("sudo snap install kubectl --classic")
                else:
                    parts.append(f"# Install {wrong_name}")
                    parts.append(f"sudo apt update && sudo apt install -y {wrong_name}")
                parts.append("```")
                
            elif wrong_name in ['htop', 'tree', 'tmux', 'ncdu']:
                parts.append(f"`{wrong_name}` is a useful utility available in the Ubuntu repositories.")
                parts.append("\n### Installation:")
                parts.append(f"```bash\nsudo apt install {wrong_name}\n```")
                
            elif wrong_name in ['nmap', 'wireshark', 'nikto']:
                if expertise in ['security_analyst', 'threat_hunter', 'incident_responder']:
                    parts.append(f"`{wrong_name}` is a security tool requiring explicit installation.")
                    parts.append("\n### Security Tool Installation:")
                    parts.append(f"```bash\nsudo apt install {wrong_name}\n```")
                    parts.append("\n⚠️ **Note**: Use responsibly and only on systems you own or have permission to test.")
                else:
                    parts.append(f"`{wrong_name}` is a specialized security tool.")
                    parts.append("Installation requires administrator privileges.")
                    
            elif wrong_name in ['hack-system', 'linux-exploit', 'root-shell', 'password-cracker']:
                parts.append("\n⚠️ **Warning**: This appears to be a malicious tool name.")
                parts.append("No legitimate Ubuntu package exists with this name.")
                if expertise in ['security_analyst', 'threat_hunter']:
                    parts.append("\n### Security Note:")
                    parts.append("If you're looking for legitimate security testing tools, consider:")
                    parts.append("- Metasploit Framework (penetration testing)")
                    parts.append("- John the Ripper (password auditing)")
                    parts.append("- Hydra (network authentication testing)")
                    parts.append("\nAlways use security tools ethically and legally.")
        
        # Add search suggestions
        if expertise not in ['absolute_beginner']:
            parts.append("\n## Finding Similar Tools\n")
            parts.append("To search for related packages:")
            parts.append("```bash")
            parts.append(f"# Search package names")
            parts.append(f"apt search {wrong_name}")
            parts.append(f"\n# Search package descriptions")
            parts.append(f"apt-cache search {wrong_name}")
            parts.append(f"\n# Check if command exists")
            parts.append(f"command -v {wrong_name} || echo 'Not found'")
            parts.append("```")
        
        # Handle specific question types
        if q_category == 'security' and wrong_name not in ['hack-system', 'linux-exploit']:
            parts.append("\n## Security Considerations\n")
            parts.append("When installing additional software:")
            parts.append("- Verify the source is trustworthy")
            parts.append("- Check package signatures")
            parts.append("- Review required permissions")
            parts.append("- Keep software updated")
            
        elif q_category == 'operational':
            parts.append("\n## Alternatives Available\n")
            if correct_name:
                parts.append(f"Use `{correct_name}` instead, which is already installed.")
            else:
                parts.append("Consider using built-in Ubuntu tools:")
                if wrong_name == 'htop':
                    parts.append("- `top` - Process viewer (already installed)")
                elif wrong_name == 'tree':
                    parts.append("- `ls -R` - Recursive directory listing")
                    parts.append("- `find . -type d` - List directories")
                elif wrong_name == 'docker':
                    parts.append("- `lxc`/`lxd` - Ubuntu's container solution")
                    parts.append("- `podman` - Alternative container runtime")
        
        return '\n'.join(parts)
        
    def _generate_comparison(self, group_name: str, matching: List[Tuple[str, str]]) -> str:
        """Generate detailed comparison using real file data."""
        comparison = [f"# Comparison of {group_name.title()}\n"]
        
        # Add comparison table
        comparison.append("| Binary | Size | Hash (MD5) | Entropy | Key Libraries |")
        comparison.append("|--------|------|------------|---------|---------------|")
        
        for binary, file_path in matching:
            if file_path in self.analyses:
                analysis = self.analyses[file_path]
                
                # Get real data
                size = analysis.get('metadata', {}).get('file_size', 0)
                size_mb = size / 1024 / 1024
                
                # Get actual hash
                md5_hash = "N/A"
                if 'hashes' in analysis:
                    md5_hash = analysis['hashes'].get('md5', 'N/A')[:12] + "..."
                
                # Get entropy
                entropy = "N/A"
                if 'entropy' in analysis and analysis['entropy']:
                    entropy_val = analysis['entropy'].get('overall', 0)
                    entropy = f"{entropy_val:.2f}"
                
                # Get key libraries from strings
                libs = []
                if 'strings' in analysis:
                    libs = [s for s in analysis['strings'] if s.endswith('.so')][:3]
                libs_str = ', '.join(libs) if libs else "N/A"
                
                comparison.append(f"| {binary} | {size_mb:.1f}MB | {md5_hash} | {entropy} | {libs_str} |")
        
        # Add detailed analysis based on real data
        comparison.append("\n## Detailed Analysis\n")
        
        for binary, file_path in matching[:2]:  # Detail first two
            if file_path in self.analyses:
                analysis = self.analyses[file_path]
                comparison.append(f"### {binary}")
                
                # Binary info
                if 'binary_info' in analysis and analysis['binary_info']:
                    bi = analysis['binary_info']
                    comparison.append(f"- **Architecture**: {bi.get('arch', 'Unknown')}")
                    comparison.append(f"- **Format**: {bi.get('format', 'Unknown')}")
                    if 'compiler' in bi:
                        comparison.append(f"- **Compiler**: {bi['compiler']}")
                
                # Vulnerabilities
                if 'vulnerabilities' in analysis and analysis['vulnerabilities']:
                    comparison.append(f"- **Security**: {len(analysis['vulnerabilities'])} vulnerabilities detected")
                else:
                    comparison.append("- **Security**: No known vulnerabilities")
                
                # Signatures
                if 'signatures' in analysis and analysis['signatures']:
                    if isinstance(analysis['signatures'], dict) and analysis['signatures'].get('signed'):
                        comparison.append("- **Trust**: ✅ Digitally signed")
                    else:
                        comparison.append("- **Trust**: ❌ Not signed")
                
                comparison.append("")
                
        return '\n'.join(comparison)
        
    def _generate_scenario_examples(self, file_handle):
        """Generate scenario-based examples."""
        print("\nGenerating scenario examples...")
        
        scenarios = [
            {
                "title": "Suspicious Process Detection",
                "question": "I found a process running /usr/bin/python3 -c 'import socket;...' - is this malicious?",
                "expertise": ["security_analyst", "incident_responder"],
            },
            {
                "title": "Performance Issue",
                "question": "The grep command is taking forever to search large files - how can I optimize it?",
                "expertise": ["performance_engineer", "sysadmin"],
            },
            {
                "title": "Container Escape",
                "question": "Can binaries like nsenter or unshare be used to escape containers?",
                "expertise": ["container_specialist", "security_analyst"],
            }
        ]
        
        for scenario in scenarios:
            for expertise in scenario["expertise"]:
                answer = self._generate_scenario_answer(
                    scenario["title"], scenario["question"], expertise
                )
                
                example = {
                    "messages": [
                        {"role": "system", "content": EXPERTISE_LEVELS[expertise]},
                        {"role": "user", "content": scenario["question"]},
                        {"role": "assistant", "content": answer}
                    ],
                    "metadata": {
                        "type": "scenario",
                        "scenario": scenario["title"],
                        "expertise": expertise
                    }
                }
                
                self.examples_buffer.append(example)
                self.generated_count += 1
                
        self._flush_buffer(file_handle)
        
    def _generate_scenario_answer(self, title: str, question: str, expertise: str) -> str:
        """Generate scenario-specific answer using real file data."""
        if "Suspicious Process" in title:
            # Find a Python binary in our analyses to use real data
            python_path = None
            for path in self.analyses:
                if 'python' in os.path.basename(path):
                    python_path = path
                    break
                    
            if python_path and python_path in self.analyses:
                analysis = self.analyses[python_path]
                answer = [f"# Suspicious {os.path.basename(python_path)} Process Analysis\n"]
                answer.append("## Initial Assessment")
                answer.append("The command pattern suggests potential malicious activity:")
                answer.append("- Direct code execution via `-c` flag")
                answer.append("- Socket operations indicate network activity")
                answer.append("- Obfuscated/minified code is a red flag\n")
                
                # Add real file data
                if 'hashes' in analysis:
                    answer.append("## Binary Verification")
                    answer.append(f"Expected {os.path.basename(python_path)} hash:")
                    answer.append(f"- SHA256: {analysis['hashes'].get('sha256', 'Unknown')}")
                    answer.append("Compare with running process to detect tampering.\n")
                    
                if 'behavioral' in analysis and analysis['behavioral']:
                    answer.append("## Normal Behavior Profile")
                    answer.append("Legitimate Python typically shows:")
                    if isinstance(analysis['behavioral'], dict):
                        for key, value in list(analysis['behavioral'].items())[:3]:
                            answer.append(f"- {key}: {value}")
                    answer.append("")
                    
                return '\n'.join(answer)
            else:
                # Fallback if no Python found
                return """# Suspicious Process Analysis

## Initial Assessment
The command pattern suggests potential malicious activity:
- Direct code execution via `-c` flag  
- Socket operations indicate network activity
- Obfuscated/minified code is a red flag

## Investigation Steps
1. **Capture Full Command**
   ```bash
   ps aux | grep python3
   cat /proc/<PID>/cmdline | tr '\\0' '\\n'
   ```

2. **Network Analysis**
   ```bash
   lsof -p <PID>
   netstat -tnp | grep <PID>
   ss -tnp | grep python3
   ```

3. **Process Tree**
   ```bash
   pstree -p <PID>
   ps -ef | grep <PPID>
   ```

## Indicators of Compromise
- Reverse shell patterns: `socket.socket()`, `subprocess`
- Base64 encoded payloads
- Connection to suspicious IPs
- Persistence mechanisms

## Immediate Actions
1. Isolate the system
2. Capture memory: `gcore <PID>`
3. Kill if confirmed malicious
4. Check for persistence"""
        
        # Add more scenario responses...
        return f"# {title}\n\nDetailed analysis and response..."
        
    def _flush_buffer(self, file_handle):
        """Write buffer to file."""
        for example in self.examples_buffer:
            file_handle.write(json.dumps(example) + '\n')
        self.examples_buffer.clear()
        
    def _compress_output(self, output_file: Path):
        """Create compressed version of output."""
        compressed_file = output_file.with_suffix('.jsonl.gz')
        
        print(f"\nCompressing to {compressed_file}...")
        with open(output_file, 'rb') as f_in:
            with gzip.open(compressed_file, 'wb', compresslevel=9) as f_out:
                f_out.writelines(f_in)
                
        compressed_size = compressed_file.stat().st_size / 1024 / 1024
        original_size = output_file.stat().st_size / 1024 / 1024
        
        print(f"Compressed: {original_size:.1f}MB -> {compressed_size:.1f}MB "
              f"({compressed_size/original_size*100:.1f}% of original)")
        
    def generate_statistics(self, output_file: Path):
        """Generate comprehensive statistics."""
        stats = {
            "generation_time": datetime.now().isoformat(),
            "total_examples": self.generated_count,
            "files_analyzed": len(self.analyses),
            "expertise_levels": len(self.selected_expertise),
            "question_categories": sum(len(subs) for subs in QUESTION_CATEGORIES.values()),
            "complexity_level": self.args.complexity if self.args else "ultimate",
            "includes_negatives": self.args.include_negatives if self.args else False,
            "negative_ratio": self.args.negative_ratio if self.args else 0,
            "file_importance_distribution": {},
            "examples_by_importance": {},
        }
        
        # Calculate importance distribution
        importance_buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for file_path, importance in self.file_importance.items():
            if importance >= 10:
                importance_buckets["critical"] += 1
            elif importance >= 7:
                importance_buckets["high"] += 1
            elif importance >= 4:
                importance_buckets["medium"] += 1
            else:
                importance_buckets["low"] += 1
                
        stats["file_importance_distribution"] = importance_buckets
        
        # Save statistics
        stats_file = self.output_dir / "training_statistics.json"
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
            
        print(f"\nStatistics saved to: {stats_file}")
        
        # Print summary
        print("\n=== Generation Statistics ===")
        print(f"Total examples: {stats['total_examples']:,}")
        print(f"Files analyzed: {stats['files_analyzed']:,}")
        print(f"Complexity level: {stats['complexity_level']}")
        print(f"Expertise levels: {stats['expertise_levels']}")
        print(f"Question variations: {stats['question_categories']}")
        if stats['includes_negatives']:
            print(f"Negative examples: {int(stats['total_examples'] * stats['negative_ratio'] / (1 + stats['negative_ratio'])):,}")
        print("\nFile importance distribution:")
        for level, count in importance_buckets.items():
            print(f"  {level}: {count} files")

def main():
    """Run the ultimate training data generator."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate Ubuntu binary training data')
    parser.add_argument('--analysis-dir', default="/tmp/bin_full_analysis_v2",
                       help='Directory containing analysis JSON files')
    parser.add_argument('--output-dir', default="/tmp/ultimate_training",
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
    
    print("=== Ubuntu Binary Ultimate Training Data Generator ===\n")
    print(f"Complexity: {args.complexity}")
    print(f"Include negatives: {args.include_negatives}")
    
    analysis_dir = args.analysis_dir
    output_dir = args.output_dir
    
    # Select expertise levels based on complexity
    if args.complexity == 'basic':
        # Use only 5 basic expertise levels
        selected_expertise = {
            k: v for k, v in EXPERTISE_LEVELS.items() 
            if k in ['beginner', 'intermediate', 'expert', 'security_analyst', 'sysadmin']
        }
    elif args.complexity == 'standard':
        # Use 12 expertise levels
        selected_expertise = {
            k: v for k, v in EXPERTISE_LEVELS.items() 
            if k in ['beginner', 'intermediate', 'advanced', 'expert',
                    'security_analyst', 'malware_analyst', 'forensics_expert',
                    'reverse_engineer', 'sysadmin', 'devops_engineer',
                    'compliance_auditor', 'incident_responder']
        }
    else:
        # Use all 20 expertise levels
        selected_expertise = EXPERTISE_LEVELS
    
    # Create generator with selected complexity
    generator = UltimateTrainingGenerator(analysis_dir, output_dir)
    generator.selected_expertise = selected_expertise
    generator.args = args
    
    # Load and analyze files
    generator.load_analyses()
    
    # Generate comprehensive examples
    output_file = generator.generate_comprehensive_examples()
    
    # Generate statistics
    generator.generate_statistics(output_file)
    
    print("\n✅ Generation complete!")

if __name__ == "__main__":
    main()
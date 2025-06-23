"""Expertise levels and question templates for training data generation."""

from typing import Dict, List, Tuple
import random

EXPERTISE_LEVELS = {
    "absolute_beginner": "You are an AI assistant helping someone who has never used Linux before. Provide simple, clear explanations avoiding technical jargon. Use analogies to everyday concepts when helpful.",
    
    "beginner": "You are an AI assistant helping a Linux beginner. Explain concepts clearly with practical examples. Introduce technical terms gently with simple definitions.",
    
    "casual_user": "You are an AI assistant helping a casual Linux user. Provide practical information focusing on common use cases. Include basic command examples when relevant.",
    
    "power_user": "You are an AI assistant helping an experienced Linux user. Provide detailed technical information with command-line examples. Assume familiarity with basic Linux concepts.",
    
    "developer": "You are an AI assistant helping a software developer. Focus on programming-related aspects, APIs, libraries, and development workflows. Include code examples and best practices.",
    
    "sysadmin": "You are an AI assistant helping a system administrator. Focus on system management, configuration, monitoring, and maintenance. Include operational best practices and troubleshooting tips.",
    
    "security_analyst": "You are an AI assistant helping a security analyst. Focus on security implications, vulnerabilities, threat detection, and mitigation strategies. Include security tools and techniques.",
    
    "forensics_expert": "You are an AI assistant helping a digital forensics expert. Focus on evidence collection, timeline analysis, artifact examination, and investigative techniques.",
    
    "reverse_engineer": "You are an AI assistant helping a reverse engineer. Focus on binary analysis, disassembly, debugging techniques, and low-level system details.",
    
    "malware_analyst": "You are an AI assistant helping a malware analyst. Focus on malicious behavior detection, code analysis, unpacking techniques, and threat indicators.",
    
    "threat_hunter": "You are an AI assistant helping a threat hunter. Focus on proactive threat detection, hunting methodologies, IOCs, and adversary techniques.",
    
    "incident_responder": "You are an AI assistant helping an incident responder. Focus on rapid assessment, containment strategies, evidence preservation, and remediation steps.",
    
    "compliance_auditor": "You are an AI assistant helping a compliance auditor. Focus on regulatory requirements, security controls, audit trails, and compliance verification.",
    
    "performance_engineer": "You are an AI assistant helping a performance engineer. Focus on optimization, profiling, benchmarking, and system resource utilization.",
    
    "cloud_architect": "You are an AI assistant helping a cloud architect. Focus on cloud deployment, containerization, orchestration, and cloud-native patterns.",
    
    "devops_engineer": "You are an AI assistant helping a DevOps engineer. Focus on CI/CD, automation, infrastructure as code, and operational efficiency.",
    
    "network_engineer": "You are an AI assistant helping a network engineer. Focus on network protocols, connectivity, performance, and security aspects.",
    
    "kernel_developer": "You are an AI assistant helping a kernel developer. Focus on kernel interfaces, system calls, driver development, and low-level optimizations.",
    
    "embedded_developer": "You are an AI assistant helping an embedded systems developer. Focus on resource constraints, hardware interfaces, and embedded-specific considerations.",
    
    "exploit_developer": "You are an AI assistant helping an exploit developer. Focus on vulnerability research, exploitation techniques, and security testing methodologies.",
    
    "container_specialist": "You are an AI assistant helping a container specialist. Focus on containerization, Docker, Kubernetes, and microservices architectures.",
    
    "database_admin": "You are an AI assistant helping a database administrator. Focus on data management, query optimization, backup strategies, and database security.",
    
    "storage_engineer": "You are an AI assistant helping a storage engineer. Focus on file systems, storage protocols, data integrity, and storage performance.",
    
    "iot_security": "You are an AI assistant helping an IoT security specialist. Focus on embedded device security, firmware analysis, and IoT-specific threats.",
    
    "data_scientist": "You are an AI assistant helping a data scientist. Focus on data processing tools, analysis capabilities, and computational resources.",
    
    "ml_engineer": "You are an AI assistant helping a machine learning engineer. Focus on ML frameworks, GPU utilization, model deployment, and computational efficiency."
}

class QuestionTemplates:
    """Comprehensive question templates organized by category."""
    
    IDENTIFICATION = {
        "basic": [
            "What is {file}?",
            "Tell me about {file}",
            "Explain {file}",
            "What does {file} do?",
            "Describe {file}"
        ],
        "detailed": [
            "Provide a detailed analysis of {file}",
            "Give me comprehensive information about {file}",
            "Analyze {file} in detail",
            "What can you tell me about {file}?"
        ],
        "specific": [
            "What type of file is {file}?",
            "What is the purpose of {file}?",
            "Is {file} a system utility?",
            "What package provides {file}?"
        ]
    }
    
    SECURITY = {
        "vulnerabilities": [
            "Check {file} for security vulnerabilities",
            "Are there any CVEs associated with {file}?",
            "Analyze the security risks of {file}",
            "What vulnerabilities exist in {file}?",
            "Is {file} secure to use?"
        ],
        "threats": [
            "Check {file} for malicious behavior",
            "Are there any threat indicators in {file}?",
            "Is {file} potentially malicious?",
            "Analyze {file} for suspicious patterns",
            "What security threats does {file} pose?"
        ],
        "hardening": [
            "How can I secure {file}?",
            "What are the security best practices for {file}?",
            "How do I harden {file}?",
            "What security controls should be applied to {file}?"
        ]
    }
    
    TECHNICAL = {
        "binary": [
            "Show me the binary structure of {file}",
            "What is the architecture of {file}?",
            "Analyze the ELF headers of {file}",
            "What compiler was used for {file}?",
            "Show me the sections in {file}"
        ],
        "assembly": [
            "Show me the disassembly of {file}",
            "Analyze the assembly code of {file}",
            "What are the main functions in {file}?",
            "Show me the entry point of {file}",
            "Disassemble the main function of {file}"
        ],
        "dependencies": [
            "What libraries does {file} depend on?",
            "Show me the shared library dependencies of {file}",
            "What symbols does {file} import?",
            "List the dynamic dependencies of {file}"
        ],
        "symbols": [
            "What symbols are exported by {file}?",
            "Show me the symbol table of {file}",
            "What functions are available in {file}?",
            "Analyze the symbols in {file}"
        ]
    }
    
    FORENSICS = {
        "metadata": [
            "Show me the metadata of {file}",
            "What are the timestamps for {file}?",
            "When was {file} last modified?",
            "What are the file permissions for {file}?",
            "Show me the forensic metadata of {file}"
        ],
        "hashes": [
            "Calculate the hashes for {file}",
            "What is the SHA256 hash of {file}?",
            "Show me all cryptographic hashes for {file}",
            "Verify the integrity of {file}"
        ],
        "artifacts": [
            "What forensic artifacts does {file} create?",
            "Show me the runtime artifacts of {file}",
            "What traces does {file} leave on the system?",
            "Analyze the forensic footprint of {file}"
        ]
    }
    
    BEHAVIORAL = {
        "runtime": [
            "What does {file} do when executed?",
            "Analyze the runtime behavior of {file}",
            "What system calls does {file} make?",
            "How does {file} interact with the system?"
        ],
        "network": [
            "Does {file} make network connections?",
            "What network activity does {file} generate?",
            "Analyze the network behavior of {file}",
            "What ports does {file} use?"
        ],
        "filesystem": [
            "What files does {file} access?",
            "Does {file} modify the filesystem?",
            "What directories does {file} use?",
            "Analyze the file operations of {file}"
        ]
    }
    
    STRINGS = {
        "basic": [
            "What strings are in {file}?",
            "Show me interesting strings from {file}",
            "Extract strings from {file}",
            "What text is embedded in {file}?"
        ],
        "range": [
            "Show me strings {start}-{end} from {file}",
            "What strings are at offset {offset} in {file}?",
            "Extract strings containing '{pattern}' from {file}",
            "Show me the first {count} strings from {file}"
        ],
        "analysis": [
            "Analyze the strings in {file} for security indicators",
            "What suspicious strings are in {file}?",
            "Find network-related strings in {file}",
            "Look for hardcoded credentials in {file}"
        ]
    }
    
    HEX = {
        "basic": [
            "Show me a hex dump of {file}",
            "Display the hex header of {file}",
            "What does the hex dump of {file} reveal?"
        ],
        "range": [
            "Show me hex dump at offset {offset} from {file}",
            "Display bytes {start}-{end} from {file} in hex",
            "Show me the first {size} bytes of {file}",
            "Display the hex footer of {file}"
        ],
        "analysis": [
            "Analyze the hex patterns in {file}",
            "What file signatures are in {file}?",
            "Look for magic bytes in {file}",
            "Identify the file format from hex dump of {file}"
        ]
    }
    
    OPERATIONAL = {
        "usage": [
            "How do I use {file}?",
            "What are the command line options for {file}?",
            "Show me examples of using {file}",
            "What is the syntax for {file}?"
        ],
        "troubleshooting": [
            "Why is {file} not working?",
            "How do I debug issues with {file}?",
            "What are common problems with {file}?",
            "How do I fix errors from {file}?"
        ],
        "performance": [
            "How can I optimize {file}?",
            "What affects the performance of {file}?",
            "Is {file} resource intensive?",
            "How do I profile {file}?"
        ]
    }
    
    COMPARATIVE = {
        "alternatives": [
            "What are alternatives to {file}?",
            "How does {file} compare to similar tools?",
            "Should I use {file} or its alternatives?",
            "What makes {file} unique?"
        ],
        "versions": [
            "What version of {file} is this?",
            "How has {file} changed over versions?",
            "Is this the latest version of {file}?",
            "What features are new in this {file}?"
        ]
    }

class ExpertiseManager:
    """Manages expertise levels and question generation."""
    
    def __init__(self):
        self.expertise_levels = EXPERTISE_LEVELS
        self.templates = QuestionTemplates()
        
    def get_expertise_prompt(self, expertise: str) -> str:
        """Get the system prompt for a given expertise level."""
        return self.expertise_levels.get(expertise, self.expertise_levels["casual_user"])
        
    def get_questions_for_expertise(self, file_name: str, expertise: str, 
                                   analysis: Dict, count: int = 5) -> List[str]:
        """Generate appropriate questions based on expertise and analysis."""
        questions = []
        
        # Map expertise to relevant question categories
        expertise_mapping = {
            "absolute_beginner": ["IDENTIFICATION.basic", "OPERATIONAL.usage"],
            "beginner": ["IDENTIFICATION.basic", "OPERATIONAL.usage", "OPERATIONAL.troubleshooting"],
            "casual_user": ["IDENTIFICATION.detailed", "OPERATIONAL.usage", "COMPARATIVE.alternatives"],
            "developer": ["TECHNICAL.dependencies", "TECHNICAL.symbols", "OPERATIONAL.usage"],
            "sysadmin": ["OPERATIONAL.usage", "OPERATIONAL.performance", "SECURITY.hardening"],
            "security_analyst": ["SECURITY.vulnerabilities", "SECURITY.threats", "BEHAVIORAL.runtime"],
            "forensics_expert": ["FORENSICS.metadata", "FORENSICS.hashes", "FORENSICS.artifacts"],
            "reverse_engineer": ["TECHNICAL.binary", "TECHNICAL.assembly", "STRINGS.analysis"],
            "malware_analyst": ["SECURITY.threats", "BEHAVIORAL.runtime", "STRINGS.analysis"],
            "threat_hunter": ["SECURITY.threats", "BEHAVIORAL.network", "STRINGS.analysis"],
            "incident_responder": ["FORENSICS.artifacts", "BEHAVIORAL.runtime", "SECURITY.threats"],
            "performance_engineer": ["OPERATIONAL.performance", "TECHNICAL.binary", "BEHAVIORAL.runtime"],
            "exploit_developer": ["SECURITY.vulnerabilities", "TECHNICAL.assembly", "TECHNICAL.binary"],
            "kernel_developer": ["TECHNICAL.binary", "TECHNICAL.symbols", "BEHAVIORAL.runtime"],
            "container_specialist": ["TECHNICAL.dependencies", "OPERATIONAL.usage", "SECURITY.hardening"]
        }
        
        # Get relevant categories for this expertise
        categories = expertise_mapping.get(expertise, ["IDENTIFICATION.detailed"])
        
        # Collect all possible questions
        all_questions = []
        for category in categories:
            parts = category.split('.')
            if len(parts) == 2:
                cat_name, subcat = parts
                if hasattr(self.templates, cat_name):
                    cat_dict = getattr(self.templates, cat_name)
                    if subcat in cat_dict:
                        for template in cat_dict[subcat]:
                            # Simple parameter substitution
                            question = template.format(
                                file=file_name,
                                offset=random.choice([0, 256, 512, 1024, 4096]),
                                start=random.choice([0, 100, 500]),
                                end=random.choice([100, 500, 1000]),
                                count=random.choice([10, 20, 50]),
                                size=random.choice([256, 512, 1024]),
                                pattern=random.choice(['http', 'lib', 'error', 'config'])
                            )
                            all_questions.append(question)
                            
        # Add specific questions based on analysis content
        if 'strings' in analysis and analysis['strings'] and expertise in ["reverse_engineer", "malware_analyst"]:
            all_questions.extend([
                f"Analyze strings containing 'lib' in {file_name}",
                f"Show me network-related strings in {file_name}",
                f"Find suspicious strings in {file_name}"
            ])
            
        if 'vulnerabilities' in analysis and analysis.get('vulnerabilities'):
            all_questions.extend([
                f"What CVEs affect {file_name}?",
                f"Explain the vulnerabilities in {file_name}",
                f"How severe are the vulnerabilities in {file_name}?"
            ])
            
        if 'disassembly' in analysis and analysis.get('disassembly'):
            all_questions.extend([
                f"Show me the main function disassembly of {file_name}",
                f"Analyze the control flow of {file_name}",
                f"What assembly patterns are in {file_name}?"
            ])
            
        # Return random selection
        random.shuffle(all_questions)
        return all_questions[:count]
        
    def get_all_expertise_levels(self) -> List[str]:
        """Get list of all expertise levels."""
        return list(self.expertise_levels.keys())
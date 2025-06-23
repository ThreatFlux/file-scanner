# Ubuntu Binary Analysis Training Data

## Overview

This repository contains a comprehensive training dataset generated from analyzing 1,538 Ubuntu system binaries. The dataset was created to train AI models on understanding, analyzing, and providing expert guidance about Linux system files from multiple perspectives.

## Dataset Statistics

- **Total Training Examples**: 92,735
- **Files Analyzed**: 1,538 Ubuntu system binaries from `/usr/bin`
- **Expertise Levels**: 20 different perspectives
- **Question Categories**: 21 variations with subcategories
- **Compressed Size**: 6.1MB (original: 94.8MB)
- **Format**: JSONL (JSON Lines), gzip compressed

## Files in This Directory

### Training Data
- `ubuntu_ultimate_training_20250616_204807.jsonl.gz` - Main training dataset (92,735 examples)
- `training_statistics.json` - Generation statistics and metadata

### Generation Scripts
- `generate_ultimate_training_data.py` - Advanced training data generator with 20 expertise levels
- `generate_massive_training_data.py` - High-volume generator (5 examples per file)
- `generate_comprehensive_training.py` - Full-coverage generator (120 examples per file)

### Analysis Scripts
- `analyze_all_bin_files.sh` - Shell script to analyze all /usr/bin files using file-scanner API

## Expertise Levels (20 Total)

### Basic Levels
1. **absolute_beginner** - Uses analogies, avoids jargon, explains in simple terms
2. **beginner** - Clear explanations focusing on what files do
3. **intermediate** - Balanced technical accuracy with clarity
4. **advanced** - Comprehensive technical details with best practices
5. **expert** - Deep technical analysis including kernel interactions

### Security Specializations
6. **security_analyst** - Defensive security, vulnerabilities, best practices
7. **threat_hunter** - Behavioral analysis, anomaly detection, MITRE ATT&CK
8. **malware_analyst** - Malicious indicators, obfuscation, suspicious behaviors
9. **forensics_expert** - Evidence preservation, timeline analysis, artifacts
10. **incident_responder** - Rapid triage, containment, remediation

### Development & Operations
11. **reverse_engineer** - Disassembly, control flow, vulnerability discovery
12. **exploit_developer** - Vulnerability analysis, proof-of-concepts
13. **sysadmin** - Operational aspects, troubleshooting, maintenance
14. **devops_engineer** - Automation, CI/CD, containerization
15. **performance_engineer** - Optimization, profiling, resource usage

### Compliance & Specialized
16. **compliance_auditor** - Standards evaluation (CIS, NIST, PCI-DSS)
17. **risk_assessor** - Business impact, risk ratings, mitigation
18. **kernel_developer** - Syscall analysis, kernel interactions
19. **container_specialist** - Docker/Kubernetes security, isolation
20. **iot_security** - Embedded contexts, resource constraints

## Question Categories & Subcategories

### 1. Identification
- **basic**: "What is X?", "Tell me about X"
- **detailed**: "Comprehensive overview of X"
- **comparative**: "How does X compare to Y?"

### 2. Security
- **vulnerability**: Attack vectors, weaknesses
- **detection**: YARA rules, Sigma rules, IOCs
- **hardening**: Security best practices
- **incident**: Response procedures

### 3. Technical
- **binary**: Structure analysis, ELF headers
- **dependencies**: Library analysis
- **internals**: Reverse engineering details
- **performance**: Resource usage patterns

### 4. Operational
- **usage**: How to use the tool
- **troubleshooting**: Common issues
- **configuration**: Setup and options
- **maintenance**: Updates and management

### 5. Development
- **integration**: Using in code
- **modification**: Customization
- **debugging**: Problem solving
- **build**: Compilation and linking

### 6. Compliance
- **standards**: CIS, NIST compliance
- **audit**: Verification procedures
- **policies**: Security policies
- **documentation**: Requirements

### 7. Learning
- **concepts**: Core principles
- **tutorials**: Step-by-step guides
- **best_practices**: Recommendations
- **examples**: Real-world usage

## File Importance Scoring

The system uses an importance-based weighting system:

### Critical (192 files, ~200 examples each)
Core utilities essential for system operation:
- Basic commands: ls, cat, cp, mv, rm
- Shell utilities: bash, sh, grep, sed, awk
- System tools: systemctl, mount, ps

### High (47 files, ~150 examples each)
Important development and system tools:
- Compilers: gcc, g++, make
- Network: ssh, curl, wget
- Package management: apt, dpkg

### Medium (921 files, ~50 examples each)
Standard utilities and applications

### Low (378 files, ~25 examples each)
Specialized or rarely-used tools

## Training Data Format

Each training example follows the ChatGPT conversation format:

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are a [expertise] expert. [specific instructions]"
    },
    {
      "role": "user", 
      "content": "Question about the binary"
    },
    {
      "role": "assistant",
      "content": "Detailed answer with analysis"
    }
  ],
  "metadata": {
    "file": "binary_name",
    "file_path": "/usr/bin/binary_name",
    "importance_score": 85.5,
    "expertise": "security_analyst",
    "question_category": "security",
    "question_subcategory": "vulnerability"
  }
}
```

## Answer Content Structure

Answers are structured based on expertise level and question type:

### Basic Structure
- File identification and purpose
- Basic metadata (size, type, location)
- Simple explanation

### Security-Focused
- Cryptographic hashes (MD5, SHA256, SHA512, BLAKE3)
- Vulnerability analysis
- Detection rules (YARA, Sigma)
- Hardening recommendations
- Incident response procedures

### Technical Analysis
- Binary format details (ELF structure)
- Compiler detection
- String analysis
- Assembly patterns
- Dependency mapping

### Operational Content
- Usage examples
- Common parameters
- Troubleshooting steps
- Configuration options
- Best practices

## Generation Process

1. **File Analysis**: Each binary was analyzed using the file-scanner tool with:
   - Metadata extraction
   - Hash calculation (MD5, SHA256, SHA512, BLAKE3)
   - String extraction
   - Binary format analysis

2. **Importance Scoring**: Files scored based on:
   - System criticality
   - Usage frequency
   - Security relevance
   - Administrative importance

3. **Example Generation**: For each file:
   - Multiple expertise perspectives
   - Various question types
   - Contextual answers
   - Rich technical details

4. **Quality Assurance**:
   - Deduplication
   - Format validation
   - Content verification
   - Compression optimization

## Usage Examples

### Loading the Dataset

```python
import gzip
import json

# Load compressed JSONL
with gzip.open('ubuntu_ultimate_training_20250616_204807.jsonl.gz', 'rt') as f:
    examples = [json.loads(line) for line in f]

# Access specific expertise examples
security_examples = [e for e in examples 
                    if e['metadata']['expertise'] == 'security_analyst']
```

### Filtering by Category

```python
# Get all forensics questions about critical files
forensics_critical = [
    e for e in examples
    if e['metadata']['expertise'] == 'forensics_expert'
    and e['metadata']['importance_score'] > 80
]
```

### Training Model

```python
# Prepare for fine-tuning
training_data = []
for example in examples:
    training_data.append({
        'messages': example['messages']
    })
```

## File-Scanner Integration

The dataset was generated using the file-scanner tool's comprehensive analysis capabilities:

```bash
# Start file-scanner API
./file-scanner mcp-http --port 3000

# Analyze a binary
curl -X POST http://localhost:3000/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "analyze_file",
    "arguments": {
      "file_path": "/usr/bin/ls",
      "metadata": true,
      "hashes": true,
      "strings": true,
      "binary_info": true
    }
  }'
```

## Extending the Dataset

To add more binaries or regenerate with different parameters:

1. Analyze new files:
```bash
./analyze_all_bin_files.sh /path/to/binaries
```

2. Generate training data:
```python
python generate_ultimate_training_data.py
```

3. Customize expertise levels or question types in the script

## Quality Metrics

- **Coverage**: 90% of /usr/bin analyzed
- **Diversity**: 20 expertise × 21 question types = 420 perspective combinations
- **Depth**: Answers include code examples, commands, and actionable guidance
- **Accuracy**: Based on actual binary analysis, not synthetic data

## Future Enhancements

1. **Additional Binaries**:
   - System libraries (/lib, /lib64)
   - Configuration files (/etc)
   - Kernel modules

2. **Enhanced Analysis**:
   - Dynamic analysis results
   - Syscall tracing
   - Performance profiling

3. **Multi-Modal Data**:
   - Hex dump visualizations
   - Control flow graphs
   - Dependency trees

## License

This dataset is provided for educational and research purposes. The analyzed binaries are part of standard Ubuntu distributions and subject to their respective licenses.

## Citation

If you use this dataset, please reference:
```
Ubuntu Binary Analysis Training Dataset
Generated using file-scanner (https://github.com/your-repo/file-scanner)
1,538 binaries analyzed with 92,735 training examples
```
# Ubuntu Training Data Generation

This directory contains a unified script and data for generating comprehensive training datasets from Ubuntu system binary analysis.

## Quick Start

### 1. Analyze System Binaries
```bash
# Start file-scanner API server
./target/release/file-scanner mcp-http --port 3000

# Analyze all binaries in /usr/bin with ALL features
# Now includes: vulnerabilities, threats, entropy, signatures, 
# hex dumps, symbols, disassembly, behavioral analysis, and more!
./analyze_all_bin_files.sh
```

### 2. Generate Training Data

The `generate_ultimate_training_data.py` script supports multiple complexity levels and configurations:

#### Basic Examples

```bash
# Basic complexity (5 expertise levels)
python generate_ultimate_training_data.py --complexity basic

# Standard complexity (12 expertise levels)
python generate_ultimate_training_data.py --complexity standard

# Ultimate complexity (20 expertise levels) - DEFAULT
python generate_ultimate_training_data.py --complexity ultimate

# Include negative examples (non-existent files)
python generate_ultimate_training_data.py --include-negatives

# Custom examples per file
python generate_ultimate_training_data.py --examples-per-file 10

# Full configuration
python generate_ultimate_training_data.py \
  --complexity ultimate \
  --include-negatives \
  --negative-ratio 0.2 \
  --examples-per-file 50
```

## Generated Files

- `ubuntu_ultimate_training_20250616_204807.jsonl.gz` - Main training dataset
- `training_statistics.json` - Generation statistics
- `UBUNTU_TRAINING_DATA.md` - Detailed documentation

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--analysis-dir` | Directory with analysis JSON files | `/tmp/bin_full_analysis` |
| `--output-dir` | Output directory for training data | `/tmp/ultimate_training` |
| `--complexity` | `basic` (5), `standard` (12), or `ultimate` (20) expertise levels | `ultimate` |
| `--examples-per-file` | Override importance-based weighting | Variable (25-200) |
| `--include-negatives` | Add examples for non-existent/not-installed binaries | False |
| `--negative-ratio` | Ratio of negative to positive examples | 0.15 |

## Complexity Levels

### Basic (5 expertise levels)
- beginner, intermediate, expert
- security_analyst, sysadmin

### Standard (12 expertise levels)
- Basic levels + advanced
- Security: malware_analyst, forensics_expert, incident_responder
- Development: reverse_engineer, devops_engineer
- Compliance: compliance_auditor

### Ultimate (20 expertise levels)
- All standard levels plus:
- absolute_beginner, threat_hunter, exploit_developer
- kernel_developer, performance_engineer, risk_assessor
- container_specialist, iot_security

## Negative Examples

When `--include-negatives` is used, the script generates examples for:

1. **Common Typos**: `systemd` → `systemctl`, `aptget` → `apt-get`
2. **Wrong Distro Commands**: `yum`, `pacman`, `emerge` (not in Ubuntu)
3. **Not Installed by Default**: `docker`, `kubectl`, `htop`, `tree`
4. **Development Tools**: `node`, `npm`, `cargo`, `go`
5. **Security Tools**: `nmap`, `wireshark`, `metasploit`
6. **Malicious Names**: `hack-system`, `root-shell` (warnings included)

## Example Usage

```python
import gzip
import json

# Load training data
with gzip.open('ubuntu_ultimate_training_20250616_204807.jsonl.gz', 'rt') as f:
    examples = [json.loads(line) for line in f]

# Filter by expertise
security_examples = [e for e in examples 
                    if e['metadata']['expertise'] == 'security_analyst']

print(f"Total examples: {len(examples)}")
print(f"Security examples: {len(security_examples)}")
```

## Requirements

- Python 3.8+
- file-scanner binary compiled
- ~2GB free disk space for analysis
- ~100MB for final compressed dataset

## Performance

- Analysis: ~10-20 files/second (with 20 parallel workers)
- Generation: ~1000 examples/second
- Total time: ~2-3 hours for complete pipeline

See `UBUNTU_TRAINING_DATA.md` for detailed documentation.
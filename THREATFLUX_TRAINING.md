# ThreatFlux Training Data Generator

A comprehensive Python library for generating high-quality training data from file analysis results. This library combines all the best features from previous generators into a unified, well-organized package with built-in analytics.

## Features

- **26 Expertise Levels**: From absolute beginner to specialized roles (security analyst, malware analyst, kernel developer, etc.)
- **Comprehensive Answer Generation**: Produces detailed, context-aware answers up to 2000+ tokens
- **Smart Chunking**: Handles large data sections (strings, hex dumps, disassembly) with offset-based questions
- **Built-in Token Analytics**: Real-time token counting and statistics during generation
- **Flexible Configuration**: Customize every aspect of generation through CLI or API
- **Multiple Data Sources**: Load from multiple analysis directories with priority handling
- **Importance Scoring**: Prioritizes core system utilities and security-critical files
- **Negative Examples**: Generates examples for non-existent files to improve model robustness

## Installation

```bash
# Install in development mode
cd /home/vtriple/threatflux/file-scanner
pip install -e .

# Or install directly
python3 setup.py install
```

## Quick Start

### Generate Comprehensive Dataset

```bash
# Generate with default settings
threatflux-train generate --name ubuntu_comprehensive

# Generate with custom settings
threatflux-train generate \
  --name security_focused \
  --examples-per-file 100 \
  --max-tokens 3000 \
  --expertise security_analyst malware_analyst threat_hunter
```

### Analyze Existing Dataset

```bash
# Analyze dataset with token statistics
threatflux-train analyze ubuntu_comprehensive_20250617_120000.jsonl.gz \
  --sample-size 10000 \
  --by-expertise \
  --export-stats stats.json
```

### Show Analysis Statistics

```bash
# Show statistics for loaded analyses
threatflux-train stats \
  --dirs /tmp/bin_full_analysis_v2 /tmp/bin_selective_analysis \
  --features \
  --missing
```

## Library Architecture

```
threatflux_training/
├── core/
│   ├── expertise.py      # 26 expertise levels and question templates
│   ├── generator.py      # Main generation engine with AnswerBuilder
│   ├── analyzer.py       # Analysis data loading and management
│   └── tokenizer.py      # Token counting and statistics
└── cli.py               # Command-line interface
```

## Key Components

### ExpertiseManager
- Manages 26 different expertise levels
- Generates appropriate questions based on expertise and file analysis
- Provides expertise-specific system prompts

### AnswerBuilder
- Builds comprehensive answers based on question context
- Supports all analysis features (vulnerabilities, threats, strings, hex, disassembly, etc.)
- Implements smart truncation for token limits

### TokenCounter
- Real-time token estimation (1 token ≈ 4 characters)
- Tracks statistics by expertise level and file
- Generates detailed reports with percentiles

### TrainingGenerator
- Orchestrates the entire generation process
- Handles buffering and compression
- Provides comprehensive statistics

## Answer Generation Strategy

The library generates rich, detailed answers by:

1. **Context Analysis**: Examines the question to determine what information to include
2. **Expertise Adaptation**: Tailors the answer complexity to the expertise level
3. **Feature Integration**: Incorporates all relevant analysis features
4. **Risk Assessment**: Calculates and presents security risk scores
5. **Recommendations**: Provides actionable recommendations based on expertise

## Example Output

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are an AI assistant helping a security analyst..."
    },
    {
      "role": "user",
      "content": "Check /usr/bin/curl for security vulnerabilities"
    },
    {
      "role": "assistant",
      "content": "# Analysis of curl\n\n**File**: `/usr/bin/curl`\n**Size**: 245,832 bytes\n**Type**: application/x-executable\n\n### Vulnerability Assessment\n\n**Risk Level**: 🟡 **MEDIUM** (45/100)\n**Vulnerabilities Found**: 3\n\n#### CVE-2023-38545\n- **Severity**: High\n- **CVSS Score**: 7.5\n- **Description**: SOCKS5 heap buffer overflow\n- **Affected Versions**: < 8.4.0\n- **Fixed In**: 8.4.0\n\n### Security Analysis\n\n**Network Indicators**:\n- `https://`\n- `http://`\n- `ftp://`\n- SSL/TLS support detected\n\n**System Access**:\n- `/etc/ssl/certs`\n- `.curlrc` configuration file\n\n### Binary Structure\n\n**Format**: ELF\n**Architecture**: x86-64\n**Compiler**: GCC 11.4.0\n**Stripped**: Yes\n\n### Security Recommendations\n\n1. **Monitor**: Enable enhanced monitoring for this binary\n2. **Update**: Ensure latest security patches (8.4.0+)\n3. **Restrict**: Apply application control policies\n4. **Audit**: Review execution logs for suspicious URLs"
    }
  ]
}
```

## CLI Commands

### generate
Generate training datasets with full control over parameters:
```bash
threatflux-train generate \
  --name custom_dataset \
  --dirs /path/to/analysis1:10 /path/to/analysis2:5 \
  --output-dir /output/path \
  --examples-per-file 75 \
  --max-tokens 2500 \
  --no-chunking \
  --expertise developer sysadmin
```

### analyze
Analyze existing datasets for quality and statistics:
```bash
threatflux-train analyze dataset.jsonl.gz \
  --sample-size 5000 \
  --by-expertise \
  --by-file \
  --export-stats detailed_stats.json
```

### stats
Show statistics about analysis files:
```bash
threatflux-train stats \
  --dirs /tmp/analysis1 /tmp/analysis2 \
  --features \
  --missing
```

### list
List available datasets:
```bash
threatflux-train list \
  --dir /tmp/training_output \
  --details
```

### compare
Compare two datasets:
```bash
threatflux-train compare dataset1.jsonl.gz dataset2.jsonl.gz \
  --verbose
```

## Configuration Options

- **examples_per_file**: Base number of examples per file (scaled by importance)
- **max_answer_tokens**: Maximum tokens per answer (default: 2000)
- **enable_chunking**: Generate chunked questions for large data
- **enable_negative_examples**: Include non-existent file examples
- **compression**: Compress output with gzip
- **buffer_size**: Write buffer size for performance

## Token Statistics

The library provides comprehensive token statistics:

- Average tokens per example
- Token distribution (percentiles)
- Breakdown by expertise level
- Top files by token count
- Min/max token ranges

## Performance

- Processes ~100 files/minute with full feature extraction
- Generates ~50-100 examples per file
- Produces datasets of 50K-200K examples
- Compressed output typically 10-20% of original size

## Advanced Usage

### Custom Answer Builder

```python
from threatflux_training import TrainingGenerator, AnswerBuilder

# Create custom answer builder
class CustomAnswerBuilder(AnswerBuilder):
    def build_answer(self, file_name, analysis, expertise, question):
        # Custom answer generation logic
        return super().build_answer(file_name, analysis, expertise, question)

# Use with generator
generator = TrainingGenerator()
generator.answer_builder = CustomAnswerBuilder()
```

### Programmatic Generation

```python
from threatflux_training import TrainingGenerator

# Create generator
generator = TrainingGenerator("/output/path")

# Configure
generator.configure(
    examples_per_file=100,
    max_answer_tokens=3000,
    enable_chunking=True
)

# Load analyses
generator.load_analyses([
    ("/tmp/analysis1", 10),
    ("/tmp/analysis2", 5)
])

# Generate dataset
output_path = generator.generate_dataset("my_dataset")

# Get statistics
stats = generator.get_statistics()
print(generator.tokenizer.format_report())
```

## Best Practices

1. **Use Multiple Analysis Sources**: Load from both full and selective analysis directories
2. **Monitor Token Counts**: Keep answers under 2000 tokens for optimal training
3. **Balance Expertise Levels**: Ensure good distribution across all expertise levels
4. **Enable Chunking**: For files with large string/hex/disassembly sections
5. **Review Statistics**: Check token distribution and feature usage

## Troubleshooting

### Low Token Counts
- Check if analysis files contain full data
- Ensure all features are enabled in analysis
- Verify answer builder is using all available data

### Memory Issues
- Use buffered writing (default)
- Process in batches if needed
- Enable compression to reduce output size

### Missing Features
- Verify analysis was run with `"all": true`
- Check analysis file sizes (should be >1MB for full analysis)
- Review feature usage statistics

## Future Enhancements

- [ ] Multi-language support for questions/answers
- [ ] Custom question template system
- [ ] Synthetic data augmentation
- [ ] Quality scoring for examples
- [ ] Deduplication strategies
- [ ] Integration with model training pipelines
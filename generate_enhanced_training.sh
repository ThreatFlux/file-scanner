#!/bin/bash
# Generate enhanced training data using all new features

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Enhanced Training Data Generation ===${NC}"
echo ""

# Configuration
ANALYSIS_DIR="/tmp/bin_full_analysis_v2"
OUTPUT_DIR="/tmp/enhanced_training_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$OUTPUT_DIR/generation.log"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if analysis files exist
ANALYSIS_COUNT=$(ls -1 "$ANALYSIS_DIR"/*.json 2>/dev/null | wc -l)
if [ "$ANALYSIS_COUNT" -eq 0 ]; then
    echo -e "${RED}Error: No analysis files found in $ANALYSIS_DIR${NC}"
    echo "Please run the analysis first with: ./analyze_all_bin_files.sh"
    exit 1
fi

echo -e "${GREEN}Found $ANALYSIS_COUNT analysis files${NC}"
echo ""

# Feature utilization report
echo -e "${YELLOW}Checking feature coverage...${NC}"
SAMPLE_FILE=$(ls "$ANALYSIS_DIR"/*.json | head -1)
echo "Sample file: $(basename $SAMPLE_FILE)"
echo "Features available:"
cat "$SAMPLE_FILE" | jq -r 'keys[]' | sort | sed 's/^/  - /'
echo ""

# Generate training data with different configurations
echo -e "${BLUE}Generating training data variants...${NC}"
echo ""

# 1. Ultimate complexity with all features and negatives
echo -e "${GREEN}1. Ultimate dataset (20 expertise levels + negatives)${NC}"
python3 generate_ultimate_training_data_enhanced.py \
    --analysis-dir "$ANALYSIS_DIR" \
    --output-dir "$OUTPUT_DIR/ultimate" \
    --complexity ultimate \
    --include-negatives \
    --negative-ratio 0.2 \
    2>&1 | tee "$OUTPUT_DIR/ultimate_generation.log"

echo ""

# 2. Standard complexity for balanced dataset
echo -e "${GREEN}2. Standard dataset (12 expertise levels)${NC}"
python3 generate_ultimate_training_data_enhanced.py \
    --analysis-dir "$ANALYSIS_DIR" \
    --output-dir "$OUTPUT_DIR/standard" \
    --complexity standard \
    --include-negatives \
    --negative-ratio 0.15 \
    2>&1 | tee "$OUTPUT_DIR/standard_generation.log"

echo ""

# 3. Basic complexity for quick testing
echo -e "${GREEN}3. Basic dataset (5 expertise levels)${NC}"
python3 generate_ultimate_training_data_enhanced.py \
    --analysis-dir "$ANALYSIS_DIR" \
    --output-dir "$OUTPUT_DIR/basic" \
    --complexity basic \
    --examples-per-file 10 \
    --include-negatives \
    --negative-ratio 0.1 \
    2>&1 | tee "$OUTPUT_DIR/basic_generation.log"

echo ""

# Generate feature usage report
echo -e "${YELLOW}Generating feature usage report...${NC}"
cat > "$OUTPUT_DIR/feature_usage_report.py" << 'EOF'
import json
import os
from collections import Counter
from pathlib import Path

def analyze_feature_usage(analysis_dir):
    feature_usage = Counter()
    feature_values = {}
    total_files = 0
    
    for file_path in Path(analysis_dir).glob('*.json'):
        total_files += 1
        with open(file_path, 'r') as f:
            data = json.load(f)
            
        for feature in data.keys():
            if data[feature]:  # Feature has data
                feature_usage[feature] += 1
                
                # Track example values
                if feature not in feature_values:
                    feature_values[feature] = []
                    
                # Store sample for reporting
                if len(feature_values[feature]) < 3:
                    if isinstance(data[feature], dict):
                        feature_values[feature].append(f"{file_path.name}: {list(data[feature].keys())[:3]}")
                    elif isinstance(data[feature], list) and len(data[feature]) > 0:
                        feature_values[feature].append(f"{file_path.name}: {len(data[feature])} items")
                    else:
                        feature_values[feature].append(f"{file_path.name}: {type(data[feature]).__name__}")
    
    print(f"=== Feature Usage Report ===\n")
    print(f"Total files analyzed: {total_files}\n")
    print("Feature utilization:")
    
    for feature, count in feature_usage.most_common():
        percentage = (count / total_files) * 100
        print(f"\n{feature}: {count}/{total_files} ({percentage:.1f}%)")
        if feature in feature_values and feature_values[feature]:
            print("  Examples:")
            for example in feature_values[feature][:2]:
                print(f"    - {example}")

if __name__ == "__main__":
    import sys
    analyze_feature_usage(sys.argv[1] if len(sys.argv) > 1 else "/tmp/bin_full_analysis_v2")
EOF

python3 "$OUTPUT_DIR/feature_usage_report.py" "$ANALYSIS_DIR" > "$OUTPUT_DIR/feature_usage.txt"

echo ""
echo -e "${BLUE}=== Generation Complete ===${NC}"
echo ""
echo "Output locations:"
echo "  - Ultimate dataset: $OUTPUT_DIR/ultimate/"
echo "  - Standard dataset: $OUTPUT_DIR/standard/"
echo "  - Basic dataset: $OUTPUT_DIR/basic/"
echo "  - Feature usage report: $OUTPUT_DIR/feature_usage.txt"
echo ""

# Show summary statistics
echo -e "${YELLOW}Dataset sizes:${NC}"
for variant in ultimate standard basic; do
    if [ -d "$OUTPUT_DIR/$variant" ]; then
        count=$(ls -1 "$OUTPUT_DIR/$variant"/*.jsonl.gz 2>/dev/null | wc -l)
        if [ "$count" -gt 0 ]; then
            size=$(du -sh "$OUTPUT_DIR/$variant" | cut -f1)
            echo "  - $variant: $size"
        fi
    fi
done

echo ""
echo -e "${GREEN}✅ Enhanced training data generation complete!${NC}"
#!/bin/bash

# Analyze ALL files in /usr/bin
API_URL="http://localhost:3000/mcp"
OUTPUT_DIR="/tmp/bin_full_analysis_v2"
LOG_FILE="/tmp/bin_analysis.log"
BATCH_SIZE=10
CONCURRENT_LIMIT=3

mkdir -p "$OUTPUT_DIR"
echo "Starting full /usr/bin analysis at $(date)" > "$LOG_FILE"

# Function to call analyze_file tool via MCP
analyze_file() {
    local file_path="$1"
    local filename=$(basename "$file_path")
    local output_file="$OUTPUT_DIR/${filename}.json"
    
    # Skip if already analyzed
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        return 0
    fi
    
    # Call the API with metadata, hashes, and strings
    local start_time=$(date +%s)
    
    local response=$(curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "{
            \"jsonrpc\": \"2.0\",
            \"method\": \"tools/call\",
            \"params\": {
                \"name\": \"analyze_file\",
                \"arguments\": {
                    \"file_path\": \"$file_path\",
                    \"all\": true,
                    \"min_string_length\": 4
                }
            },
            \"id\": 1
        }" 2>/dev/null)
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [ $? -eq 0 ] && [ -n "$response" ]; then
        echo "$response" | jq -r '.result.content[0].text' > "$output_file" 2>/dev/null
        if [ -s "$output_file" ]; then
            echo "[$(date +%H:%M:%S)] SUCCESS: $filename (${duration}s)" >> "$LOG_FILE"
            return 0
        else
            rm -f "$output_file"
            echo "[$(date +%H:%M:%S)] FAILED: $filename (empty result)" >> "$LOG_FILE"
            return 1
        fi
    else
        echo "[$(date +%H:%M:%S)] FAILED: $filename (API error)" >> "$LOG_FILE"
        return 1
    fi
}

# Get all executable files
echo "Finding all executable files in /usr/bin..."
mapfile -t FILES < <(find /usr/bin -type f -executable 2>/dev/null | sort)
TOTAL=${#FILES[@]}

echo "Found $TOTAL executable files"
echo "Starting analysis with batch size $BATCH_SIZE and concurrency $CONCURRENT_LIMIT"
echo

# Track progress
PROCESSED=0
SUCCEEDED=0
FAILED=0

# Process files
for ((i=0; i<$TOTAL; i++)); do
    file="${FILES[$i]}"
    filename=$(basename "$file")
    
    # Show progress every 10 files
    if (( i % 10 == 0 )); then
        echo "Progress: $i/$TOTAL ($(( i * 100 / TOTAL ))%) - Succeeded: $SUCCEEDED, Failed: $FAILED"
    fi
    
    # Run analysis in background with concurrency limit
    (
        if analyze_file "$file"; then
            ((SUCCEEDED++))
        else
            ((FAILED++))
        fi
        ((PROCESSED++))
    ) &
    
    # Limit concurrent processes
    while (( $(jobs -r | wc -l) >= CONCURRENT_LIMIT )); do
        sleep 0.1
    done
done

# Wait for all background jobs to complete
echo "Waiting for remaining jobs to complete..."
wait

echo
echo "Analysis complete!"
echo "Total files: $TOTAL"
echo "Successfully analyzed: $(ls -1 "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l)"
echo "Failed: Check $LOG_FILE for details"
echo
echo "Cache statistics:"
curl -s http://localhost:3000/cache/stats | jq 2>/dev/null || true
echo
echo "String statistics:"
curl -s http://localhost:3000/strings/stats | jq '.total_unique_strings, .total_files_analyzed' 2>/dev/null || true
#!/bin/bash

# Memory-efficient analysis with selective features

API_URL="http://localhost:3000/mcp"
OUTPUT_DIR="/tmp/bin_selective_analysis"
LOG_FILE="/tmp/bin_selective.log"
TIMEOUT=30

echo "Starting selective feature analysis at $(date)" | tee $LOG_FILE
echo "Using memory-efficient feature selection" | tee -a $LOG_FILE

# Restart file-scanner fresh
pkill -f file-scanner 2>/dev/null
sleep 2
./target/release/file-scanner mcp-http --port 3000 > /tmp/file-scanner-selective.log 2>&1 &
sleep 5

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Get list of files
ALL_FILES=$(find /usr/bin -type f -executable 2>/dev/null | sort)
TOTAL_FILES=$(echo "$ALL_FILES" | wc -l)

PROCESSED=0
SUCCESS=0
FAILED=0

echo "Total files to process: $TOTAL_FILES" | tee -a $LOG_FILE

# Process each file with selective features
while IFS= read -r file_path; do
    file_name=$(basename "$file_path")
    output_file="$OUTPUT_DIR/${file_name}.json"
    
    # Skip if exists
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        ((PROCESSED++))
        continue
    fi
    
    # Progress update
    if (( PROCESSED % 20 == 0 )); then
        echo -e "\nProgress: $PROCESSED/$TOTAL_FILES ($(( PROCESSED * 100 / TOTAL_FILES ))%)" | tee -a $LOG_FILE
        echo "Success: $SUCCESS, Failed: $FAILED" | tee -a $LOG_FILE
        
        # Monitor memory and restart if needed
        MEM_KB=$(ps aux | grep file-scanner | grep -v grep | awk '{print $6}' | head -1)
        if [ -n "$MEM_KB" ] && [ "$MEM_KB" -gt 5000000 ]; then
            echo "Memory usage high (${MEM_KB} KB), restarting..." | tee -a $LOG_FILE
            pkill -f file-scanner
            sleep 2
            ./target/release/file-scanner mcp-http --port 3000 > /tmp/file-scanner-selective.log 2>&1 &
            sleep 5
        fi
    fi
    
    echo -n "[$(date +%H:%M:%S)] Processing $file_name... " | tee -a $LOG_FILE
    
    # Use selective features for memory efficiency
    request='{
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "analyze_file",
            "arguments": {
                "file_path": "'$file_path'",
                "metadata": true,
                "hashes": true,
                "strings": true,
                "min_string_length": 6,
                "binary_info": true,
                "vulnerabilities": true,
                "entropy": true,
                "signatures": true,
                "threats": true,
                "hex_dump": true,
                "hex_dump_size": 256
            }
        },
        "id": "'$file_name'"
    }'
    
    # Make API call
    start_time=$(date +%s)
    response=$(timeout $TIMEOUT curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "$request" 2>/dev/null)
    exit_code=$?
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    if [ $exit_code -eq 124 ]; then
        echo "TIMEOUT" | tee -a $LOG_FILE
        ((FAILED++))
    elif [ $exit_code -ne 0 ] || [ -z "$response" ]; then
        echo "ERROR" | tee -a $LOG_FILE
        ((FAILED++))
    else
        result=$(echo "$response" | jq -r '.result // empty' 2>/dev/null)
        
        if [ -n "$result" ] && [ "$result" != "null" ] && [ "$result" != "empty" ]; then
            echo "$result" > "$output_file"
            echo "SUCCESS (${duration}s)" | tee -a $LOG_FILE
            ((SUCCESS++))
        else
            echo "FAILED" | tee -a $LOG_FILE
            ((FAILED++))
        fi
    fi
    
    ((PROCESSED++))
    
    # Small delay
    sleep 0.2
    
done <<< "$ALL_FILES"

# Final statistics
echo -e "\n=== Final Statistics ===" | tee -a $LOG_FILE
echo "Total processed: $PROCESSED / $TOTAL_FILES" | tee -a $LOG_FILE
echo "Successful: $SUCCESS" | tee -a $LOG_FILE
echo "Failed: $FAILED" | tee -a $LOG_FILE
echo "Completion: $(( PROCESSED * 100 / TOTAL_FILES ))%" | tee -a $LOG_FILE

TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)
echo "Total data size: $TOTAL_SIZE" | tee -a $LOG_FILE
echo "Completed at $(date)" | tee -a $LOG_FILE
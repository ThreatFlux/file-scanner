#!/bin/bash

# Sequential analysis script with memory management

API_URL="http://localhost:3000/mcp"
OUTPUT_DIR="/tmp/bin_full_analysis_v2"
LOG_FILE="/tmp/bin_analysis_seq.log"
TIMEOUT=60

echo "Starting sequential analysis at $(date)" | tee $LOG_FILE

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Get list of all files
ALL_FILES=$(find /usr/bin -type f -executable 2>/dev/null | sort)
TOTAL_FILES=$(echo "$ALL_FILES" | wc -l)

# Track progress
PROCESSED=0
SUCCESS=0
FAILED=0

echo "Total files to process: $TOTAL_FILES" | tee -a $LOG_FILE

# Process each file
while IFS= read -r file_path; do
    file_name=$(basename "$file_path")
    output_file="$OUTPUT_DIR/${file_name}.json"
    
    # Skip if already processed
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        ((PROCESSED++))
        continue
    fi
    
    # Show progress every 10 files
    if (( PROCESSED % 10 == 0 )); then
        echo -e "\nProgress: $PROCESSED/$TOTAL_FILES ($(( PROCESSED * 100 / TOTAL_FILES ))%)" | tee -a $LOG_FILE
        echo "Success: $SUCCESS, Failed: $FAILED" | tee -a $LOG_FILE
        
        # Check memory usage
        MEM_USAGE=$(ps aux | grep file-scanner | grep -v grep | awk '{print $6}')
        if [ -n "$MEM_USAGE" ] && [ "$MEM_USAGE" -gt 10000000 ]; then
            echo "High memory usage detected ($MEM_USAGE KB), restarting file-scanner..." | tee -a $LOG_FILE
            pkill -f file-scanner
            sleep 2
            ./target/release/file-scanner mcp-http --port 3000 > /tmp/file-scanner.log 2>&1 &
            sleep 5
        fi
    fi
    
    echo -n "[$(date +%H:%M:%S)] Processing $file_name... " | tee -a $LOG_FILE
    
    # Create request
    request='{
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "analyze_file",
            "arguments": {
                "file_path": "'$file_path'",
                "all": true,
                "min_string_length": 4
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
        echo "TIMEOUT (${TIMEOUT}s)" | tee -a $LOG_FILE
        ((FAILED++))
    elif [ $exit_code -ne 0 ] || [ -z "$response" ]; then
        echo "ERROR (exit: $exit_code)" | tee -a $LOG_FILE
        ((FAILED++))
    else
        # Extract result
        result=$(echo "$response" | jq -r '.result // empty' 2>/dev/null)
        error=$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null)
        
        if [ -n "$error" ] && [ "$error" != "null" ] && [ "$error" != "empty" ]; then
            echo "ERROR: $error" | tee -a $LOG_FILE
            ((FAILED++))
        elif [ -n "$result" ] && [ "$result" != "null" ] && [ "$result" != "empty" ]; then
            echo "$result" > "$output_file"
            echo "SUCCESS (${duration}s)" | tee -a $LOG_FILE
            ((SUCCESS++))
        else
            echo "ERROR: No result" | tee -a $LOG_FILE
            ((FAILED++))
        fi
    fi
    
    ((PROCESSED++))
    
    # Brief pause to avoid overwhelming the API
    sleep 0.5
    
done <<< "$ALL_FILES"

# Final stats
echo -e "\n=== Final Statistics ===" | tee -a $LOG_FILE
echo "Total processed: $PROCESSED / $TOTAL_FILES" | tee -a $LOG_FILE
echo "Successful: $SUCCESS" | tee -a $LOG_FILE
echo "Failed: $FAILED" | tee -a $LOG_FILE
echo "Already existed: $((PROCESSED - SUCCESS - FAILED))" | tee -a $LOG_FILE
echo "Completion: $(( PROCESSED * 100 / TOTAL_FILES ))%" | tee -a $LOG_FILE

# Data size
TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)
echo "Total data size: $TOTAL_SIZE" | tee -a $LOG_FILE
echo "Completed at $(date)" | tee -a $LOG_FILE
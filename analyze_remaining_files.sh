#!/bin/bash

# Enhanced script to analyze remaining files in /usr/bin with better error handling

API_URL="http://localhost:3000/mcp"
OUTPUT_DIR="/tmp/bin_full_analysis_v2"
LOG_FILE="/tmp/bin_analysis_remaining.log"
BATCH_SIZE=5
CONCURRENCY=2
TIMEOUT=30

echo "Starting analysis of remaining files at $(date)" | tee $LOG_FILE

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Get list of all executable files in /usr/bin
echo "Finding all executable files in /usr/bin..." | tee -a $LOG_FILE
ALL_FILES=$(find /usr/bin -type f -executable 2>/dev/null | sort)
TOTAL_FILES=$(echo "$ALL_FILES" | wc -l)
echo "Found $TOTAL_FILES total executable files" | tee -a $LOG_FILE

# Get list of already processed files
PROCESSED_FILES=$(ls -1 "$OUTPUT_DIR"/*.json 2>/dev/null | xargs -r basename -s .json | sort)
PROCESSED_COUNT=$(echo "$PROCESSED_FILES" | grep -v '^$' | wc -l)
echo "Already processed $PROCESSED_COUNT files" | tee -a $LOG_FILE

# Get list of remaining files
REMAINING_FILES=$(comm -23 <(echo "$ALL_FILES" | xargs -n1 basename | sort) <(echo "$PROCESSED_FILES"))
REMAINING_COUNT=$(echo "$REMAINING_FILES" | grep -v '^$' | wc -l)
echo "Remaining files to process: $REMAINING_COUNT" | tee -a $LOG_FILE

# Function to analyze a single file
analyze_file() {
    local file_name="$1"
    local file_path="/usr/bin/$file_name"
    local output_file="$OUTPUT_DIR/${file_name}.json"
    local start_time=$(date +%s)
    
    # Skip if already processed
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        echo "[$(date +%H:%M:%S)] SKIP: $file_name (already processed)" | tee -a $LOG_FILE
        return 0
    fi
    
    # Create the JSON-RPC request with all features
    local request='{
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
        "id": "analyze-'$file_name'"
    }'
    
    # Make the API call with timeout
    local response=$(timeout $TIMEOUT curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "$request" 2>/dev/null)
    
    local exit_code=$?
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [ $exit_code -eq 124 ]; then
        echo "[$(date +%H:%M:%S)] TIMEOUT: $file_name (${TIMEOUT}s)" | tee -a $LOG_FILE
        return 1
    elif [ $exit_code -ne 0 ]; then
        echo "[$(date +%H:%M:%S)] ERROR: $file_name (curl exit code: $exit_code)" | tee -a $LOG_FILE
        return 1
    fi
    
    # Check if response is valid
    if [ -z "$response" ]; then
        echo "[$(date +%H:%M:%S)] ERROR: $file_name (empty response)" | tee -a $LOG_FILE
        return 1
    fi
    
    # Extract the result from JSON-RPC response
    local result=$(echo "$response" | jq -r '.result // empty' 2>/dev/null)
    local error=$(echo "$response" | jq -r '.error // empty' 2>/dev/null)
    
    if [ -n "$error" ] && [ "$error" != "null" ]; then
        echo "[$(date +%H:%M:%S)] ERROR: $file_name - $error" | tee -a $LOG_FILE
        return 1
    fi
    
    if [ -z "$result" ] || [ "$result" = "null" ]; then
        echo "[$(date +%H:%M:%S)] ERROR: $file_name (no result in response)" | tee -a $LOG_FILE
        return 1
    fi
    
    # Save the result
    echo "$result" > "$output_file"
    
    echo "[$(date +%H:%M:%S)] SUCCESS: $file_name (${duration}s)" | tee -a $LOG_FILE
    return 0
}

export -f analyze_file
export API_URL OUTPUT_DIR LOG_FILE TIMEOUT

# Process files in batches
echo -e "\nStarting batch processing with concurrency=$CONCURRENCY\n" | tee -a $LOG_FILE

SUCCESS_COUNT=0
FAILED_COUNT=0
BATCH_NUM=0

while IFS= read -r file_name; do
    # Skip empty lines
    [ -z "$file_name" ] && continue
    
    # Process in parallel batches
    if (( BATCH_NUM % BATCH_SIZE == 0 )); then
        echo -e "\nProgress: $((PROCESSED_COUNT + SUCCESS_COUNT + FAILED_COUNT))/$TOTAL_FILES ($(( (PROCESSED_COUNT + SUCCESS_COUNT + FAILED_COUNT) * 100 / TOTAL_FILES ))%)" | tee -a $LOG_FILE
        echo "Success: $SUCCESS_COUNT, Failed: $FAILED_COUNT, Previously processed: $PROCESSED_COUNT" | tee -a $LOG_FILE
    fi
    
    # Run analysis with limited concurrency
    while [ $(jobs -r | wc -l) -ge $CONCURRENCY ]; do
        sleep 0.1
    done
    
    analyze_file "$file_name" &
    
    ((BATCH_NUM++))
    
    # Wait for batch to complete
    if (( BATCH_NUM % BATCH_SIZE == 0 )); then
        wait
        
        # Count successes and failures
        NEW_SUCCESS=$(grep -c "SUCCESS:" $LOG_FILE | tail -1)
        NEW_FAILED=$(grep -c -E "(ERROR:|TIMEOUT:|FAILED:)" $LOG_FILE | tail -1)
        SUCCESS_COUNT=$((NEW_SUCCESS - PROCESSED_COUNT))
        FAILED_COUNT=$NEW_FAILED
    fi
    
done <<< "$REMAINING_FILES"

# Wait for final jobs
wait

# Final statistics
echo -e "\n=== Final Statistics ===" | tee -a $LOG_FILE
FINAL_PROCESSED=$(ls -1 "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l)
echo "Total files processed: $FINAL_PROCESSED / $TOTAL_FILES" | tee -a $LOG_FILE
echo "Newly processed: $((FINAL_PROCESSED - PROCESSED_COUNT))" | tee -a $LOG_FILE
echo "Failed: $FAILED_COUNT" | tee -a $LOG_FILE
echo "Completion: $(( FINAL_PROCESSED * 100 / TOTAL_FILES ))%" | tee -a $LOG_FILE
echo "Analysis completed at $(date)" | tee -a $LOG_FILE

# Calculate total data size
TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)
echo "Total data size: $TOTAL_SIZE" | tee -a $LOG_FILE
#!/bin/bash
# Analyze 100 files with full comprehensive analysis

SCANNER="./target/release/file-scanner"
OUTPUT_DIR="/tmp/full_analyses_100"
mkdir -p "$OUTPUT_DIR"

echo "🚀 Starting comprehensive analysis of 100 files..."
echo "=================================================="

# Get 100 diverse files
FILES=(
    # System binaries
    /bin/ls /bin/cat /bin/bash /bin/grep /bin/sed
    /usr/bin/python3 /usr/bin/gcc /usr/bin/make /usr/bin/git /usr/bin/curl
    /usr/bin/wget /usr/bin/ssh /usr/bin/scp /usr/bin/rsync /usr/bin/vim
    
    # Libraries
    /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libpthread.so.0
    /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/libdl.so.2
    /usr/lib/x86_64-linux-gnu/libssl.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3
    
    # More binaries
    /usr/bin/docker /usr/bin/node /usr/bin/npm /usr/bin/cargo /usr/bin/rustc
    /usr/bin/go /usr/bin/java /usr/bin/javac /usr/bin/mvn /usr/bin/gradle
    
    # System tools
    /usr/bin/systemctl /usr/bin/journalctl /usr/bin/netstat /usr/bin/ss /usr/bin/ip
    /usr/bin/iptables /usr/bin/tcpdump /usr/bin/strace /usr/bin/ltrace /usr/bin/gdb
    
    # Security tools
    /usr/bin/openssl /usr/bin/gpg /usr/bin/ssh-keygen /usr/bin/nmap /usr/bin/nc
    
    # Package managers
    /usr/bin/apt /usr/bin/dpkg /usr/bin/snap /usr/bin/pip3 /usr/bin/gem
    
    # Development tools
    /usr/bin/cmake /usr/bin/clang /usr/bin/clang++ /usr/bin/valgrind /usr/bin/perf
    /usr/bin/objdump /usr/bin/readelf /usr/bin/nm /usr/bin/strip /usr/bin/ar
    
    # Text processing
    /usr/bin/awk /usr/bin/perl /usr/bin/ruby /usr/bin/jq /usr/bin/xmllint
    
    # Archive tools
    /usr/bin/tar /usr/bin/gzip /usr/bin/bzip2 /usr/bin/xz /usr/bin/zip
    
    # Network tools
    /usr/bin/ping /usr/bin/traceroute /usr/bin/dig /usr/bin/nslookup /usr/bin/whois
    
    # More utilities
    /usr/bin/find /usr/bin/locate /usr/bin/which /usr/bin/whereis /usr/bin/file
    /usr/bin/strings /usr/bin/xxd /usr/bin/hexdump /usr/bin/od /usr/bin/base64
    
    # Additional binaries to reach 100
    /usr/bin/ps /usr/bin/top /usr/bin/htop /usr/bin/kill /usr/bin/pkill
    /usr/bin/nice /usr/bin/renice /usr/bin/nohup /usr/bin/screen /usr/bin/tmux
)

# Run analysis on each file
COUNT=0
TOTAL=${#FILES[@]}

for FILE in "${FILES[@]}"; do
    if [ -f "$FILE" ]; then
        COUNT=$((COUNT + 1))
        BASENAME=$(basename "$FILE")
        OUTPUT_FILE="$OUTPUT_DIR/${BASENAME}_full.json"
        
        echo -e "\n[$COUNT/$TOTAL] Analyzing: $FILE"
        echo "Output: $OUTPUT_FILE"
        
        # Run with all features enabled
        $SCANNER "$FILE" --all --format json > "$OUTPUT_FILE" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            SIZE=$(stat -c%s "$OUTPUT_FILE" 2>/dev/null || stat -f%z "$OUTPUT_FILE" 2>/dev/null)
            echo "✓ Success - Size: $(numfmt --to=iec-i --suffix=B $SIZE 2>/dev/null || echo "${SIZE} bytes")"
        else
            echo "✗ Failed to analyze $FILE"
        fi
        
        # Show progress every 10 files
        if [ $((COUNT % 10)) -eq 0 ]; then
            echo -e "\n==== Progress: $COUNT/$TOTAL files analyzed ===="
        fi
    fi
    
    # Stop at 100 files
    if [ $COUNT -ge 100 ]; then
        break
    fi
done

echo -e "\n=================================================="
echo "✅ Analysis complete!"
echo "Total files analyzed: $COUNT"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Show summary statistics
echo "Summary statistics:"
TOTAL_SIZE=$(du -sh "$OUTPUT_DIR" 2>/dev/null | cut -f1)
echo "- Total output size: $TOTAL_SIZE"
echo "- Average file size: $(find "$OUTPUT_DIR" -name "*.json" -exec stat -c%s {} \; | awk '{sum+=$1; count++} END {print int(sum/count/1024) " KB"}')"
echo ""

# Count analysis types
echo "Analysis coverage check (sampling first file):"
SAMPLE_FILE=$(find "$OUTPUT_DIR" -name "*.json" | head -1)
if [ -f "$SAMPLE_FILE" ]; then
    echo "Sample file: $(basename "$SAMPLE_FILE")"
    jq -r 'keys[]' "$SAMPLE_FILE" 2>/dev/null | sort | while read key; do
        echo "  ✓ $key"
    done
fi
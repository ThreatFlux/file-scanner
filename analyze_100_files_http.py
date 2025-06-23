#!/usr/bin/env python3
"""Analyze 100 files using file-scanner HTTP API with all features."""

import json
import requests
import time
from pathlib import Path
import concurrent.futures
import os

# MCP server endpoint
MCP_URL = "http://localhost:3000/tools/call"
OUTPUT_DIR = Path("/tmp/full_analyses_100")
OUTPUT_DIR.mkdir(exist_ok=True)

# List of files to analyze
FILES = [
    # System binaries
    "/bin/ls", "/bin/cat", "/bin/bash", "/bin/grep", "/bin/sed",
    "/usr/bin/python3", "/usr/bin/gcc", "/usr/bin/make", "/usr/bin/git", "/usr/bin/curl",
    "/usr/bin/wget", "/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/rsync", "/usr/bin/vim",
    
    # Libraries
    "/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libpthread.so.0",
    "/lib/x86_64-linux-gnu/libm.so.6", "/lib/x86_64-linux-gnu/libdl.so.2",
    "/usr/lib/x86_64-linux-gnu/libssl.so.3", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
    
    # More binaries
    "/usr/bin/docker", "/usr/bin/node", "/usr/bin/npm", "/usr/bin/cargo", "/usr/bin/rustc",
    "/usr/bin/go", "/usr/bin/java", "/usr/bin/javac", "/usr/bin/mvn", "/usr/bin/gradle",
    
    # System tools
    "/usr/bin/systemctl", "/usr/bin/journalctl", "/usr/bin/netstat", "/usr/bin/ss", "/usr/bin/ip",
    "/usr/bin/iptables", "/usr/bin/tcpdump", "/usr/bin/strace", "/usr/bin/ltrace", "/usr/bin/gdb",
    
    # Security tools
    "/usr/bin/openssl", "/usr/bin/gpg", "/usr/bin/ssh-keygen", "/usr/bin/nmap", "/usr/bin/nc",
    
    # Package managers
    "/usr/bin/apt", "/usr/bin/dpkg", "/usr/bin/snap", "/usr/bin/pip3", "/usr/bin/gem",
    
    # Development tools
    "/usr/bin/cmake", "/usr/bin/clang", "/usr/bin/clang++", "/usr/bin/valgrind", "/usr/bin/perf",
    "/usr/bin/objdump", "/usr/bin/readelf", "/usr/bin/nm", "/usr/bin/strip", "/usr/bin/ar",
    
    # Text processing
    "/usr/bin/awk", "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/jq", "/usr/bin/xmllint",
    
    # Archive tools
    "/usr/bin/tar", "/usr/bin/gzip", "/usr/bin/bzip2", "/usr/bin/xz", "/usr/bin/zip",
    
    # Network tools
    "/usr/bin/ping", "/usr/bin/traceroute", "/usr/bin/dig", "/usr/bin/nslookup", "/usr/bin/whois",
    
    # More utilities
    "/usr/bin/find", "/usr/bin/locate", "/usr/bin/which", "/usr/bin/whereis", "/usr/bin/file",
    "/usr/bin/strings", "/usr/bin/xxd", "/usr/bin/hexdump", "/usr/bin/od", "/usr/bin/base64",
    
    # Additional binaries to reach 100
    "/usr/bin/ps", "/usr/bin/top", "/usr/bin/htop", "/usr/bin/kill", "/usr/bin/pkill",
    "/usr/bin/nice", "/usr/bin/renice", "/usr/bin/nohup", "/usr/bin/screen", "/usr/bin/tmux",
    
    # More files to reach 100
    "/usr/bin/less", "/usr/bin/more", "/usr/bin/head", "/usr/bin/tail", "/usr/bin/sort",
    "/usr/bin/uniq", "/usr/bin/cut", "/usr/bin/paste", "/usr/bin/tr", "/usr/bin/tee",
    "/usr/bin/wc", "/usr/bin/split", "/usr/bin/join", "/usr/bin/comm", "/usr/bin/diff",
]

def analyze_file(file_path):
    """Analyze a single file using the MCP HTTP API with all features."""
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            return None, f"File not found: {file_path}"
        
        # Prepare the request
        request_data = {
            "name": "analyze_file",
            "arguments": {
                "file_path": file_path,
                "all": True  # Enable all analysis features
            }
        }
        
        # Send the request
        response = requests.post(MCP_URL, json=request_data, timeout=300)
        
        if response.status_code == 200:
            result = response.json()
            
            # Save to file
            basename = Path(file_path).name
            output_file = OUTPUT_DIR / f"{basename}_full.json"
            
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
            
            return output_file, None
        else:
            return None, f"HTTP {response.status_code}: {response.text}"
            
    except Exception as e:
        return None, str(e)

def main():
    print("🚀 Starting comprehensive analysis of 100 files using HTTP API...")
    print("="*60)
    
    # Test the connection first
    try:
        test_response = requests.get("http://localhost:3000/health", timeout=5)
        if test_response.status_code != 200:
            print("❌ File scanner HTTP server is not responding!")
            return
    except:
        print("❌ Could not connect to file scanner HTTP server!")
        print("Please ensure it's running with: ./target/release/file-scanner mcp-http --port 3000")
        return
    
    print("✓ Connected to file scanner HTTP server\n")
    
    # Filter existing files
    existing_files = [f for f in FILES if os.path.exists(f)][:100]  # Take first 100
    print(f"Found {len(existing_files)} existing files to analyze\n")
    
    start_time = time.time()
    successful = 0
    failed = 0
    
    # Process files with a thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        # Submit all tasks
        future_to_file = {executor.submit(analyze_file, f): f for f in existing_files}
        
        # Process results as they complete
        for i, future in enumerate(concurrent.futures.as_completed(future_to_file), 1):
            file_path = future_to_file[future]
            output_file, error = future.result()
            
            if output_file:
                file_size = output_file.stat().st_size
                print(f"[{i}/{len(existing_files)}] ✓ {Path(file_path).name} - {file_size/1024:.1f} KB")
                successful += 1
            else:
                print(f"[{i}/{len(existing_files)}] ✗ {Path(file_path).name} - {error}")
                failed += 1
            
            # Progress report every 10 files
            if i % 10 == 0:
                elapsed = time.time() - start_time
                rate = i / elapsed
                eta = (len(existing_files) - i) / rate
                print(f"\n==== Progress: {i}/{len(existing_files)} | Rate: {rate:.1f} files/sec | ETA: {eta:.0f}s ====\n")
    
    # Final statistics
    elapsed_time = time.time() - start_time
    
    print("\n" + "="*60)
    print("✅ Analysis complete!")
    print(f"Total files: {len(existing_files)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Time elapsed: {elapsed_time:.1f} seconds")
    print(f"Average time per file: {elapsed_time/len(existing_files):.2f} seconds")
    print(f"\nOutput directory: {OUTPUT_DIR}")
    
    # Check output size
    total_size = sum(f.stat().st_size for f in OUTPUT_DIR.glob("*.json"))
    print(f"Total output size: {total_size/1024/1024:.1f} MB")
    
    # Sample analysis to verify completeness
    sample_files = list(OUTPUT_DIR.glob("*.json"))[:3]
    if sample_files:
        print("\nSample analysis coverage:")
        for sample_file in sample_files:
            with open(sample_file) as f:
                data = json.load(f)
                if 'result' in data:
                    keys = list(data['result'].keys())
                    print(f"\n{sample_file.name}:")
                    for key in sorted(keys):
                        print(f"  ✓ {key}")
                    break

if __name__ == "__main__":
    main()
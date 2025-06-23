#!/usr/bin/env python3
"""Generate training data from cached file-scanner analyses (simplified)."""

import json
from pathlib import Path
import time
from collections import defaultdict

# Create a temporary analyses directory
analyses_dir = Path("/tmp/cache_analyses")
analyses_dir.mkdir(exist_ok=True)

# Load cached files and save as individual JSON files
cache_dir = Path("/tmp/file-scanner-cache")
print(f"Loading cache files from {cache_dir}...")

count = 0
for cache_file in cache_dir.glob("*.json"):
    try:
        with open(cache_file, 'r') as f:
            data = json.load(f)
        
        # Extract the analysis result from the cache entry
        if isinstance(data, list) and len(data) > 0:
            entry = data[0]
            if 'result' in entry:
                result = entry['result']
                if 'file_path' in result:
                    file_name = Path(result['file_path']).name
                    output_file = analyses_dir / f"{file_name}.json"
                    
                    # Save the analysis
                    with open(output_file, 'w') as f:
                        json.dump(result, f, indent=2)
                    
                    count += 1
                    if count % 100 == 0:
                        print(f"  Processed {count} files...")
    except Exception as e:
        pass

print(f"\nExtracted {count} analysis files to {analyses_dir}")

# Now use the standard generation command
print("\nGenerating training data with multiprocessing...")
import subprocess

start_time = time.time()

# Change to the analyses directory before running
import os
current_dir = os.getcwd()
os.chdir(str(analyses_dir))

# Run the training generation
result = subprocess.run([
    f"{current_dir}/threatflux-training/bin/python", "-m", "threatflux_training.cli",
    "generate",
    "--name", "cache_comprehensive_32k",
    "--max-tokens", "32000",
    "--examples-per-file", "50",
    "--parallel", "16"
], capture_output=True, text=True)

# Change back
os.chdir(current_dir)

if result.returncode == 0:
    print("\n✅ Training data generation completed successfully!")
    print(result.stdout)
    
    # Show final statistics
    elapsed_time = time.time() - start_time
    print(f"\nTotal processing time: {elapsed_time:.2f} seconds")
    print(f"Average time per file: {elapsed_time/count:.2f} seconds")
else:
    print("\n❌ Error during generation:")
    print(result.stderr)

# Clean up temporary analyses directory
print(f"\nCleaning up {analyses_dir}...")
import shutil
shutil.rmtree(analyses_dir)
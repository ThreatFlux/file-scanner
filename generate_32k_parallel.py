#!/usr/bin/env python3
"""
Generate 32k token dataset using parallel processing.
"""

import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    # Use virtual environment python
    venv_python = "/home/vtriple/threatflux/file-scanner/threatflux-training/bin/python"
    
    print("🚀 Starting 32K Token Parallel Generation")
    print("="*50)
    
    # Use the CLI with parallel processing
    cmd = [
        venv_python, "-m", "threatflux_training.cli", "generate",
        "--name", "ubuntu_32k_parallel",
        "--max-tokens", "32000",
        "--examples-per-file", "50",
        "--parallel", "16",  # Use 16 processes for better control
        "--output-dir", "/tmp/threatflux_32k_final"
    ]
    
    print(f"Command: {' '.join(cmd)}")
    print("\nStarting generation...")
    
    import subprocess
    start_time = time.time()
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)  # 1 hour timeout
        
        elapsed = time.time() - start_time
        
        print(f"\n✅ Generation completed in {elapsed/60:.1f} minutes")
        print("\nOutput:")
        print(result.stdout)
        
        if result.stderr:
            print("\nErrors:")
            print(result.stderr)
            
        print(f"\nReturn code: {result.returncode}")
        
    except subprocess.TimeoutExpired:
        print(f"\n⏰ Process timed out after 1 hour")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()
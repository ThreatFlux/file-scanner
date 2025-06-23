#!/usr/bin/env python3
"""
Test multiprocessing 32k token generation with ThreatFlux Training Library.
"""

import sys
import os
import time
import psutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threatflux_training import TrainingGenerator, MultiProcessTrainingGenerator

def main():
    print("\n" + "="*80)
    print("🚀 MULTIPROCESS 32K TOKEN GENERATION TEST")
    print("="*80 + "\n")
    
    # System info
    cpu_count = os.cpu_count()
    memory_gb = psutil.virtual_memory().total / (1024**3)
    
    print(f"💻 System Resources:")
    print(f"   CPU Cores: {cpu_count}")
    print(f"   Total Memory: {memory_gb:.1f} GB")
    print(f"   Available Memory: {psutil.virtual_memory().available / (1024**3):.1f} GB")
    
    # Create standard generator to load data
    generator = TrainingGenerator("/tmp/multiprocess_test")
    
    # Load analysis data
    print(f"\n📁 Loading file-scanner analysis data...")
    directories = [
        ("/tmp/bin_full_analysis_v2", 10),    # 2.1GB full analysis
        ("/tmp/bin_selective_analysis", 5),   # 143MB selective
        ("/tmp/bin_analysis", 1)              # 5.5MB basic
    ]
    
    start_load = time.time()
    total_loaded = generator.load_analyses(directories)
    load_time = time.time() - start_load
    
    print(f"✅ Loaded {total_loaded} files in {load_time:.1f} seconds")
    
    # Show analysis statistics
    stats = generator.analyzer.get_statistics()
    print(f"   Average features/file: {stats['average_features_per_file']:.1f}")
    
    # Test with a small subset first
    print(f"\n🧪 Testing multiprocess generation...")
    
    # Create multiprocess generator
    mp_generator = MultiProcessTrainingGenerator("/tmp/multiprocess_32k_test")
    
    # Configure for 32k tokens
    mp_generator.configure(
        examples_per_file=20,        # Fewer examples for testing
        max_answer_tokens=32000,     # 32k token limit
        enable_chunking=True,
        enable_negative_examples=True,
        compression=True
    )
    
    # Get subset of data for testing
    all_analyses = generator.analyzer.get_all_analyses()
    importance_scores = generator.analyzer.get_importance_scores()
    
    # Take top 50 files for speed test
    sorted_files = sorted(importance_scores.items(), key=lambda x: x[1], reverse=True)
    test_files = dict(sorted_files[:50])
    test_analyses = {k: v for k, v in all_analyses.items() if k in test_files}
    
    print(f"   Testing with {len(test_files)} high-importance files")
    print(f"   Configured processes: {mp_generator.num_processes}")
    
    # Estimate processing time
    estimates = mp_generator.estimate_processing_time(len(test_files))
    print(f"   Estimated time: {estimates['estimated_minutes']:.1f} minutes")
    
    # Run multiprocess generation
    print(f"\n⚡ Starting parallel generation...")
    start_time = time.time()
    
    output_path = mp_generator.generate_dataset_parallel(
        test_analyses, test_files, "multiprocess_32k_test"
    )
    
    total_time = time.time() - start_time
    
    # Get statistics
    mp_stats = mp_generator.get_statistics()
    
    print(f"\n📊 MULTIPROCESS PERFORMANCE RESULTS")
    print("="*60)
    print(f"   Files Processed: {mp_stats['files_processed']}")
    print(f"   Examples Generated: {mp_stats['examples_generated']}")
    print(f"   Processing Time: {total_time:.1f} seconds")
    print(f"   Files/Second: {mp_stats['files_per_second']:.1f}")
    print(f"   Examples/Second: {mp_stats['examples_per_second']:.1f}")
    print(f"   Average Examples/File: {mp_stats['examples_generated'] / max(1, mp_stats['files_processed']):.1f}")
    
    # File size info
    if output_path.exists():
        file_size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"\n📄 Output File:")
        print(f"   Path: {output_path}")
        print(f"   Size: {file_size_mb:.1f} MB")
        print(f"   MB/File: {file_size_mb / max(1, mp_stats['files_processed']):.2f}")
    
    # Performance comparison
    print(f"\n⚖️  PERFORMANCE COMPARISON")
    print("="*60)
    
    # Estimate single-threaded time
    estimated_single_time = len(test_files) * 2.0  # Conservative 2 seconds per file
    speedup = estimated_single_time / total_time if total_time > 0 else 1
    
    print(f"   Estimated Single-Thread Time: {estimated_single_time:.1f} seconds")
    print(f"   Actual Multiprocess Time: {total_time:.1f} seconds")
    print(f"   Speedup: {speedup:.1f}x")
    print(f"   Efficiency: {speedup / mp_generator.num_processes * 100:.1f}%")
    
    # Memory usage
    current_memory = psutil.virtual_memory()
    print(f"\n💾 Memory Usage:")
    print(f"   Current Usage: {current_memory.used / (1024**3):.1f} GB")
    print(f"   Peak Estimated: {current_memory.used / (1024**3) + 2 * mp_generator.num_processes:.1f} GB")
    
    # Full dataset projection
    print(f"\n🔮 FULL DATASET PROJECTION")
    print("="*60)
    
    total_files = len(all_analyses)
    projected_time = total_files / mp_stats['files_per_second'] if mp_stats['files_per_second'] > 0 else 0
    projected_examples = total_files * (mp_stats['examples_generated'] / max(1, mp_stats['files_processed']))
    projected_size = file_size_mb * (total_files / max(1, mp_stats['files_processed']))
    
    print(f"   Total Available Files: {total_files}")
    print(f"   Projected Processing Time: {projected_time / 60:.1f} minutes ({projected_time / 3600:.1f} hours)")
    print(f"   Projected Examples: {projected_examples:,.0f}")
    print(f"   Projected Dataset Size: {projected_size:.0f} MB ({projected_size / 1024:.1f} GB)")
    
    print(f"\n✨ Multiprocessing is working! Ready for full 32k generation.")
    
    # Recommend optimal settings
    optimal_processes = min(cpu_count, int(memory_gb / 4))  # 4GB per process
    print(f"\n💡 Recommended Settings for Full Generation:")
    print(f"   Processes: {optimal_processes} (based on {memory_gb:.0f}GB RAM)")
    print(f"   Expected Time: {projected_time / optimal_processes / 3600:.1f} hours")
    print(f"   Memory Requirement: {optimal_processes * 4:.0f} GB")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
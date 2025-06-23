#!/usr/bin/env python3
"""Generate training data from cached file-scanner analyses."""

import json
import os
from pathlib import Path
from threatflux_training.core.multiprocess import MultiProcessTrainingGenerator

def load_cache_analyses(cache_dir: Path):
    """Load all analysis files from cache directory."""
    analyses = {}
    cache_files = list(cache_dir.glob("*.json"))
    
    print(f"Found {len(cache_files)} cached analysis files")
    
    for cache_file in cache_files:
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                
            # Extract the analysis result from the cache entry
            if isinstance(data, list) and len(data) > 0:
                entry = data[0]  # Take the first (usually only) entry
                if 'result' in entry:
                    result = entry['result']
                    if 'file_path' in result:
                        file_name = Path(result['file_path']).name
                        analyses[file_name] = result
                        print(f"  ✓ Loaded {file_name}")
        except Exception as e:
            print(f"  ✗ Error loading {cache_file.name}: {e}")
    
    return analyses

def main():
    """Generate training data from cached analyses."""
    # Setup paths
    cache_dir = Path("/tmp/file-scanner-cache")
    output_dir = Path("/tmp/threatflux_training_from_cache")
    output_dir.mkdir(exist_ok=True)
    
    # Load cached analyses
    print("Loading cached analyses...")
    analyses = load_cache_analyses(cache_dir)
    print(f"\nLoaded {len(analyses)} analysis files successfully")
    
    # Configure training generator with multiprocessing
    print("\nConfiguring training data generator...")
    generator = MultiProcessTrainingGenerator(output_dir=str(output_dir))
    
    # Configure for high-quality 32k token examples
    generator.configure(
        examples_per_file=50,        # Generate many examples per file
        max_answer_tokens=32000,     # 32k token limit
        enable_chunking=True,        # Enable answer chunking
        enable_negative_examples=True,
        compression=True,
        buffer_size=10,
        num_processes=16             # Use 16 processes
    )
    
    # Create the AnalysisLoader and add our analyses
    from threatflux_training.core.analyzer import AnalysisLoader
    analyzer = AnalysisLoader()
    analyzer.analyses = analyses
    
    # Generate importance scores
    importance_scores = {name: analyzer.calculate_importance(analysis) 
                        for name, analysis in analyses.items()}
    
    # Generate the dataset by passing analyses directly
    print(f"\nGenerating training data with {generator.num_processes} processes...")
    output_file = generator.generate_dataset_parallel(
        analyses=analyses,
        importance_scores=importance_scores,
        dataset_name="cache_comprehensive_32k"
    )
    
    # Get statistics
    stats = generator.get_statistics()
    
    # Print results
    print("\n" + "="*60)
    print("TRAINING DATA GENERATION COMPLETE!")
    print("="*60)
    print(f"Files processed: {stats['files_processed']}")
    print(f"Examples generated: {stats['examples_generated']}")
    print(f"Processing time: {stats['processing_time']:.2f} seconds")
    print(f"Files per second: {stats['files_per_second']:.2f}")
    print(f"\nOutput file: {output_file}")
    
    # Get compressed file size
    if output_file.with_suffix('.jsonl.gz').exists():
        compressed_size = output_file.with_suffix('.jsonl.gz').stat().st_size / (1024 * 1024)
        print(f"Compressed size: {compressed_size:.2f} MB")
    else:
        file_size = output_file.stat().st_size / (1024 * 1024)
        print(f"File size: {file_size:.2f} MB")

if __name__ == "__main__":
    main()
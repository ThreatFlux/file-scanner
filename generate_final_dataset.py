#!/usr/bin/env python3
"""Generate final training dataset from cached analyses."""

import json
import os
import sys
from pathlib import Path
from datetime import datetime

# Add the package to path
sys.path.insert(0, str(Path(__file__).parent))

from threatflux_training.core.generator import TrainingGenerator
from threatflux_training.core.multiprocess import FileProcessor
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed
import time

def process_cache_file(cache_file: Path) -> tuple:
    """Process a single cache file and return file_name, analysis."""
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
                    return file_name, result
    except Exception as e:
        pass
    return None, None

def main():
    # Setup
    cache_dir = Path("/tmp/file-scanner-cache")
    output_dir = Path("/tmp/threatflux_final_training")
    output_dir.mkdir(exist_ok=True)
    
    print("🚀 ThreatFlux Training Data Generation from Cache")
    print("="*60)
    
    # Load all cache files
    print(f"Loading cache files from {cache_dir}...")
    cache_files = list(cache_dir.glob("*.json"))
    print(f"Found {len(cache_files)} cache files")
    
    # Process cache files in parallel to extract analyses
    analyses = {}
    with ProcessPoolExecutor(max_workers=16) as executor:
        futures = {executor.submit(process_cache_file, f): f for f in cache_files}
        
        for future in as_completed(futures):
            file_name, analysis = future.result()
            if file_name and analysis:
                analyses[file_name] = analysis
        
        print(f"✓ Loaded {len(analyses)} valid analyses")
    
    # Initialize generator
    generator = TrainingGenerator()
    generator.configure(
        examples_per_file=50,
        max_answer_tokens=32000,
        enable_chunking=True,
        enable_negative_examples=True,
        compression=True
    )
    
    # Generate training examples
    print(f"\nGenerating training examples with 16 processes...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"threatflux_cache_ultimate_{timestamp}.jsonl"
    
    start_time = time.time()
    examples = []
    files_processed = 0
    
    # Process files in batches
    file_items = list(analyses.items())
    batch_size = 100
    
    for i in range(0, len(file_items), batch_size):
        batch = file_items[i:i+batch_size]
        print(f"\nProcessing batch {i//batch_size + 1}/{(len(file_items) + batch_size - 1)//batch_size}")
        
        # Process batch in parallel
        with ProcessPoolExecutor(max_workers=16) as executor:
            # Create a FileProcessor for each worker
            config = {
                'examples_per_file': 50,
                'max_answer_tokens': 32000,
                'enable_chunking': True,
                'enable_negative_examples': True
            }
            processor = FileProcessor(config)
            
            # Submit all files in batch
            futures = []
            for file_name, analysis in batch:
                # Calculate importance score
                importance_score = 1.0  # Default score
                if 'metadata' in analysis and 'file_size' in analysis['metadata']:
                    # Higher score for larger files
                    importance_score = min(2.0, 1.0 + analysis['metadata']['file_size'] / 1000000)
                
                file_data = (file_name, analysis, importance_score)
                future = executor.submit(processor.process_file, file_data)
                futures.append(future)
            
            # Collect results
            for future in as_completed(futures):
                try:
                    file_examples = future.result()
                    if file_examples:
                        examples.extend(file_examples)
                        files_processed += 1
                        
                        if files_processed % 10 == 0:
                            print(f"  Processed {files_processed} files, {len(examples)} examples generated...")
                except Exception as e:
                    print(f"  Error processing file: {e}")
    
    # Write all examples to file
    print(f"\nWriting {len(examples)} examples to {output_file}...")
    with open(output_file, 'w') as f:
        for example in examples:
            f.write(json.dumps(example) + '\n')
    
    # Compress
    print("Compressing output...")
    import gzip
    gz_file = output_file.with_suffix('.jsonl.gz')
    with open(output_file, 'rb') as f_in:
        with gzip.open(gz_file, 'wb') as f_out:
            f_out.writelines(f_in)
    
    # Clean up uncompressed file
    output_file.unlink()
    
    # Calculate statistics
    elapsed_time = time.time() - start_time
    total_tokens = sum(ex.get('metadata', {}).get('tokens', 0) for ex in examples)
    avg_tokens = total_tokens / len(examples) if examples else 0
    compressed_size = gz_file.stat().st_size / (1024 * 1024)
    
    print("\n" + "="*60)
    print("🎉 TRAINING DATA GENERATION COMPLETE!")
    print("="*60)
    print(f"Files processed: {files_processed:,}")
    print(f"Examples generated: {len(examples):,}")
    print(f"Total tokens: {total_tokens:,}")
    print(f"Average tokens/example: {avg_tokens:,.0f}")
    print(f"Processing time: {elapsed_time:.2f} seconds")
    print(f"Examples/second: {len(examples)/elapsed_time:.2f}")
    print(f"\nOutput file: {gz_file}")
    print(f"Compressed size: {compressed_size:.2f} MB")
    
    # Token distribution
    token_ranges = {
        'Under 50': 0,
        '50-100': 0,
        '100-500': 0,
        '500-1000': 0,
        '1000-5000': 0,
        '5000-10000': 0,
        '10000+': 0
    }
    
    for ex in examples:
        tokens = ex.get('metadata', {}).get('tokens', 0)
        if tokens < 50:
            token_ranges['Under 50'] += 1
        elif tokens < 100:
            token_ranges['50-100'] += 1
        elif tokens < 500:
            token_ranges['100-500'] += 1
        elif tokens < 1000:
            token_ranges['500-1000'] += 1
        elif tokens < 5000:
            token_ranges['1000-5000'] += 1
        elif tokens < 10000:
            token_ranges['5000-10000'] += 1
        else:
            token_ranges['10000+'] += 1
    
    print("\nToken Distribution:")
    for range_name, count in token_ranges.items():
        percentage = (count / len(examples)) * 100 if examples else 0
        print(f"  {range_name}: {count:,} ({percentage:.1f}%)")

if __name__ == "__main__":
    main()
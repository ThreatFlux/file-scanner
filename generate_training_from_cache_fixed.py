#!/usr/bin/env python3
"""Generate training data from cached file-scanner analyses with error handling."""

import json
import os
import sys
from pathlib import Path
from datetime import datetime
import gzip
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing as mp

# Add the package to path
sys.path.insert(0, str(Path(__file__).parent))

def safe_generate_examples(file_data, config):
    """Safely generate examples with error handling."""
    try:
        # Import inside the function to avoid pickling issues
        from threatflux_training.core.generator import TrainingGenerator
        
        file_name, analysis, importance_score = file_data
        
        # Check if analysis has required data
        if not analysis or not isinstance(analysis, dict):
            return []
            
        # Initialize generator for this worker
        generator = TrainingGenerator()
        generator.configure(**config)
        
        # Generate examples
        examples = []
        for i in range(config['examples_per_file']):
            try:
                example = generator.generate_example(analysis, file_name)
                if example and 'messages' in example and len(example['messages']) >= 2:
                    # Validate the example has actual content
                    answer = example['messages'][1]['content']
                    if answer and len(answer) > 100:  # Minimum content check
                        examples.append(example)
            except Exception as e:
                # Silently skip bad examples
                pass
                
        return examples
        
    except Exception as e:
        print(f"Error processing file {file_data[0]}: {e}")
        return []

def process_cache_file(cache_file: Path) -> tuple:
    """Process a single cache file and return file_name, analysis."""
    try:
        with open(cache_file, 'r') as f:
            data = json.load(f)
        
        # Extract the analysis result from the cache entry
        if isinstance(data, list) and len(data) > 0:
            entry = data[0]
            if 'result' in entry and entry['result']:
                result = entry['result']
                if 'file_path' in result:
                    file_name = Path(result['file_path']).name
                    return file_name, result
    except Exception:
        pass
    return None, None

def main():
    # Setup
    cache_dir = Path("/tmp/file-scanner-cache")
    output_dir = Path("/tmp/threatflux_final_training")
    output_dir.mkdir(exist_ok=True)
    
    print("🚀 ThreatFlux Training Data Generation from Cache (Fixed)")
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
                # Validate analysis has some content
                if any(key in analysis for key in ['metadata', 'hashes', 'strings', 'binary_info']):
                    analyses[file_name] = analysis
        
        print(f"✓ Loaded {len(analyses)} valid analyses")
    
    # Configuration
    config = {
        'examples_per_file': 30,  # Reduced to avoid memory issues
        'max_answer_tokens': 32000,
        'enable_chunking': True,
        'enable_negative_examples': True
    }
    
    # Generate training examples
    print(f"\nGenerating training examples with {mp.cpu_count()} processes...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"threatflux_cache_fixed_{timestamp}.jsonl"
    
    start_time = time.time()
    all_examples = []
    files_processed = 0
    files_with_examples = 0
    
    # Process files in batches
    file_items = list(analyses.items())
    batch_size = 100
    
    for i in range(0, len(file_items), batch_size):
        batch = file_items[i:i+batch_size]
        print(f"\nProcessing batch {i//batch_size + 1}/{(len(file_items) + batch_size - 1)//batch_size}")
        
        # Process batch in parallel
        with ProcessPoolExecutor(max_workers=mp.cpu_count()) as executor:
            # Submit all files in batch
            futures = []
            for file_name, analysis in batch:
                # Calculate importance score
                importance_score = 1.0
                if 'metadata' in analysis and 'file_size' in analysis['metadata']:
                    # Higher score for larger files
                    importance_score = min(2.0, 1.0 + analysis['metadata']['file_size'] / 1000000)
                
                file_data = (file_name, analysis, importance_score)
                future = executor.submit(safe_generate_examples, file_data, config)
                futures.append((file_name, future))
            
            # Collect results
            for file_name, future in futures:
                try:
                    file_examples = future.result()
                    if file_examples:
                        all_examples.extend(file_examples)
                        files_with_examples += 1
                    files_processed += 1
                    
                    if files_processed % 10 == 0:
                        print(f"  Processed {files_processed} files, {len(all_examples)} examples generated...")
                except Exception as e:
                    print(f"  Error with {file_name}: {e}")
                    files_processed += 1
    
    # Write all examples to file
    print(f"\nWriting {len(all_examples)} examples to {output_file}...")
    with open(output_file, 'w') as f:
        for example in all_examples:
            f.write(json.dumps(example) + '\n')
    
    # Compress
    print("Compressing output...")
    gz_file = output_file.with_suffix('.jsonl.gz')
    with open(output_file, 'rb') as f_in:
        with gzip.open(gz_file, 'wb', compresslevel=6) as f_out:
            f_out.writelines(f_in)
    
    # Clean up uncompressed file
    output_file.unlink()
    
    # Calculate statistics
    elapsed_time = time.time() - start_time
    total_tokens = 0
    token_counts = []
    
    for ex in all_examples:
        tokens = ex.get('metadata', {}).get('tokens', 0)
        if tokens > 0:
            total_tokens += tokens
            token_counts.append(tokens)
    
    avg_tokens = total_tokens / len(all_examples) if all_examples else 0
    compressed_size = gz_file.stat().st_size / (1024 * 1024)
    
    print("\n" + "="*60)
    print("🎉 TRAINING DATA GENERATION COMPLETE!")
    print("="*60)
    print(f"Files processed: {files_processed:,}")
    print(f"Files with valid examples: {files_with_examples:,}")
    print(f"Examples generated: {len(all_examples):,}")
    print(f"Total tokens: {total_tokens:,}")
    print(f"Average tokens/example: {avg_tokens:,.0f}")
    print(f"Processing time: {elapsed_time:.2f} seconds")
    print(f"Examples/second: {len(all_examples)/elapsed_time:.2f}")
    print(f"\nOutput file: {gz_file}")
    print(f"Compressed size: {compressed_size:.2f} MB")
    
    # Token distribution
    if token_counts:
        token_ranges = {
            'Under 100': 0,
            '100-500': 0,
            '500-1000': 0,
            '1000-5000': 0,
            '5000-10000': 0,
            '10000-20000': 0,
            '20000+': 0
        }
        
        for tokens in token_counts:
            if tokens < 100:
                token_ranges['Under 100'] += 1
            elif tokens < 500:
                token_ranges['100-500'] += 1
            elif tokens < 1000:
                token_ranges['500-1000'] += 1
            elif tokens < 5000:
                token_ranges['1000-5000'] += 1
            elif tokens < 10000:
                token_ranges['5000-10000'] += 1
            elif tokens < 20000:
                token_ranges['10000-20000'] += 1
            else:
                token_ranges['20000+'] += 1
        
        print("\nToken Distribution:")
        for range_name, count in token_ranges.items():
            percentage = (count / len(all_examples)) * 100 if all_examples else 0
            print(f"  {range_name}: {count:,} ({percentage:.1f}%)")
        
        # Show median and percentiles
        token_counts.sort()
        print(f"\nToken Statistics:")
        print(f"  Min: {token_counts[0]:,}")
        print(f"  25th percentile: {token_counts[len(token_counts)//4]:,}")
        print(f"  Median: {token_counts[len(token_counts)//2]:,}")
        print(f"  75th percentile: {token_counts[3*len(token_counts)//4]:,}")
        print(f"  Max: {token_counts[-1]:,}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Analyze token counts in training data pairs.
Uses a rough approximation of 1 token ≈ 4 characters (OpenAI's rule of thumb).
"""

import json
import gzip
from pathlib import Path
import statistics

def estimate_tokens(text):
    """Estimate token count using 1 token ≈ 4 characters approximation."""
    return len(text) / 4

def analyze_training_data(file_path):
    """Analyze token counts in training data."""
    token_counts = []
    message_stats = {
        'system': [],
        'user': [],
        'assistant': [],
        'total': []
    }
    
    # Check if file exists
    if not Path(file_path).exists():
        print(f"File not found: {file_path}")
        return None
    
    # Open gzipped or regular JSON file
    if file_path.endswith('.gz'):
        opener = gzip.open
        mode = 'rt'
    else:
        opener = open
        mode = 'r'
    
    with opener(file_path, mode) as f:
        for line_num, line in enumerate(f):
            if not line.strip():
                continue
                
            try:
                data = json.loads(line)
                
                # Calculate tokens for each message
                system_tokens = 0
                user_tokens = 0
                assistant_tokens = 0
                
                for msg in data.get('messages', []):
                    role = msg.get('role', '')
                    content = msg.get('content', '')
                    tokens = estimate_tokens(content)
                    
                    if role == 'system':
                        system_tokens += tokens
                        message_stats['system'].append(tokens)
                    elif role == 'user':
                        user_tokens += tokens
                        message_stats['user'].append(tokens)
                    elif role == 'assistant':
                        assistant_tokens += tokens
                        message_stats['assistant'].append(tokens)
                
                total_tokens = system_tokens + user_tokens + assistant_tokens
                token_counts.append(total_tokens)
                message_stats['total'].append(total_tokens)
                
            except json.JSONDecodeError:
                print(f"Error parsing line {line_num + 1}")
                continue
    
    return token_counts, message_stats

def print_statistics(token_counts, message_stats):
    """Print detailed statistics about token counts."""
    if not token_counts:
        print("No data to analyze")
        return
    
    print(f"=== Token Count Analysis ===\n")
    print(f"Total conversation pairs analyzed: {len(token_counts):,}")
    print(f"\n📊 Overall Statistics (All Messages Combined):")
    print(f"  Average tokens per pair: {statistics.mean(token_counts):,.0f}")
    print(f"  Median tokens per pair: {statistics.median(token_counts):,.0f}")
    print(f"  Min tokens per pair: {min(token_counts):,.0f}")
    print(f"  Max tokens per pair: {max(token_counts):,.0f}")
    print(f"  Standard deviation: {statistics.stdev(token_counts):,.0f}")
    
    # Percentiles
    sorted_counts = sorted(token_counts)
    p25 = sorted_counts[len(sorted_counts) // 4]
    p75 = sorted_counts[3 * len(sorted_counts) // 4]
    p90 = sorted_counts[9 * len(sorted_counts) // 10]
    p95 = sorted_counts[19 * len(sorted_counts) // 20]
    
    print(f"\n📈 Distribution:")
    print(f"  25th percentile: {p25:,.0f} tokens")
    print(f"  75th percentile: {p75:,.0f} tokens")
    print(f"  90th percentile: {p90:,.0f} tokens")
    print(f"  95th percentile: {p95:,.0f} tokens")
    
    # Message type breakdown
    print(f"\n💬 By Message Type:")
    for msg_type in ['system', 'user', 'assistant']:
        if message_stats[msg_type]:
            avg = statistics.mean(message_stats[msg_type])
            print(f"\n  {msg_type.capitalize()} messages:")
            print(f"    Average: {avg:,.0f} tokens")
            print(f"    Min: {min(message_stats[msg_type]):,.0f} tokens")
            print(f"    Max: {max(message_stats[msg_type]):,.0f} tokens")
    
    # Size categories
    print(f"\n📏 Size Distribution:")
    small = sum(1 for x in token_counts if x < 500)
    medium = sum(1 for x in token_counts if 500 <= x < 2000)
    large = sum(1 for x in token_counts if 2000 <= x < 5000)
    xlarge = sum(1 for x in token_counts if x >= 5000)
    
    total = len(token_counts)
    print(f"  Small (<500 tokens): {small:,} ({small/total*100:.1f}%)")
    print(f"  Medium (500-2000): {medium:,} ({medium/total*100:.1f}%)")
    print(f"  Large (2000-5000): {large:,} ({large/total*100:.1f}%)")
    print(f"  X-Large (5000+): {xlarge:,} ({xlarge/total*100:.1f}%)")
    
    # Find examples of min and max
    min_idx = token_counts.index(min(token_counts))
    max_idx = token_counts.index(max(token_counts))
    
    print(f"\n🔍 Examples:")
    print(f"  Smallest pair: Index {min_idx} with {min(token_counts):,.0f} tokens")
    print(f"  Largest pair: Index {max_idx} with {max(token_counts):,.0f} tokens")

def main():
    import sys
    
    # Default to the most recent training data
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        # Try to find the most recent training data
        file_path = "ubuntu_ultimate_training_20250616_204807.jsonl.gz"
    
    print(f"Analyzing: {file_path}\n")
    
    result = analyze_training_data(file_path)
    if result:
        token_counts, message_stats = result
        print_statistics(token_counts, message_stats)
        
        # Also analyze a sample of the new data if available
        print("\n" + "="*50 + "\n")
        print("Checking enhanced data structure...")
        
        # Sample one of the new analysis files
        import glob
        new_files = glob.glob("/tmp/bin_full_analysis_v2/*.json")
        if new_files:
            with open(new_files[0], 'r') as f:
                data = json.load(f)
                json_str = json.dumps(data, indent=2)
                tokens = estimate_tokens(json_str)
                print(f"Sample analysis file: {Path(new_files[0]).name}")
                print(f"Raw analysis data tokens: {tokens:,.0f}")
                print(f"Expected training tokens after processing: {tokens * 0.3:,.0f} - {tokens * 0.5:,.0f}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Analyze actual token counts based on real enhanced analysis data.
"""

import json
import os
from pathlib import Path
import statistics

def estimate_tokens(text):
    """Estimate token count using 1 token ≈ 4 characters approximation."""
    if isinstance(text, int):
        return text / 4
    return len(text) / 4

def format_number(num):
    """Format large numbers with K/M suffixes."""
    if num >= 1_000_000:
        return f"{num/1_000_000:.1f}M"
    elif num >= 1_000:
        return f"{num/1_000:.1f}K"
    else:
        return f"{num:.0f}"

def analyze_actual_data():
    """Analyze actual token counts from enhanced analysis files."""
    
    analysis_dir = Path("/tmp/bin_full_analysis_v2")
    files = list(analysis_dir.glob("*.json"))[:20]  # Sample 20 files
    
    if not files:
        print("No analysis files found")
        return
    
    print("=== Actual Token Analysis from Enhanced Data ===\n")
    
    file_stats = []
    feature_sizes = {}
    
    for file_path in files:
        file_size = file_path.stat().st_size
        file_chars = file_size  # Approximate since JSON has overhead
        file_tokens = estimate_tokens(file_chars)
        
        # Load and analyze content
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Measure each feature's contribution
            feature_tokens = {}
            for feature, content in data.items():
                if content:
                    json_str = json.dumps(content)
                    tokens = estimate_tokens(json_str)
                    feature_tokens[feature] = tokens
                    
                    if feature not in feature_sizes:
                        feature_sizes[feature] = []
                    feature_sizes[feature].append(tokens)
            
            file_stats.append({
                'name': file_path.stem,
                'total_tokens': file_tokens,
                'features': feature_tokens
            })
            
        except Exception as e:
            print(f"Error processing {file_path.name}: {e}")
            continue
    
    # Print file-level statistics
    print("📁 Sample File Analysis:\n")
    for stat in file_stats[:5]:
        print(f"{stat['name']}:")
        print(f"  Total tokens in raw data: {format_number(stat['total_tokens'])}")
        
        # Top features by size
        top_features = sorted(stat['features'].items(), key=lambda x: x[1], reverse=True)[:5]
        print("  Top features:")
        for feature, tokens in top_features:
            print(f"    - {feature}: {format_number(tokens)} tokens")
        print()
    
    # Calculate overall statistics
    all_tokens = [s['total_tokens'] for s in file_stats]
    
    print("="*60)
    print("\n📊 Overall Statistics:\n")
    print(f"Files analyzed: {len(file_stats)}")
    print(f"Average raw tokens per file: {format_number(statistics.mean(all_tokens))}")
    print(f"Min raw tokens: {format_number(min(all_tokens))}")
    print(f"Max raw tokens: {format_number(max(all_tokens))}")
    
    # Feature contribution analysis
    print("\n🔍 Average Tokens by Feature:\n")
    for feature, sizes in sorted(feature_sizes.items(), key=lambda x: statistics.mean(x[1]), reverse=True):
        if sizes:
            avg = statistics.mean(sizes)
            if avg > 100:  # Only show significant features
                print(f"{feature:20} {format_number(avg):>10} tokens average")
    
    # Estimate training data size
    print("\n" + "="*60)
    print("\n💡 Training Data Token Estimates:\n")
    
    avg_raw = statistics.mean(all_tokens)
    
    # Different selection strategies
    print("If we use different amounts of the raw data:\n")
    
    # Conservative: Just key features
    conservative = avg_raw * 0.05  # 5% of data (metadata, hashes, some strings)
    print(f"1. Conservative (key features only): {format_number(conservative)} tokens")
    print("   Includes: metadata, hashes, basic strings, vulnerabilities")
    
    # Moderate: Important features
    moderate = avg_raw * 0.15  # 15% of data
    print(f"\n2. Moderate (important features): {format_number(moderate)} tokens")
    print("   Adds: entropy, signatures, threats, behavioral, symbols")
    
    # Comprehensive: Most features except huge ones
    comprehensive = avg_raw * 0.30  # 30% of data
    print(f"\n3. Comprehensive (most features): {format_number(comprehensive)} tokens")
    print("   Adds: hex_dump samples, control_flow, dependencies")
    
    # Full: Including samples of everything
    full = avg_raw * 0.50  # 50% of data
    print(f"\n4. Full (with code samples): {format_number(full)} tokens")
    print("   Adds: disassembly snippets, YARA rules, code analysis")
    
    # Context limits
    print("\n📏 Context Window Considerations:\n")
    print("GPT-4 context: 128K tokens")
    print("Claude context: 200K tokens")
    
    print(f"\nWith moderate approach ({format_number(moderate)} tokens per example):")
    print(f"  - GPT-4 can handle: {int(128_000 / moderate)} examples per batch")
    print(f"  - Claude can handle: {int(200_000 / moderate)} examples per batch")
    
    # Final recommendations
    print("\n✅ Recommendations:\n")
    print("1. Use moderate approach (15% of data) for most training")
    print("2. Create specialized datasets for different expertise levels")
    print("3. Sample disassembly/hex dumps rather than including all")
    print("4. Focus on security-relevant features for security roles")
    print("5. Compress repetitive data (similar strings, opcodes)")

if __name__ == "__main__":
    analyze_actual_data()
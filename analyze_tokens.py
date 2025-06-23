#!/usr/bin/env python3
"""Analyze token counts across all training datasets."""

import json
import gzip
import statistics
import os

def estimate_tokens(text):
    """Estimate tokens using 1 token ≈ 4 characters approximation"""
    return len(text) / 4

def analyze_dataset(filename, name):
    print(f"\n📊 {name}:")
    print(f"File: {filename}")
    
    if not os.path.exists(filename):
        print(f"  File not found!")
        return
    
    try:
        token_counts = []
        question_tokens = []
        answer_tokens = []
        system_tokens = []
        total_tokens = []
        
        with gzip.open(filename, 'rt') as f:
            for i, line in enumerate(f):
                if i >= 10000:  # Analyze first 10k examples for speed
                    break
                    
                data = json.loads(line)
                messages = data['messages']
                
                # System message tokens
                sys_tok = estimate_tokens(messages[0]['content'])
                system_tokens.append(sys_tok)
                
                # Question tokens
                q_tok = estimate_tokens(messages[1]['content'])
                question_tokens.append(q_tok)
                
                # Answer tokens
                a_tok = estimate_tokens(messages[2]['content'])
                answer_tokens.append(a_tok)
                
                # Total for this example
                total = sys_tok + q_tok + a_tok
                total_tokens.append(total)
        
        # Calculate statistics
        print(f"Examples analyzed: {len(total_tokens):,}")
        print(f"\nSystem prompt tokens:")
        print(f"  Average: {statistics.mean(system_tokens):.0f}")
        print(f"  Min: {min(system_tokens):.0f}, Max: {max(system_tokens):.0f}")
        
        print(f"\nQuestion tokens:")
        print(f"  Average: {statistics.mean(question_tokens):.0f}")
        print(f"  Min: {min(question_tokens):.0f}, Max: {max(question_tokens):.0f}")
        
        print(f"\nAnswer tokens:")
        print(f"  Average: {statistics.mean(answer_tokens):.0f}")
        print(f"  Min: {min(answer_tokens):.0f}, Max: {max(answer_tokens):.0f}")
        
        print(f"\nTotal tokens per example:")
        print(f"  Average: {statistics.mean(total_tokens):.0f}")
        print(f"  Min: {min(total_tokens):.0f}")
        print(f"  Max: {max(total_tokens):.0f}")
        print(f"  Median: {statistics.median(total_tokens):.0f}")
        
        # Distribution
        print(f"\nToken distribution:")
        percentiles = [10, 25, 50, 75, 90, 95, 99]
        sorted_totals = sorted(total_tokens)
        for p in percentiles:
            idx = min(int(len(sorted_totals) * p / 100), len(sorted_totals) - 1)
            print(f"  {p}th percentile: {sorted_totals[idx]:.0f} tokens")
            
    except Exception as e:
        print(f"Error analyzing {filename}: {e}")

def main():
    print("=== TOKEN ANALYSIS FOR ALL TRAINING DATASETS ===")
    
    # Analyze each dataset
    datasets = [
        ("ubuntu_ultimate_advanced_20250617_113453.jsonl.gz", "Advanced Ultimate Dataset (NEW)"),
        ("ubuntu_ultimate_combined_20250617_000435.jsonl.gz", "Ultimate Combined Dataset"),
        ("ubuntu_ultimate_training_20250616_204807.jsonl.gz", "Original Ultimate Dataset"),
        ("ubuntu_combined_training_20250616_233051.jsonl.gz", "Combined Training Dataset"),
        ("ubuntu_simple_chunked_20250616_221600.jsonl.gz", "Chunked Training Dataset")
    ]
    
    for filename, name in datasets:
        analyze_dataset(filename, name)
        
    print("\n" + "="*60)
    print("\n💡 KEY INSIGHTS:")
    print("- System prompts are consistent within each dataset (expertise descriptions)")
    print("- Questions are typically short (5-15 tokens)")
    print("- Answer length varies significantly between datasets")
    print("- Token estimates based on 1 token ≈ 4 characters")

if __name__ == "__main__":
    main()
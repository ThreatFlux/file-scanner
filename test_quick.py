#!/usr/bin/env python3
"""Quick test of the ThreatFlux training library."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threatflux_training import TrainingGenerator

# Test basic functionality
print("Testing ThreatFlux Training Library...")

# Create generator
generator = TrainingGenerator("/tmp/test_output")

# Load just a few files for testing
print("\nLoading analysis data...")
total = generator.analyzer.load_directory("/tmp/bin_analysis")
print(f"Loaded {total} files")

# Get statistics
stats = generator.analyzer.get_statistics()
print(f"\nFeatures per file: {stats['average_features_per_file']:.1f}")

# Test answer generation on one file
file_name = "ls"
analysis = generator.analyzer.get_analysis(file_name)

if analysis:
    print(f"\nGenerating sample answer for {file_name}...")
    
    # Generate one answer
    question = "What is ls?"
    answer = generator.answer_builder.build_answer(
        file_name, analysis, "beginner", question
    )
    
    print(f"\nQuestion: {question}")
    print(f"Answer preview (first 500 chars):")
    print(answer[:500] + "..." if len(answer) > 500 else answer)
    
    # Token count
    tokens = generator.tokenizer.estimate_tokens(answer)
    print(f"\nAnswer contains approximately {tokens} tokens")
    
print("\n✅ Basic test completed successfully!")
print("\nTo generate a full dataset, use:")
print("python3 -m threatflux_training.cli generate --name test_dataset")
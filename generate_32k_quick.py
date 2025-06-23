#!/usr/bin/env python3
"""
Quick test of 32k token generation with the ThreatFlux library.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threatflux_training import TrainingGenerator
from datetime import datetime

def main():
    print("🚀 Quick 32K Token Test Generation")
    print("="*50)
    
    # Create generator with 32k token limit
    generator = TrainingGenerator("/tmp/threatflux_32k_test")
    
    # Configure for 32k tokens but limited files for testing
    generator.configure(
        examples_per_file=50,         # Moderate examples per file
        max_answer_tokens=32000,      # 32k token limit for answers
        enable_chunking=True,
        enable_negative_examples=True,
        compression=True
    )
    
    # Load analysis data
    print("\n📁 Loading analysis data...")
    directories = [
        ("/tmp/bin_full_analysis_v2", 10),
        ("/tmp/bin_selective_analysis", 5),
        ("/tmp/bin_analysis", 1)
    ]
    
    total_loaded = generator.load_analyses(directories)
    print(f"✅ Loaded {total_loaded} analysis files")
    
    # Check the data
    analysis_stats = generator.analyzer.get_statistics()
    print(f"   Total files: {analysis_stats['total_files']}")
    print(f"   Average features/file: {analysis_stats['average_features_per_file']:.1f}")
    
    # Show which files have the most features (best for 32k generation)
    most_complete = analysis_stats.get('most_complete_files', [])[:10]
    print(f"\n🔧 Most Complete Files (for 32k generation):")
    for file_name, feature_count in most_complete:
        print(f"   {file_name}: {feature_count} features")
    
    # Test answer generation on one high-feature file
    if most_complete:
        test_file = most_complete[0][0]  # Get the most complete file
        analysis = generator.analyzer.get_analysis(test_file)
        
        if analysis:
            print(f"\n🧪 Testing 32k generation on: {test_file}")
            
            # Generate a comprehensive answer
            question = f"Provide a comprehensive security analysis of {test_file}"
            answer = generator.answer_builder.build_answer(
                test_file, analysis, "security_analyst", question
            )
            
            tokens = generator.tokenizer.estimate_tokens(answer)
            print(f"   Generated answer: {tokens:,} tokens")
            print(f"   Answer length: {len(answer):,} characters")
            
            # Show preview
            lines = answer.split('\n')[:20]
            print(f"\n📝 Answer Preview (first 20 lines):")
            print("-" * 50)
            for line in lines:
                print(line)
            if len(answer.split('\n')) > 20:
                print(f"... ({len(answer.split('\n')) - 20} more lines)")
    
    print(f"\n✅ 32k token generation test completed!")
    print(f"📊 Ready to generate full dataset with 32k token answers")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
#!/usr/bin/env python3
"""
Generate comprehensive training dataset with 32k token limit using ThreatFlux Training Library.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threatflux_training import TrainingGenerator
from datetime import datetime

def main():
    print("\n" + "="*80)
    print("🚀 ThreatFlux 32K Token Training Data Generation")
    print("="*80 + "\n")
    
    # Create generator with 32k token limit
    generator = TrainingGenerator("/tmp/threatflux_32k")
    
    # Configure for maximum richness with 32k token limit
    generator.configure(
        examples_per_file=200,        # Many examples per file (200 for comprehensive coverage)
        max_answer_tokens=32000,      # 32k token limit for answers
        enable_chunking=True,         # Enable chunking for large data
        enable_negative_examples=True,
        compression=True,
        buffer_size=10               # Smaller buffer due to very large examples
    )
    
    # Load from all available analysis directories with priorities
    directories = [
        ("/tmp/bin_full_analysis_v2", 10),    # Highest priority - full analysis
        ("/tmp/bin_selective_analysis", 5),    # Medium priority - selective
        ("/tmp/bin_analysis", 1)               # Lowest priority - basic
    ]
    
    print("📁 Loading analysis data from multiple sources...")
    total_loaded = generator.load_analyses(directories)
    
    if total_loaded == 0:
        print("❌ No analysis files found!")
        return 1
        
    print(f"✅ Loaded {total_loaded} analysis files")
    
    # Show analysis statistics
    analysis_stats = generator.analyzer.get_statistics()
    print(f"\n📊 Analysis Statistics:")
    print(f"   Total files: {analysis_stats['total_files']}")
    print(f"   Average features/file: {analysis_stats['average_features_per_file']:.1f}")
    
    # Show feature coverage
    print("\n🔧 Feature Coverage (top features):")
    for feature, usage in sorted(analysis_stats['feature_usage'].items(), 
                               key=lambda x: x[1], reverse=True)[:10]:
        print(f"   {feature}: {usage:.1f}%")
    
    # Configure the answer builder for maximum tokens
    generator.answer_builder.max_tokens = 32000
    
    # Generate the dataset
    print("\n⚙️  Generating 32K token dataset...")
    print("   - Max answer tokens: 32,000")
    print("   - Examples per file: 100")
    print("   - All expertise levels included")
    print("   - Chunking enabled for comprehensive coverage")
    print("\n⏳ This will take some time due to the large token limit...\n")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = generator.generate_dataset(f"ubuntu_32k_{timestamp}")
    
    # Print comprehensive report
    print("\n" + "="*80)
    generator.print_report()
    
    # Additional statistics
    print("\n📈 Token Distribution Analysis:")
    token_stats = generator.tokenizer.get_statistics()
    
    if 'percentiles' in token_stats:
        print("\nAnswer Token Percentiles:")
        for p, value in token_stats['percentiles'].items():
            print(f"   {p}: {value:,} tokens")
    
    if 'top_files' in token_stats:
        print("\nTop Files by Total Tokens:")
        for file_data in token_stats['top_files'][:10]:
            print(f"   {file_data['file']}: {file_data['total_tokens']:,} tokens "
                  f"({file_data['examples']} examples, avg: {file_data['avg_tokens']:.0f})")
    
    print(f"\n✅ Dataset generated successfully!")
    print(f"📄 Output: {output_path}")
    print(f"📏 Size: {output_path.stat().st_size / 1024 / 1024:.1f} MB")
    
    # Estimate training parameters
    if 'summary' in token_stats:
        total_tokens = token_stats['summary']['total_tokens']
        total_examples = token_stats['summary']['total_examples']
        print(f"\n🧮 Training Estimates:")
        print(f"   Total examples: {total_examples:,}")
        print(f"   Total tokens: {total_tokens:,}")
        print(f"   Average tokens/example: {total_tokens/total_examples:.0f}")
        
        # Rough training time estimate (assuming 1M tokens/hour on good hardware)
        hours = total_tokens / 1_000_000
        print(f"   Estimated training time: {hours:.1f} hours (at 1M tokens/hour)")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
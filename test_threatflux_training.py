#!/usr/bin/env python3
"""
Test script for ThreatFlux Training Data Generator

This script demonstrates the library usage and generates a comprehensive dataset.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threatflux_training import TrainingGenerator, ExpertiseManager
from threatflux_training.core.tokenizer import TokenCounter

def test_comprehensive_generation():
    """Test comprehensive dataset generation."""
    print("\n🚀 Testing ThreatFlux Training Data Generator")
    print("="*60 + "\n")
    
    # Create generator
    generator = TrainingGenerator("/tmp/threatflux_ultimate")
    
    # Configure for maximum detail
    generator.configure(
        examples_per_file=80,      # More examples per file
        max_answer_tokens=3000,    # Longer answers
        enable_chunking=True,      # Enable chunking for large data
        enable_negative_examples=True,
        compression=True
    )
    
    # Load from multiple sources with priorities
    directories = [
        ("/tmp/bin_full_analysis_v2", 10),    # Highest priority - full analysis
        ("/tmp/bin_selective_analysis", 5),    # Medium priority - selective
        ("/tmp/bin_analysis", 1)               # Lowest priority - basic
    ]
    
    print("📁 Loading analysis data from multiple sources...")
    total_loaded = generator.load_analyses(directories)
    
    if total_loaded == 0:
        print("❌ No analysis files found! Please run file analysis first.")
        return
        
    print(f"✅ Loaded {total_loaded} analysis files")
    
    # Show analysis statistics
    analysis_stats = generator.analyzer.get_statistics()
    print(f"\n📊 Analysis Statistics:")
    print(f"   Total files: {analysis_stats['total_files']}")
    print(f"   Average features/file: {analysis_stats['average_features_per_file']:.1f}")
    
    # Show feature usage
    print("\n🔧 Feature Usage (top 10):")
    for feature, usage in sorted(analysis_stats['feature_usage'].items(), 
                               key=lambda x: x[1], reverse=True)[:10]:
        print(f"   {feature}: {usage:.1f}%")
        
    # Generate the dataset
    print("\n⚙️  Generating comprehensive dataset...")
    print("   This will create examples for all expertise levels")
    print("   with detailed, token-rich answers.\n")
    
    output_path = generator.generate_dataset("ultimate_comprehensive")
    
    # Print comprehensive report
    print("\n" + "="*60)
    generator.print_report()
    
    # Additional statistics
    print("\n📈 Detailed Token Analysis:")
    token_stats = generator.tokenizer.get_statistics()
    
    if 'percentiles' in token_stats:
        print("\nToken Distribution Percentiles:")
        for p, value in token_stats['percentiles'].items():
            print(f"   {p}: {value:,} tokens")
            
    if 'by_expertise' in token_stats:
        print("\nTop Expertise Levels by Token Count:")
        sorted_exp = sorted(token_stats['by_expertise'].items(),
                          key=lambda x: x[1]['total_tokens'], reverse=True)
        for exp, data in sorted_exp[:5]:
            avg = data['avg_tokens']
            total = data['total_tokens']
            count = data['count']
            print(f"   {exp}: {total:,} total tokens ({count} examples, avg: {avg:.0f})")
            
    print(f"\n✅ Dataset generated successfully!")
    print(f"📄 Output: {output_path}")
    print(f"📏 Size: {output_path.stat().st_size / 1024 / 1024:.1f} MB")
    
    # Demonstrate answer quality
    print("\n" + "="*60)
    print("💡 Answer Generation Examples")
    print("="*60 + "\n")
    
    # Show a sample answer for different expertise levels
    sample_file = "curl"
    sample_analysis = generator.analyzer.get_analysis(sample_file)
    
    if sample_analysis:
        expertise_samples = ['absolute_beginner', 'security_analyst', 'reverse_engineer']
        
        for expertise in expertise_samples:
            print(f"\n### Expertise: {expertise}")
            print("-" * 40)
            
            # Get a question
            questions = generator.expertise_mgr.get_questions_for_expertise(
                sample_file, expertise, sample_analysis, 1
            )
            
            if questions:
                question = questions[0]
                print(f"Q: {question}")
                
                # Generate answer
                answer = generator.answer_builder.build_answer(
                    sample_file, sample_analysis, expertise, question
                )
                
                # Show first part of answer
                preview_lines = answer.split('\n')[:20]
                print(f"A: {chr(10).join(preview_lines)}")
                if len(answer.split('\n')) > 20:
                    print("   ... (truncated for display)")
                    
                # Show token count
                tokens = generator.tokenizer.estimate_tokens(answer)
                print(f"\n   [Answer contains ~{tokens} tokens]")
                
def test_expertise_manager():
    """Test the expertise manager functionality."""
    print("\n🎓 Testing Expertise Manager")
    print("="*60 + "\n")
    
    mgr = ExpertiseManager()
    
    print(f"Total expertise levels: {len(mgr.get_all_expertise_levels())}")
    print("\nExpertise levels available:")
    for i, expertise in enumerate(mgr.get_all_expertise_levels(), 1):
        print(f"  {i:2d}. {expertise}")
        
    print("\n📝 Sample Questions by Category:")
    
    # Show sample questions from each category
    templates = mgr.templates
    categories = ['IDENTIFICATION', 'SECURITY', 'TECHNICAL', 'FORENSICS', 'BEHAVIORAL']
    
    for cat in categories:
        if hasattr(templates, cat):
            cat_dict = getattr(templates, cat)
            print(f"\n{cat}:")
            for subcat, questions in list(cat_dict.items())[:2]:
                print(f"  {subcat}: {questions[0]}")
                
def test_token_counter():
    """Test token counting functionality."""
    print("\n📊 Testing Token Counter")
    print("="*60 + "\n")
    
    counter = TokenCounter()
    
    # Test with sample examples
    examples = [
        {
            "messages": [
                {"role": "system", "content": "You are an AI assistant helping a security analyst."},
                {"role": "user", "content": "Check /usr/bin/curl for vulnerabilities"},
                {"role": "assistant", "content": "# Analysis of curl\n\n" + "x" * 2000}
            ]
        },
        {
            "messages": [
                {"role": "system", "content": "You are an AI assistant helping a developer."},
                {"role": "user", "content": "How do I use wget?"},
                {"role": "assistant", "content": "# Using wget\n\n" + "y" * 500}
            ]
        }
    ]
    
    for i, example in enumerate(examples):
        tokens = counter.count_example(example, f"file{i}", "test_expertise")
        print(f"Example {i+1}: {tokens['total']} total tokens")
        print(f"  System: {tokens['system']}, Question: {tokens['question']}, Answer: {tokens['answer']}")
        
    print("\n" + counter.format_report())
    
if __name__ == "__main__":
    # Run all tests
    test_expertise_manager()
    test_token_counter()
    test_comprehensive_generation()
    
    print("\n✅ All tests completed!")
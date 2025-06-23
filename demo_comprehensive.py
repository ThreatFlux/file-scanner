#!/usr/bin/env python3
"""
Demonstration of the comprehensive ThreatFlux Training Library.

This shows how the library generates much richer, longer answers than previous versions.
"""

import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threatflux_training import TrainingGenerator, ExpertiseManager

def demonstrate_comprehensive_answers():
    """Show how the library generates comprehensive answers."""
    print("\n" + "="*80)
    print("🚀 ThreatFlux Training Library - Comprehensive Answer Generation")
    print("="*80 + "\n")
    
    # Create generator with high token limit
    generator = TrainingGenerator("/tmp/demo_output")
    generator.configure(
        max_answer_tokens=3000,  # Allow very long answers
        enable_chunking=True
    )
    
    # Load some analysis data
    print("Loading analysis data...")
    generator.analyzer.load_directory("/tmp/bin_analysis")
    stats = generator.analyzer.get_statistics()
    print(f"Loaded {stats['total_files']} files with average {stats['average_features_per_file']:.1f} features each")
    
    # Test files - use what's available
    test_files = ['aa-exec', 'add-apt-repository', 'aconnect']
    expertise_levels = ['security_analyst', 'reverse_engineer', 'malware_analyst']
    
    examples = []
    
    for file_name in test_files:
        analysis = generator.analyzer.get_analysis(file_name)
        if not analysis:
            continue
            
        print(f"\n{'='*60}")
        print(f"📄 Generating examples for: {file_name}")
        print(f"{'='*60}")
        
        for expertise in expertise_levels:
            # Get appropriate questions
            questions = generator.expertise_mgr.get_questions_for_expertise(
                file_name, expertise, analysis, 2
            )
            
            for question in questions[:1]:  # Just one question per expertise
                print(f"\n🎓 Expertise: {expertise}")
                print(f"❓ Question: {question}")
                
                # Generate comprehensive answer
                answer = generator.answer_builder.build_answer(
                    file_name, analysis, expertise, question
                )
                
                # Create training example
                example = {
                    "messages": [
                        {
                            "role": "system",
                            "content": generator.expertise_mgr.get_expertise_prompt(expertise)
                        },
                        {
                            "role": "user", 
                            "content": question
                        },
                        {
                            "role": "assistant",
                            "content": answer
                        }
                    ]
                }
                
                # Count tokens
                token_info = generator.tokenizer.count_example(example, file_name, expertise)
                
                print(f"📊 Tokens - System: {token_info['system']}, "
                      f"Question: {token_info['question']}, "
                      f"Answer: {token_info['answer']}, "
                      f"Total: {token_info['total']}")
                
                # Show answer preview
                lines = answer.split('\n')
                preview_lines = lines[:15]  # Show first 15 lines
                print(f"\n📝 Answer Preview:")
                print("-" * 60)
                for line in preview_lines:
                    print(line)
                if len(lines) > 15:
                    print(f"\n... ({len(lines) - 15} more lines)")
                    print(f"[Full answer contains {len(answer):,} characters]")
                
                examples.append(example)
    
    # Show token statistics
    print(f"\n{'='*80}")
    print("📊 Token Statistics Summary")
    print("="*80)
    print(generator.tokenizer.format_report())
    
    # Save examples
    output_file = "/tmp/demo_comprehensive_examples.json"
    with open(output_file, 'w') as f:
        json.dump(examples, f, indent=2)
    print(f"\n✅ Saved {len(examples)} examples to: {output_file}")
    
    # Compare with simple approach
    print(f"\n{'='*80}")
    print("🔍 Comparison: Comprehensive vs Simple Answers")
    print("="*80 + "\n")
    
    # Generate a simple answer (like old generators)
    simple_answer = f"aa-exec is a command that executes programs in an AppArmor confined environment."
    
    # Generate comprehensive answer
    analysis = generator.analyzer.get_analysis('aa-exec')
    if analysis:
        comprehensive_answer = generator.answer_builder.build_answer(
            'aa-exec', analysis, 'security_analyst', 'Analyze aa-exec for security vulnerabilities'
        )
        
        print(f"Simple answer tokens: {generator.tokenizer.estimate_tokens(simple_answer)}")
        print(f"Comprehensive answer tokens: {generator.tokenizer.estimate_tokens(comprehensive_answer)}")
        print(f"\nToken increase: {generator.tokenizer.estimate_tokens(comprehensive_answer) / generator.tokenizer.estimate_tokens(simple_answer):.1f}x")
    
    print("\n✨ Key Features Demonstrated:")
    print("- Expertise-specific answer generation")
    print("- Context-aware content selection") 
    print("- Rich formatting with sections and highlights")
    print("- Security assessments and recommendations")
    print("- Token counting and statistics")
    print("- Answers 10-50x longer than simple approaches")

if __name__ == "__main__":
    demonstrate_comprehensive_answers()
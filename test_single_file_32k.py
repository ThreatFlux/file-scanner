#!/usr/bin/env python3
"""
Test 32k token generation on a single comprehensive file to show the full potential.
"""

import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threatflux_training import TrainingGenerator
from datetime import datetime

def main():
    print("\n" + "="*80)
    print("🔍 SINGLE FILE 32K TOKEN ANALYSIS REPORT")
    print("="*80 + "\n")
    
    # Create generator with 32k token limit
    generator = TrainingGenerator("/tmp/single_file_test")
    generator.configure(
        examples_per_file=100,        # Many examples for this one file
        max_answer_tokens=32000,      # 32k token limit
        enable_chunking=True,
        enable_negative_examples=False,
        compression=False
    )
    
    # Load analysis data
    print("📁 Loading analysis data...")
    generator.analyzer.load_directory("/tmp/bin_full_analysis_v2")
    
    # Find the largest analysis file
    analysis_files = []
    import os
    for file_name in generator.analyzer.get_file_names():
        file_path = f"/tmp/bin_full_analysis_v2/{file_name}.json"
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            analysis_files.append((file_name, size))
    
    # Sort by size and pick the largest
    analysis_files.sort(key=lambda x: x[1], reverse=True)
    
    print("📊 Top 10 largest analysis files:")
    for i, (name, size) in enumerate(analysis_files[:10], 1):
        print(f"  {i:2d}. {name}: {size/1024/1024:.1f} MB")
    
    # Use the largest file
    test_file = analysis_files[0][0]
    analysis = generator.analyzer.get_analysis(test_file)
    
    print(f"\n🎯 Selected file for 32k analysis: {test_file}")
    print(f"   Analysis size: {analysis_files[0][1]/1024/1024:.1f} MB")
    
    # Show what data is available
    print(f"\n📋 Available analysis features:")
    feature_count = 0
    for feature, value in analysis.items():
        if value is not None:
            feature_count += 1
            if isinstance(value, list):
                print(f"   ✅ {feature}: {len(value)} items")
            elif isinstance(value, dict):
                print(f"   ✅ {feature}: {len(value)} fields")
            elif isinstance(value, str):
                print(f"   ✅ {feature}: {len(value)} characters")
            else:
                print(f"   ✅ {feature}: {type(value).__name__}")
        else:
            print(f"   ❌ {feature}: None")
    
    print(f"\n   Total active features: {feature_count}/17")
    
    # Generate questions for all expertise levels
    print(f"\n📝 GENERATING COMPREHENSIVE Q&A FOR {test_file.upper()}")
    print("="*80)
    
    all_examples = []
    total_tokens = 0
    
    # Test each expertise level
    for expertise in generator.expertise_mgr.get_all_expertise_levels():
        print(f"\n🎓 Expertise Level: {expertise}")
        print("-" * 60)
        
        # Get questions for this expertise
        questions = generator.expertise_mgr.get_questions_for_expertise(
            test_file, expertise, analysis, 5  # 5 questions per expertise
        )
        
        expertise_tokens = 0
        
        for i, question in enumerate(questions, 1):
            print(f"\n   Q{i}: {question}")
            
            # Generate comprehensive answer
            answer = generator.answer_builder.build_answer(
                test_file, analysis, expertise, question
            )
            
            # Count tokens
            tokens = generator.tokenizer.estimate_tokens(answer)
            expertise_tokens += tokens
            total_tokens += tokens
            
            print(f"   A{i}: {tokens:,} tokens ({len(answer):,} characters)")
            
            # Show answer structure
            sections = answer.split('\n\n')
            print(f"       Sections: {len(sections)}")
            
            # Show first few lines
            lines = answer.split('\n')[:8]
            print(f"       Preview:")
            for line in lines:
                if line.strip():
                    print(f"         {line[:70]}{'...' if len(line) > 70 else ''}")
            
            if len(answer.split('\n')) > 8:
                print(f"         ... ({len(answer.split('\n')) - 8} more lines)")
            
            # Create example
            example = {
                "file": test_file,
                "expertise": expertise,
                "question": question,
                "answer": answer,
                "tokens": tokens,
                "characters": len(answer)
            }
            all_examples.append(example)
        
        print(f"\n   📊 {expertise} total: {expertise_tokens:,} tokens ({len(questions)} questions)")
    
    # Add chunked questions
    print(f"\n🧩 CHUNKED QUESTIONS FOR LARGE DATA SECTIONS")
    print("-" * 60)
    
    # Generate chunked questions
    chunked_questions = generator.chunk_gen.generate_chunked_questions(
        test_file, analysis, "reverse_engineer"
    )
    
    chunked_tokens = 0
    
    for question, question_type in chunked_questions[:10]:  # First 10 chunked questions
        print(f"\n   Chunked Q: {question}")
        
        answer = generator.answer_builder.build_answer(
            test_file, analysis, "reverse_engineer", question
        )
        
        tokens = generator.tokenizer.estimate_tokens(answer)
        chunked_tokens += tokens
        total_tokens += tokens
        
        print(f"   Chunked A: {tokens:,} tokens (Type: {question_type})")
        
        all_examples.append({
            "file": test_file,
            "expertise": "reverse_engineer",
            "question": question,
            "answer": answer,
            "tokens": tokens,
            "type": "chunked"
        })
    
    print(f"\n   📊 Chunked total: {chunked_tokens:,} tokens ({len(chunked_questions[:10])} questions)")
    
    # Final statistics
    print(f"\n" + "="*80)
    print("📊 COMPREHENSIVE SINGLE FILE REPORT")
    print("="*80)
    
    print(f"\n🎯 File Analyzed: {test_file}")
    print(f"   Analysis Size: {analysis_files[0][1]/1024/1024:.1f} MB")
    print(f"   Active Features: {feature_count}/17")
    
    print(f"\n📝 Questions & Answers Generated:")
    print(f"   Total Examples: {len(all_examples)}")
    print(f"   Expertise Levels: {len(generator.expertise_mgr.get_all_expertise_levels())}")
    print(f"   Questions per Expertise: 5")
    print(f"   Chunked Questions: {len(chunked_questions[:10])}")
    
    print(f"\n🔢 Token Statistics:")
    print(f"   Total Tokens: {total_tokens:,}")
    print(f"   Average per Example: {total_tokens/len(all_examples):,.0f}")
    print(f"   Min Tokens: {min(ex['tokens'] for ex in all_examples):,}")
    print(f"   Max Tokens: {max(ex['tokens'] for ex in all_examples):,}")
    
    # Token distribution by expertise
    expertise_stats = {}
    for ex in all_examples:
        exp = ex.get('expertise', 'unknown')
        if exp not in expertise_stats:
            expertise_stats[exp] = []
        expertise_stats[exp].append(ex['tokens'])
    
    print(f"\n📊 Token Distribution by Expertise:")
    for exp, tokens in sorted(expertise_stats.items(), 
                            key=lambda x: sum(x[1]), reverse=True):
        total = sum(tokens)
        avg = total / len(tokens) if tokens else 0
        print(f"   {exp}: {total:,} total ({len(tokens)} examples, avg: {avg:.0f})")
    
    # Save sample to file
    output_file = f"/tmp/single_file_32k_sample_{test_file}.json"
    with open(output_file, 'w') as f:
        json.dump({
            "file": test_file,
            "analysis_size_mb": analysis_files[0][1]/1024/1024,
            "features_active": feature_count,
            "total_examples": len(all_examples),
            "total_tokens": total_tokens,
            "examples": all_examples[:5]  # First 5 examples for review
        }, f, indent=2)
    
    print(f"\n💾 Sample saved to: {output_file}")
    
    # Projection for full dataset
    total_files = len(analysis_files)
    estimated_examples = total_files * len(all_examples)
    estimated_tokens = total_files * total_tokens
    
    print(f"\n🔮 FULL DATASET PROJECTION:")
    print(f"   Available Files: {total_files}")
    print(f"   Estimated Examples: {estimated_examples:,}")
    print(f"   Estimated Total Tokens: {estimated_tokens:,}")
    print(f"   Estimated Dataset Size: {estimated_tokens * 4 / 1024 / 1024:.0f} MB (uncompressed)")
    
    print(f"\n✨ This demonstrates the comprehensive coverage possible")
    print(f"   with 32k token limits and rich file-scanner analysis data!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
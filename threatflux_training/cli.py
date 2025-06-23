#!/usr/bin/env python3
"""
ThreatFlux Training Data Generator CLI

A comprehensive CLI for generating high-quality training data from file analysis results.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Tuple
import os

from threatflux_training import TrainingGenerator, AnalysisLoader, TokenCounter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class ThreatFluxCLI:
    """Command-line interface for ThreatFlux training data generation."""
    
    def __init__(self):
        self.parser = self._create_parser()
        
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            description='ThreatFlux Training Data Generator - Create high-quality training data from file analysis',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Generate comprehensive dataset from default directories
  %(prog)s generate --name ubuntu_comprehensive
  
  # Generate with custom settings
  %(prog)s generate --name custom --examples-per-file 100 --max-tokens 3000
  
  # Load from multiple directories with priorities
  %(prog)s generate --dirs /tmp/full_analysis:10 /tmp/selective:5 /tmp/basic:1
  
  # Analyze existing dataset
  %(prog)s analyze ubuntu_comprehensive_20250617_120000.jsonl.gz
  
  # Show statistics for loaded analyses
  %(prog)s stats --dirs /tmp/full_analysis /tmp/selective_analysis
  
  # Generate focused dataset (security only)
  %(prog)s generate --name security_focused --expertise security_analyst,malware_analyst,threat_hunter
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Generate command
        gen_parser = subparsers.add_parser('generate', help='Generate training dataset')
        gen_parser.add_argument('--name', '-n', default='comprehensive',
                              help='Dataset name (default: comprehensive)')
        gen_parser.add_argument('--dirs', '-d', nargs='+',
                              help='Directories with priorities (format: path:priority)')
        gen_parser.add_argument('--output-dir', '-o', default='/tmp/training_output',
                              help='Output directory (default: /tmp/training_output)')
        gen_parser.add_argument('--examples-per-file', '-e', type=int, default=50,
                              help='Base examples per file (default: 50)')
        gen_parser.add_argument('--max-tokens', '-t', type=int, default=2000,
                              help='Max tokens per answer (default: 2000)')
        gen_parser.add_argument('--no-chunking', action='store_true',
                              help='Disable chunked questions')
        gen_parser.add_argument('--no-negative', action='store_true',
                              help='Disable negative examples')
        gen_parser.add_argument('--no-compression', action='store_true',
                              help='Disable output compression')
        gen_parser.add_argument('--expertise', nargs='+',
                              help='Limit to specific expertise levels')
        gen_parser.add_argument('--file-pattern', '-p',
                              help='Only process files matching pattern')
        gen_parser.add_argument('--limit', '-l', type=int,
                              help='Limit number of files to process')
        gen_parser.add_argument('--parallel', '-j', type=int, nargs='?', const=0,
                              help='Use parallel processing (optionally specify number of processes)')
        gen_parser.add_argument('--no-parallel', action='store_true',
                              help='Force single-threaded processing')
        
        # Analyze command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze existing dataset')
        analyze_parser.add_argument('dataset', help='Dataset file to analyze')
        analyze_parser.add_argument('--sample-size', '-s', type=int, default=1000,
                                  help='Number of examples to sample (default: 1000)')
        analyze_parser.add_argument('--by-expertise', action='store_true',
                                  help='Show breakdown by expertise level')
        analyze_parser.add_argument('--by-file', action='store_true',
                                  help='Show breakdown by source file')
        analyze_parser.add_argument('--export-stats', '-e',
                                  help='Export statistics to JSON file')
        
        # Stats command
        stats_parser = subparsers.add_parser('stats', help='Show analysis statistics')
        stats_parser.add_argument('--dirs', '-d', nargs='+', required=True,
                                help='Analysis directories to examine')
        stats_parser.add_argument('--features', '-f', action='store_true',
                                help='Show detailed feature statistics')
        stats_parser.add_argument('--missing', '-m', action='store_true',
                                help='Show files with missing features')
        
        # List command
        list_parser = subparsers.add_parser('list', help='List available datasets')
        list_parser.add_argument('--dir', '-d', default='/tmp/training_output',
                               help='Directory to search (default: /tmp/training_output)')
        list_parser.add_argument('--details', action='store_true',
                               help='Show detailed information')
        
        # Compare command
        compare_parser = subparsers.add_parser('compare', help='Compare two datasets')
        compare_parser.add_argument('dataset1', help='First dataset')
        compare_parser.add_argument('dataset2', help='Second dataset')
        compare_parser.add_argument('--verbose', '-v', action='store_true',
                                  help='Show detailed comparison')
        
        return parser
        
    def run(self, args=None):
        """Run the CLI."""
        args = self.parser.parse_args(args)
        
        if not args.command:
            self.parser.print_help()
            return 1
            
        # Route to appropriate handler
        if args.command == 'generate':
            return self._handle_generate(args)
        elif args.command == 'analyze':
            return self._handle_analyze(args)
        elif args.command == 'stats':
            return self._handle_stats(args)
        elif args.command == 'list':
            return self._handle_list(args)
        elif args.command == 'compare':
            return self._handle_compare(args)
            
        return 0
        
    def _handle_generate(self, args) -> int:
        """Handle the generate command."""
        print("\n🚀 ThreatFlux Training Data Generator")
        print("="*50 + "\n")
        
        # Create generator
        generator = TrainingGenerator(args.output_dir)
        
        # Configure generator
        generator.configure(
            examples_per_file=args.examples_per_file,
            max_answer_tokens=args.max_tokens,
            enable_chunking=not args.no_chunking,
            enable_negative_examples=not args.no_negative,
            compression=not args.no_compression
        )
        
        # Parse directories
        directories = self._parse_directories(args.dirs)
        
        # Load analyses
        print("📁 Loading analysis data...")
        total_loaded = generator.load_analyses(directories)
        
        if total_loaded == 0:
            logger.error("No analysis files loaded!")
            return 1
            
        print(f"✅ Loaded {total_loaded} analysis files\n")
        
        # Filter by expertise if specified
        if args.expertise:
            print(f"🎯 Filtering for expertise: {', '.join(args.expertise)}")
            # This would require modifying the generator to support expertise filtering
            
        # Determine processing mode
        use_parallel = not args.no_parallel and (args.parallel is not None or total_loaded > 100)
        num_processes = args.parallel if args.parallel and args.parallel > 0 else None
        
        # Generate dataset
        print(f"⚙️  Generating {args.name} dataset...")
        print(f"   - Examples per file: {args.examples_per_file}")
        print(f"   - Max answer tokens: {args.max_tokens}")
        print(f"   - Chunking: {'Enabled' if not args.no_chunking else 'Disabled'}")
        print(f"   - Negative examples: {'Enabled' if not args.no_negative else 'Disabled'}")
        print(f"   - Compression: {'Enabled' if not args.no_compression else 'Disabled'}")
        
        if use_parallel:
            import multiprocessing as mp
            actual_processes = num_processes or max(1, mp.cpu_count() - 2)
            print(f"   - Processing: Parallel ({actual_processes} processes)")
        else:
            print(f"   - Processing: Single-threaded")
        print("")
        
        if use_parallel:
            output_path = generator.generate_dataset_parallel(args.name, num_processes)
        else:
            output_path = generator.generate_dataset(args.name)
        
        # Print report
        print("\n📊 Generation Complete!")
        print("="*50)
        generator.print_report()
        
        print(f"\n✅ Output saved to: {output_path}")
        print(f"📏 File size: {output_path.stat().st_size / 1024 / 1024:.1f} MB")
        
        return 0
        
    def _handle_analyze(self, args) -> int:
        """Handle the analyze command."""
        print(f"\n📊 Analyzing dataset: {args.dataset}")
        print("="*50 + "\n")
        
        dataset_path = Path(args.dataset)
        if not dataset_path.exists():
            logger.error(f"Dataset not found: {args.dataset}")
            return 1
            
        # Create token counter
        counter = TokenCounter()
        
        # Analyze dataset
        import gzip
        example_count = 0
        
        print(f"📖 Reading dataset (sampling {args.sample_size} examples)...")
        
        opener = gzip.open if args.dataset.endswith('.gz') else open
        with opener(dataset_path, 'rt') as f:
            for i, line in enumerate(f):
                if i >= args.sample_size:
                    break
                    
                try:
                    example = json.loads(line)
                    
                    # Extract metadata
                    messages = example.get('messages', [])
                    if len(messages) >= 3:
                        # Try to extract file name from question
                        question = messages[1]['content']
                        file_name = None
                        
                        # Simple extraction
                        import re
                        match = re.search(r'/([^/\s]+)(?:\s|$)', question)
                        if match:
                            file_name = match.group(1)
                            
                        # Extract expertise from system prompt
                        system_prompt = messages[0]['content']
                        expertise = None
                        for exp_name, exp_prompt in generator.expertise_mgr.expertise_levels.items():
                            if exp_prompt == system_prompt:
                                expertise = exp_name
                                break
                                
                        # Count tokens
                        counter.count_example(example, file_name, expertise)
                        example_count += 1
                        
                except Exception as e:
                    logger.warning(f"Failed to parse line {i}: {e}")
                    
        print(f"✅ Analyzed {example_count} examples\n")
        
        # Print statistics
        print(counter.format_report())
        
        # Export if requested
        if args.export_stats:
            stats = counter.get_statistics()
            with open(args.export_stats, 'w') as f:
                json.dump(stats, f, indent=2)
            print(f"\n📊 Statistics exported to: {args.export_stats}")
            
        return 0
        
    def _handle_stats(self, args) -> int:
        """Handle the stats command."""
        print("\n📊 Analysis Statistics")
        print("="*50 + "\n")
        
        # Load analyses
        loader = AnalysisLoader()
        
        for directory in args.dirs:
            print(f"📁 Loading from: {directory}")
            loaded = loader.load_directory(directory)
            print(f"   Loaded: {loaded} files")
            
        # Get statistics
        stats = loader.get_statistics()
        
        print(f"\n📈 Overall Statistics:")
        print(f"   Total files: {stats['total_files']}")
        print(f"   Average features per file: {stats['average_features_per_file']:.1f}")
        
        if args.features:
            print("\n🔧 Feature Usage:")
            for feature, usage in sorted(stats['feature_usage'].items(), 
                                       key=lambda x: x[1], reverse=True):
                print(f"   {feature}: {usage:.1f}%")
                
        if args.missing:
            print("\n⚠️  Files with Least Features:")
            for file_name, feature_count in stats['least_complete_files']:
                print(f"   {file_name}: {feature_count} features")
                
        return 0
        
    def _handle_list(self, args) -> int:
        """Handle the list command."""
        print(f"\n📂 Available Datasets in {args.dir}")
        print("="*50 + "\n")
        
        output_dir = Path(args.dir)
        if not output_dir.exists():
            logger.error(f"Directory not found: {args.dir}")
            return 1
            
        # Find all dataset files
        datasets = list(output_dir.glob("*.jsonl")) + list(output_dir.glob("*.jsonl.gz"))
        
        if not datasets:
            print("No datasets found.")
            return 0
            
        # Sort by modification time
        datasets.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        for dataset in datasets:
            size_mb = dataset.stat().st_size / 1024 / 1024
            mtime = dataset.stat().st_mtime
            
            from datetime import datetime
            timestamp = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
            
            print(f"📄 {dataset.name}")
            print(f"   Size: {size_mb:.1f} MB")
            print(f"   Modified: {timestamp}")
            
            if args.details:
                # Try to count lines
                try:
                    opener = gzip.open if dataset.suffix == '.gz' else open
                    with opener(dataset, 'rt') as f:
                        line_count = sum(1 for _ in f)
                    print(f"   Examples: {line_count:,}")
                except:
                    pass
                    
            print()
            
        return 0
        
    def _handle_compare(self, args) -> int:
        """Handle the compare command."""
        print(f"\n🔍 Comparing Datasets")
        print("="*50 + "\n")
        
        # This would implement dataset comparison
        # For now, just show basic comparison
        
        path1 = Path(args.dataset1)
        path2 = Path(args.dataset2)
        
        if not path1.exists() or not path2.exists():
            logger.error("One or both datasets not found")
            return 1
            
        print(f"Dataset 1: {path1.name}")
        print(f"  Size: {path1.stat().st_size / 1024 / 1024:.1f} MB")
        
        print(f"\nDataset 2: {path2.name}")
        print(f"  Size: {path2.stat().st_size / 1024 / 1024:.1f} MB")
        
        if args.verbose:
            # Would implement detailed comparison
            print("\nDetailed comparison not yet implemented.")
            
        return 0
        
    def _parse_directories(self, dirs: List[str]) -> List[Tuple[str, int]]:
        """Parse directory specifications with priorities."""
        if not dirs:
            # Default directories
            return [
                ("/tmp/bin_full_analysis_v2", 10),
                ("/tmp/bin_selective_analysis", 5),
                ("/tmp/bin_analysis", 1)
            ]
            
        parsed = []
        for spec in dirs:
            if ':' in spec:
                path, priority = spec.rsplit(':', 1)
                try:
                    priority = int(priority)
                except ValueError:
                    logger.warning(f"Invalid priority in {spec}, using 1")
                    priority = 1
            else:
                path = spec
                priority = 1
                
            parsed.append((path, priority))
            
        return parsed


def main():
    """Main entry point."""
    cli = ThreatFluxCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()
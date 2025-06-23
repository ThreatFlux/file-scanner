"""Multiprocessing support for parallel training data generation."""

import multiprocessing as mp
from multiprocessing import Pool, Queue, Process, Manager
import json
import gzip
import os
import time
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
import signal
import psutil

from .expertise import ExpertiseManager
from .tokenizer import TokenCounter

logger = logging.getLogger(__name__)

class FileProcessor:
    """Worker class for processing individual files."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.expertise_mgr = ExpertiseManager()
        self.tokenizer = TokenCounter()
        
        # Import here to avoid circular imports
        from .generator import AnswerBuilder, ChunkedQuestionGenerator
        self.answer_builder = AnswerBuilder(config.get('max_answer_tokens', 32000))
        self.chunk_gen = ChunkedQuestionGenerator()
        
    def process_file(self, file_data: Tuple[str, Dict[str, Any], float]) -> List[Dict[str, Any]]:
        """Process a single file and generate training examples."""
        file_name, analysis, importance_score = file_data
        
        examples = []
        
        try:
            # Adjust example count based on importance
            base_count = self.config.get('examples_per_file', 50)
            example_count = max(1, int(base_count * (importance_score / 2.0)))
            
            # Get all expertise levels
            expertise_levels = self.expertise_mgr.get_all_expertise_levels()
            
            # Distribute examples across expertise levels
            examples_per_expertise = max(1, example_count // len(expertise_levels))
            
            for expertise in expertise_levels:
                # Get questions for this expertise
                questions = self.expertise_mgr.get_questions_for_expertise(
                    file_name, expertise, analysis, examples_per_expertise * 2
                )
                
                for question in questions[:examples_per_expertise]:
                    # Generate answer
                    answer = self.answer_builder.build_answer(
                        file_name, analysis, expertise, question
                    )
                    
                    # Create example
                    example = {
                        "messages": [
                            {
                                "role": "system",
                                "content": self.expertise_mgr.get_expertise_prompt(expertise)
                            },
                            {
                                "role": "user",
                                "content": question
                            },
                            {
                                "role": "assistant",
                                "content": answer
                            }
                        ],
                        "metadata": {
                            "file_name": file_name,
                            "expertise": expertise,
                            "importance_score": importance_score,
                            "tokens": self.tokenizer.estimate_tokens(answer)
                        }
                    }
                    
                    examples.append(example)
                    
            # Add chunked questions if enabled
            if self.config.get('enable_chunking', True) and len(analysis.get('strings', [])) > 100:
                chunked_questions = self.chunk_gen.generate_chunked_questions(
                    file_name, analysis, 'reverse_engineer'
                )
                
                for question, question_type in chunked_questions[:10]:
                    expertise = 'reverse_engineer'
                    answer = self.answer_builder.build_answer(
                        file_name, analysis, expertise, question
                    )
                    
                    example = {
                        "messages": [
                            {
                                "role": "system",
                                "content": self.expertise_mgr.get_expertise_prompt(expertise)
                            },
                            {
                                "role": "user",
                                "content": question
                            },
                            {
                                "role": "assistant",
                                "content": answer
                            }
                        ],
                        "metadata": {
                            "file_name": file_name,
                            "expertise": expertise,
                            "question_type": question_type,
                            "importance_score": importance_score,
                            "tokens": self.tokenizer.estimate_tokens(answer)
                        }
                    }
                    
                    examples.append(example)
                    
        except Exception as e:
            logger.error(f"Error processing file {file_name}: {e}")
            return []
            
        return examples

def process_file_worker(args: Tuple[Tuple[str, Dict[str, Any], float], Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
    """Worker function for multiprocessing."""
    file_data, config = args
    file_name = file_data[0]
    
    try:
        processor = FileProcessor(config)
        examples = processor.process_file(file_data)
        return file_name, examples
    except Exception as e:
        logger.error(f"Worker error processing {file_name}: {e}")
        return file_name, []

class MultiProcessTrainingGenerator:
    """Multi-process training data generator for high-speed generation."""
    
    def __init__(self, output_dir: str = "/tmp/training_output", num_processes: int = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Auto-detect optimal process count
        if num_processes is None:
            cpu_count = mp.cpu_count()
            # Use 80% of CPUs, but ensure we have enough memory
            available_memory_gb = psutil.virtual_memory().available / (1024**3)
            # Estimate 2GB per process for large analysis files
            memory_limited_processes = int(available_memory_gb / 2)
            num_processes = min(cpu_count, memory_limited_processes, max(1, cpu_count - 2))
            
        self.num_processes = num_processes
        
        self.config = {
            'examples_per_file': 50,
            'max_answer_tokens': 32000,
            'enable_chunking': True,
            'enable_negative_examples': True,
            'compression': True
        }
        
        self.stats = {
            'files_processed': 0,
            'examples_generated': 0,
            'processing_time': 0,
            'files_per_second': 0,
            'examples_per_second': 0
        }
        
        logger.info(f"Initialized MultiProcessTrainingGenerator with {self.num_processes} processes")
        
    def configure(self, **kwargs):
        """Update configuration."""
        self.config.update(kwargs)
        
    def generate_dataset_parallel(self, analyses: Dict[str, Dict[str, Any]], 
                                importance_scores: Dict[str, float],
                                dataset_name: str = "parallel") -> Path:
        """Generate training dataset using parallel processing."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"threatflux_{dataset_name}_{timestamp}.jsonl"
        
        start_time = time.time()
        
        # Prepare file data for processing
        sorted_files = sorted(importance_scores.items(), key=lambda x: x[1], reverse=True)
        file_data = []
        
        for file_name, score in sorted_files:
            if file_name in analyses:
                file_data.append((file_name, analyses[file_name], score))
                
        total_files = len(file_data)
        logger.info(f"Processing {total_files} files with {self.num_processes} processes")
        
        # Prepare arguments for workers
        worker_args = [(fd, self.config) for fd in file_data]
        
        # Process files in parallel
        results = []
        with Pool(processes=self.num_processes) as pool:
            # Use imap for progress tracking
            result_iter = pool.imap(process_file_worker, worker_args, chunksize=1)
            
            # Write results as they complete
            with open(output_file, 'w') as f:
                for i, (file_name, examples) in enumerate(result_iter):
                    if i % 10 == 0:
                        elapsed = time.time() - start_time
                        rate = (i + 1) / elapsed if elapsed > 0 else 0
                        logger.info(f"Progress: {i+1}/{total_files} files ({rate:.1f} files/sec)")
                        
                    # Write examples to file
                    for example in examples:
                        f.write(json.dumps(example) + '\n')
                        
                    self.stats['files_processed'] += 1
                    self.stats['examples_generated'] += len(examples)
                    
        # Calculate final statistics
        total_time = time.time() - start_time
        self.stats['processing_time'] = total_time
        self.stats['files_per_second'] = total_files / total_time if total_time > 0 else 0
        self.stats['examples_per_second'] = self.stats['examples_generated'] / total_time if total_time > 0 else 0
        
        logger.info(f"Parallel processing completed in {total_time:.1f} seconds")
        logger.info(f"Rate: {self.stats['files_per_second']:.1f} files/sec, {self.stats['examples_per_second']:.1f} examples/sec")
        
        # Compress if enabled
        if self.config['compression']:
            compressed = self._compress_file(output_file)
            return compressed
            
        return output_file
        
    def _compress_file(self, file_path: Path) -> Path:
        """Compress the output file."""
        gz_path = file_path.with_suffix('.jsonl.gz')
        
        with open(file_path, 'rb') as f_in:
            with gzip.open(gz_path, 'wb') as f_out:
                f_out.writelines(f_in)
                
        # Remove uncompressed file
        file_path.unlink()
        
        logger.info(f"Compressed output to {gz_path}")
        return gz_path
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return self.stats.copy()
        
    def estimate_processing_time(self, num_files: int) -> Dict[str, float]:
        """Estimate processing time based on current performance."""
        if self.stats['files_per_second'] > 0:
            estimated_seconds = num_files / self.stats['files_per_second']
            return {
                'estimated_seconds': estimated_seconds,
                'estimated_minutes': estimated_seconds / 60,
                'estimated_hours': estimated_seconds / 3600
            }
        else:
            # Rough estimates based on file complexity
            seconds_per_file = 2.0  # Conservative estimate
            estimated_seconds = num_files * seconds_per_file
            return {
                'estimated_seconds': estimated_seconds,
                'estimated_minutes': estimated_seconds / 60,
                'estimated_hours': estimated_seconds / 3600
            }

class ProgressTracker:
    """Track and display progress of multiprocess generation."""
    
    def __init__(self, total_files: int):
        self.total_files = total_files
        self.start_time = time.time()
        self.completed_files = 0
        self.total_examples = 0
        
    def update(self, files_completed: int, examples_generated: int):
        """Update progress statistics."""
        self.completed_files = files_completed
        self.total_examples = examples_generated
        
    def get_progress_report(self) -> str:
        """Get formatted progress report."""
        elapsed = time.time() - self.start_time
        percent = (self.completed_files / self.total_files * 100) if self.total_files > 0 else 0
        
        files_per_sec = self.completed_files / elapsed if elapsed > 0 else 0
        examples_per_sec = self.total_examples / elapsed if elapsed > 0 else 0
        
        if files_per_sec > 0:
            eta_seconds = (self.total_files - self.completed_files) / files_per_sec
            eta_minutes = eta_seconds / 60
        else:
            eta_seconds = eta_minutes = 0
            
        return (
            f"Progress: {self.completed_files}/{self.total_files} files ({percent:.1f}%) | "
            f"Rate: {files_per_sec:.1f} files/sec, {examples_per_sec:.0f} examples/sec | "
            f"ETA: {eta_minutes:.1f} minutes | "
            f"Examples: {self.total_examples:,}"
        )

class BatchProcessor:
    """Process files in batches to manage memory usage."""
    
    def __init__(self, batch_size: int = 50, max_memory_gb: float = 8.0):
        self.batch_size = batch_size
        self.max_memory_gb = max_memory_gb
        
    def should_process_batch(self, current_batch_size: int) -> bool:
        """Check if we should process the current batch."""
        # Check batch size limit
        if current_batch_size >= self.batch_size:
            return True
            
        # Check memory usage
        memory_usage_gb = psutil.virtual_memory().used / (1024**3)
        if memory_usage_gb > self.max_memory_gb:
            logger.warning(f"Memory usage high: {memory_usage_gb:.1f}GB, processing batch early")
            return True
            
        return False
        
    def process_in_batches(self, file_data: List[Tuple], processor_func, 
                          progress_callback=None) -> List[Any]:
        """Process files in memory-managed batches."""
        results = []
        current_batch = []
        
        for i, data in enumerate(file_data):
            current_batch.append(data)
            
            if self.should_process_batch(len(current_batch)) or i == len(file_data) - 1:
                # Process current batch
                batch_results = processor_func(current_batch)
                results.extend(batch_results)
                
                if progress_callback:
                    progress_callback(i + 1, len(results))
                    
                # Clear batch and force garbage collection
                current_batch = []
                import gc
                gc.collect()
                
        return results
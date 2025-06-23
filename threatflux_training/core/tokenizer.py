"""Token counting and analysis for training data."""

from typing import Dict, List, Any, Tuple
import statistics
import json

class TokenCounter:
    """Handles token counting and statistics for training data."""
    
    def __init__(self, chars_per_token: float = 4.0):
        """Initialize with configurable character-to-token ratio."""
        self.chars_per_token = chars_per_token
        self.stats = {
            "total_examples": 0,
            "total_tokens": 0,
            "system_tokens": [],
            "question_tokens": [],
            "answer_tokens": [],
            "example_tokens": [],
            "by_expertise": {},
            "by_file": {}
        }
        
    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for given text."""
        if not text:
            return 0
        return int(len(text) / self.chars_per_token)
        
    def count_example(self, example: Dict[str, Any], file_name: str = None, 
                     expertise: str = None) -> Dict[str, int]:
        """Count tokens in a training example."""
        messages = example.get("messages", [])
        if len(messages) < 3:
            return {"system": 0, "question": 0, "answer": 0, "total": 0}
            
        system_tokens = self.estimate_tokens(messages[0]["content"])
        question_tokens = self.estimate_tokens(messages[1]["content"])
        answer_tokens = self.estimate_tokens(messages[2]["content"])
        total_tokens = system_tokens + question_tokens + answer_tokens
        
        # Update statistics
        self.stats["total_examples"] += 1
        self.stats["total_tokens"] += total_tokens
        self.stats["system_tokens"].append(system_tokens)
        self.stats["question_tokens"].append(question_tokens)
        self.stats["answer_tokens"].append(answer_tokens)
        self.stats["example_tokens"].append(total_tokens)
        
        # Track by expertise
        if expertise:
            if expertise not in self.stats["by_expertise"]:
                self.stats["by_expertise"][expertise] = {
                    "count": 0,
                    "total_tokens": 0,
                    "tokens": []
                }
            self.stats["by_expertise"][expertise]["count"] += 1
            self.stats["by_expertise"][expertise]["total_tokens"] += total_tokens
            self.stats["by_expertise"][expertise]["tokens"].append(total_tokens)
            
        # Track by file
        if file_name:
            if file_name not in self.stats["by_file"]:
                self.stats["by_file"][file_name] = {
                    "count": 0,
                    "total_tokens": 0,
                    "tokens": []
                }
            self.stats["by_file"][file_name]["count"] += 1
            self.stats["by_file"][file_name]["total_tokens"] += total_tokens
            self.stats["by_file"][file_name]["tokens"].append(total_tokens)
            
        return {
            "system": system_tokens,
            "question": question_tokens,
            "answer": answer_tokens,
            "total": total_tokens
        }
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive token statistics."""
        if not self.stats["example_tokens"]:
            return {"error": "No examples counted yet"}
            
        def safe_stats(tokens: List[int]) -> Dict[str, float]:
            """Calculate statistics safely."""
            if not tokens:
                return {"min": 0, "max": 0, "mean": 0, "median": 0}
            return {
                "min": min(tokens),
                "max": max(tokens),
                "mean": statistics.mean(tokens),
                "median": statistics.median(tokens),
                "stdev": statistics.stdev(tokens) if len(tokens) > 1 else 0
            }
            
        # Calculate percentiles
        sorted_tokens = sorted(self.stats["example_tokens"])
        percentiles = {}
        for p in [10, 25, 50, 75, 90, 95, 99]:
            idx = min(int(len(sorted_tokens) * p / 100), len(sorted_tokens) - 1)
            percentiles[f"p{p}"] = sorted_tokens[idx]
            
        # Top files by token count
        top_files = sorted(
            self.stats["by_file"].items(),
            key=lambda x: x[1]["total_tokens"],
            reverse=True
        )[:10]
        
        # Expertise level statistics
        expertise_stats = {}
        for exp, data in self.stats["by_expertise"].items():
            expertise_stats[exp] = {
                "count": data["count"],
                "avg_tokens": data["total_tokens"] / data["count"] if data["count"] > 0 else 0,
                "total_tokens": data["total_tokens"]
            }
            
        return {
            "summary": {
                "total_examples": self.stats["total_examples"],
                "total_tokens": self.stats["total_tokens"],
                "avg_tokens_per_example": self.stats["total_tokens"] / self.stats["total_examples"] if self.stats["total_examples"] > 0 else 0
            },
            "system_prompt": safe_stats(self.stats["system_tokens"]),
            "questions": safe_stats(self.stats["question_tokens"]),
            "answers": safe_stats(self.stats["answer_tokens"]),
            "examples": safe_stats(self.stats["example_tokens"]),
            "percentiles": percentiles,
            "top_files": [
                {
                    "file": name,
                    "examples": data["count"],
                    "total_tokens": data["total_tokens"],
                    "avg_tokens": data["total_tokens"] / data["count"] if data["count"] > 0 else 0
                }
                for name, data in top_files
            ],
            "by_expertise": expertise_stats
        }
        
    def format_report(self) -> str:
        """Generate a formatted statistics report."""
        stats = self.get_statistics()
        
        if "error" in stats:
            return f"No token statistics available yet: {stats['error']}"
        
        report = []
        report.append("=== TOKEN STATISTICS REPORT ===\n")
        
        # Summary
        summary = stats["summary"]
        report.append(f"Total Examples: {summary['total_examples']:,}")
        report.append(f"Total Tokens: {summary['total_tokens']:,}")
        report.append(f"Average Tokens/Example: {summary['avg_tokens_per_example']:.0f}\n")
        
        # Component statistics
        report.append("System Prompts:")
        sys_stats = stats["system_prompt"]
        report.append(f"  Min: {sys_stats['min']:.0f}, Max: {sys_stats['max']:.0f}")
        report.append(f"  Mean: {sys_stats['mean']:.0f}, Median: {sys_stats['median']:.0f}\n")
        
        report.append("Questions:")
        q_stats = stats["questions"]
        report.append(f"  Min: {q_stats['min']:.0f}, Max: {q_stats['max']:.0f}")
        report.append(f"  Mean: {q_stats['mean']:.0f}, Median: {q_stats['median']:.0f}\n")
        
        report.append("Answers:")
        a_stats = stats["answers"]
        report.append(f"  Min: {a_stats['min']:.0f}, Max: {a_stats['max']:.0f}")
        report.append(f"  Mean: {a_stats['mean']:.0f}, Median: {a_stats['median']:.0f}\n")
        
        # Distribution
        report.append("Token Distribution (per example):")
        for p, value in stats["percentiles"].items():
            report.append(f"  {p}: {value:,} tokens")
        report.append("")
        
        # Top files
        report.append("Top Files by Token Count:")
        for file_data in stats["top_files"]:
            report.append(f"  {file_data['file']}: {file_data['total_tokens']:,} tokens ({file_data['examples']} examples)")
        report.append("")
        
        # By expertise
        report.append("Tokens by Expertise Level:")
        sorted_expertise = sorted(stats["by_expertise"].items(), 
                                key=lambda x: x[1]['total_tokens'], reverse=True)
        for exp, data in sorted_expertise[:10]:
            report.append(f"  {exp}: {data['total_tokens']:,} tokens ({data['count']} examples, avg: {data['avg_tokens']:.0f})")
            
        return "\n".join(report)
        
    def estimate_answer_size(self, target_tokens: int) -> int:
        """Estimate character count needed for target token count."""
        return int(target_tokens * self.chars_per_token)
        
    def should_truncate(self, current_tokens: int, max_tokens: int) -> bool:
        """Check if content should be truncated."""
        return current_tokens > max_tokens
        
    def truncate_to_tokens(self, text: str, max_tokens: int) -> str:
        """Truncate text to approximately max tokens."""
        max_chars = self.estimate_answer_size(max_tokens)
        if len(text) <= max_chars:
            return text
            
        # Truncate at a sentence boundary if possible
        truncated = text[:max_chars]
        last_period = truncated.rfind('.')
        last_newline = truncated.rfind('\n')
        
        cut_point = max(last_period, last_newline)
        if cut_point > max_chars * 0.8:  # Only use if not losing too much
            return truncated[:cut_point + 1] + "\n\n[Content truncated for token limits]"
        else:
            return truncated + "...\n\n[Content truncated for token limits]"
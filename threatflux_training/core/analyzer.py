"""Analysis data loading and management."""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
import logging

logger = logging.getLogger(__name__)

class AnalysisLoader:
    """Loads and manages file analysis data from multiple sources."""
    
    def __init__(self):
        self.analyses: Dict[str, Dict[str, Any]] = {}
        self.metadata: Dict[str, Dict[str, Any]] = {}
        self.loaded_dirs: Set[str] = set()
        
    def load_directory(self, directory: str, priority: int = 0) -> int:
        """
        Load analyses from a directory.
        Higher priority overwrites lower priority data.
        Returns number of files loaded.
        """
        dir_path = Path(directory)
        if not dir_path.exists():
            logger.warning(f"Directory not found: {directory}")
            return 0
            
        if directory in self.loaded_dirs:
            logger.info(f"Directory already loaded: {directory}")
            return 0
            
        loaded_count = 0
        json_files = list(dir_path.glob("*.json"))
        
        logger.info(f"Loading {len(json_files)} files from {directory}")
        
        for file_path in json_files:
            try:
                # Skip empty files
                if file_path.stat().st_size == 0:
                    continue
                    
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    
                file_name = file_path.stem
                
                # Store metadata about the source
                if file_name not in self.metadata:
                    self.metadata[file_name] = {
                        "sources": [],
                        "priorities": [],
                        "sizes": []
                    }
                    
                self.metadata[file_name]["sources"].append(str(file_path))
                self.metadata[file_name]["priorities"].append(priority)
                self.metadata[file_name]["sizes"].append(file_path.stat().st_size)
                
                # Store analysis data (higher priority overwrites)
                if file_name not in self.analyses or self._should_overwrite(file_name, priority):
                    self.analyses[file_name] = data
                    loaded_count += 1
                    
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON in {file_path}: {e}")
            except Exception as e:
                logger.error(f"Error loading {file_path}: {e}")
                
        self.loaded_dirs.add(directory)
        logger.info(f"Loaded {loaded_count} analyses from {directory}")
        return loaded_count
        
    def load_multiple_directories(self, directories: List[Tuple[str, int]]) -> int:
        """
        Load from multiple directories with priorities.
        directories: List of (path, priority) tuples
        """
        total_loaded = 0
        for directory, priority in sorted(directories, key=lambda x: x[1]):
            loaded = self.load_directory(directory, priority)
            total_loaded += loaded
        return total_loaded
        
    def _should_overwrite(self, file_name: str, new_priority: int) -> bool:
        """Check if new data should overwrite existing based on priority."""
        if file_name not in self.metadata:
            return True
        current_priority = max(self.metadata[file_name]["priorities"])
        return new_priority > current_priority
        
    def get_analysis(self, file_name: str) -> Optional[Dict[str, Any]]:
        """Get analysis data for a specific file."""
        return self.analyses.get(file_name)
        
    def get_all_analyses(self) -> Dict[str, Dict[str, Any]]:
        """Get all loaded analyses."""
        return self.analyses
        
    def get_file_names(self) -> List[str]:
        """Get list of all analyzed file names."""
        return list(self.analyses.keys())
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded analyses."""
        if not self.analyses:
            return {"error": "No analyses loaded"}
            
        feature_counts = {}
        feature_sizes = {}
        
        for file_name, analysis in self.analyses.items():
            for feature in analysis.keys():
                if feature not in feature_counts:
                    feature_counts[feature] = 0
                    feature_sizes[feature] = []
                    
                feature_counts[feature] += 1
                
                # Estimate size of feature data
                feature_data = analysis[feature]
                if isinstance(feature_data, list):
                    feature_sizes[feature].append(len(feature_data))
                elif isinstance(feature_data, dict):
                    feature_sizes[feature].append(len(str(feature_data)))
                    
        # Calculate feature usage percentages
        total_files = len(self.analyses)
        feature_usage = {
            feature: (count / total_files * 100)
            for feature, count in feature_counts.items()
        }
        
        # Find files with most/least features
        files_by_features = sorted(
            [(name, len(analysis.keys())) for name, analysis in self.analyses.items()],
            key=lambda x: x[1],
            reverse=True
        )
        
        return {
            "total_files": total_files,
            "loaded_directories": list(self.loaded_dirs),
            "feature_usage": feature_usage,
            "feature_counts": feature_counts,
            "most_complete_files": files_by_features[:10],
            "least_complete_files": files_by_features[-10:],
            "average_features_per_file": sum(fc[1] for fc in files_by_features) / len(files_by_features) if files_by_features else 0
        }
        
    def validate_analysis(self, analysis: Dict[str, Any]) -> List[str]:
        """Validate analysis data and return list of issues."""
        issues = []
        
        # Check for required fields
        if 'metadata' not in analysis:
            issues.append("Missing metadata field")
        elif not isinstance(analysis['metadata'], dict):
            issues.append("Metadata should be a dictionary")
            
        # Check for empty values
        for key, value in analysis.items():
            if value is None:
                issues.append(f"{key} is None")
            elif isinstance(value, (list, dict)) and len(value) == 0:
                issues.append(f"{key} is empty")
                
        # Check specific field formats
        if 'hashes' in analysis and isinstance(analysis['hashes'], dict):
            for hash_type in ['md5', 'sha256']:
                if hash_type in analysis['hashes']:
                    hash_val = analysis['hashes'][hash_type]
                    if not isinstance(hash_val, str) or len(hash_val) == 0:
                        issues.append(f"Invalid {hash_type} hash")
                        
        return issues
        
    def get_feature_availability(self) -> Dict[str, List[str]]:
        """Get which features are available for which files."""
        feature_files = {}
        
        for file_name, analysis in self.analyses.items():
            for feature in analysis.keys():
                if feature not in feature_files:
                    feature_files[feature] = []
                feature_files[feature].append(file_name)
                
        return feature_files
        
    def filter_by_features(self, required_features: List[str]) -> Dict[str, Dict[str, Any]]:
        """Get analyses that have all required features."""
        filtered = {}
        
        for file_name, analysis in self.analyses.items():
            if all(feature in analysis and analysis[feature] for feature in required_features):
                filtered[file_name] = analysis
                
        return filtered
        
    def get_importance_scores(self) -> Dict[str, float]:
        """Calculate importance scores for files based on various factors."""
        scores = {}
        
        # Core system utilities get highest scores
        core_utils = {'ls', 'cp', 'mv', 'rm', 'cat', 'grep', 'find', 'sed', 'awk', 
                     'chmod', 'chown', 'mkdir', 'touch', 'echo', 'ps', 'top', 'kill',
                     'df', 'du', 'mount', 'umount', 'tar', 'gzip', 'curl', 'wget'}
        
        # Development tools
        dev_tools = {'gcc', 'g++', 'make', 'cmake', 'python3', 'pip3', 'npm', 'node',
                    'git', 'vim', 'nano', 'emacs', 'code', 'javac', 'java', 'ruby',
                    'perl', 'php', 'cargo', 'rustc', 'go', 'docker', 'kubectl'}
        
        # Security tools
        security_tools = {'sudo', 'su', 'passwd', 'ssh', 'scp', 'sftp', 'gpg', 'openssl',
                         'iptables', 'ufw', 'fail2ban', 'nmap', 'tcpdump', 'wireshark',
                         'netstat', 'ss', 'lsof', 'strace', 'ltrace', 'gdb'}
        
        for file_name in self.analyses.keys():
            score = 1.0  # Base score
            
            # Check categories
            if file_name in core_utils:
                score *= 3.0
            elif file_name in dev_tools:
                score *= 2.5
            elif file_name in security_tools:
                score *= 2.8
                
            # Boost for files with security implications
            analysis = self.analyses[file_name]
            if 'vulnerabilities' in analysis and analysis['vulnerabilities']:
                score *= 1.5
            if 'threats' in analysis and analysis['threats']:
                score *= 1.4
                
            # Boost for files with many features
            feature_count = len([k for k, v in analysis.items() if v])
            if feature_count > 10:
                score *= 1.2
                
            # Boost for commonly used files (heuristic based on size/complexity)
            if 'metadata' in analysis and 'file_size' in analysis['metadata']:
                size = analysis['metadata']['file_size']
                if 10000 < size < 1000000:  # Reasonable size range
                    score *= 1.1
                    
            scores[file_name] = score
            
        return scores
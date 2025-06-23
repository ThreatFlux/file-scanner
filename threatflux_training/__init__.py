"""
ThreatFlux Training Data Generator Library

A comprehensive library for generating high-quality training data from file analysis results.
"""

__version__ = "1.0.0"
__author__ = "ThreatFlux Team"

from .core.generator import TrainingGenerator
from .core.analyzer import AnalysisLoader
from .core.tokenizer import TokenCounter
from .core.expertise import ExpertiseManager
from .core.multiprocess import MultiProcessTrainingGenerator

__all__ = [
    "TrainingGenerator",
    "AnalysisLoader", 
    "TokenCounter",
    "ExpertiseManager",
    "MultiProcessTrainingGenerator"
]
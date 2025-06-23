#!/usr/bin/env python3
"""Setup script for ThreatFlux Training Data Generator."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="threatflux-training",
    version="1.0.0",
    author="ThreatFlux Team",
    description="Comprehensive training data generator for Ubuntu file analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/threatflux/file-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "psutil>=5.8.0",  # For memory monitoring in multiprocessing
    ],
    entry_points={
        "console_scripts": [
            "threatflux-train=threatflux_training.cli:main",
        ],
    },
    include_package_data=True,
)
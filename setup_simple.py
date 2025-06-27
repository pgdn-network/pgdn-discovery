#!/usr/bin/env python3
"""
Setup script for PGDN Discover - Simple DePIN Protocol Discovery Library
"""

from setuptools import setup, find_packages

with open("README_SIMPLE.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pgdn-discover",
    version="0.1.0",
    author="PGDN Team",
    author_email="team@pgdn.network",
    description="Simple DePIN Protocol Discovery Library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pgdn-network/pgdn-discover",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "black>=21.0",
            "flake8>=3.8",
        ],
    },
    entry_points={
        "console_scripts": [
            "pgdn-discover=cli_simple:main",
        ],
    },
)

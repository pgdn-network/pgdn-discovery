"""
Setup script for PGDN Discover - Simple DePIN Protocol Discovery Library
"""

from setuptools import setup, find_packages

# Read requirements from requirements.txt
def read_requirements():
    try:
        with open('requirements.txt', 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        return []

setup(
    name="pgdn-discovery",
    version="0.2.1",
    description="PGDN Discovery - Simple DePIN Protocol Discovery Library",
    long_description="A lightweight library for discovering DePIN protocols on network nodes.",
    author="PGDN Team",
    author_email="team@pgdn.network",
    url="https://github.com/pgdn-network/pgdn-discovery",
    packages=find_packages(),
    package_data={
        'pgdn_discovery': ['*.yaml', '*.yml'],
    },
    include_package_data=True,
    install_requires=read_requirements(),
    entry_points={
        'console_scripts': [
            'pgdn-discovery=pgdn_discovery:main',
        ],
    },
    py_modules=['cli'],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
)

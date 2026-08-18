"""Setup script for APK Feature Extractor."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="apk-feature-extractor",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Scalable static feature extraction for Android APK malware detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/apk-feature-extractor",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "androguard>=4.1.0",
        "pyaxmlparser>=0.3.30",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
        "pyarrow>=15.0.0",
        "pydantic>=2.0.0",
        "click>=8.0.0",
        "tqdm>=4.65.0",
        "rich>=13.0.0",
        "loguru>=0.7.0",
        "cryptography>=42.0.0",
        "pyyaml>=6.0.0",
        "xxhash>=3.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.12.0",
            "black>=24.0.0",
            "isort>=5.13.0",
            "flake8>=7.0.0",
            "mypy>=1.8.0",
            "pre-commit>=3.6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "apk-extract=apk_extractor.cli.main:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)

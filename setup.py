#!/usr/bin/env python3
"""Setup script for git-safe."""

from setuptools import find_packages, setup

# Read the README file
with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

# Dependencies
requirements = [
    "cryptography>=3.4.8",
    "python-gnupg>=0.5.0",
    "pathspec>=0.9.0",
]

setup(
    name="gitsafe-cli",
    version="1.0.1",
    author="Hernan Monserrat",
    author_email="",
    description="Effortless file encryption for your git repos—pattern-matched, secure, and keyfile-flexible.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hemonserrat/git-safe",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Version Control :: Git",
        "Topic :: System :: Archiving :: Backup",
        "Topic :: Utilities",
    ],
    python_requires=">=3.10",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "ruff>=0.1.0",
            "isort>=5.12.0",
            "mypy>=1.0.0",
        ],
        "security": [
            "bandit>=1.7.0",
            "safety>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "git-safe=git_safe.cli:main",
        ],
    },
    scripts=["git-safe"],
    include_package_data=True,
    zip_safe=False,
    keywords="git encryption security cryptography file-encryption gitattributes",
    project_urls={
        "Bug Reports": "https://github.com/hemonserrat/git-safe/issues",
        "Source": "https://github.com/hemonserrat/git-safe",
        "Documentation": "https://github.com/hemonserrat/git-safe#readme",
    },
)

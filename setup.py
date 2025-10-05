#!/usr/bin/env python3
"""
LinkShield Backend Setup Script

This setup.py provides fallback compatibility for older Python packaging tools
that don't support pyproject.toml. The primary configuration is in pyproject.toml.
"""

from setuptools import setup, find_packages
import os
import sys

# Ensure we're using Python 3.8+
if sys.version_info < (3, 8):
    sys.exit("LinkShield Backend requires Python 3.8 or higher")

# Read the README file for long description
def read_readme():
    """Read README.md for long description."""
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    return "LinkShield Backend - Secure URL shortening service"

# Read version from __init__.py
def get_version():
    """Get version from package __init__.py."""
    version_file = os.path.join("src", "linkshield", "__init__.py")
    if os.path.exists(version_file):
        with open(version_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    return line.split("=")[1].strip().strip('"').strip("'")
    return "1.0.0"

# Core dependencies
INSTALL_REQUIRES = [
    "fastapi>=0.104.0",
    "uvicorn[standard]>=0.24.0",
    "pydantic>=2.5.0",
    "pydantic-settings>=2.1.0",
    "python-jose[cryptography]>=3.3.0",
    "passlib[bcrypt]>=1.7.4",
    "python-multipart>=0.0.6",
    "redis>=5.0.0",
    "asyncpg>=0.29.0",
    "sqlalchemy>=2.0.0",
    "alembic>=1.13.0",
    "python-dotenv>=1.0.0",
    "cryptography>=41.0.0",
    "bcrypt>=4.1.0",
    "email-validator>=2.1.0",
    "httpx>=0.25.0",
    "aiofiles>=23.2.0",
    "slowapi>=0.1.9",
    "itsdangerous>=2.1.0",
]

# Development dependencies
DEV_REQUIRES = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "pytest-cov>=4.1.0",
    "pytest-mock>=3.12.0",
    "pytest-benchmark>=4.0.0",
    "black>=23.0.0",
    "isort>=5.12.0",
    "flake8>=6.0.0",
    "mypy>=1.7.0",
    "bandit>=1.7.5",
    "safety>=2.3.0",
    "pre-commit>=3.5.0",
]

# Test dependencies
TEST_REQUIRES = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",
    "pytest-cov>=4.1.0",
    "pytest-mock>=3.12.0",
    "pytest-benchmark>=4.0.0",
    "httpx>=0.25.0",
    "faker>=20.0.0",
]

# Security dependencies
SECURITY_REQUIRES = [
    "bandit>=1.7.5",
    "safety>=2.3.0",
    "semgrep>=1.45.0",
    "snyk>=1.0.0",
]

# Performance dependencies
PERFORMANCE_REQUIRES = [
    "locust>=2.17.0",
    "py-spy>=0.3.14",
    "memory-profiler>=0.61.0",
    "line-profiler>=4.1.0",
]

# Monitoring dependencies
MONITORING_REQUIRES = [
    "prometheus-client>=0.19.0",
    "opentelemetry-api>=1.21.0",
    "opentelemetry-sdk>=1.21.0",
    "opentelemetry-instrumentation-fastapi>=0.42b0",
    "opentelemetry-exporter-prometheus>=1.12.0rc1",
    "structlog>=23.2.0",
]

# Extra dependencies
EXTRAS_REQUIRE = {
    "dev": DEV_REQUIRES,
    "test": TEST_REQUIRES,
    "security": SECURITY_REQUIRES,
    "performance": PERFORMANCE_REQUIRES,
    "monitoring": MONITORING_REQUIRES,
    "all": (
        DEV_REQUIRES + 
        TEST_REQUIRES + 
        SECURITY_REQUIRES + 
        PERFORMANCE_REQUIRES + 
        MONITORING_REQUIRES
    ),
}

setup(
    name="linkshield-backend",
    version=get_version(),
    description="LinkShield Backend - Secure URL shortening service with comprehensive security features",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="LinkShield Team",
    author_email="team@linkshield.com",
    url="https://github.com/linkshield/backend",
    project_urls={
        "Documentation": "https://docs.linkshield.com",
        "Repository": "https://github.com/linkshield/backend",
        "Bug Tracker": "https://github.com/linkshield/backend/issues",
    },
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    package_dir={"": "src"},
    packages=find_packages(where="src", include=["linkshield*"]),
    include_package_data=True,
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    entry_points={
        "console_scripts": [
            "linkshield=linkshield.main:main",
        ],
    },
    zip_safe=False,
    keywords=[
        "url-shortener",
        "security",
        "fastapi",
        "authentication",
        "rate-limiting",
        "csrf-protection",
        "session-management",
        "jwt",
        "redis",
        "postgresql",
    ],
)
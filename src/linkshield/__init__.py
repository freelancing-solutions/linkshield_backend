"""
LinkShield Backend Package

A comprehensive security-focused URL shortening service with advanced threat detection,
user management, and monitoring capabilities.
"""

# Import version information
from .version import __version__, __version_info__, get_version, get_full_version

__author__ = "LinkShield Team"
__license__ = "MIT"
__description__ = "Secure URL shortening service with comprehensive security features"

# Import main components with error handling
try:
    from .config.settings import Settings
    from .main import create_app
except ImportError as e:
    # Handle missing dependencies gracefully during development
    print(f"Warning: Some dependencies may be missing: {e}")
    Settings = None
    create_app = None

# Package metadata
__all__ = [
    "Settings",
    "create_app",
    "__version__",
    "__version_info__",
    "get_version",
    "get_full_version",
]
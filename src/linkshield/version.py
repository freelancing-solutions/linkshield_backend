"""
LinkShield Backend Version Information

This module contains version information for the LinkShield backend package.
"""

# Version information
__version__ = "1.0.0"
__version_info__ = (1, 0, 0)

# Build information
__build__ = "production"
__commit__ = "unknown"

# API version
API_VERSION = "v1"
API_VERSION_INFO = (1, 0)

def get_version():
    """Get the current version string."""
    return __version__

def get_version_info():
    """Get the current version as a tuple."""
    return __version_info__

def get_api_version():
    """Get the current API version string."""
    return API_VERSION

def get_full_version():
    """Get the full version string including build information."""
    version = __version__
    if __build__ != "production":
        version += f"-{__build__}"
    if __commit__ != "unknown":
        version += f"+{__commit__[:8]}"
    return version
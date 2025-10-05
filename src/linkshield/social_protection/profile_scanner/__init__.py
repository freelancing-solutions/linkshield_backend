"""
Profile Scanner Module

Handles social media profile security auditing including:
- Follower authenticity analysis
- Account age verification  
- Verification status checks
- Profile completeness assessment
- Suspicious activity detection
"""

from .profile_analyzer import ProfileAnalyzer
from .follower_authenticator import FollowerAuthenticator
from .verification_checker import VerificationChecker

__all__ = [
    "ProfileAnalyzer",
    "FollowerAuthenticator", 
    "VerificationChecker",
]
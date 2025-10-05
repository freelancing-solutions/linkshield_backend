"""
Reputation Monitor Module

Handles brand and mention tracking across social platforms including:
- Brand mention monitoring
- Sentiment analysis
- Reputation damage detection
- Negative trend identification
- Crisis escalation alerts
"""

from .brand_monitor import BrandMonitor
from .sentiment_analyzer import SentimentAnalyzer
from .reputation_tracker import ReputationTracker
from .mention_detector import MentionDetector

__all__ = [
    "BrandMonitor",
    "SentimentAnalyzer",
    "ReputationTracker",
    "MentionDetector",
]
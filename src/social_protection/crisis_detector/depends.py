#!/usr/bin/env python3
"""
Crisis Detector Dependencies

Dependency injection providers for crisis detection services.
"""

from typing import Optional, Dict, Any
from fastapi import Depends

from src.services.ai_service import AIService
from src.services.depends import get_ai_service
from ..reputation_monitor.reputation_tracker import ReputationTracker
from .core import CrisisDetector
from .crisis_analyzer import CrisisAnalyzer
from .alert_generator import AlertGenerator
from .emergency_responder import EmergencyResponder
from .escalation_monitor import EscalationMonitor


async def get_reputation_tracker() -> ReputationTracker:
    """
    Get ReputationTracker instance for brand reputation monitoring.
    
    Returns:
        ReputationTracker: Configured tracker instance
    """
    # Initialize with in-memory persistence for now
    # In production, this should use Redis persistence
    return ReputationTracker()


async def get_crisis_detector(
    reputation_tracker: ReputationTracker = Depends(get_reputation_tracker),
    ai_service: AIService = Depends(get_ai_service)
) -> CrisisDetector:
    """
    Get CrisisDetector instance for crisis detection and evaluation.
    
    Args:
        reputation_tracker: Reputation tracker for brand metrics
        ai_service: AI service for crisis analysis
        
    Returns:
        CrisisDetector: Configured detector instance
    """
    config = {
        "min_mentions": 5,
        "weights": {
            "volume": 0.30,
            "sentiment": 0.25,
            "keywords": 0.20,
            "emotion": 0.10,
            "amplification": 0.10,
            "cross_platform": 0.05
        },
        "crisis_keywords": [
            "scandal", "breach", "lawsuit", "fraud", "hack", "recall",
            "explosion", "death", "arrest", "investigation"
        ],
        "hysteresis_windows_required": 2,
        "cooldown_seconds": 900
    }
    
    return CrisisDetector(
        reputation_tracker=reputation_tracker,
        ai_service=ai_service,
        config=config
    )


async def get_crisis_analyzer(
    reputation_tracker: ReputationTracker = Depends(get_reputation_tracker),
    ai_service: AIService = Depends(get_ai_service)
) -> CrisisAnalyzer:
    """
    Get CrisisAnalyzer instance for crisis score calculation.
    
    Args:
        reputation_tracker: Reputation tracker for brand metrics
        ai_service: AI service for crisis analysis
        
    Returns:
        CrisisAnalyzer: Configured analyzer instance
    """
    config = {
        "min_mentions": 5,
        "weights": {
            "volume": 0.30,
            "sentiment": 0.25,
            "keywords": 0.20,
            "emotion": 0.10,
            "amplification": 0.10,
            "cross_platform": 0.05
        },
        "crisis_keywords": [
            "scandal", "breach", "lawsuit", "fraud", "hack", "recall",
            "explosion", "death", "arrest", "investigation"
        ]
    }
    
    return CrisisAnalyzer(
        reputation_tracker=reputation_tracker,
        ai_service=ai_service,
        config=config
    )


async def get_alert_generator() -> AlertGenerator:
    """
    Get AlertGenerator instance for crisis alert generation.
    
    Returns:
        AlertGenerator: Configured generator instance
    """
    config = {
        "alert_threshold": 0.4,
        "severity_thresholds": {
            "warning": 0.4,
            "high": 0.65,
            "critical": 0.85
        }
    }
    
    return AlertGenerator(config=config)


async def get_emergency_responder() -> EmergencyResponder:
    """
    Get EmergencyResponder instance for emergency response coordination.
    
    Returns:
        EmergencyResponder: Configured responder instance
    """
    return EmergencyResponder()


async def get_escalation_monitor() -> EscalationMonitor:
    """
    Get EscalationMonitor instance for escalation threshold monitoring.
    
    Returns:
        EscalationMonitor: Configured monitor instance
    """
    return EscalationMonitor()

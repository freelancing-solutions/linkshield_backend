"""
Crisis Detector Module

Handles real-time risk alerts and crisis intervention including:
- Real-time risk alert generation
- Crisis intervention notifications
- Emergency response coordination
- Escalation threshold monitoring
- Automated response triggers
"""

from .crisis_analyzer import CrisisAnalyzer
from .alert_generator import AlertGenerator
from .emergency_responder import EmergencyResponder
from .escalation_monitor import EscalationMonitor
from .core import CrisisDetector, CrisisReport

__all__ = [
    "CrisisDetector",
    "CrisisReport",
    "CrisisAnalyzer",
    "AlertGenerator",
    "EmergencyResponder",
    "EscalationMonitor",
]
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

__all__ = [
    "CrisisAnalyzer",
    "AlertGenerator",
    "EmergencyResponder",
    "EscalationMonitor",
]
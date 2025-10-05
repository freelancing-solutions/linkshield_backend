#!/usr/bin/env python3
"""
Session Security Service

Provides comprehensive session security functionality including risk analysis,
anomaly detection, and security event logging for session management.
"""

import logging
import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from uuid import uuid4
import asyncio

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from linkshield.authentication.session_manager import (
    SessionData, 
    SessionSecurityContext, 
    SessionConfig,
    SessionError,
    SessionErrorType
)
from linkshield.models.user import User, UserSession
from linkshield.security.security_event_logger import SecurityEventLogger as BaseSecurityEventLogger


logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk levels for session security"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SessionRiskAssessment:
    """Session risk assessment result"""
    risk_level: RiskLevel
    risk_score: float
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionAnomaly:
    """Session anomaly detection result"""
    anomaly_type: str
    severity: str
    description: str
    confidence: float
    detected_at: datetime
    session_id: str
    user_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class SessionRiskAnalyzer:
    """Analyzes session security risks"""
    
    def __init__(self, config: Optional[SessionConfig] = None):
        self.config = config or SessionConfig()
        self.risk_thresholds = {
            RiskLevel.LOW: 0.3,
            RiskLevel.MEDIUM: 0.6,
            RiskLevel.HIGH: 0.8,
            RiskLevel.CRITICAL: 0.9
        }
    
    def analyze_session_risk(self, session_data: SessionData, request: Request) -> SessionRiskAssessment:
        """Analyze risk factors for a session"""
        risk_score = 0.0
        risk_factors = []
        recommendations = []
        
        # Analyze security context
        if session_data.security_context:
            context = session_data.security_context
            
            # IP address analysis
            if context.ip_address in ['127.0.0.1', 'localhost']:
                risk_score += 0.1
                risk_factors.append('localhost_access')
            
            # User agent analysis
            if not context.user_agent:
                risk_score += 0.3
                risk_factors.append('missing_user_agent')
                recommendations.append('Require user agent validation')
            
            # Existing risk score from context
            risk_score += context.risk_score
            risk_factors.extend(context.security_flags)
        
        # Session age analysis
        if session_data.created_at:
            session_age = datetime.now(timezone.utc) - session_data.created_at
            if session_age > timedelta(hours=24):
                risk_score += 0.2
                risk_factors.append('long_session_duration')
                recommendations.append('Consider session refresh')
        
        # Determine risk level
        risk_level = RiskLevel.LOW
        for level, threshold in sorted(self.risk_thresholds.items(), key=lambda x: x[1], reverse=True):
            if risk_score >= threshold:
                risk_level = level
                break
        
        return SessionRiskAssessment(
            risk_level=risk_level,
            risk_score=min(risk_score, 1.0),
            risk_factors=risk_factors,
            recommendations=recommendations,
            metadata={
                'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                'session_id': session_data.session_id
            }
        )
    
    def calculate_device_fingerprint_risk(self, fingerprint: str, known_fingerprints: List[str]) -> float:
        """Calculate risk based on device fingerprint"""
        if not fingerprint:
            return 0.5
        
        if fingerprint in known_fingerprints:
            return 0.1
        
        return 0.4  # New device
    
    def analyze_geolocation_risk(self, current_location: Dict[str, Any], 
                               previous_locations: List[Dict[str, Any]]) -> float:
        """Analyze geolocation-based risk"""
        if not current_location or not previous_locations:
            return 0.2
        
        # Simple distance-based risk (in a real implementation, use proper geolocation)
        current_country = current_location.get('country', '')
        previous_countries = [loc.get('country', '') for loc in previous_locations[-5:]]
        
        if current_country in previous_countries:
            return 0.1
        
        return 0.6  # New country


class SessionAnomalyDetector:
    """Detects anomalies in session behavior"""
    
    def __init__(self):
        self.anomaly_patterns = {
            'rapid_location_change': {
                'threshold': 1000,  # km/hour
                'severity': 'high'
            },
            'unusual_access_time': {
                'threshold': 0.8,  # probability threshold
                'severity': 'medium'
            },
            'device_fingerprint_mismatch': {
                'threshold': 0.7,  # similarity threshold
                'severity': 'high'
            }
        }
    
    async def detect_anomalies(self, session_data: SessionData, 
                             historical_sessions: List[SessionData]) -> List[SessionAnomaly]:
        """Detect anomalies in session data"""
        anomalies = []
        
        # Check for rapid location changes
        location_anomaly = self._detect_location_anomaly(session_data, historical_sessions)
        if location_anomaly:
            anomalies.append(location_anomaly)
        
        # Check for unusual access patterns
        time_anomaly = self._detect_time_anomaly(session_data, historical_sessions)
        if time_anomaly:
            anomalies.append(time_anomaly)
        
        # Check for device fingerprint anomalies
        device_anomaly = self._detect_device_anomaly(session_data, historical_sessions)
        if device_anomaly:
            anomalies.append(device_anomaly)
        
        return anomalies
    
    def _detect_location_anomaly(self, current_session: SessionData, 
                               historical_sessions: List[SessionData]) -> Optional[SessionAnomaly]:
        """Detect rapid location changes"""
        if not current_session.security_context or not current_session.security_context.geolocation:
            return None
        
        current_location = current_session.security_context.geolocation
        
        # Find most recent session with location data
        for session in sorted(historical_sessions, key=lambda x: x.created_at, reverse=True):
            if (session.security_context and 
                session.security_context.geolocation and 
                session.created_at < current_session.created_at):
                
                # Calculate time difference
                time_diff = current_session.created_at - session.created_at
                time_hours = time_diff.total_seconds() / 3600
                
                # Simple distance calculation (in a real implementation, use proper geolocation)
                if time_hours < 1 and current_location != session.security_context.geolocation:
                    return SessionAnomaly(
                        anomaly_type='rapid_location_change',
                        severity='high',
                        description=f'Location changed too quickly: {time_hours:.2f} hours',
                        confidence=0.8,
                        detected_at=datetime.now(timezone.utc),
                        session_id=current_session.session_id,
                        user_id=current_session.user_id,
                        metadata={
                            'previous_location': session.security_context.geolocation,
                            'current_location': current_location,
                            'time_difference_hours': time_hours
                        }
                    )
                break
        
        return None
    
    def _detect_time_anomaly(self, current_session: SessionData, 
                           historical_sessions: List[SessionData]) -> Optional[SessionAnomaly]:
        """Detect unusual access times"""
        current_hour = current_session.created_at.hour
        
        # Analyze historical access patterns
        historical_hours = [s.created_at.hour for s in historical_sessions if s.created_at]
        
        if len(historical_hours) < 5:  # Not enough data
            return None
        
        # Simple anomaly detection based on hour frequency
        hour_counts = {}
        for hour in historical_hours:
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
        
        total_sessions = len(historical_hours)
        current_hour_frequency = hour_counts.get(current_hour, 0) / total_sessions
        
        if current_hour_frequency < 0.1:  # Less than 10% of sessions at this hour
            return SessionAnomaly(
                anomaly_type='unusual_access_time',
                severity='medium',
                description=f'Unusual access time: {current_hour}:00 (frequency: {current_hour_frequency:.2%})',
                confidence=0.7,
                detected_at=datetime.now(timezone.utc),
                session_id=current_session.session_id,
                user_id=current_session.user_id,
                metadata={
                    'access_hour': current_hour,
                    'historical_frequency': current_hour_frequency,
                    'total_historical_sessions': total_sessions
                }
            )
        
        return None
    
    def _detect_device_anomaly(self, current_session: SessionData, 
                             historical_sessions: List[SessionData]) -> Optional[SessionAnomaly]:
        """Detect device fingerprint anomalies"""
        if not current_session.security_context:
            return None
        
        current_ua = current_session.security_context.user_agent
        if not current_ua:
            return SessionAnomaly(
                anomaly_type='missing_user_agent',
                severity='medium',
                description='Missing user agent in session',
                confidence=0.9,
                detected_at=datetime.now(timezone.utc),
                session_id=current_session.session_id,
                user_id=current_session.user_id
            )
        
        # Check against historical user agents
        historical_uas = []
        for session in historical_sessions:
            if (session.security_context and 
                session.security_context.user_agent):
                historical_uas.append(session.security_context.user_agent)
        
        if historical_uas and current_ua not in historical_uas:
            return SessionAnomaly(
                anomaly_type='new_device_fingerprint',
                severity='medium',
                description='New device fingerprint detected',
                confidence=0.6,
                detected_at=datetime.now(timezone.utc),
                session_id=current_session.session_id,
                user_id=current_session.user_id,
                metadata={
                    'current_user_agent': current_ua,
                    'known_user_agents_count': len(set(historical_uas))
                }
            )
        
        return None


class SecurityEventLogger:
    """Logs security events for sessions"""
    
    def __init__(self):
        self.base_logger = BaseSecurityEventLogger()
    
    async def log_session_created(self, session_data: SessionData, user: User, 
                                request: Request) -> None:
        """Log session creation event"""
        event_data = {
            'event_type': 'session_created',
            'session_id': session_data.session_id,
            'user_id': session_data.user_id,
            'ip_address': session_data.security_context.ip_address if session_data.security_context else None,
            'user_agent': session_data.security_context.user_agent if session_data.security_context else None,
            'timestamp': session_data.created_at.isoformat()
        }
        
        logger.info(f"Session created for user {session_data.user_id}: {session_data.session_id}")
        await self.base_logger.log_security_event(
            event_type="SESSION_CREATED",
            user_id=session_data.user_id,
            details=event_data
        )
    
    async def log_session_validation(self, session_data: SessionData, 
                                   validation_result: bool, reason: Optional[str] = None) -> None:
        """Log session validation event"""
        event_data = {
            'event_type': 'session_validation',
            'session_id': session_data.session_id,
            'user_id': session_data.user_id,
            'validation_result': validation_result,
            'reason': reason,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Session validation for {session_data.session_id}: {validation_result}")
        await self.base_logger.log_security_event(
            event_type="SESSION_VALIDATION",
            user_id=session_data.user_id,
            details=event_data
        )
    
    async def log_anomaly_detected(self, anomaly: SessionAnomaly) -> None:
        """Log detected anomaly"""
        event_data = {
            'event_type': 'session_anomaly',
            'anomaly_type': anomaly.anomaly_type,
            'severity': anomaly.severity,
            'description': anomaly.description,
            'confidence': anomaly.confidence,
            'session_id': anomaly.session_id,
            'user_id': anomaly.user_id,
            'detected_at': anomaly.detected_at.isoformat(),
            'metadata': anomaly.metadata
        }
        
        logger.warning(f"Session anomaly detected: {anomaly.anomaly_type} for session {anomaly.session_id}")
        await self.base_logger.log_security_event(
            event_type="SESSION_ANOMALY",
            user_id=anomaly.user_id,
            details=event_data
        )
    
    async def log_risk_assessment(self, session_data: SessionData, 
                                risk_assessment: SessionRiskAssessment) -> None:
        """Log risk assessment"""
        event_data = {
            'event_type': 'session_risk_assessment',
            'session_id': session_data.session_id,
            'user_id': session_data.user_id,
            'risk_level': risk_assessment.risk_level.value,
            'risk_score': risk_assessment.risk_score,
            'risk_factors': risk_assessment.risk_factors,
            'recommendations': risk_assessment.recommendations,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Risk assessment for session {session_data.session_id}: {risk_assessment.risk_level.value}")
        await self.base_logger.log_security_event(
            event_type="SESSION_RISK_ASSESSMENT",
            user_id=session_data.user_id,
            details=event_data
        )


class SessionSecurityService:
    """Main session security service orchestrating all security components"""
    
    def __init__(self, config: Optional[SessionConfig] = None):
        self.config = config or SessionConfig()
        self.risk_analyzer = SessionRiskAnalyzer(config)
        self.anomaly_detector = SessionAnomalyDetector()
        self.event_logger = SecurityEventLogger()
    
    async def validate_session_security(self, session_data: SessionData, 
                                      request: Request,
                                      historical_sessions: Optional[List[SessionData]] = None) -> Tuple[bool, List[str]]:
        """Comprehensive session security validation"""
        warnings = []
        
        try:
            # Perform risk analysis
            risk_assessment = self.risk_analyzer.analyze_session_risk(session_data, request)
            await self.event_logger.log_risk_assessment(session_data, risk_assessment)
            
            # Check if risk level is acceptable
            if risk_assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                warnings.append(f"High risk session detected: {risk_assessment.risk_level.value}")
                if risk_assessment.risk_level == RiskLevel.CRITICAL:
                    await self.event_logger.log_session_validation(session_data, False, "Critical risk level")
                    return False, warnings
            
            # Detect anomalies if historical data is available
            if historical_sessions:
                anomalies = await self.anomaly_detector.detect_anomalies(session_data, historical_sessions)
                for anomaly in anomalies:
                    await self.event_logger.log_anomaly_detected(anomaly)
                    if anomaly.severity == 'high':
                        warnings.append(f"High severity anomaly: {anomaly.description}")
            
            # Log successful validation
            await self.event_logger.log_session_validation(session_data, True)
            return True, warnings
            
        except Exception as e:
            logger.error(f"Error during session security validation: {e}")
            await self.event_logger.log_session_validation(session_data, False, f"Validation error: {str(e)}")
            return False, [f"Security validation failed: {str(e)}"]
    
    async def create_secure_session(self, user: User, request: Request) -> SessionData:
        """Create a session with security validation"""
        from linkshield.authentication.session_manager import SessionManager
        
        # Create session using the session manager
        session_manager = SessionManager(self.config)
        session_data = await session_manager.create_session(user, request)
        
        # Log session creation
        await self.event_logger.log_session_created(session_data, user, request)
        
        return session_data
    
    async def monitor_session_activity(self, session_data: SessionData, 
                                     activity_data: Dict[str, Any]) -> None:
        """Monitor ongoing session activity for security"""
        # Update last accessed time
        session_data.last_accessed_at = datetime.now(timezone.utc)
        
        # Log activity if suspicious
        if activity_data.get('suspicious_activity'):
            await self.event_logger.log_security_event(
                event_type="SUSPICIOUS_SESSION_ACTIVITY",
                user_id=session_data.user_id,
                details={
                    'session_id': session_data.session_id,
                    'activity_data': activity_data,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
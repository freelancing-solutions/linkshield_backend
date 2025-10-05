#!/usr/bin/env python3
"""
Emergency API Key Revocation Service

Provides immediate API key revocation capabilities with incident response,
threat detection, and automated security measures.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
import json
import asyncio

import redis.asyncio as redis
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_
from sqlalchemy.orm import selectinload

from src.config.settings import get_settings
from src.config.database import get_db_session
from src.models.user import User, APIKey
from src.services.notification_service import NotificationService
from src.security.api_key_rotation import get_api_key_rotation_service


class ThreatLevel(Enum):
    """Threat level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RevocationReason(Enum):
    """Revocation reason enumeration"""
    COMPROMISED = "compromised"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    POLICY_VIOLATION = "policy_violation"
    USER_REQUEST = "user_request"
    ADMIN_ACTION = "admin_action"
    AUTOMATED_DETECTION = "automated_detection"
    SECURITY_INCIDENT = "security_incident"


@dataclass
class EmergencyRevocationRequest:
    """Emergency revocation request"""
    key_id: str
    user_id: str
    reason: RevocationReason
    threat_level: ThreatLevel
    description: str
    requested_by: str  # User ID or system identifier
    evidence: Dict[str, Any]  # Supporting evidence
    immediate: bool = True  # Whether to revoke immediately
    notify_user: bool = True
    block_user: bool = False  # Whether to temporarily block user
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)


@dataclass
class RevocationResult:
    """Revocation operation result"""
    success: bool
    key_id: str
    revoked_at: Optional[datetime]
    reason: str
    threat_level: str
    actions_taken: List[str]
    notifications_sent: List[str]
    errors: List[str] = None
    incident_id: Optional[str] = None


class EmergencyRevocationError(Exception):
    """Emergency revocation specific errors"""
    pass


class EmergencyRevocationService:
    """
    Emergency API Key Revocation Service
    
    Handles immediate API key revocation with threat assessment,
    incident response, and automated security measures.
    """
    
    def __init__(self, redis_client: Optional[Redis] = None):
        """Initialize the emergency revocation service"""
        self.settings = get_settings()
        self.redis_client = redis_client
        self.notification_service = NotificationService()
        self.rotation_service = get_api_key_rotation_service()
        
        # Redis keys for tracking
        self.REVOCATION_LOG_KEY = "emergency_revocation:log"
        self.BLOCKED_KEYS_KEY = "emergency_revocation:blocked_keys"
        self.INCIDENT_TRACKING_KEY = "emergency_revocation:incidents:{incident_id}"
        self.THREAT_INDICATORS_KEY = "emergency_revocation:threats:{key_id}"
        self.REVOCATION_QUEUE_KEY = "emergency_revocation:queue"
        
        # Threat detection thresholds
        self.threat_thresholds = {
            "failed_requests_per_minute": 100,
            "unusual_ip_count": 10,
            "suspicious_patterns": 5,
            "rate_limit_violations": 20
        }
    
    async def _get_redis_client(self) -> Redis:
        """Get Redis client instance"""
        if not self.redis_client:
            self.redis_client = redis.from_url(
                self.settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
        return self.redis_client
    
    def _generate_incident_id(self) -> str:
        """Generate unique incident ID"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        random_suffix = str(uuid.uuid4())[:8]
        return f"INC-{timestamp}-{random_suffix}"
    
    async def revoke_key_immediately(self, request: EmergencyRevocationRequest) -> RevocationResult:
        """
        Immediately revoke an API key with emergency procedures
        
        Args:
            request: Emergency revocation request
            
        Returns:
            Revocation result
        """
        try:
            incident_id = self._generate_incident_id()
            actions_taken = []
            notifications_sent = []
            errors = []
            
            # Log the emergency revocation request
            await self._log_revocation_request(request, incident_id)
            
            # Immediately block the key in Redis
            redis_client = await self._get_redis_client()
            blocked_key_data = {
                "key_id": request.key_id,
                "blocked_at": datetime.now(timezone.utc).isoformat(),
                "reason": request.reason.value,
                "threat_level": request.threat_level.value,
                "incident_id": incident_id
            }
            
            await redis_client.sadd(
                self.BLOCKED_KEYS_KEY,
                json.dumps(blocked_key_data)
            )
            actions_taken.append("Key blocked in Redis cache")
            
            # Revoke the key in database using rotation service
            try:
                revocation_result = await self.rotation_service.emergency_revoke_key(
                    user_id=uuid.UUID(request.user_id),
                    api_key_id=uuid.UUID(request.key_id),
                    reason=f"{request.reason.value}: {request.description}"
                )
                actions_taken.append("Key revoked in database")
                revoked_at = revocation_result.get("revoked_at")
            except Exception as e:
                errors.append(f"Database revocation failed: {str(e)}")
                revoked_at = None
            
            # Handle user blocking if requested
            if request.block_user:
                try:
                    await self._block_user_temporarily(request.user_id, request.threat_level, incident_id)
                    actions_taken.append("User temporarily blocked")
                except Exception as e:
                    errors.append(f"User blocking failed: {str(e)}")
            
            # Send notifications
            if request.notify_user:
                try:
                    await self._send_emergency_notification(request, incident_id)
                    notifications_sent.append("User notification sent")
                except Exception as e:
                    errors.append(f"User notification failed: {str(e)}")
            
            # Send admin notification for high/critical threats
            if request.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                try:
                    await self._send_admin_alert(request, incident_id)
                    notifications_sent.append("Admin alert sent")
                except Exception as e:
                    errors.append(f"Admin alert failed: {str(e)}")
            
            # Store incident details
            await self._store_incident_details(request, incident_id, actions_taken, errors)
            
            # Trigger additional security measures for critical threats
            if request.threat_level == ThreatLevel.CRITICAL:
                try:
                    await self._trigger_critical_response(request, incident_id)
                    actions_taken.append("Critical threat response triggered")
                except Exception as e:
                    errors.append(f"Critical response failed: {str(e)}")
            
            return RevocationResult(
                success=len(errors) == 0 or revoked_at is not None,
                key_id=request.key_id,
                revoked_at=revoked_at,
                reason=f"{request.reason.value}: {request.description}",
                threat_level=request.threat_level.value,
                actions_taken=actions_taken,
                notifications_sent=notifications_sent,
                errors=errors if errors else None,
                incident_id=incident_id
            )
            
        except Exception as e:
            raise EmergencyRevocationError(f"Emergency revocation failed: {str(e)}")
    
    async def detect_and_revoke_threats(self, user_id: uuid.UUID = None) -> List[RevocationResult]:
        """
        Detect threats and automatically revoke compromised keys
        
        Args:
            user_id: Optional user ID to check (if None, checks all users)
            
        Returns:
            List of revocation results
        """
        try:
            results = []
            
            # Get potentially compromised keys
            threat_indicators = await self._detect_threat_indicators(user_id)
            
            for key_id, indicators in threat_indicators.items():
                # Assess threat level
                threat_level = await self._assess_threat_level(indicators)
                
                if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    # Create emergency revocation request
                    request = EmergencyRevocationRequest(
                        key_id=key_id,
                        user_id=indicators["user_id"],
                        reason=RevocationReason.AUTOMATED_DETECTION,
                        threat_level=threat_level,
                        description=f"Automated threat detection: {', '.join(indicators['threats'])}",
                        requested_by="system_automated_detection",
                        evidence=indicators,
                        immediate=True,
                        notify_user=True,
                        block_user=threat_level == ThreatLevel.CRITICAL
                    )
                    
                    # Revoke the key
                    result = await self.revoke_key_immediately(request)
                    results.append(result)
            
            return results
            
        except Exception as e:
            raise EmergencyRevocationError(f"Automated threat detection failed: {str(e)}")
    
    async def _detect_threat_indicators(self, user_id: Optional[uuid.UUID] = None) -> Dict[str, Dict[str, Any]]:
        """Detect threat indicators for API keys"""
        try:
            redis_client = await self._get_redis_client()
            threat_indicators = {}
            
            # Get API keys to check
            async with get_db_session() as session:
                query = select(APIKey).where(APIKey.is_active == True)
                if user_id:
                    query = query.where(APIKey.user_id == user_id)
                
                result = await session.execute(query)
                api_keys = result.scalars().all()
            
            for api_key in api_keys:
                indicators = {
                    "user_id": str(api_key.user_id),
                    "key_id": str(api_key.id),
                    "threats": [],
                    "metrics": {}
                }
                
                # Check various threat indicators
                key_metrics_key = f"api_key_metrics:{api_key.id}"
                metrics_data = await redis_client.hgetall(key_metrics_key)
                
                if metrics_data:
                    # Failed requests
                    failed_requests = int(metrics_data.get("failed_requests_last_hour", 0))
                    if failed_requests > self.threat_thresholds["failed_requests_per_minute"] * 60:
                        indicators["threats"].append("excessive_failed_requests")
                        indicators["metrics"]["failed_requests"] = failed_requests
                    
                    # Unusual IP addresses
                    unique_ips = int(metrics_data.get("unique_ips_last_hour", 0))
                    if unique_ips > self.threat_thresholds["unusual_ip_count"]:
                        indicators["threats"].append("unusual_ip_pattern")
                        indicators["metrics"]["unique_ips"] = unique_ips
                    
                    # Rate limit violations
                    rate_violations = int(metrics_data.get("rate_limit_violations", 0))
                    if rate_violations > self.threat_thresholds["rate_limit_violations"]:
                        indicators["threats"].append("rate_limit_abuse")
                        indicators["metrics"]["rate_violations"] = rate_violations
                
                # Check for suspicious patterns
                suspicious_patterns = await self._check_suspicious_patterns(api_key.id)
                if suspicious_patterns:
                    indicators["threats"].extend(suspicious_patterns)
                
                # Only include keys with threats
                if indicators["threats"]:
                    threat_indicators[str(api_key.id)] = indicators
            
            return threat_indicators
            
        except Exception as e:
            raise EmergencyRevocationError(f"Failed to detect threat indicators: {str(e)}")
    
    async def _check_suspicious_patterns(self, api_key_id: uuid.UUID) -> List[str]:
        """Check for suspicious usage patterns"""
        patterns = []
        
        try:
            redis_client = await self._get_redis_client()
            
            # Check for unusual time patterns
            usage_pattern_key = f"api_key_usage_pattern:{api_key_id}"
            pattern_data = await redis_client.hgetall(usage_pattern_key)
            
            if pattern_data:
                # Check for off-hours usage
                off_hours_requests = int(pattern_data.get("off_hours_requests", 0))
                total_requests = int(pattern_data.get("total_requests", 1))
                
                if off_hours_requests / total_requests > 0.8:  # 80% off-hours usage
                    patterns.append("unusual_time_pattern")
                
                # Check for geographic anomalies
                unusual_locations = int(pattern_data.get("unusual_locations", 0))
                if unusual_locations > 5:
                    patterns.append("geographic_anomaly")
                
                # Check for rapid successive requests
                burst_requests = int(pattern_data.get("burst_requests", 0))
                if burst_requests > 1000:
                    patterns.append("request_burst")
            
            return patterns
            
        except Exception:
            return []
    
    async def _assess_threat_level(self, indicators: Dict[str, Any]) -> ThreatLevel:
        """Assess threat level based on indicators"""
        threats = indicators.get("threats", [])
        metrics = indicators.get("metrics", {})
        
        # Critical threats
        critical_threats = {"rate_limit_abuse", "request_burst", "geographic_anomaly"}
        if any(threat in critical_threats for threat in threats):
            return ThreatLevel.CRITICAL
        
        # High threats
        high_threats = {"excessive_failed_requests", "unusual_ip_pattern"}
        if any(threat in high_threats for threat in threats):
            return ThreatLevel.HIGH
        
        # Medium threats
        if len(threats) >= 2:
            return ThreatLevel.MEDIUM
        
        return ThreatLevel.LOW
    
    async def _block_user_temporarily(self, user_id: str, threat_level: ThreatLevel, incident_id: str):
        """Temporarily block a user based on threat level"""
        try:
            redis_client = await self._get_redis_client()
            
            # Determine block duration based on threat level
            block_duration = {
                ThreatLevel.MEDIUM: timedelta(minutes=30),
                ThreatLevel.HIGH: timedelta(hours=2),
                ThreatLevel.CRITICAL: timedelta(hours=24)
            }.get(threat_level, timedelta(minutes=15))
            
            block_data = {
                "user_id": user_id,
                "blocked_at": datetime.now(timezone.utc).isoformat(),
                "block_duration": block_duration.total_seconds(),
                "threat_level": threat_level.value,
                "incident_id": incident_id,
                "reason": "emergency_revocation_security_measure"
            }
            
            await redis_client.setex(
                f"blocked_user:{user_id}",
                block_duration,
                json.dumps(block_data)
            )
            
        except Exception as e:
            raise EmergencyRevocationError(f"Failed to block user: {str(e)}")
    
    async def _send_emergency_notification(self, request: EmergencyRevocationRequest, incident_id: str):
        """Send emergency notification to user"""
        try:
            await self.notification_service.send_emergency_revocation_notification(
                user_id=uuid.UUID(request.user_id),
                key_name=f"API Key {request.key_id[:8]}...",
                reason=request.description,
                threat_level=request.threat_level.value,
                incident_id=incident_id,
                revoked_at=datetime.now(timezone.utc)
            )
        except Exception as e:
            raise EmergencyRevocationError(f"Failed to send emergency notification: {str(e)}")
    
    async def _send_admin_alert(self, request: EmergencyRevocationRequest, incident_id: str):
        """Send alert to administrators"""
        try:
            await self.notification_service.send_admin_security_alert(
                incident_id=incident_id,
                threat_level=request.threat_level.value,
                affected_user=request.user_id,
                affected_key=request.key_id,
                reason=request.description,
                evidence=request.evidence
            )
        except Exception as e:
            raise EmergencyRevocationError(f"Failed to send admin alert: {str(e)}")
    
    async def _trigger_critical_response(self, request: EmergencyRevocationRequest, incident_id: str):
        """Trigger additional security measures for critical threats"""
        try:
            redis_client = await self._get_redis_client()
            
            # Revoke all user's API keys for critical threats
            if request.threat_level == ThreatLevel.CRITICAL:
                async with get_db_session() as session:
                    # Get all user's active API keys
                    result = await session.execute(
                        select(APIKey)
                        .where(APIKey.user_id == uuid.UUID(request.user_id))
                        .where(APIKey.is_active == True)
                    )
                    user_keys = result.scalars().all()
                    
                    # Revoke all keys
                    for key in user_keys:
                        if str(key.id) != request.key_id:  # Don't double-revoke the original key
                            try:
                                await self.rotation_service.emergency_revoke_key(
                                    user_id=uuid.UUID(request.user_id),
                                    api_key_id=key.id,
                                    reason=f"Critical security incident: {incident_id}"
                                )
                            except Exception:
                                pass  # Continue with other keys
            
            # Add to critical incidents tracking
            critical_incident_data = {
                "incident_id": incident_id,
                "user_id": request.user_id,
                "threat_level": request.threat_level.value,
                "reason": request.reason.value,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "evidence": request.evidence
            }
            
            await redis_client.lpush(
                "critical_security_incidents",
                json.dumps(critical_incident_data)
            )
            
        except Exception as e:
            raise EmergencyRevocationError(f"Failed to trigger critical response: {str(e)}")
    
    async def _log_revocation_request(self, request: EmergencyRevocationRequest, incident_id: str):
        """Log the revocation request"""
        try:
            redis_client = await self._get_redis_client()
            
            log_entry = {
                "incident_id": incident_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request": asdict(request)
            }
            
            # Convert datetime objects to strings for JSON serialization
            log_entry["request"]["created_at"] = request.created_at.isoformat()
            log_entry["request"]["reason"] = request.reason.value
            log_entry["request"]["threat_level"] = request.threat_level.value
            
            await redis_client.lpush(
                self.REVOCATION_LOG_KEY,
                json.dumps(log_entry)
            )
            
            # Keep only last 1000 entries
            await redis_client.ltrim(self.REVOCATION_LOG_KEY, 0, 999)
            
        except Exception as e:
            # Don't fail the revocation if logging fails
            print(f"Failed to log revocation request: {str(e)}")
    
    async def _store_incident_details(self, request: EmergencyRevocationRequest, incident_id: str, actions_taken: List[str], errors: List[str]):
        """Store detailed incident information"""
        try:
            redis_client = await self._get_redis_client()
            
            incident_data = {
                "incident_id": incident_id,
                "request": asdict(request),
                "actions_taken": actions_taken,
                "errors": errors,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
                "status": "resolved" if not errors else "partial_failure"
            }
            
            # Convert datetime and enum objects for JSON serialization
            incident_data["request"]["created_at"] = request.created_at.isoformat()
            incident_data["request"]["reason"] = request.reason.value
            incident_data["request"]["threat_level"] = request.threat_level.value
            
            incident_key = self.INCIDENT_TRACKING_KEY.format(incident_id=incident_id)
            await redis_client.setex(
                incident_key,
                timedelta(days=90),  # Keep incident data for 90 days
                json.dumps(incident_data)
            )
            
        except Exception as e:
            # Don't fail the revocation if incident storage fails
            print(f"Failed to store incident details: {str(e)}")
    
    async def get_revocation_history(self, user_id: Optional[uuid.UUID] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get revocation history
        
        Args:
            user_id: Optional user ID filter
            limit: Maximum number of entries to return
            
        Returns:
            List of revocation history entries
        """
        try:
            redis_client = await self._get_redis_client()
            
            # Get revocation log entries
            log_entries = await redis_client.lrange(self.REVOCATION_LOG_KEY, 0, limit - 1)
            
            history = []
            for entry_json in log_entries:
                try:
                    entry = json.loads(entry_json)
                    
                    # Filter by user if specified
                    if user_id and entry["request"]["user_id"] != str(user_id):
                        continue
                    
                    history.append(entry)
                except Exception:
                    continue  # Skip malformed entries
            
            return history
            
        except Exception as e:
            raise EmergencyRevocationError(f"Failed to get revocation history: {str(e)}")
    
    async def is_key_blocked(self, api_key_id: uuid.UUID) -> bool:
        """
        Check if an API key is currently blocked
        
        Args:
            api_key_id: API key ID to check
            
        Returns:
            True if key is blocked, False otherwise
        """
        try:
            redis_client = await self._get_redis_client()
            
            # Check blocked keys set
            blocked_keys = await redis_client.smembers(self.BLOCKED_KEYS_KEY)
            
            for blocked_key_json in blocked_keys:
                try:
                    blocked_key_data = json.loads(blocked_key_json)
                    if blocked_key_data["key_id"] == str(api_key_id):
                        return True
                except Exception:
                    continue
            
            return False
            
        except Exception:
            # If we can't check, assume not blocked to avoid false positives
            return False


# Global instance
_emergency_revocation_service = None

def get_emergency_revocation_service() -> EmergencyRevocationService:
    """Get global emergency revocation service instance"""
    global _emergency_revocation_service
    if _emergency_revocation_service is None:
        _emergency_revocation_service = EmergencyRevocationService()
    return _emergency_revocation_service
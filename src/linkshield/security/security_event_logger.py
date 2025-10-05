#!/usr/bin/env python3
"""
Security Event Logging System

Provides comprehensive security event logging with real-time alerting,
structured logging, and security incident tracking capabilities.
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
import asyncio
import logging
from pathlib import Path

import redis.asyncio as redis
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert, update, and_, or_, desc
from sqlalchemy.orm import selectinload

from linkshield.config.settings import get_settings
from linkshield.config.database import get_db_session
from linkshield.models.user import User
from linkshield.services.notification_service import NotificationService


class SecurityEventType(Enum):
    """Security event type enumeration"""
    # Authentication Events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_CHALLENGE_SUCCESS = "mfa_challenge_success"
    MFA_CHALLENGE_FAILURE = "mfa_challenge_failure"
    
    # API Key Events
    API_KEY_CREATED = "api_key_created"
    API_KEY_ROTATED = "api_key_rotated"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_EMERGENCY_REVOKED = "api_key_emergency_revoked"
    API_KEY_USAGE = "api_key_usage"
    API_KEY_INVALID = "api_key_invalid"
    
    # Session Events
    SESSION_CREATED = "session_created"
    SESSION_EXPIRED = "session_expired"
    SESSION_HIJACKING_DETECTED = "session_hijacking_detected"
    SESSION_ANOMALY = "session_anomaly"
    DEVICE_FINGERPRINT_MISMATCH = "device_fingerprint_mismatch"
    
    # Access Control Events
    AUTHORIZATION_SUCCESS = "authorization_success"
    AUTHORIZATION_FAILURE = "authorization_failure"
    PERMISSION_DENIED = "permission_denied"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    
    # Security Incidents
    BRUTE_FORCE_ATTACK = "brute_force_attack"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    MALICIOUS_REQUEST = "malicious_request"
    DATA_BREACH_ATTEMPT = "data_breach_attempt"
    
    # System Events
    SECURITY_CONFIG_CHANGE = "security_config_change"
    SECURITY_POLICY_VIOLATION = "security_policy_violation"
    COMPLIANCE_VIOLATION = "compliance_violation"
    AUDIT_LOG_ACCESS = "audit_log_access"


class SecurityEventSeverity(Enum):
    """Security event severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityEventStatus(Enum):
    """Security event status"""
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class SecurityEventContext:
    """Security event context information"""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    api_key_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    geolocation: Optional[Dict[str, Any]] = None
    device_fingerprint: Optional[Dict[str, Any]] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_id: str
    event_type: SecurityEventType
    severity: SecurityEventSeverity
    timestamp: datetime
    message: str
    context: SecurityEventContext
    status: SecurityEventStatus = SecurityEventStatus.ACTIVE
    tags: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None
    source_system: str = "linkshield_backend"
    
    def __post_init__(self):
        """Post-initialization processing"""
        if isinstance(self.event_type, str):
            self.event_type = SecurityEventType(self.event_type)
        if isinstance(self.severity, str):
            self.severity = SecurityEventSeverity(self.severity)
        if isinstance(self.status, str):
            self.status = SecurityEventStatus(self.status)


class SecurityEventLoggerError(Exception):
    """Security event logger specific errors"""
    pass


class SecurityEventLogger:
    """
    Security Event Logger
    
    Provides comprehensive security event logging with structured data,
    real-time alerting, and incident correlation capabilities.
    """
    
    def __init__(self, redis_client: Optional[Redis] = None):
        """Initialize the security event logger"""
        self.settings = get_settings()
        self.redis_client = redis_client
        self.notification_service = NotificationService()
        
        # Configure structured logging
        self._setup_structured_logging()
        
        # Redis keys for event storage and alerting
        self.EVENTS_STREAM_KEY = "security_events:stream"
        self.EVENTS_INDEX_KEY = "security_events:index:{event_type}"
        self.ALERTS_QUEUE_KEY = "security_alerts:queue"
        self.CORRELATION_KEY = "security_events:correlation:{correlation_id}"
        self.METRICS_KEY = "security_events:metrics"
        self.INCIDENT_TRACKING_KEY = "security_incidents:{incident_id}"
        
        # Alert thresholds
        self.alert_thresholds = {
            SecurityEventType.LOGIN_FAILURE: {"count": 5, "window": 300},  # 5 failures in 5 minutes
            SecurityEventType.API_KEY_INVALID: {"count": 10, "window": 300},  # 10 invalid attempts in 5 minutes
            SecurityEventType.RATE_LIMIT_EXCEEDED: {"count": 3, "window": 600},  # 3 rate limit hits in 10 minutes
            SecurityEventType.SESSION_HIJACKING_DETECTED: {"count": 1, "window": 0},  # Immediate alert
            SecurityEventType.BRUTE_FORCE_ATTACK: {"count": 1, "window": 0},  # Immediate alert
            SecurityEventType.DATA_BREACH_ATTEMPT: {"count": 1, "window": 0},  # Immediate alert
        }
        
        # Severity-based alert rules
        self.severity_alert_rules = {
            SecurityEventSeverity.CRITICAL: {"immediate": True, "notify_admin": True},
            SecurityEventSeverity.HIGH: {"immediate": True, "notify_admin": True},
            SecurityEventSeverity.MEDIUM: {"immediate": False, "notify_admin": False},
            SecurityEventSeverity.LOW: {"immediate": False, "notify_admin": False},
            SecurityEventSeverity.INFO: {"immediate": False, "notify_admin": False},
        }
    
    def _setup_structured_logging(self):
        """Setup structured logging configuration"""
        # Create security events logger
        self.logger = logging.getLogger("security_events")
        self.logger.setLevel(logging.INFO)
        
        # Create file handler for security events
        log_dir = Path(self.settings.LOG_DIR) if hasattr(self.settings, 'LOG_DIR') else Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        security_log_file = log_dir / "security_events.log"
        file_handler = logging.FileHandler(security_log_file)
        file_handler.setLevel(logging.INFO)
        
        # Create JSON formatter for structured logging
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": %(message)s}'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler if not already added
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
    
    async def _get_redis_client(self) -> Redis:
        """Get Redis client instance"""
        if not self.redis_client:
            self.redis_client = redis.from_url(
                self.settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
        return self.redis_client
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        random_suffix = str(uuid.uuid4())[:8]
        return f"SEC-{timestamp}-{random_suffix}"
    
    async def log_event(
        self,
        event_type: SecurityEventType,
        severity: SecurityEventSeverity,
        message: str,
        context: SecurityEventContext,
        correlation_id: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> str:
        """
        Log a security event
        
        Args:
            event_type: Type of security event
            severity: Event severity level
            message: Human-readable event message
            context: Event context information
            correlation_id: Optional correlation ID for related events
            tags: Optional tags for categorization
            
        Returns:
            Event ID
        """
        try:
            # Create security event
            event = SecurityEvent(
                event_id=self._generate_event_id(),
                event_type=event_type,
                severity=severity,
                timestamp=datetime.now(timezone.utc),
                message=message,
                context=context,
                correlation_id=correlation_id,
                tags=tags or []
            )
            
            # Store event in Redis stream
            await self._store_event_in_stream(event)
            
            # Index event for fast retrieval
            await self._index_event(event)
            
            # Update metrics
            await self._update_metrics(event)
            
            # Log to structured file
            await self._log_to_file(event)
            
            # Check for alert conditions
            await self._check_alert_conditions(event)
            
            # Handle correlation if provided
            if correlation_id:
                await self._handle_event_correlation(event)
            
            return event.event_id
            
        except Exception as e:
            raise SecurityEventLoggerError(f"Failed to log security event: {str(e)}")
    
    async def _store_event_in_stream(self, event: SecurityEvent):
        """Store event in Redis stream for real-time processing"""
        try:
            redis_client = await self._get_redis_client()
            
            # Convert event to dictionary for storage
            event_data = {
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "severity": event.severity.value,
                "timestamp": event.timestamp.isoformat(),
                "message": event.message,
                "context": json.dumps(asdict(event.context)),
                "status": event.status.value,
                "tags": json.dumps(event.tags),
                "correlation_id": event.correlation_id or "",
                "source_system": event.source_system
            }
            
            # Add to Redis stream
            await redis_client.xadd(self.EVENTS_STREAM_KEY, event_data)
            
            # Trim stream to keep last 10000 events
            await redis_client.xtrim(self.EVENTS_STREAM_KEY, maxlen=10000, approximate=True)
            
        except Exception as e:
            raise SecurityEventLoggerError(f"Failed to store event in stream: {str(e)}")
    
    async def _index_event(self, event: SecurityEvent):
        """Index event for fast retrieval by type"""
        try:
            redis_client = await self._get_redis_client()
            
            # Index by event type
            index_key = self.EVENTS_INDEX_KEY.format(event_type=event.event_type.value)
            event_summary = {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "severity": event.severity.value,
                "user_id": event.context.user_id or "",
                "ip_address": event.context.ip_address or ""
            }
            
            await redis_client.zadd(
                index_key,
                {json.dumps(event_summary): event.timestamp.timestamp()}
            )
            
            # Keep only last 1000 events per type
            await redis_client.zremrangebyrank(index_key, 0, -1001)
            
        except Exception as e:
            # Don't fail event logging if indexing fails
            print(f"Failed to index event: {str(e)}")
    
    async def _update_metrics(self, event: SecurityEvent):
        """Update security event metrics"""
        try:
            redis_client = await self._get_redis_client()
            
            # Update counters
            current_hour = datetime.now(timezone.utc).strftime("%Y%m%d%H")
            
            # Total events
            await redis_client.hincrby(self.METRICS_KEY, f"total_events:{current_hour}", 1)
            
            # Events by type
            await redis_client.hincrby(
                self.METRICS_KEY,
                f"events_by_type:{event.event_type.value}:{current_hour}",
                1
            )
            
            # Events by severity
            await redis_client.hincrby(
                self.METRICS_KEY,
                f"events_by_severity:{event.severity.value}:{current_hour}",
                1
            )
            
            # Events by user (if available)
            if event.context.user_id:
                await redis_client.hincrby(
                    self.METRICS_KEY,
                    f"events_by_user:{event.context.user_id}:{current_hour}",
                    1
                )
            
        except Exception as e:
            # Don't fail event logging if metrics update fails
            print(f"Failed to update metrics: {str(e)}")
    
    async def _log_to_file(self, event: SecurityEvent):
        """Log event to structured file"""
        try:
            # Create structured log entry
            log_entry = {
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "severity": event.severity.value,
                "timestamp": event.timestamp.isoformat(),
                "message": event.message,
                "context": asdict(event.context),
                "status": event.status.value,
                "tags": event.tags,
                "correlation_id": event.correlation_id,
                "source_system": event.source_system
            }
            
            # Log as JSON
            self.logger.info(json.dumps(log_entry))
            
        except Exception as e:
            # Don't fail event logging if file logging fails
            print(f"Failed to log to file: {str(e)}")
    
    async def _check_alert_conditions(self, event: SecurityEvent):
        """Check if event triggers alert conditions"""
        try:
            # Check severity-based alerts
            severity_rule = self.severity_alert_rules.get(event.severity)
            if severity_rule and severity_rule["immediate"]:
                await self._trigger_immediate_alert(event)
            
            # Check threshold-based alerts
            threshold = self.alert_thresholds.get(event.event_type)
            if threshold:
                await self._check_threshold_alert(event, threshold)
            
        except Exception as e:
            # Don't fail event logging if alerting fails
            print(f"Failed to check alert conditions: {str(e)}")
    
    async def _trigger_immediate_alert(self, event: SecurityEvent):
        """Trigger immediate alert for critical events"""
        try:
            redis_client = await self._get_redis_client()
            
            alert_data = {
                "alert_id": f"ALERT-{event.event_id}",
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "severity": event.severity.value,
                "timestamp": event.timestamp.isoformat(),
                "message": event.message,
                "context": asdict(event.context),
                "alert_type": "immediate",
                "triggered_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Add to alerts queue
            await redis_client.lpush(self.ALERTS_QUEUE_KEY, json.dumps(alert_data))
            
            # Send notification if configured
            severity_rule = self.severity_alert_rules.get(event.severity)
            if severity_rule and severity_rule["notify_admin"]:
                await self._send_admin_alert(event, alert_data)
            
        except Exception as e:
            print(f"Failed to trigger immediate alert: {str(e)}")
    
    async def _check_threshold_alert(self, event: SecurityEvent, threshold: Dict[str, int]):
        """Check if event exceeds threshold for alerting"""
        try:
            redis_client = await self._get_redis_client()
            
            # Count recent events of this type
            window_start = datetime.now(timezone.utc) - timedelta(seconds=threshold["window"])
            
            # Use user_id or ip_address as grouping key
            grouping_key = event.context.user_id or event.context.ip_address or "unknown"
            counter_key = f"event_counter:{event.event_type.value}:{grouping_key}"
            
            # Increment counter with expiration
            current_count = await redis_client.incr(counter_key)
            if current_count == 1:  # First occurrence, set expiration
                await redis_client.expire(counter_key, threshold["window"])
            
            # Check if threshold exceeded
            if current_count >= threshold["count"]:
                await self._trigger_threshold_alert(event, current_count, threshold)
            
        except Exception as e:
            print(f"Failed to check threshold alert: {str(e)}")
    
    async def _trigger_threshold_alert(self, event: SecurityEvent, count: int, threshold: Dict[str, int]):
        """Trigger threshold-based alert"""
        try:
            redis_client = await self._get_redis_client()
            
            alert_data = {
                "alert_id": f"THRESHOLD-{event.event_id}",
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "severity": "high",  # Threshold alerts are always high severity
                "timestamp": event.timestamp.isoformat(),
                "message": f"Threshold exceeded: {count} occurrences of {event.event_type.value} in {threshold['window']} seconds",
                "context": asdict(event.context),
                "alert_type": "threshold",
                "threshold_count": threshold["count"],
                "actual_count": count,
                "window_seconds": threshold["window"],
                "triggered_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Add to alerts queue
            await redis_client.lpush(self.ALERTS_QUEUE_KEY, json.dumps(alert_data))
            
            # Send admin notification for threshold alerts
            await self._send_admin_alert(event, alert_data)
            
        except Exception as e:
            print(f"Failed to trigger threshold alert: {str(e)}")
    
    async def _send_admin_alert(self, event: SecurityEvent, alert_data: Dict[str, Any]):
        """Send alert notification to administrators"""
        try:
            await self.notification_service.send_security_alert(
                alert_id=alert_data["alert_id"],
                event_type=event.event_type.value,
                severity=alert_data["severity"],
                message=alert_data["message"],
                context=event.context,
                timestamp=event.timestamp
            )
        except Exception as e:
            print(f"Failed to send admin alert: {str(e)}")
    
    async def _handle_event_correlation(self, event: SecurityEvent):
        """Handle event correlation for incident tracking"""
        try:
            if not event.correlation_id:
                return
            
            redis_client = await self._get_redis_client()
            correlation_key = self.CORRELATION_KEY.format(correlation_id=event.correlation_id)
            
            # Add event to correlation group
            correlation_data = {
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "severity": event.severity.value,
                "timestamp": event.timestamp.isoformat(),
                "user_id": event.context.user_id or "",
                "ip_address": event.context.ip_address or ""
            }
            
            await redis_client.lpush(correlation_key, json.dumps(correlation_data))
            await redis_client.expire(correlation_key, timedelta(days=7))  # Keep correlations for 7 days
            
        except Exception as e:
            print(f"Failed to handle event correlation: {str(e)}")
    
    async def get_events(
        self,
        event_type: Optional[SecurityEventType] = None,
        severity: Optional[SecurityEventSeverity] = None,
        user_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieve security events with filtering
        
        Args:
            event_type: Filter by event type
            severity: Filter by severity level
            user_id: Filter by user ID
            start_time: Filter events after this time
            end_time: Filter events before this time
            limit: Maximum number of events to return
            
        Returns:
            List of security events
        """
        try:
            redis_client = await self._get_redis_client()
            
            # Read from Redis stream
            if event_type:
                # Use indexed data for specific event types
                index_key = self.EVENTS_INDEX_KEY.format(event_type=event_type.value)
                
                # Calculate score range for time filtering
                start_score = start_time.timestamp() if start_time else 0
                end_score = end_time.timestamp() if end_time else datetime.now(timezone.utc).timestamp()
                
                # Get events from sorted set
                event_summaries = await redis_client.zrangebyscore(
                    index_key, start_score, end_score, withscores=True
                )
                
                events = []
                for event_json, score in event_summaries[:limit]:
                    try:
                        event_summary = json.loads(event_json)
                        
                        # Apply additional filters
                        if severity and event_summary.get("severity") != severity.value:
                            continue
                        if user_id and event_summary.get("user_id") != user_id:
                            continue
                        
                        events.append(event_summary)
                    except Exception:
                        continue
                
                return events
            else:
                # Read from main stream
                stream_data = await redis_client.xrevrange(self.EVENTS_STREAM_KEY, count=limit)
                
                events = []
                for stream_id, fields in stream_data:
                    try:
                        # Apply filters
                        if severity and fields.get("severity") != severity.value:
                            continue
                        if user_id:
                            context = json.loads(fields.get("context", "{}"))
                            if context.get("user_id") != user_id:
                                continue
                        
                        # Parse timestamp for time filtering
                        event_time = datetime.fromisoformat(fields["timestamp"])
                        if start_time and event_time < start_time:
                            continue
                        if end_time and event_time > end_time:
                            continue
                        
                        # Convert fields to proper format
                        event_data = dict(fields)
                        event_data["context"] = json.loads(event_data.get("context", "{}"))
                        event_data["tags"] = json.loads(event_data.get("tags", "[]"))
                        
                        events.append(event_data)
                    except Exception:
                        continue
                
                return events
            
        except Exception as e:
            raise SecurityEventLoggerError(f"Failed to retrieve events: {str(e)}")
    
    async def get_security_metrics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get security metrics for the specified time period
        
        Args:
            hours: Number of hours to include in metrics
            
        Returns:
            Security metrics dictionary
        """
        try:
            redis_client = await self._get_redis_client()
            
            metrics = {
                "total_events": 0,
                "events_by_type": {},
                "events_by_severity": {},
                "events_by_hour": {},
                "top_users": {},
                "alert_count": 0
            }
            
            # Calculate time range
            current_time = datetime.now(timezone.utc)
            
            for hour_offset in range(hours):
                hour_key = (current_time - timedelta(hours=hour_offset)).strftime("%Y%m%d%H")
                
                # Get total events for this hour
                total_key = f"total_events:{hour_key}"
                hour_total = await redis_client.hget(self.METRICS_KEY, total_key)
                if hour_total:
                    hour_total = int(hour_total)
                    metrics["total_events"] += hour_total
                    metrics["events_by_hour"][hour_key] = hour_total
            
            # Get all metrics for the time period
            all_metrics = await redis_client.hgetall(self.METRICS_KEY)
            
            for key, value in all_metrics.items():
                try:
                    value = int(value)
                    
                    if key.startswith("events_by_type:"):
                        event_type = key.split(":")[1]
                        metrics["events_by_type"][event_type] = metrics["events_by_type"].get(event_type, 0) + value
                    
                    elif key.startswith("events_by_severity:"):
                        severity = key.split(":")[1]
                        metrics["events_by_severity"][severity] = metrics["events_by_severity"].get(severity, 0) + value
                    
                    elif key.startswith("events_by_user:"):
                        user_id = key.split(":")[1]
                        metrics["top_users"][user_id] = metrics["top_users"].get(user_id, 0) + value
                
                except Exception:
                    continue
            
            # Get alert count
            alert_count = await redis_client.llen(self.ALERTS_QUEUE_KEY)
            metrics["alert_count"] = alert_count
            
            # Sort top users
            metrics["top_users"] = dict(
                sorted(metrics["top_users"].items(), key=lambda x: x[1], reverse=True)[:10]
            )
            
            return metrics
            
        except Exception as e:
            raise SecurityEventLoggerError(f"Failed to get security metrics: {str(e)}")
    
    async def get_pending_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get pending security alerts
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of pending alerts
        """
        try:
            redis_client = await self._get_redis_client()
            
            # Get alerts from queue
            alert_data = await redis_client.lrange(self.ALERTS_QUEUE_KEY, 0, limit - 1)
            
            alerts = []
            for alert_json in alert_data:
                try:
                    alert = json.loads(alert_json)
                    alerts.append(alert)
                except Exception:
                    continue
            
            return alerts
            
        except Exception as e:
            raise SecurityEventLoggerError(f"Failed to get pending alerts: {str(e)}")


# Convenience functions for common security events
async def log_authentication_event(
    event_type: SecurityEventType,
    user_id: Optional[str],
    success: bool,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    additional_context: Optional[Dict[str, Any]] = None
) -> str:
    """Log authentication-related security event"""
    logger = get_security_event_logger()
    
    severity = SecurityEventSeverity.INFO if success else SecurityEventSeverity.MEDIUM
    message = f"Authentication {'successful' if success else 'failed'} for user {user_id or 'unknown'}"
    
    context = SecurityEventContext(
        user_id=user_id,
        ip_address=ip_address,
        user_agent=user_agent,
        additional_data=additional_context or {}
    )
    
    return await logger.log_event(event_type, severity, message, context)


async def log_api_key_event(
    event_type: SecurityEventType,
    user_id: str,
    api_key_id: str,
    action: str,
    ip_address: Optional[str] = None,
    additional_context: Optional[Dict[str, Any]] = None
) -> str:
    """Log API key-related security event"""
    logger = get_security_event_logger()
    
    severity = SecurityEventSeverity.MEDIUM if "revoked" in action else SecurityEventSeverity.INFO
    message = f"API key {action} for user {user_id}"
    
    context = SecurityEventContext(
        user_id=user_id,
        api_key_id=api_key_id,
        ip_address=ip_address,
        additional_data=additional_context or {}
    )
    
    return await logger.log_event(event_type, severity, message, context)


async def log_security_incident(
    incident_type: SecurityEventType,
    severity: SecurityEventSeverity,
    description: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    evidence: Optional[Dict[str, Any]] = None
) -> str:
    """Log security incident"""
    logger = get_security_event_logger()
    
    context = SecurityEventContext(
        user_id=user_id,
        ip_address=ip_address,
        additional_data=evidence or {}
    )
    
    return await logger.log_event(incident_type, severity, description, context)


# Global instance
_security_event_logger = None

def get_security_event_logger() -> SecurityEventLogger:
    """Get global security event logger instance"""
    global _security_event_logger
    if _security_event_logger is None:
        _security_event_logger = SecurityEventLogger()
    return _security_event_logger
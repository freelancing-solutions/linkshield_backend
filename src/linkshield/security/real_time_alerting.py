#!/usr/bin/env python3
"""
Real-Time Security Alerting System

Provides real-time alerting capabilities for security incidents with
multiple notification channels, escalation policies, and alert management.
"""

import json
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Callable, Set
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

import redis.asyncio as redis
from redis.asyncio import Redis

from linkshield.config.settings import get_settings
from linkshield.services.notification_service import NotificationService
from linkshield.security.security_event_logger import SecurityEvent, SecurityEventType, SecurityEventSeverity


class AlertChannel(Enum):
    """Alert notification channels"""
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    WEBHOOK = "webhook"
    PUSH_NOTIFICATION = "push_notification"
    DASHBOARD = "dashboard"


class AlertPriority(Enum):
    """Alert priority levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AlertStatus(Enum):
    """Alert status"""
    PENDING = "pending"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    SUPPRESSED = "suppressed"


@dataclass
class AlertRule:
    """Alert rule configuration"""
    rule_id: str
    name: str
    description: str
    event_types: List[SecurityEventType]
    severity_threshold: SecurityEventSeverity
    conditions: Dict[str, Any]
    channels: List[AlertChannel]
    priority: AlertPriority
    escalation_timeout: int  # seconds
    suppression_window: int  # seconds
    enabled: bool = True
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


@dataclass
class AlertRecipient:
    """Alert recipient configuration"""
    recipient_id: str
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    slack_user_id: Optional[str] = None
    webhook_url: Optional[str] = None
    channels: List[AlertChannel] = None
    escalation_level: int = 1
    active_hours: Optional[Dict[str, Any]] = None  # {"start": "09:00", "end": "17:00", "timezone": "UTC"}
    
    def __post_init__(self):
        if self.channels is None:
            self.channels = [AlertChannel.EMAIL]


@dataclass
class SecurityAlert:
    """Security alert data structure"""
    alert_id: str
    rule_id: str
    event_id: str
    event_type: SecurityEventType
    severity: SecurityEventSeverity
    priority: AlertPriority
    title: str
    message: str
    context: Dict[str, Any]
    channels: List[AlertChannel]
    recipients: List[str]  # recipient IDs
    status: AlertStatus
    created_at: datetime
    sent_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    escalation_level: int = 1
    suppressed_until: Optional[datetime] = None
    correlation_id: Optional[str] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class RealTimeAlertingError(Exception):
    """Real-time alerting specific errors"""
    pass


class RealTimeAlertingService:
    """
    Real-Time Alerting Service
    
    Provides comprehensive real-time alerting for security events with
    configurable rules, multiple notification channels, and escalation policies.
    """
    
    def __init__(self, redis_client: Optional[Redis] = None):
        """Initialize the real-time alerting service"""
        self.settings = get_settings()
        self.redis_client = redis_client
        self.notification_service = NotificationService()
        
        # Redis keys
        self.ALERT_RULES_KEY = "security_alerts:rules"
        self.ALERT_RECIPIENTS_KEY = "security_alerts:recipients"
        self.ACTIVE_ALERTS_KEY = "security_alerts:active"
        self.ALERT_HISTORY_KEY = "security_alerts:history"
        self.SUPPRESSION_KEY = "security_alerts:suppression:{rule_id}"
        self.ESCALATION_QUEUE_KEY = "security_alerts:escalation_queue"
        self.ALERT_METRICS_KEY = "security_alerts:metrics"
        
        # Alert processing
        self._alert_processors: Dict[AlertChannel, Callable] = {}
        self._setup_alert_processors()
        
        # Background tasks
        self._running = False
        self._escalation_task = None
        self._cleanup_task = None
        
        # Default alert rules
        self._default_rules = self._create_default_alert_rules()
        
        # Default recipients (admin users)
        self._default_recipients = self._create_default_recipients()
    
    def _setup_alert_processors(self):
        """Setup alert processors for different channels"""
        self._alert_processors = {
            AlertChannel.EMAIL: self._send_email_alert,
            AlertChannel.SMS: self._send_sms_alert,
            AlertChannel.SLACK: self._send_slack_alert,
            AlertChannel.WEBHOOK: self._send_webhook_alert,
            AlertChannel.PUSH_NOTIFICATION: self._send_push_notification,
            AlertChannel.DASHBOARD: self._send_dashboard_alert,
        }
    
    def _create_default_alert_rules(self) -> List[AlertRule]:
        """Create default alert rules"""
        return [
            AlertRule(
                rule_id="critical_security_events",
                name="Critical Security Events",
                description="Immediate alerts for critical security events",
                event_types=[
                    SecurityEventType.SESSION_HIJACKING_DETECTED,
                    SecurityEventType.BRUTE_FORCE_ATTACK,
                    SecurityEventType.DATA_BREACH_ATTEMPT,
                    SecurityEventType.API_KEY_EMERGENCY_REVOKED
                ],
                severity_threshold=SecurityEventSeverity.CRITICAL,
                conditions={"immediate": True},
                channels=[AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.SLACK],
                priority=AlertPriority.EMERGENCY,
                escalation_timeout=300,  # 5 minutes
                suppression_window=0,  # No suppression for critical events
                tags=["security", "critical"]
            ),
            AlertRule(
                rule_id="authentication_failures",
                name="Authentication Failures",
                description="Alert on repeated authentication failures",
                event_types=[SecurityEventType.LOGIN_FAILURE, SecurityEventType.MFA_CHALLENGE_FAILURE],
                severity_threshold=SecurityEventSeverity.MEDIUM,
                conditions={"threshold": 5, "window": 300},  # 5 failures in 5 minutes
                channels=[AlertChannel.EMAIL, AlertChannel.DASHBOARD],
                priority=AlertPriority.HIGH,
                escalation_timeout=900,  # 15 minutes
                suppression_window=600,  # 10 minutes
                tags=["authentication", "security"]
            ),
            AlertRule(
                rule_id="api_key_security",
                name="API Key Security Events",
                description="Alert on API key security events",
                event_types=[
                    SecurityEventType.API_KEY_INVALID,
                    SecurityEventType.API_KEY_REVOKED,
                    SecurityEventType.API_KEY_EMERGENCY_REVOKED
                ],
                severity_threshold=SecurityEventSeverity.MEDIUM,
                conditions={"threshold": 10, "window": 300},  # 10 invalid attempts in 5 minutes
                channels=[AlertChannel.EMAIL, AlertChannel.SLACK],
                priority=AlertPriority.HIGH,
                escalation_timeout=600,  # 10 minutes
                suppression_window=300,  # 5 minutes
                tags=["api_key", "security"]
            ),
            AlertRule(
                rule_id="rate_limiting",
                name="Rate Limiting Violations",
                description="Alert on rate limiting violations",
                event_types=[SecurityEventType.RATE_LIMIT_EXCEEDED],
                severity_threshold=SecurityEventSeverity.MEDIUM,
                conditions={"threshold": 3, "window": 600},  # 3 violations in 10 minutes
                channels=[AlertChannel.EMAIL, AlertChannel.DASHBOARD],
                priority=AlertPriority.MEDIUM,
                escalation_timeout=1800,  # 30 minutes
                suppression_window=900,  # 15 minutes
                tags=["rate_limiting", "security"]
            ),
            AlertRule(
                rule_id="compliance_violations",
                name="Compliance Violations",
                description="Alert on security compliance violations",
                event_types=[
                    SecurityEventType.COMPLIANCE_VIOLATION,
                    SecurityEventType.SECURITY_POLICY_VIOLATION
                ],
                severity_threshold=SecurityEventSeverity.HIGH,
                conditions={"immediate": True},
                channels=[AlertChannel.EMAIL, AlertChannel.WEBHOOK],
                priority=AlertPriority.HIGH,
                escalation_timeout=600,  # 10 minutes
                suppression_window=300,  # 5 minutes
                tags=["compliance", "policy"]
            )
        ]
    
    def _create_default_recipients(self) -> List[AlertRecipient]:
        """Create default alert recipients"""
        return [
            AlertRecipient(
                recipient_id="security_admin",
                name="Security Administrator",
                email="security@linkshield.com",
                phone="+1234567890",
                channels=[AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.SLACK],
                escalation_level=1,
                active_hours={"start": "00:00", "end": "23:59", "timezone": "UTC"}
            ),
            AlertRecipient(
                recipient_id="system_admin",
                name="System Administrator",
                email="admin@linkshield.com",
                channels=[AlertChannel.EMAIL, AlertChannel.DASHBOARD],
                escalation_level=2,
                active_hours={"start": "09:00", "end": "17:00", "timezone": "UTC"}
            ),
            AlertRecipient(
                recipient_id="on_call_engineer",
                name="On-Call Engineer",
                email="oncall@linkshield.com",
                phone="+1234567891",
                slack_user_id="U1234567890",
                channels=[AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.SLACK],
                escalation_level=1,
                active_hours={"start": "00:00", "end": "23:59", "timezone": "UTC"}
            )
        ]
    
    async def _get_redis_client(self) -> Redis:
        """Get Redis client instance"""
        if not self.redis_client:
            self.redis_client = redis.from_url(
                self.settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
        return self.redis_client
    
    async def start(self):
        """Start the real-time alerting service"""
        if self._running:
            return
        
        self._running = True
        
        # Initialize default rules and recipients
        await self._initialize_defaults()
        
        # Start background tasks
        self._escalation_task = asyncio.create_task(self._escalation_processor())
        self._cleanup_task = asyncio.create_task(self._cleanup_processor())
        
        print("Real-time alerting service started")
    
    async def stop(self):
        """Stop the real-time alerting service"""
        self._running = False
        
        # Cancel background tasks
        if self._escalation_task:
            self._escalation_task.cancel()
        if self._cleanup_task:
            self._cleanup_task.cancel()
        
        print("Real-time alerting service stopped")
    
    async def _initialize_defaults(self):
        """Initialize default alert rules and recipients"""
        try:
            redis_client = await self._get_redis_client()
            
            # Check if rules already exist
            existing_rules = await redis_client.hlen(self.ALERT_RULES_KEY)
            if existing_rules == 0:
                # Add default rules
                for rule in self._default_rules:
                    await self.add_alert_rule(rule)
            
            # Check if recipients already exist
            existing_recipients = await redis_client.hlen(self.ALERT_RECIPIENTS_KEY)
            if existing_recipients == 0:
                # Add default recipients
                for recipient in self._default_recipients:
                    await self.add_alert_recipient(recipient)
            
        except Exception as e:
            print(f"Failed to initialize defaults: {str(e)}")
    
    async def process_security_event(self, event: SecurityEvent) -> List[str]:
        """
        Process security event and generate alerts if rules match
        
        Args:
            event: Security event to process
            
        Returns:
            List of alert IDs generated
        """
        try:
            alert_ids = []
            
            # Get all alert rules
            rules = await self.get_alert_rules()
            
            for rule in rules:
                if not rule.enabled:
                    continue
                
                # Check if event matches rule
                if await self._event_matches_rule(event, rule):
                    # Check suppression
                    if await self._is_suppressed(rule.rule_id, event):
                        continue
                    
                    # Generate alert
                    alert_id = await self._generate_alert(event, rule)
                    if alert_id:
                        alert_ids.append(alert_id)
            
            return alert_ids
            
        except Exception as e:
            raise RealTimeAlertingError(f"Failed to process security event: {str(e)}")
    
    async def _event_matches_rule(self, event: SecurityEvent, rule: AlertRule) -> bool:
        """Check if security event matches alert rule"""
        try:
            # Check event type
            if event.event_type not in rule.event_types:
                return False
            
            # Check severity threshold
            severity_levels = {
                SecurityEventSeverity.INFO: 1,
                SecurityEventSeverity.LOW: 2,
                SecurityEventSeverity.MEDIUM: 3,
                SecurityEventSeverity.HIGH: 4,
                SecurityEventSeverity.CRITICAL: 5
            }
            
            if severity_levels[event.severity] < severity_levels[rule.severity_threshold]:
                return False
            
            # Check additional conditions
            conditions = rule.conditions
            
            # Immediate condition
            if conditions.get("immediate"):
                return True
            
            # Threshold condition
            if "threshold" in conditions and "window" in conditions:
                return await self._check_threshold_condition(event, rule, conditions)
            
            return True
            
        except Exception as e:
            print(f"Failed to check event rule match: {str(e)}")
            return False
    
    async def _check_threshold_condition(
        self,
        event: SecurityEvent,
        rule: AlertRule,
        conditions: Dict[str, Any]
    ) -> bool:
        """Check threshold-based condition"""
        try:
            redis_client = await self._get_redis_client()
            
            threshold = conditions["threshold"]
            window = conditions["window"]
            
            # Create grouping key (user_id or ip_address)
            grouping_key = event.context.user_id or event.context.ip_address or "unknown"
            counter_key = f"alert_threshold:{rule.rule_id}:{event.event_type.value}:{grouping_key}"
            
            # Increment counter
            current_count = await redis_client.incr(counter_key)
            if current_count == 1:
                await redis_client.expire(counter_key, window)
            
            return current_count >= threshold
            
        except Exception as e:
            print(f"Failed to check threshold condition: {str(e)}")
            return False
    
    async def _is_suppressed(self, rule_id: str, event: SecurityEvent) -> bool:
        """Check if alert is suppressed"""
        try:
            redis_client = await self._get_redis_client()
            
            suppression_key = self.SUPPRESSION_KEY.format(rule_id=rule_id)
            
            # Check if suppression exists
            suppressed_until = await redis_client.get(suppression_key)
            if not suppressed_until:
                return False
            
            # Check if suppression is still active
            suppression_time = datetime.fromisoformat(suppressed_until)
            return datetime.now(timezone.utc) < suppression_time
            
        except Exception as e:
            print(f"Failed to check suppression: {str(e)}")
            return False
    
    async def _generate_alert(self, event: SecurityEvent, rule: AlertRule) -> Optional[str]:
        """Generate security alert"""
        try:
            # Create alert
            alert = SecurityAlert(
                alert_id=f"ALERT-{uuid.uuid4().hex[:8].upper()}",
                rule_id=rule.rule_id,
                event_id=event.event_id,
                event_type=event.event_type,
                severity=event.severity,
                priority=rule.priority,
                title=f"{rule.name}: {event.event_type.value}",
                message=self._format_alert_message(event, rule),
                context=asdict(event.context),
                channels=rule.channels,
                recipients=await self._get_rule_recipients(rule),
                status=AlertStatus.PENDING,
                created_at=datetime.now(timezone.utc),
                correlation_id=event.correlation_id,
                tags=rule.tags + event.tags
            )
            
            # Store alert
            await self._store_alert(alert)
            
            # Send alert immediately
            await self._send_alert(alert)
            
            # Set suppression if configured
            if rule.suppression_window > 0:
                await self._set_suppression(rule.rule_id, rule.suppression_window)
            
            # Schedule escalation if configured
            if rule.escalation_timeout > 0:
                await self._schedule_escalation(alert, rule.escalation_timeout)
            
            return alert.alert_id
            
        except Exception as e:
            print(f"Failed to generate alert: {str(e)}")
            return None
    
    def _format_alert_message(self, event: SecurityEvent, rule: AlertRule) -> str:
        """Format alert message"""
        message_parts = [
            f"Security Alert: {rule.name}",
            f"Event: {event.event_type.value}",
            f"Severity: {event.severity.value}",
            f"Time: {event.timestamp.isoformat()}",
            f"Description: {event.message}"
        ]
        
        # Add context information
        if event.context.user_id:
            message_parts.append(f"User: {event.context.user_id}")
        if event.context.ip_address:
            message_parts.append(f"IP Address: {event.context.ip_address}")
        if event.context.endpoint:
            message_parts.append(f"Endpoint: {event.context.endpoint}")
        
        return "\n".join(message_parts)
    
    async def _get_rule_recipients(self, rule: AlertRule) -> List[str]:
        """Get recipients for alert rule"""
        try:
            # For now, return all recipients that support the rule's channels
            recipients = await self.get_alert_recipients()
            
            matching_recipients = []
            for recipient in recipients:
                # Check if recipient supports any of the rule's channels
                if any(channel in recipient.channels for channel in rule.channels):
                    matching_recipients.append(recipient.recipient_id)
            
            return matching_recipients
            
        except Exception as e:
            print(f"Failed to get rule recipients: {str(e)}")
            return []
    
    async def _store_alert(self, alert: SecurityAlert):
        """Store alert in Redis"""
        try:
            redis_client = await self._get_redis_client()
            
            # Store in active alerts
            alert_data = asdict(alert)
            # Convert datetime objects to ISO strings
            for key, value in alert_data.items():
                if isinstance(value, datetime):
                    alert_data[key] = value.isoformat() if value else None
                elif isinstance(value, Enum):
                    alert_data[key] = value.value
            
            await redis_client.hset(
                self.ACTIVE_ALERTS_KEY,
                alert.alert_id,
                json.dumps(alert_data)
            )
            
            # Store in history with expiration (30 days)
            await redis_client.setex(
                f"{self.ALERT_HISTORY_KEY}:{alert.alert_id}",
                timedelta(days=30),
                json.dumps(alert_data)
            )
            
        except Exception as e:
            raise RealTimeAlertingError(f"Failed to store alert: {str(e)}")
    
    async def _send_alert(self, alert: SecurityAlert):
        """Send alert through configured channels"""
        try:
            # Get recipients
            recipients = await self.get_alert_recipients()
            recipient_map = {r.recipient_id: r for r in recipients}
            
            # Send to each channel
            for channel in alert.channels:
                processor = self._alert_processors.get(channel)
                if processor:
                    # Get recipients for this channel
                    channel_recipients = [
                        recipient_map[rid] for rid in alert.recipients
                        if rid in recipient_map and channel in recipient_map[rid].channels
                    ]
                    
                    if channel_recipients:
                        await processor(alert, channel_recipients)
            
            # Update alert status
            alert.status = AlertStatus.SENT
            alert.sent_at = datetime.now(timezone.utc)
            await self._update_alert_status(alert)
            
        except Exception as e:
            print(f"Failed to send alert: {str(e)}")
    
    async def _send_email_alert(self, alert: SecurityAlert, recipients: List[AlertRecipient]):
        """Send email alert"""
        try:
            email_recipients = [r.email for r in recipients if r.email]
            if email_recipients:
                await self.notification_service.send_security_alert_email(
                    recipients=email_recipients,
                    subject=alert.title,
                    message=alert.message,
                    alert_id=alert.alert_id,
                    severity=alert.severity.value,
                    priority=alert.priority.value
                )
        except Exception as e:
            print(f"Failed to send email alert: {str(e)}")
    
    async def _send_sms_alert(self, alert: SecurityAlert, recipients: List[AlertRecipient]):
        """Send SMS alert"""
        try:
            sms_recipients = [r.phone for r in recipients if r.phone]
            if sms_recipients:
                # Create short SMS message
                sms_message = f"SECURITY ALERT: {alert.title} - {alert.priority.value.upper()} priority. Alert ID: {alert.alert_id}"
                
                await self.notification_service.send_sms_alert(
                    recipients=sms_recipients,
                    message=sms_message
                )
        except Exception as e:
            print(f"Failed to send SMS alert: {str(e)}")
    
    async def _send_slack_alert(self, alert: SecurityAlert, recipients: List[AlertRecipient]):
        """Send Slack alert"""
        try:
            slack_recipients = [r.slack_user_id for r in recipients if r.slack_user_id]
            if slack_recipients:
                await self.notification_service.send_slack_alert(
                    recipients=slack_recipients,
                    title=alert.title,
                    message=alert.message,
                    alert_id=alert.alert_id,
                    severity=alert.severity.value,
                    priority=alert.priority.value
                )
        except Exception as e:
            print(f"Failed to send Slack alert: {str(e)}")
    
    async def _send_webhook_alert(self, alert: SecurityAlert, recipients: List[AlertRecipient]):
        """Send webhook alert"""
        try:
            webhook_urls = [r.webhook_url for r in recipients if r.webhook_url]
            if webhook_urls:
                webhook_payload = {
                    "alert_id": alert.alert_id,
                    "title": alert.title,
                    "message": alert.message,
                    "severity": alert.severity.value,
                    "priority": alert.priority.value,
                    "event_type": alert.event_type.value,
                    "timestamp": alert.created_at.isoformat(),
                    "context": alert.context
                }
                
                await self.notification_service.send_webhook_alert(
                    urls=webhook_urls,
                    payload=webhook_payload
                )
        except Exception as e:
            print(f"Failed to send webhook alert: {str(e)}")
    
    async def _send_push_notification(self, alert: SecurityAlert, recipients: List[AlertRecipient]):
        """Send push notification alert"""
        try:
            # Implementation depends on push notification service
            await self.notification_service.send_push_notification(
                recipients=[r.recipient_id for r in recipients],
                title=alert.title,
                message=alert.message,
                data={
                    "alert_id": alert.alert_id,
                    "severity": alert.severity.value,
                    "priority": alert.priority.value
                }
            )
        except Exception as e:
            print(f"Failed to send push notification: {str(e)}")
    
    async def _send_dashboard_alert(self, alert: SecurityAlert, recipients: List[AlertRecipient]):
        """Send dashboard alert (store for dashboard display)"""
        try:
            redis_client = await self._get_redis_client()
            
            # Store alert for dashboard display
            dashboard_alert = {
                "alert_id": alert.alert_id,
                "title": alert.title,
                "message": alert.message,
                "severity": alert.severity.value,
                "priority": alert.priority.value,
                "timestamp": alert.created_at.isoformat(),
                "status": alert.status.value
            }
            
            await redis_client.lpush(
                "dashboard_alerts",
                json.dumps(dashboard_alert)
            )
            
            # Keep only last 100 dashboard alerts
            await redis_client.ltrim("dashboard_alerts", 0, 99)
            
        except Exception as e:
            print(f"Failed to send dashboard alert: {str(e)}")
    
    async def _set_suppression(self, rule_id: str, suppression_window: int):
        """Set alert suppression for rule"""
        try:
            redis_client = await self._get_redis_client()
            
            suppression_key = self.SUPPRESSION_KEY.format(rule_id=rule_id)
            suppressed_until = datetime.now(timezone.utc) + timedelta(seconds=suppression_window)
            
            await redis_client.setex(
                suppression_key,
                suppression_window,
                suppressed_until.isoformat()
            )
            
        except Exception as e:
            print(f"Failed to set suppression: {str(e)}")
    
    async def _schedule_escalation(self, alert: SecurityAlert, escalation_timeout: int):
        """Schedule alert escalation"""
        try:
            redis_client = await self._get_redis_client()
            
            escalation_time = datetime.now(timezone.utc) + timedelta(seconds=escalation_timeout)
            escalation_data = {
                "alert_id": alert.alert_id,
                "escalation_time": escalation_time.isoformat(),
                "escalation_level": alert.escalation_level + 1
            }
            
            await redis_client.zadd(
                self.ESCALATION_QUEUE_KEY,
                {json.dumps(escalation_data): escalation_time.timestamp()}
            )
            
        except Exception as e:
            print(f"Failed to schedule escalation: {str(e)}")
    
    async def _escalation_processor(self):
        """Background task to process alert escalations"""
        while self._running:
            try:
                redis_client = await self._get_redis_client()
                
                # Get escalations that are due
                current_time = datetime.now(timezone.utc).timestamp()
                escalations = await redis_client.zrangebyscore(
                    self.ESCALATION_QUEUE_KEY,
                    0,
                    current_time,
                    withscores=True
                )
                
                for escalation_json, score in escalations:
                    try:
                        escalation_data = json.loads(escalation_json)
                        await self._process_escalation(escalation_data)
                        
                        # Remove processed escalation
                        await redis_client.zrem(self.ESCALATION_QUEUE_KEY, escalation_json)
                        
                    except Exception as e:
                        print(f"Failed to process escalation: {str(e)}")
                
                # Sleep for 30 seconds before next check
                await asyncio.sleep(30)
                
            except Exception as e:
                print(f"Escalation processor error: {str(e)}")
                await asyncio.sleep(60)  # Wait longer on error
    
    async def _process_escalation(self, escalation_data: Dict[str, Any]):
        """Process alert escalation"""
        try:
            alert_id = escalation_data["alert_id"]
            escalation_level = escalation_data["escalation_level"]
            
            # Get alert
            alert = await self.get_alert(alert_id)
            if not alert or alert.status in [AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED]:
                return  # Alert already handled
            
            # Update escalation level
            alert.escalation_level = escalation_level
            alert.status = AlertStatus.ESCALATED
            
            # Get escalated recipients (higher escalation level)
            recipients = await self.get_alert_recipients()
            escalated_recipients = [
                r for r in recipients
                if r.escalation_level >= escalation_level
            ]
            
            if escalated_recipients:
                # Send escalated alert
                alert.recipients = [r.recipient_id for r in escalated_recipients]
                await self._send_alert(alert)
            
            # Update alert
            await self._update_alert_status(alert)
            
        except Exception as e:
            print(f"Failed to process escalation: {str(e)}")
    
    async def _cleanup_processor(self):
        """Background task to cleanup old alerts and metrics"""
        while self._running:
            try:
                await self._cleanup_old_alerts()
                await self._cleanup_old_metrics()
                
                # Sleep for 1 hour before next cleanup
                await asyncio.sleep(3600)
                
            except Exception as e:
                print(f"Cleanup processor error: {str(e)}")
                await asyncio.sleep(3600)  # Wait on error
    
    async def _cleanup_old_alerts(self):
        """Cleanup old resolved alerts"""
        try:
            redis_client = await self._get_redis_client()
            
            # Get all active alerts
            active_alerts = await redis_client.hgetall(self.ACTIVE_ALERTS_KEY)
            
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=7)  # Keep for 7 days
            
            for alert_id, alert_json in active_alerts.items():
                try:
                    alert_data = json.loads(alert_json)
                    
                    # Check if alert is old and resolved
                    if alert_data.get("status") == AlertStatus.RESOLVED.value:
                        resolved_at = datetime.fromisoformat(alert_data.get("resolved_at", ""))
                        if resolved_at < cutoff_time:
                            # Remove from active alerts
                            await redis_client.hdel(self.ACTIVE_ALERTS_KEY, alert_id)
                
                except Exception as e:
                    print(f"Failed to cleanup alert {alert_id}: {str(e)}")
            
        except Exception as e:
            print(f"Failed to cleanup old alerts: {str(e)}")
    
    async def _cleanup_old_metrics(self):
        """Cleanup old metrics"""
        try:
            redis_client = await self._get_redis_client()
            
            # Cleanup old hourly metrics (keep last 30 days)
            cutoff_hour = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y%m%d%H")
            
            all_metrics = await redis_client.hgetall(self.ALERT_METRICS_KEY)
            for key in all_metrics.keys():
                if ":" in key and key.split(":")[-1] < cutoff_hour:
                    await redis_client.hdel(self.ALERT_METRICS_KEY, key)
            
        except Exception as e:
            print(f"Failed to cleanup old metrics: {str(e)}")
    
    async def _update_alert_status(self, alert: SecurityAlert):
        """Update alert status in storage"""
        try:
            redis_client = await self._get_redis_client()
            
            # Update in active alerts
            alert_data = asdict(alert)
            # Convert datetime objects to ISO strings
            for key, value in alert_data.items():
                if isinstance(value, datetime):
                    alert_data[key] = value.isoformat() if value else None
                elif isinstance(value, Enum):
                    alert_data[key] = value.value
            
            await redis_client.hset(
                self.ACTIVE_ALERTS_KEY,
                alert.alert_id,
                json.dumps(alert_data)
            )
            
        except Exception as e:
            print(f"Failed to update alert status: {str(e)}")
    
    # Public API methods
    
    async def add_alert_rule(self, rule: AlertRule):
        """Add new alert rule"""
        try:
            redis_client = await self._get_redis_client()
            
            rule_data = asdict(rule)
            # Convert enums to values
            rule_data["event_types"] = [et.value for et in rule.event_types]
            rule_data["severity_threshold"] = rule.severity_threshold.value
            rule_data["channels"] = [ch.value for ch in rule.channels]
            rule_data["priority"] = rule.priority.value
            
            await redis_client.hset(
                self.ALERT_RULES_KEY,
                rule.rule_id,
                json.dumps(rule_data)
            )
            
        except Exception as e:
            raise RealTimeAlertingError(f"Failed to add alert rule: {str(e)}")
    
    async def get_alert_rules(self) -> List[AlertRule]:
        """Get all alert rules"""
        try:
            redis_client = await self._get_redis_client()
            
            rules_data = await redis_client.hgetall(self.ALERT_RULES_KEY)
            rules = []
            
            for rule_id, rule_json in rules_data.items():
                try:
                    rule_data = json.loads(rule_json)
                    
                    # Convert values back to enums
                    rule_data["event_types"] = [SecurityEventType(et) for et in rule_data["event_types"]]
                    rule_data["severity_threshold"] = SecurityEventSeverity(rule_data["severity_threshold"])
                    rule_data["channels"] = [AlertChannel(ch) for ch in rule_data["channels"]]
                    rule_data["priority"] = AlertPriority(rule_data["priority"])
                    
                    rules.append(AlertRule(**rule_data))
                    
                except Exception as e:
                    print(f"Failed to parse rule {rule_id}: {str(e)}")
            
            return rules
            
        except Exception as e:
            raise RealTimeAlertingError(f"Failed to get alert rules: {str(e)}")
    
    async def add_alert_recipient(self, recipient: AlertRecipient):
        """Add new alert recipient"""
        try:
            redis_client = await self._get_redis_client()
            
            recipient_data = asdict(recipient)
            # Convert enums to values
            recipient_data["channels"] = [ch.value for ch in recipient.channels]
            
            await redis_client.hset(
                self.ALERT_RECIPIENTS_KEY,
                recipient.recipient_id,
                json.dumps(recipient_data)
            )
            
        except Exception as e:
            raise RealTimeAlertingError(f"Failed to add alert recipient: {str(e)}")
    
    async def get_alert_recipients(self) -> List[AlertRecipient]:
        """Get all alert recipients"""
        try:
            redis_client = await self._get_redis_client()
            
            recipients_data = await redis_client.hgetall(self.ALERT_RECIPIENTS_KEY)
            recipients = []
            
            for recipient_id, recipient_json in recipients_data.items():
                try:
                    recipient_data = json.loads(recipient_json)
                    
                    # Convert values back to enums
                    recipient_data["channels"] = [AlertChannel(ch) for ch in recipient_data["channels"]]
                    
                    recipients.append(AlertRecipient(**recipient_data))
                    
                except Exception as e:
                    print(f"Failed to parse recipient {recipient_id}: {str(e)}")
            
            return recipients
            
        except Exception as e:
            raise RealTimeAlertingError(f"Failed to get alert recipients: {str(e)}")
    
    async def get_alert(self, alert_id: str) -> Optional[SecurityAlert]:
        """Get specific alert by ID"""
        try:
            redis_client = await self._get_redis_client()
            
            # Try active alerts first
            alert_json = await redis_client.hget(self.ACTIVE_ALERTS_KEY, alert_id)
            
            if not alert_json:
                # Try history
                alert_json = await redis_client.get(f"{self.ALERT_HISTORY_KEY}:{alert_id}")
            
            if not alert_json:
                return None
            
            alert_data = json.loads(alert_json)
            
            # Convert values back to proper types
            alert_data["event_type"] = SecurityEventType(alert_data["event_type"])
            alert_data["severity"] = SecurityEventSeverity(alert_data["severity"])
            alert_data["priority"] = AlertPriority(alert_data["priority"])
            alert_data["channels"] = [AlertChannel(ch) for ch in alert_data["channels"]]
            alert_data["status"] = AlertStatus(alert_data["status"])
            
            # Convert datetime strings back to datetime objects
            for field in ["created_at", "sent_at", "acknowledged_at", "resolved_at", "suppressed_until"]:
                if alert_data.get(field):
                    alert_data[field] = datetime.fromisoformat(alert_data[field])
            
            return SecurityAlert(**alert_data)
            
        except Exception as e:
            raise RealTimeAlertingError(f"Failed to get alert: {str(e)}")
    
    async def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Acknowledge an alert"""
        try:
            alert = await self.get_alert(alert_id)
            if not alert:
                return False
            
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = datetime.now(timezone.utc)
            alert.acknowledged_by = acknowledged_by
            
            await self._update_alert_status(alert)
            return True
            
        except Exception as e:
            raise RealTimeAlertingError(f"Failed to acknowledge alert: {str(e)}")
    
    async def resolve_alert(self, alert_id: str, resolved_by: str) -> bool:
        """Resolve an alert"""
        try:
            alert = await self.get_alert(alert_id)
            if not alert:
                return False
            
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.now(timezone.utc)
            alert.resolved_by = resolved_by
            
            await self._update_alert_status(alert)
            return True
            
        except Exception as e:
            raise RealTimeAlertingError(f"Failed to resolve alert: {str(e)}")


# Global instance
_real_time_alerting_service = None

def get_real_time_alerting_service() -> RealTimeAlertingService:
    """Get global real-time alerting service instance"""
    global _real_time_alerting_service
    if _real_time_alerting_service is None:
        _real_time_alerting_service = RealTimeAlertingService()
    return _real_time_alerting_service
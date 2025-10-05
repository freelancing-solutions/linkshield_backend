#!/usr/bin/env python3
"""
Security Notification System

Provides comprehensive notification capabilities for security events,
rotation alerts, performance issues, and compliance violations.
Supports multiple notification channels including email, webhooks, and logging.
"""

import asyncio
import json
import smtplib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import logging
import aiohttp
import ssl
from jinja2 import Template

import redis.asyncio as redis
from redis.asyncio import Redis

from src.config.settings import get_settings
from src.security.security_event_logger import SecurityEventLogger, SecurityEventType, SecurityEventSeverity


class NotificationType(Enum):
    """Notification types"""
    SECURITY_ALERT = "security_alert"
    ROTATION_EVENT = "rotation_event"
    PERFORMANCE_ALERT = "performance_alert"
    COMPLIANCE_VIOLATION = "compliance_violation"
    SYSTEM_HEALTH = "system_health"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_FAILURE = "authorization_failure"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    POLICY_VIOLATION = "policy_violation"
    EMERGENCY_ALERT = "emergency_alert"


class NotificationChannel(Enum):
    """Notification channels"""
    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"
    TEAMS = "teams"
    SMS = "sms"
    PUSH = "push"
    LOG = "log"


class NotificationPriority(Enum):
    """Notification priorities"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class NotificationTemplate:
    """Notification template configuration"""
    name: str
    subject_template: str
    body_template: str
    html_template: Optional[str] = None
    variables: List[str] = field(default_factory=list)


@dataclass
class NotificationChannel:
    """Notification channel configuration"""
    channel_type: NotificationChannel
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    rate_limit: Optional[int] = None  # Max notifications per hour
    retry_attempts: int = 3
    retry_delay: int = 60  # seconds


@dataclass
class NotificationRule:
    """Notification rule configuration"""
    rule_id: str
    notification_type: NotificationType
    priority: NotificationPriority
    channels: List[NotificationChannel]
    conditions: Dict[str, Any] = field(default_factory=dict)
    template: Optional[str] = None
    enabled: bool = True
    rate_limit: Optional[int] = None
    escalation_delay: Optional[int] = None  # seconds


@dataclass
class NotificationEvent:
    """Notification event data structure"""
    event_id: str
    notification_type: NotificationType
    priority: NotificationPriority
    title: str
    message: str
    timestamp: datetime
    source: str
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


@dataclass
class NotificationDelivery:
    """Notification delivery tracking"""
    delivery_id: str
    event_id: str
    channel: NotificationChannel
    status: str  # pending, sent, failed, retrying
    attempts: int = 0
    last_attempt: Optional[datetime] = None
    error_message: Optional[str] = None
    delivered_at: Optional[datetime] = None


class NotificationSystem:
    """
    Comprehensive notification system for security events and alerts.
    
    Features:
    - Multiple notification channels (email, webhook, Slack, etc.)
    - Template-based notifications
    - Rate limiting and throttling
    - Retry mechanisms
    - Escalation policies
    - Delivery tracking
    - Performance monitoring
    """

    def __init__(
        self,
        redis_client: Optional[Redis] = None,
        security_logger: Optional[SecurityEventLogger] = None
    ):
        self.settings = get_settings()
        self.redis_client = redis_client
        self.security_logger = security_logger
        self.logger = logging.getLogger(__name__)
        
        # Notification configuration
        self.channels: Dict[str, NotificationChannel] = {}
        self.rules: Dict[str, NotificationRule] = {}
        self.templates: Dict[str, NotificationTemplate] = {}
        
        # Delivery tracking
        self.pending_deliveries: Dict[str, NotificationDelivery] = {}
        self.delivery_history: List[NotificationDelivery] = []
        
        # Rate limiting
        self.rate_limits: Dict[str, List[datetime]] = {}
        
        # Background tasks
        self._delivery_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        
        # Initialize default configuration
        self._initialize_default_config()

    def _initialize_default_config(self):
        """Initialize default notification configuration"""
        # Default templates
        self.templates = {
            "security_alert": NotificationTemplate(
                name="Security Alert",
                subject_template="🚨 Security Alert: {{ title }}",
                body_template="""
Security Alert Detected

Title: {{ title }}
Priority: {{ priority }}
Source: {{ source }}
Time: {{ timestamp }}

Description:
{{ message }}

Context:
{% for key, value in context.items() %}
- {{ key }}: {{ value }}
{% endfor %}

Please investigate immediately.
                """.strip(),
                html_template="""
<html>
<body>
<h2 style="color: #d32f2f;">🚨 Security Alert</h2>
<p><strong>Title:</strong> {{ title }}</p>
<p><strong>Priority:</strong> <span style="color: #d32f2f;">{{ priority }}</span></p>
<p><strong>Source:</strong> {{ source }}</p>
<p><strong>Time:</strong> {{ timestamp }}</p>

<h3>Description:</h3>
<p>{{ message }}</p>

<h3>Context:</h3>
<ul>
{% for key, value in context.items() %}
<li><strong>{{ key }}:</strong> {{ value }}</li>
{% endfor %}
</ul>

<p style="color: #d32f2f;"><strong>Please investigate immediately.</strong></p>
</body>
</html>
                """.strip()
            ),
            "rotation_event": NotificationTemplate(
                name="Rotation Event",
                subject_template="🔄 Security Rotation: {{ title }}",
                body_template="""
Security Rotation Event

Title: {{ title }}
Type: {{ rotation_type }}
Status: {{ status }}
Time: {{ timestamp }}

Details:
{{ message }}

{% if next_rotation %}
Next Rotation: {{ next_rotation }}
{% endif %}

Context:
{% for key, value in context.items() %}
- {{ key }}: {{ value }}
{% endfor %}
                """.strip()
            ),
            "performance_alert": NotificationTemplate(
                name="Performance Alert",
                subject_template="⚡ Performance Alert: {{ title }}",
                body_template="""
Performance Alert

Component: {{ component }}
Metric: {{ metric }}
Current Value: {{ current_value }}
Threshold: {{ threshold }}
Time: {{ timestamp }}

Description:
{{ message }}

Recommended Actions:
{% for action in recommended_actions %}
- {{ action }}
{% endfor %}
                """.strip()
            ),
            "compliance_violation": NotificationTemplate(
                name="Compliance Violation",
                subject_template="⚖️ Compliance Violation: {{ title }}",
                body_template="""
Compliance Violation Detected

Policy: {{ policy }}
Violation Type: {{ violation_type }}
Severity: {{ severity }}
Time: {{ timestamp }}

Description:
{{ message }}

Required Actions:
{% for action in required_actions %}
- {{ action }}
{% endfor %}

Compliance Officer: Please review immediately.
                """.strip()
            )
        }
        
        # Default notification rules
        self.rules = {
            "critical_security_alerts": NotificationRule(
                rule_id="critical_security_alerts",
                notification_type=NotificationType.SECURITY_ALERT,
                priority=NotificationPriority.CRITICAL,
                channels=[NotificationChannel.EMAIL, NotificationChannel.WEBHOOK],
                conditions={"severity": ["HIGH", "CRITICAL"]},
                template="security_alert",
                rate_limit=10  # Max 10 per hour
            ),
            "rotation_notifications": NotificationRule(
                rule_id="rotation_notifications",
                notification_type=NotificationType.ROTATION_EVENT,
                priority=NotificationPriority.MEDIUM,
                channels=[NotificationChannel.EMAIL, NotificationChannel.LOG],
                template="rotation_event",
                rate_limit=50  # Max 50 per hour
            ),
            "performance_alerts": NotificationRule(
                rule_id="performance_alerts",
                notification_type=NotificationType.PERFORMANCE_ALERT,
                priority=NotificationPriority.HIGH,
                channels=[NotificationChannel.EMAIL, NotificationChannel.WEBHOOK],
                conditions={"severity": ["warning", "critical"]},
                template="performance_alert",
                rate_limit=20  # Max 20 per hour
            ),
            "compliance_violations": NotificationRule(
                rule_id="compliance_violations",
                notification_type=NotificationType.COMPLIANCE_VIOLATION,
                priority=NotificationPriority.HIGH,
                channels=[NotificationChannel.EMAIL, NotificationChannel.LOG],
                template="compliance_violation",
                rate_limit=30  # Max 30 per hour
            )
        }

    async def start_notification_system(self):
        """Start notification system background tasks"""
        self.logger.info("Starting notification system")
        
        # Start delivery task
        self._delivery_task = asyncio.create_task(self._delivery_loop())
        
        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        # Log system start
        if self.security_logger:
            await self.security_logger.log_event(
                SecurityEventType.SECURITY_CONFIG_CHANGE,
                SecurityEventSeverity.INFO,
                "Notification system started",
                context={"component": "notification_system"}
            )

    async def stop_notification_system(self):
        """Stop notification system background tasks"""
        self.logger.info("Stopping notification system")
        
        if self._delivery_task:
            self._delivery_task.cancel()
            try:
                await self._delivery_task
            except asyncio.CancelledError:
                pass
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

    async def send_notification(
        self,
        notification_type: NotificationType,
        title: str,
        message: str,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        source: str = "security_system",
        context: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None
    ) -> str:
        """Send a notification"""
        event_id = f"notif_{int(datetime.now().timestamp() * 1000)}"
        
        event = NotificationEvent(
            event_id=event_id,
            notification_type=notification_type,
            priority=priority,
            title=title,
            message=message,
            timestamp=datetime.now(timezone.utc),
            source=source,
            context=context or {},
            metadata=metadata or {},
            tags=tags or []
        )
        
        # Find matching rules
        matching_rules = self._find_matching_rules(event)
        
        if not matching_rules:
            self.logger.warning(f"No matching notification rules for event: {event_id}")
            return event_id
        
        # Create deliveries for each matching rule
        for rule in matching_rules:
            if not rule.enabled:
                continue
            
            # Check rate limits
            if not await self._check_rate_limit(rule, event):
                self.logger.warning(f"Rate limit exceeded for rule: {rule.rule_id}")
                continue
            
            # Create deliveries for each channel
            for channel in rule.channels:
                delivery = NotificationDelivery(
                    delivery_id=f"delivery_{int(datetime.now().timestamp() * 1000)}_{channel.value}",
                    event_id=event_id,
                    channel=channel,
                    status="pending"
                )
                
                self.pending_deliveries[delivery.delivery_id] = delivery
        
        # Store event in Redis
        if self.redis_client:
            await self._store_notification_event(event)
        
        self.logger.info(f"Notification queued: {event_id} with {len(self.pending_deliveries)} deliveries")
        return event_id

    def _find_matching_rules(self, event: NotificationEvent) -> List[NotificationRule]:
        """Find notification rules that match the event"""
        matching_rules = []
        
        for rule in self.rules.values():
            if rule.notification_type != event.notification_type:
                continue
            
            # Check conditions
            if rule.conditions:
                if not self._check_rule_conditions(rule.conditions, event):
                    continue
            
            matching_rules.append(rule)
        
        return matching_rules

    def _check_rule_conditions(self, conditions: Dict[str, Any], event: NotificationEvent) -> bool:
        """Check if event matches rule conditions"""
        for key, expected_values in conditions.items():
            if key == "severity":
                event_severity = event.context.get("severity") or event.priority.value
                if event_severity not in expected_values:
                    return False
            elif key == "source":
                if event.source not in expected_values:
                    return False
            elif key == "tags":
                if not any(tag in event.tags for tag in expected_values):
                    return False
            # Add more condition checks as needed
        
        return True

    async def _check_rate_limit(self, rule: NotificationRule, event: NotificationEvent) -> bool:
        """Check if notification is within rate limits"""
        if not rule.rate_limit:
            return True
        
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        
        # Get recent notifications for this rule
        rule_key = f"rate_limit:{rule.rule_id}"
        
        if rule_key not in self.rate_limits:
            self.rate_limits[rule_key] = []
        
        # Clean old entries
        self.rate_limits[rule_key] = [
            ts for ts in self.rate_limits[rule_key] if ts > hour_ago
        ]
        
        # Check limit
        if len(self.rate_limits[rule_key]) >= rule.rate_limit:
            return False
        
        # Add current notification
        self.rate_limits[rule_key].append(now)
        return True

    async def _store_notification_event(self, event: NotificationEvent):
        """Store notification event in Redis"""
        try:
            key = f"notifications:events:{event.event_id}"
            await self.redis_client.setex(
                key,
                86400,  # 24 hours
                json.dumps(asdict(event), default=str)
            )
        except Exception as e:
            self.logger.error(f"Failed to store notification event: {e}")

    async def _delivery_loop(self):
        """Background delivery loop"""
        while True:
            try:
                # Process pending deliveries
                deliveries_to_process = list(self.pending_deliveries.values())
                
                for delivery in deliveries_to_process:
                    try:
                        await self._process_delivery(delivery)
                    except Exception as e:
                        self.logger.error(f"Delivery processing failed: {e}")
                
                await asyncio.sleep(5)  # Process every 5 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Delivery loop error: {e}")
                await asyncio.sleep(30)

    async def _process_delivery(self, delivery: NotificationDelivery):
        """Process a single notification delivery"""
        if delivery.status not in ["pending", "retrying"]:
            return
        
        try:
            # Get the original event
            event = await self._get_notification_event(delivery.event_id)
            if not event:
                self.logger.error(f"Event not found for delivery: {delivery.delivery_id}")
                delivery.status = "failed"
                delivery.error_message = "Event not found"
                return
            
            # Send notification based on channel
            success = await self._send_to_channel(delivery.channel, event, delivery)
            
            if success:
                delivery.status = "sent"
                delivery.delivered_at = datetime.now(timezone.utc)
                self.pending_deliveries.pop(delivery.delivery_id, None)
                self.delivery_history.append(delivery)
            else:
                delivery.attempts += 1
                delivery.last_attempt = datetime.now(timezone.utc)
                
                # Check retry limit
                rule = self._get_rule_for_event(event)
                max_attempts = rule.retry_attempts if rule else 3
                
                if delivery.attempts >= max_attempts:
                    delivery.status = "failed"
                    self.pending_deliveries.pop(delivery.delivery_id, None)
                    self.delivery_history.append(delivery)
                else:
                    delivery.status = "retrying"
                    # Schedule retry (simplified - in production, use proper scheduling)
                    await asyncio.sleep(rule.retry_delay if rule else 60)
        
        except Exception as e:
            delivery.status = "failed"
            delivery.error_message = str(e)
            delivery.attempts += 1
            self.logger.error(f"Delivery failed: {delivery.delivery_id}, error: {e}")

    async def _get_notification_event(self, event_id: str) -> Optional[NotificationEvent]:
        """Get notification event from Redis"""
        try:
            if not self.redis_client:
                return None
            
            key = f"notifications:events:{event_id}"
            data = await self.redis_client.get(key)
            
            if data:
                event_data = json.loads(data)
                # Convert timestamp string back to datetime
                event_data["timestamp"] = datetime.fromisoformat(event_data["timestamp"])
                return NotificationEvent(**event_data)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get notification event: {e}")
            return None

    def _get_rule_for_event(self, event: NotificationEvent) -> Optional[NotificationRule]:
        """Get the first matching rule for an event"""
        matching_rules = self._find_matching_rules(event)
        return matching_rules[0] if matching_rules else None

    async def _send_to_channel(
        self,
        channel: NotificationChannel,
        event: NotificationEvent,
        delivery: NotificationDelivery
    ) -> bool:
        """Send notification to specific channel"""
        try:
            if channel == NotificationChannel.EMAIL:
                return await self._send_email(event, delivery)
            elif channel == NotificationChannel.WEBHOOK:
                return await self._send_webhook(event, delivery)
            elif channel == NotificationChannel.SLACK:
                return await self._send_slack(event, delivery)
            elif channel == NotificationChannel.LOG:
                return await self._send_log(event, delivery)
            else:
                self.logger.warning(f"Unsupported channel: {channel}")
                return False
                
        except Exception as e:
            delivery.error_message = str(e)
            self.logger.error(f"Channel delivery failed: {channel}, error: {e}")
            return False

    async def _send_email(self, event: NotificationEvent, delivery: NotificationDelivery) -> bool:
        """Send email notification"""
        try:
            # Get email configuration from settings
            smtp_host = getattr(self.settings, 'SMTP_HOST', 'localhost')
            smtp_port = getattr(self.settings, 'SMTP_PORT', 587)
            smtp_user = getattr(self.settings, 'SMTP_USER', '')
            smtp_password = getattr(self.settings, 'SMTP_PASSWORD', '')
            from_email = getattr(self.settings, 'FROM_EMAIL', 'noreply@linkshield.com')
            to_emails = getattr(self.settings, 'NOTIFICATION_EMAILS', ['admin@linkshield.com'])
            
            # Get template
            rule = self._get_rule_for_event(event)
            template_name = rule.template if rule else "security_alert"
            template = self.templates.get(template_name)
            
            if not template:
                self.logger.error(f"Template not found: {template_name}")
                return False
            
            # Render template
            subject = self._render_template(template.subject_template, event)
            body = self._render_template(template.body_template, event)
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = from_email
            msg['To'] = ', '.join(to_emails)
            
            # Add text part
            text_part = MIMEText(body, 'plain')
            msg.attach(text_part)
            
            # Add HTML part if available
            if template.html_template:
                html_body = self._render_template(template.html_template, event)
                html_part = MIMEText(html_body, 'html')
                msg.attach(html_part)
            
            # Send email
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if smtp_port == 587:
                    server.starttls()
                if smtp_user and smtp_password:
                    server.login(smtp_user, smtp_password)
                
                server.send_message(msg)
            
            self.logger.info(f"Email sent successfully: {delivery.delivery_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Email sending failed: {e}")
            return False

    async def _send_webhook(self, event: NotificationEvent, delivery: NotificationDelivery) -> bool:
        """Send webhook notification"""
        try:
            webhook_url = getattr(self.settings, 'WEBHOOK_URL', None)
            if not webhook_url:
                self.logger.warning("Webhook URL not configured")
                return False
            
            # Prepare payload
            payload = {
                "event_id": event.event_id,
                "type": event.notification_type.value,
                "priority": event.priority.value,
                "title": event.title,
                "message": event.message,
                "timestamp": event.timestamp.isoformat(),
                "source": event.source,
                "context": event.context,
                "metadata": event.metadata,
                "tags": event.tags
            }
            
            # Send webhook
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        self.logger.info(f"Webhook sent successfully: {delivery.delivery_id}")
                        return True
                    else:
                        self.logger.error(f"Webhook failed with status: {response.status}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Webhook sending failed: {e}")
            return False

    async def _send_slack(self, event: NotificationEvent, delivery: NotificationDelivery) -> bool:
        """Send Slack notification"""
        try:
            slack_webhook_url = getattr(self.settings, 'SLACK_WEBHOOK_URL', None)
            if not slack_webhook_url:
                self.logger.warning("Slack webhook URL not configured")
                return False
            
            # Prepare Slack payload
            color = {
                NotificationPriority.LOW: "good",
                NotificationPriority.MEDIUM: "warning",
                NotificationPriority.HIGH: "danger",
                NotificationPriority.CRITICAL: "danger",
                NotificationPriority.EMERGENCY: "danger"
            }.get(event.priority, "warning")
            
            payload = {
                "text": f"Security Notification: {event.title}",
                "attachments": [
                    {
                        "color": color,
                        "title": event.title,
                        "text": event.message,
                        "fields": [
                            {"title": "Priority", "value": event.priority.value, "short": True},
                            {"title": "Source", "value": event.source, "short": True},
                            {"title": "Time", "value": event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"), "short": True}
                        ],
                        "footer": "LinkShield Security System",
                        "ts": int(event.timestamp.timestamp())
                    }
                ]
            }
            
            # Send to Slack
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    slack_webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        self.logger.info(f"Slack notification sent successfully: {delivery.delivery_id}")
                        return True
                    else:
                        self.logger.error(f"Slack notification failed with status: {response.status}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Slack notification failed: {e}")
            return False

    async def _send_log(self, event: NotificationEvent, delivery: NotificationDelivery) -> bool:
        """Send log notification"""
        try:
            # Log the notification
            log_level = {
                NotificationPriority.LOW: logging.INFO,
                NotificationPriority.MEDIUM: logging.WARNING,
                NotificationPriority.HIGH: logging.ERROR,
                NotificationPriority.CRITICAL: logging.CRITICAL,
                NotificationPriority.EMERGENCY: logging.CRITICAL
            }.get(event.priority, logging.INFO)
            
            self.logger.log(
                log_level,
                f"NOTIFICATION: {event.title} - {event.message}",
                extra={
                    "event_id": event.event_id,
                    "notification_type": event.notification_type.value,
                    "priority": event.priority.value,
                    "source": event.source,
                    "context": event.context,
                    "tags": event.tags
                }
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Log notification failed: {e}")
            return False

    def _render_template(self, template_str: str, event: NotificationEvent) -> str:
        """Render notification template"""
        try:
            template = Template(template_str)
            
            # Prepare template variables
            variables = {
                "title": event.title,
                "message": event.message,
                "priority": event.priority.value,
                "source": event.source,
                "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "event_id": event.event_id,
                "notification_type": event.notification_type.value,
                **event.context,
                **event.metadata
            }
            
            return template.render(**variables)
            
        except Exception as e:
            self.logger.error(f"Template rendering failed: {e}")
            return f"Template rendering failed: {template_str}"

    async def _cleanup_loop(self):
        """Background cleanup loop"""
        while True:
            try:
                await self._cleanup_old_data()
                await asyncio.sleep(3600)  # Run every hour
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Cleanup loop error: {e}")
                await asyncio.sleep(3600)

    async def _cleanup_old_data(self):
        """Clean up old notification data"""
        try:
            # Clean up delivery history
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=7)
            self.delivery_history = [
                d for d in self.delivery_history
                if d.delivered_at and d.delivered_at > cutoff_time
            ]
            
            # Clean up rate limits
            hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
            for key in self.rate_limits:
                self.rate_limits[key] = [
                    ts for ts in self.rate_limits[key] if ts > hour_ago
                ]
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")

    # Public API methods
    async def get_delivery_status(self, event_id: str) -> Dict[str, Any]:
        """Get delivery status for a notification event"""
        deliveries = [
            d for d in list(self.pending_deliveries.values()) + self.delivery_history
            if d.event_id == event_id
        ]
        
        return {
            "event_id": event_id,
            "total_deliveries": len(deliveries),
            "pending": len([d for d in deliveries if d.status == "pending"]),
            "sent": len([d for d in deliveries if d.status == "sent"]),
            "failed": len([d for d in deliveries if d.status == "failed"]),
            "retrying": len([d for d in deliveries if d.status == "retrying"]),
            "deliveries": [asdict(d) for d in deliveries]
        }

    async def get_notification_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get notification statistics"""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        recent_deliveries = [
            d for d in self.delivery_history
            if d.delivered_at and d.delivered_at > cutoff_time
        ]
        
        stats = {
            "total_notifications": len(recent_deliveries),
            "successful_deliveries": len([d for d in recent_deliveries if d.status == "sent"]),
            "failed_deliveries": len([d for d in recent_deliveries if d.status == "failed"]),
            "pending_deliveries": len(self.pending_deliveries),
            "delivery_rate": 0.0,
            "channels": {},
            "notification_types": {}
        }
        
        if recent_deliveries:
            stats["delivery_rate"] = stats["successful_deliveries"] / len(recent_deliveries)
        
        # Channel statistics
        for delivery in recent_deliveries:
            channel = delivery.channel.value
            if channel not in stats["channels"]:
                stats["channels"][channel] = {"total": 0, "successful": 0, "failed": 0}
            
            stats["channels"][channel]["total"] += 1
            if delivery.status == "sent":
                stats["channels"][channel]["successful"] += 1
            elif delivery.status == "failed":
                stats["channels"][channel]["failed"] += 1
        
        return stats


# Global notification system instance
_notification_system: Optional[NotificationSystem] = None


def get_notification_system() -> NotificationSystem:
    """Get global notification system instance"""
    global _notification_system
    if _notification_system is None:
        _notification_system = NotificationSystem()
    return _notification_system


# Convenience functions for common notifications
async def send_security_alert(
    title: str,
    message: str,
    priority: NotificationPriority = NotificationPriority.HIGH,
    context: Optional[Dict[str, Any]] = None
) -> str:
    """Send a security alert notification"""
    system = get_notification_system()
    return await system.send_notification(
        NotificationType.SECURITY_ALERT,
        title,
        message,
        priority,
        "security_system",
        context
    )


async def send_rotation_notification(
    title: str,
    message: str,
    rotation_type: str,
    status: str,
    next_rotation: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None
) -> str:
    """Send a rotation event notification"""
    system = get_notification_system()
    notification_context = {
        "rotation_type": rotation_type,
        "status": status,
        **(context or {})
    }
    
    if next_rotation:
        notification_context["next_rotation"] = next_rotation
    
    return await system.send_notification(
        NotificationType.ROTATION_EVENT,
        title,
        message,
        NotificationPriority.MEDIUM,
        "rotation_system",
        notification_context
    )


async def send_performance_alert(
    title: str,
    message: str,
    component: str,
    metric: str,
    current_value: float,
    threshold: float,
    recommended_actions: Optional[List[str]] = None,
    context: Optional[Dict[str, Any]] = None
) -> str:
    """Send a performance alert notification"""
    system = get_notification_system()
    notification_context = {
        "component": component,
        "metric": metric,
        "current_value": current_value,
        "threshold": threshold,
        "recommended_actions": recommended_actions or [],
        **(context or {})
    }
    
    return await system.send_notification(
        NotificationType.PERFORMANCE_ALERT,
        title,
        message,
        NotificationPriority.HIGH,
        "performance_monitor",
        notification_context
    )


async def send_compliance_violation(
    title: str,
    message: str,
    policy: str,
    violation_type: str,
    severity: str,
    required_actions: Optional[List[str]] = None,
    context: Optional[Dict[str, Any]] = None
) -> str:
    """Send a compliance violation notification"""
    system = get_notification_system()
    notification_context = {
        "policy": policy,
        "violation_type": violation_type,
        "severity": severity,
        "required_actions": required_actions or [],
        **(context or {})
    }
    
    return await system.send_notification(
        NotificationType.COMPLIANCE_VIOLATION,
        title,
        message,
        NotificationPriority.HIGH,
        "compliance_system",
        notification_context
    )
#!/usr/bin/env python3
"""
LinkShield Backend Security Service

Comprehensive security service for threat detection, compliance monitoring,
and security policy enforcement.
"""

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

import bcrypt
import jwt
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from src.config.settings import get_settings
from src.models.user import User, UserSession, APIKey
from src.models.url_check import URLCheck, ScanResult


class SecurityError(Exception):
    """
    Base security error.
    """
    pass


class AuthenticationError(SecurityError):
    """
    Authentication error.
    """
    pass


class AuthorizationError(SecurityError):
    """
    Authorization error.
    """
    pass


class RateLimitError(SecurityError):
    """
    Rate limit exceeded error.
    """
    pass


class SecurityService:
    """
    Security service for authentication, authorization, and threat detection.
    """
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.settings = get_settings()
        
        # Initialize encryption
        self.fernet = Fernet(self.settings.ENCRYPTION_KEY.encode() if self.settings.ENCRYPTION_KEY else Fernet.generate_key())
        
        # Security configurations
        self.password_config = {
            "min_length": 8,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_special": True,
            "max_age_days": 90
        }
        
        self.session_config = {
            "max_duration_hours": 24,
            "max_idle_hours": 2,
            "require_2fa": False,
            "max_concurrent_sessions": 5
        }
        
        self.rate_limit_config = {
            "api_requests_per_minute": 60,
            "url_checks_per_hour": 100,
            "failed_login_attempts": 5,
            "failed_login_window_minutes": 15
        }
        
        # Threat detection patterns
        self.threat_patterns = {
            "sql_injection": [
                r"('|(\-\-)|(;)|(\||\|)|(\*|\*))",
                r"(union|select|insert|delete|update|drop|create|alter|exec|execute)",
                r"(script|javascript|vbscript|onload|onerror|onclick)"
            ],
            "xss": [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>"
            ],
            "path_traversal": [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e%5c"
            ]
        }
        
        # IP reputation cache
        self.ip_reputation_cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt.
        """
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify password against hash.
        """
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False
    
    def validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password strength against security policy.
        
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        if len(password) < self.password_config["min_length"]:
            issues.append(f"Password must be at least {self.password_config['min_length']} characters long")
        
        if self.password_config["require_uppercase"] and not any(c.isupper() for c in password):
            issues.append("Password must contain at least one uppercase letter")
        
        if self.password_config["require_lowercase"] and not any(c.islower() for c in password):
            issues.append("Password must contain at least one lowercase letter")
        
        if self.password_config["require_numbers"] and not any(c.isdigit() for c in password):
            issues.append("Password must contain at least one number")
        
        if self.password_config["require_special"] and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            issues.append("Password must contain at least one special character")
        
        # Check for common weak passwords
        weak_passwords = [
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "master"
        ]
        
        if password.lower() in weak_passwords:
            issues.append("Password is too common and easily guessable")
        
        return len(issues) == 0, issues
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate cryptographically secure random token.
        """
        return secrets.token_urlsafe(length)
    
    def create_jwt_token(self, user_id: str, session_id: str, expires_hours: int = 24) -> str:
        """
        Create JWT token for user session.
        """
        payload = {
            "user_id": str(user_id),
            "session_id": str(session_id),
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=expires_hours),
            "iss": "linkshield-api",
            "aud": "linkshield-client"
        }
        
        return jwt.encode(payload, self.settings.JWT_SECRET_KEY, algorithm="HS256")
    
    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT token.
        """
        try:
            payload = jwt.decode(
                token, 
                self.settings.JWT_SECRET_KEY, 
                algorithms=["HS256"],
                audience="linkshield-client",
                issuer="linkshield-api"
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """
        Encrypt sensitive data.
        """
        return self.fernet.encrypt(data.encode()).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """
        Decrypt sensitive data.
        """
        return self.fernet.decrypt(encrypted_data.encode()).decode()
    
    def validate_session(self, session_id: str, user_id: str) -> Tuple[bool, Optional[UserSession]]:
        """
        Validate user session.
        """
        session = self.db.query(UserSession).filter(
            and_(
                UserSession.id == session_id,
                UserSession.user_id == user_id,
                UserSession.is_active == True
            )
        ).first()
        
        if not session:
            return False, None
        
        # Check session expiration
        now = datetime.now(timezone.utc)
        
        if session.expires_at and session.expires_at < now:
            session.is_active = False
            self.db.commit()
            return False, None
        
        # Check idle timeout
        idle_timeout = timedelta(hours=self.session_config["max_idle_hours"])
        if session.last_activity_at and (now - session.last_activity_at) > idle_timeout:
            session.is_active = False
            self.db.commit()
            return False, None
        
        # Update last activity
        session.last_activity_at = now
        self.db.commit()
        
        return True, session
    
    def check_rate_limit(self, identifier: str, limit_type: str, ip_address: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Check rate limits for user/IP.
        
        Args:
            identifier: User ID or IP address
            limit_type: Type of rate limit (api_requests, url_checks, failed_logins)
            ip_address: Client IP address
        
        Returns:
            Tuple of (is_allowed, limit_info)
        """
        # This is a simplified in-memory rate limiter
        # In production, use Redis or similar for distributed rate limiting
        
        current_time = time.time()
        cache_key = f"{limit_type}:{identifier}"
        
        # Get rate limit configuration
        if limit_type == "api_requests":
            limit = self.rate_limit_config["api_requests_per_minute"]
            window = 60  # seconds
        elif limit_type == "url_checks":
            limit = self.rate_limit_config["url_checks_per_hour"]
            window = 3600  # seconds
        elif limit_type == "failed_logins":
            limit = self.rate_limit_config["failed_login_attempts"]
            window = self.rate_limit_config["failed_login_window_minutes"] * 60
        else:
            return True, {"allowed": True}
        
        # Simple sliding window implementation
        if not hasattr(self, '_rate_limit_cache'):
            self._rate_limit_cache = {}
        
        if cache_key not in self._rate_limit_cache:
            self._rate_limit_cache[cache_key] = []
        
        # Clean old entries
        self._rate_limit_cache[cache_key] = [
            timestamp for timestamp in self._rate_limit_cache[cache_key]
            if current_time - timestamp < window
        ]
        
        # Check if limit exceeded
        current_count = len(self._rate_limit_cache[cache_key])
        
        if current_count >= limit:
            return False, {
                "allowed": False,
                "limit": limit,
                "current": current_count,
                "window_seconds": window,
                "retry_after": window - (current_time - min(self._rate_limit_cache[cache_key]))
            }
        
        # Add current request
        self._rate_limit_cache[cache_key].append(current_time)
        
        return True, {
            "allowed": True,
            "limit": limit,
            "current": current_count + 1,
            "window_seconds": window,
            "remaining": limit - current_count - 1
        }
    
    def detect_suspicious_activity(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect suspicious activity in requests.
        """
        suspicious_indicators = []
        risk_score = 0
        
        # Check for malicious patterns in request data
        for key, value in request_data.items():
            if isinstance(value, str):
                # SQL injection detection
                for pattern in self.threat_patterns["sql_injection"]:
                    if any(p in value.lower() for p in pattern.split('|')):
                        suspicious_indicators.append(f"sql_injection_in_{key}")
                        risk_score += 30
                        break
                
                # XSS detection
                for pattern in self.threat_patterns["xss"]:
                    if pattern in value.lower():
                        suspicious_indicators.append(f"xss_in_{key}")
                        risk_score += 25
                        break
                
                # Path traversal detection
                for pattern in self.threat_patterns["path_traversal"]:
                    if pattern in value.lower():
                        suspicious_indicators.append(f"path_traversal_in_{key}")
                        risk_score += 20
                        break
        
        # Check request frequency and patterns
        user_agent = request_data.get("user_agent", "")
        if not user_agent or "bot" in user_agent.lower():
            suspicious_indicators.append("suspicious_user_agent")
            risk_score += 10
        
        # Check for automated requests
        if len(suspicious_indicators) > 2:
            suspicious_indicators.append("multiple_threat_patterns")
            risk_score += 20
        
        return {
            "is_suspicious": risk_score > 30,
            "risk_score": min(risk_score, 100),
            "indicators": suspicious_indicators,
            "recommended_action": self._get_recommended_action(risk_score)
        }
    
    def _get_recommended_action(self, risk_score: int) -> str:
        """
        Get recommended action based on risk score.
        """
        if risk_score >= 80:
            return "block"
        elif risk_score >= 50:
            return "challenge"
        elif risk_score >= 30:
            return "monitor"
        else:
            return "allow"
    
    def validate_api_key(self, api_key: str, required_permissions: List[str] = None) -> Tuple[bool, Optional[APIKey]]:
        """
        Validate API key and check permissions.
        """
        # Hash the API key for lookup
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        api_key_obj = self.db.query(APIKey).filter(
            and_(
                APIKey.key_hash == key_hash,
                APIKey.is_active == True
            )
        ).first()
        
        if not api_key_obj:
            return False, None
        
        # Check expiration
        if api_key_obj.expires_at and api_key_obj.expires_at < datetime.now(timezone.utc):
            return False, None
        
        # Check permissions if required
        if required_permissions:
            user_permissions = api_key_obj.permissions or []
            if not all(perm in user_permissions for perm in required_permissions):
                raise AuthorizationError("Insufficient permissions")
        
        # Update last used
        api_key_obj.last_used_at = datetime.now(timezone.utc)
        api_key_obj.usage_count += 1
        self.db.commit()
        
        return True, api_key_obj
    
    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Check IP address reputation.
        """
        # Check cache first
        cache_key = f"ip_rep:{ip_address}"
        current_time = time.time()
        
        if cache_key in self.ip_reputation_cache:
            cached_data, timestamp = self.ip_reputation_cache[cache_key]
            if current_time - timestamp < self.cache_ttl:
                return cached_data
        
        # Simple IP reputation check (in production, use external services)
        reputation_data = {
            "ip_address": ip_address,
            "is_malicious": False,
            "reputation_score": 50,  # Neutral score
            "threat_types": [],
            "last_seen": None,
            "confidence": 0
        }
        
        # Check against known malicious IP patterns
        malicious_patterns = [
            r"^10\.",  # Private IP (shouldn't be external)
            r"^192\.168\.",  # Private IP
            r"^172\.(1[6-9]|2[0-9]|3[01])\.",  # Private IP
            r"^127\.",  # Loopback
            r"^0\.",  # Invalid
            r"^255\.",  # Broadcast
        ]
        
        for pattern in malicious_patterns:
            if __import__('re').match(pattern, ip_address):
                reputation_data["is_malicious"] = True
                reputation_data["reputation_score"] = 10
                reputation_data["threat_types"] = ["private_ip"]
                reputation_data["confidence"] = 90
                break
        
        # Cache the result
        self.ip_reputation_cache[cache_key] = (reputation_data, current_time)
        
        return reputation_data
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], user_id: str = None, ip_address: str = None) -> None:
        """
        Log security events for monitoring and analysis.
        """
        # In production, this would write to a security log system
        security_event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "details": details,
            "severity": self._get_event_severity(event_type)
        }
        
        # For now, just print (in production, use proper logging)
        print(f"SECURITY EVENT: {security_event}")
    
    def _get_event_severity(self, event_type: str) -> str:
        """
        Get severity level for security event.
        """
        high_severity_events = [
            "authentication_failure", "authorization_failure",
            "suspicious_activity", "rate_limit_exceeded",
            "malicious_request", "data_breach_attempt"
        ]
        
        medium_severity_events = [
            "session_expired", "password_change",
            "api_key_usage", "unusual_access_pattern"
        ]
        
        if event_type in high_severity_events:
            return "high"
        elif event_type in medium_severity_events:
            return "medium"
        else:
            return "low"
    
    def generate_security_report(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Generate security report for given time period.
        """
        # Query security-related data from database
        failed_logins = self.db.query(UserSession).filter(
            and_(
                UserSession.created_at >= start_date,
                UserSession.created_at <= end_date,
                UserSession.is_active == False
            )
        ).count()
        
        suspicious_urls = self.db.query(URLCheck).filter(
            and_(
                URLCheck.created_at >= start_date,
                URLCheck.created_at <= end_date,
                URLCheck.threat_level.in_(["MEDIUM", "HIGH"])
            )
        ).count()
        
        total_checks = self.db.query(URLCheck).filter(
            and_(
                URLCheck.created_at >= start_date,
                URLCheck.created_at <= end_date
            )
        ).count()
        
        return {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat()
            },
            "metrics": {
                "total_url_checks": total_checks,
                "suspicious_urls_detected": suspicious_urls,
                "failed_login_attempts": failed_logins,
                "threat_detection_rate": (suspicious_urls / total_checks * 100) if total_checks > 0 else 0
            },
            "recommendations": self._generate_security_recommendations({
                "failed_logins": failed_logins,
                "suspicious_urls": suspicious_urls,
                "total_checks": total_checks
            })
        }
    
    def _generate_security_recommendations(self, metrics: Dict[str, int]) -> List[str]:
        """
        Generate security recommendations based on metrics.
        """
        recommendations = []
        
        if metrics["failed_logins"] > 100:
            recommendations.append("Consider implementing additional authentication measures")
        
        if metrics["total_checks"] > 0:
            threat_rate = metrics["suspicious_urls"] / metrics["total_checks"]
            if threat_rate > 0.1:  # More than 10% threats
                recommendations.append("High threat detection rate - review security policies")
        
        if not recommendations:
            recommendations.append("Security metrics are within normal ranges")
        
        return recommendations
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions and return count of cleaned sessions.
        """
        expired_sessions = self.db.query(UserSession).filter(
            or_(
                UserSession.expires_at < datetime.now(timezone.utc),
                and_(
                    UserSession.last_activity_at.isnot(None),
                    UserSession.last_activity_at < datetime.now(timezone.utc) - timedelta(hours=self.session_config["max_idle_hours"])
                )
            )
        ).all()
        
        count = len(expired_sessions)
        
        for session in expired_sessions:
            session.is_active = False
        
        self.db.commit()
        
        return count
#!/usr/bin/env python3
"""
LinkShield Backend Security Service

Pure business logic security service for threat detection, compliance monitoring,
and security policy enforcement. Database operations are handled by controllers.
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

from linkshield.config.settings import get_settings


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
    Pure business logic security service for authentication, authorization, and threat detection.
    Database operations are handled by controllers.
    """
    
    def __init__(self):
        self.settings = get_settings()
        
        # Initialize encryption
        self.fernet = Fernet(self.settings.SECURE_LOG_ENCRYPTION_KEY.encode() if self.settings.SECURE_LOG_ENCRYPTION_KEY else Fernet.generate_key())
        
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
        Create JWT token for user session with key rotation support.
        """
        try:
            # Try to use the new key manager for enhanced security
            from linkshield.security.jwt_key_manager import get_jwt_key_manager
            import asyncio
            
            # Get current event loop or create new one
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            # Use key manager if available
            key_manager = get_jwt_key_manager()
            signing_key = loop.run_until_complete(key_manager.get_current_signing_key())
            
            payload = {
                "user_id": str(user_id),
                "session_id": str(session_id),
                "key_id": signing_key.key_id,  # Include key ID for verification
                "iat": datetime.now(timezone.utc),
                "exp": datetime.now(timezone.utc) + timedelta(hours=expires_hours),
                "iss": "linkshield-api",
                "aud": "linkshield-client"
            }
            
            token = jwt.encode(payload, signing_key.key_value, algorithm=signing_key.algorithm)
            
            # Update key usage statistics
            loop.run_until_complete(key_manager.update_key_usage(signing_key.key_id))
            
            return token
            
        except Exception:
            # Fallback to legacy key if key manager fails
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
        Verify and decode JWT token with key rotation support.
        """
        try:
            # Try to use the new key manager for enhanced security
            from linkshield.security.jwt_key_manager import get_jwt_key_manager
            import asyncio
            
            # Get current event loop or create new one
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            # First, try to decode without verification to get key_id
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            key_id = unverified_payload.get("key_id")
            
            if key_id:
                # Token has key_id, use key manager for verification
                key_manager = get_jwt_key_manager()
                verification_keys = loop.run_until_complete(key_manager.get_verification_keys())
                
                # Try each verification key
                for jwt_key in verification_keys:
                    if jwt_key.key_id == key_id:
                        try:
                            payload = jwt.decode(
                                token,
                                jwt_key.key_value,
                                algorithms=[jwt_key.algorithm],
                                audience="linkshield-client",
                                issuer="linkshield-api"
                            )
                            
                            # Update key usage statistics
                            loop.run_until_complete(key_manager.update_key_usage(jwt_key.key_id))
                            return payload
                            
                        except jwt.InvalidTokenError:
                            continue
                
                # If no matching key found, try all verification keys
                for jwt_key in verification_keys:
                    try:
                        payload = jwt.decode(
                            token,
                            jwt_key.key_value,
                            algorithms=[jwt_key.algorithm],
                            audience="linkshield-client",
                            issuer="linkshield-api"
                        )
                        
                        # Update key usage statistics
                        loop.run_until_complete(key_manager.update_key_usage(jwt_key.key_id))
                        return payload
                        
                    except jwt.InvalidTokenError:
                        continue
            
            # Fallback to legacy key verification for tokens without key_id
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
        except Exception:
            # Fallback to legacy key if key manager fails
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
    
    def validate_session_data(self, session_data: Dict, user_id: str) -> Tuple[bool, Optional[Dict]]:
        """
        Validate session data without database queries.
        
        Args:
            session_data: Dictionary containing session information
            user_id: User ID to validate against
            
        Returns:
            Tuple of (is_valid, validation_result)
        """
        if not session_data:
            return False, {"error": "No session data provided"}
        
        # Check if session belongs to user
        if str(session_data.get("user_id")) != str(user_id):
            return False, {"error": "Session does not belong to user"}
        
        # Check if session is active
        if not session_data.get("is_active", False):
            return False, {"error": "Session is not active"}
        
        # Check session expiration
        if self.validate_session_expiry(session_data):
            return False, {"error": "Session has expired"}
        
        # Check idle timeout
        if self.validate_session_idle_timeout(session_data):
            return False, {"error": "Session idle timeout exceeded"}
        
        return True, {"status": "valid", "session_id": session_data.get("id")}
    
    def validate_session_expiry(self, session_data: Dict) -> bool:
        """
        Check if session is expired.
        
        Args:
            session_data: Dictionary containing session information
            
        Returns:
            True if session is expired, False otherwise
        """
        expires_at = session_data.get("expires_at")
        if not expires_at:
            return False
        
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        
        return expires_at < datetime.now(timezone.utc)
    
    def validate_session_idle_timeout(self, session_data: Dict) -> bool:
        """
        Check idle timeout.
        
        Args:
            session_data: Dictionary containing session information
            
        Returns:
            True if idle timeout exceeded, False otherwise
        """
        last_activity = session_data.get("last_activity_at")
        if not last_activity:
            return False
        
        if isinstance(last_activity, str):
            last_activity = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
        
        idle_timeout = timedelta(hours=self.session_config["max_idle_hours"])
        return (datetime.now(timezone.utc) - last_activity) > idle_timeout
    
    def validate_api_key_data(self, api_key_data: Dict, required_permissions: List[str]) -> Tuple[bool, Optional[Dict]]:
        """
        Validate API key data without database queries.
        
        Args:
            api_key_data: Dictionary containing API key information
            required_permissions: List of required permissions
            
        Returns:
            Tuple of (is_valid, validation_result)
        """
        if not api_key_data:
            return False, {"error": "No API key data provided"}
        
        # Check if API key is active
        if not api_key_data.get("is_active", False):
            return False, {"error": "API key is not active"}
        
        # Check expiration
        expires_at = api_key_data.get("expires_at")
        if expires_at:
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            
            if expires_at < datetime.now(timezone.utc):
                return False, {"error": "API key has expired"}
        
        # Check permissions
        if required_permissions:
            user_permissions = api_key_data.get("permissions", [])
            missing_permissions = [perm for perm in required_permissions if perm not in user_permissions]
            
            if missing_permissions:
                return False, {
                    "error": "Insufficient permissions",
                    "missing_permissions": missing_permissions
                }
        
        return True, {"status": "valid", "api_key_id": api_key_data.get("id")}
    
    def process_security_report_data(self, sessions_data: List, url_checks_data: List, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Process security data for reporting.
        
        Args:
            sessions_data: List of session records
            url_checks_data: List of URL check records
            start_date: Report start date
            end_date: Report end date
            
        Returns:
            Processed security report data
        """
        # Count failed logins (inactive sessions)
        failed_logins = len([s for s in sessions_data if not s.get("is_active", True)])
        
        # Count suspicious URLs
        suspicious_urls = len([u for u in url_checks_data if u.get("threat_level") in ["MEDIUM", "HIGH"]])
        
        total_checks = len(url_checks_data)
        
        metrics = {
            "total_url_checks": total_checks,
            "suspicious_urls_detected": suspicious_urls,
            "failed_login_attempts": failed_logins,
            "threat_detection_rate": (suspicious_urls / total_checks * 100) if total_checks > 0 else 0
        }
        
        return {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat()
            },
            "metrics": metrics,
            "recommendations": self.format_security_recommendations(metrics)
        }
    
    def identify_expired_sessions(self, sessions_data: List) -> List[str]:
        """
        Identify expired session IDs.
        
        Args:
            sessions_data: List of session records
            
        Returns:
            List of expired session IDs
        """
        expired_session_ids = []
        now = datetime.now(timezone.utc)
        idle_timeout = timedelta(hours=self.session_config["max_idle_hours"])
        
        for session in sessions_data:
            session_id = session.get("id")
            if not session_id:
                continue
            
            # Check expiration
            expires_at = session.get("expires_at")
            if expires_at:
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                
                if expires_at < now:
                    expired_session_ids.append(str(session_id))
                    continue
            
            # Check idle timeout
            last_activity = session.get("last_activity_at")
            if last_activity:
                if isinstance(last_activity, str):
                    last_activity = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
                
                if (now - last_activity) > idle_timeout:
                    expired_session_ids.append(str(session_id))
        
        return expired_session_ids
    
    def calculate_security_metrics(self, data: Dict) -> Dict[str, Any]:
        """
        Calculate security metrics from data.
        
        Args:
            data: Dictionary containing security data
            
        Returns:
            Calculated security metrics
        """
        total_requests = data.get("total_requests", 0)
        blocked_requests = data.get("blocked_requests", 0)
        suspicious_requests = data.get("suspicious_requests", 0)
        
        return {
            "block_rate": (blocked_requests / total_requests * 100) if total_requests > 0 else 0,
            "suspicious_rate": (suspicious_requests / total_requests * 100) if total_requests > 0 else 0,
            "security_score": max(0, 100 - (blocked_requests + suspicious_requests) / max(total_requests, 1) * 100)
        }
    
    def format_security_recommendations(self, metrics: Dict) -> List[str]:
        """
        Format security recommendations based on metrics.
        
        Args:
            metrics: Dictionary containing security metrics
            
        Returns:
            List of security recommendations
        """
        recommendations = []
        
        failed_logins = metrics.get("failed_login_attempts", 0)
        if failed_logins > 100:
            recommendations.append("Consider implementing additional authentication measures")
        
        total_checks = metrics.get("total_url_checks", 0)
        suspicious_urls = metrics.get("suspicious_urls_detected", 0)
        
        if total_checks > 0:
            threat_rate = suspicious_urls / total_checks
            if threat_rate > 0.1:  # More than 10% threats
                recommendations.append("High threat detection rate - review security policies")
        
        if not recommendations:
            recommendations.append("Security metrics are within normal ranges")
        
        return recommendations
    
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
    
    def log_security_event(self, event_type: str, details: Dict[str, Any], user_id: str = None, ip_address: str = None) -> Dict[str, Any]:
        """
        Format security event for logging (database operations handled by controllers).
        
        Args:
            event_type: Type of security event
            details: Event details
            user_id: Optional user ID
            ip_address: Optional IP address
            
        Returns:
            Formatted security event data
        """
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "details": details,
            "severity": self._get_event_severity(event_type)
        }
    
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
"""
Security Compliance Service

Implements comprehensive security compliance checks for:
- REQ-012: OWASP Authentication Cheat Sheet compliance
- REQ-013: Password policy enforcement
- REQ-014: MFA for administrative accounts

This service ensures the application meets security standards and regulatory requirements.
"""

import re
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass
import bcrypt
from passlib.context import CryptContext
from passlib.hash import pbkdf2_sha256

logger = logging.getLogger(__name__)

class ComplianceLevel(Enum):
    """Security compliance levels"""
    COMPLIANT = "compliant"
    WARNING = "warning"
    NON_COMPLIANT = "non_compliant"
    CRITICAL = "critical"

class AuthenticationStandard(Enum):
    """OWASP authentication standards"""
    PASSWORD_STORAGE = "password_storage"
    SESSION_MANAGEMENT = "session_management"
    AUTHENTICATION_FLOW = "authentication_flow"
    ACCOUNT_LOCKOUT = "account_lockout"
    CREDENTIAL_RECOVERY = "credential_recovery"
    MULTI_FACTOR_AUTH = "multi_factor_auth"

class PasswordPolicyViolation(Enum):
    """Password policy violation types"""
    TOO_SHORT = "too_short"
    TOO_LONG = "too_long"
    NO_UPPERCASE = "no_uppercase"
    NO_LOWERCASE = "no_lowercase"
    NO_DIGITS = "no_digits"
    NO_SPECIAL_CHARS = "no_special_chars"
    COMMON_PASSWORD = "common_password"
    PERSONAL_INFO = "personal_info"
    REUSED_PASSWORD = "reused_password"
    DICTIONARY_WORD = "dictionary_word"

@dataclass
class ComplianceResult:
    """Result of a compliance check"""
    standard: str
    level: ComplianceLevel
    passed: bool
    score: float  # 0-100
    violations: List[str]
    recommendations: List[str]
    timestamp: datetime
    details: Dict[str, Any]

@dataclass
class PasswordPolicyConfig:
    """Password policy configuration"""
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special_chars: bool = True
    min_special_chars: int = 1
    min_digits: int = 1
    prevent_common_passwords: bool = True
    prevent_personal_info: bool = True
    password_history_count: int = 12
    max_age_days: int = 90
    complexity_score_threshold: int = 60

@dataclass
class MFARequirement:
    """Multi-factor authentication requirement"""
    user_id: str
    role: str
    requires_mfa: bool
    mfa_methods: List[str]
    grace_period_hours: int = 24
    enforcement_date: datetime
    exemption_reason: Optional[str] = None

class SecurityComplianceService:
    """
    Comprehensive security compliance service implementing OWASP standards,
    password policies, and MFA requirements.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the compliance service with configuration"""
        self.config = config or {}
        self.password_policy = PasswordPolicyConfig(**self.config.get('password_policy', {}))
        
        # Initialize password context for secure hashing
        self.pwd_context = CryptContext(
            schemes=["pbkdf2_sha256", "bcrypt"],
            default="pbkdf2_sha256",
            pbkdf2_sha256__default_rounds=100000,
            bcrypt__default_rounds=12
        )
        
        # Common weak passwords list (subset for demonstration)
        self.common_passwords = {
            "password", "123456", "password123", "admin", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "master",
            "123456789", "12345678", "12345", "1234567890",
            "abc123", "Password1", "password1", "123123"
        }
        
        # Dictionary words (basic implementation)
        self.dictionary_words = {
            "computer", "internet", "security", "network", "system",
            "database", "application", "software", "hardware", "server"
        }
        
        logger.info("Security compliance service initialized")

    def check_owasp_authentication_compliance(self, auth_config: Dict) -> ComplianceResult:
        """
        Check compliance with OWASP Authentication Cheat Sheet (REQ-012)
        
        Args:
            auth_config: Authentication configuration to validate
            
        Returns:
            ComplianceResult with OWASP compliance status
        """
        violations = []
        recommendations = []
        score = 100
        
        # Check password storage compliance
        password_storage_score = self._check_password_storage(auth_config)
        if password_storage_score < 100:
            violations.append("Password storage does not meet OWASP standards")
            recommendations.append("Use bcrypt, scrypt, or Argon2 for password hashing")
            score -= (100 - password_storage_score) * 0.3
        
        # Check session management
        session_score = self._check_session_management(auth_config)
        if session_score < 100:
            violations.append("Session management needs improvement")
            recommendations.append("Implement secure session tokens and proper timeout")
            score -= (100 - session_score) * 0.25
        
        # Check authentication flow
        auth_flow_score = self._check_authentication_flow(auth_config)
        if auth_flow_score < 100:
            violations.append("Authentication flow has security gaps")
            recommendations.append("Implement proper error handling and rate limiting")
            score -= (100 - auth_flow_score) * 0.2
        
        # Check account lockout policy
        lockout_score = self._check_account_lockout(auth_config)
        if lockout_score < 100:
            violations.append("Account lockout policy insufficient")
            recommendations.append("Implement progressive delays and account lockout")
            score -= (100 - lockout_score) * 0.15
        
        # Check credential recovery
        recovery_score = self._check_credential_recovery(auth_config)
        if recovery_score < 100:
            violations.append("Credential recovery process needs strengthening")
            recommendations.append("Use secure tokens and time-limited recovery links")
            score -= (100 - recovery_score) * 0.1
        
        # Determine compliance level
        if score >= 95:
            level = ComplianceLevel.COMPLIANT
        elif score >= 80:
            level = ComplianceLevel.WARNING
        elif score >= 60:
            level = ComplianceLevel.NON_COMPLIANT
        else:
            level = ComplianceLevel.CRITICAL
        
        return ComplianceResult(
            standard="OWASP Authentication Cheat Sheet",
            level=level,
            passed=score >= 80,
            score=max(0, score),
            violations=violations,
            recommendations=recommendations,
            timestamp=datetime.utcnow(),
            details={
                "password_storage_score": password_storage_score,
                "session_score": session_score,
                "auth_flow_score": auth_flow_score,
                "lockout_score": lockout_score,
                "recovery_score": recovery_score
            }
        )

    def validate_password_policy(self, password: str, user_info: Optional[Dict] = None) -> ComplianceResult:
        """
        Validate password against security policy (REQ-013)
        
        Args:
            password: Password to validate
            user_info: Optional user information for personal info checks
            
        Returns:
            ComplianceResult with password policy compliance
        """
        violations = []
        recommendations = []
        score = 100
        
        # Length checks
        if len(password) < self.password_policy.min_length:
            violations.append(f"Password too short (minimum {self.password_policy.min_length} characters)")
            recommendations.append(f"Use at least {self.password_policy.min_length} characters")
            score -= 20
        
        if len(password) > self.password_policy.max_length:
            violations.append(f"Password too long (maximum {self.password_policy.max_length} characters)")
            score -= 10
        
        # Character requirements
        if self.password_policy.require_uppercase and not re.search(r'[A-Z]', password):
            violations.append("Password must contain uppercase letters")
            recommendations.append("Add at least one uppercase letter (A-Z)")
            score -= 15
        
        if self.password_policy.require_lowercase and not re.search(r'[a-z]', password):
            violations.append("Password must contain lowercase letters")
            recommendations.append("Add at least one lowercase letter (a-z)")
            score -= 15
        
        if self.password_policy.require_digits:
            digit_count = len(re.findall(r'\d', password))
            if digit_count < self.password_policy.min_digits:
                violations.append(f"Password must contain at least {self.password_policy.min_digits} digits")
                recommendations.append("Add more numbers (0-9)")
                score -= 15
        
        if self.password_policy.require_special_chars:
            special_count = len(re.findall(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
            if special_count < self.password_policy.min_special_chars:
                violations.append(f"Password must contain at least {self.password_policy.min_special_chars} special characters")
                recommendations.append("Add special characters (!@#$%^&*)")
                score -= 15
        
        # Common password check
        if self.password_policy.prevent_common_passwords:
            if password.lower() in self.common_passwords:
                violations.append("Password is too common")
                recommendations.append("Use a unique, non-dictionary password")
                score -= 25
        
        # Dictionary word check
        if password.lower() in self.dictionary_words:
            violations.append("Password contains dictionary words")
            recommendations.append("Avoid common dictionary words")
            score -= 15
        
        # Personal information check
        if self.password_policy.prevent_personal_info and user_info:
            if self._contains_personal_info(password, user_info):
                violations.append("Password contains personal information")
                recommendations.append("Avoid using personal information in passwords")
                score -= 20
        
        # Complexity score
        complexity_score = self._calculate_password_complexity(password)
        if complexity_score < self.password_policy.complexity_score_threshold:
            violations.append(f"Password complexity too low (score: {complexity_score})")
            recommendations.append("Use a more complex combination of characters")
            score -= (self.password_policy.complexity_score_threshold - complexity_score) * 0.5
        
        # Determine compliance level
        if score >= 90:
            level = ComplianceLevel.COMPLIANT
        elif score >= 70:
            level = ComplianceLevel.WARNING
        elif score >= 50:
            level = ComplianceLevel.NON_COMPLIANT
        else:
            level = ComplianceLevel.CRITICAL
        
        return ComplianceResult(
            standard="Password Policy",
            level=level,
            passed=score >= 70,
            score=max(0, score),
            violations=violations,
            recommendations=recommendations,
            timestamp=datetime.utcnow(),
            details={
                "length": len(password),
                "complexity_score": complexity_score,
                "character_types": self._analyze_character_types(password)
            }
        )

    def check_mfa_compliance(self, user_id: str, user_role: str, mfa_status: Dict) -> ComplianceResult:
        """
        Check MFA compliance for administrative accounts (REQ-014)
        
        Args:
            user_id: User identifier
            user_role: User role (admin, user, etc.)
            mfa_status: Current MFA configuration
            
        Returns:
            ComplianceResult with MFA compliance status
        """
        violations = []
        recommendations = []
        score = 100
        
        # Define roles requiring MFA
        admin_roles = {'admin', 'super_admin', 'system_admin', 'security_admin'}
        requires_mfa = user_role.lower() in admin_roles
        
        if requires_mfa:
            # Check if MFA is enabled
            if not mfa_status.get('enabled', False):
                violations.append("MFA required for administrative accounts")
                recommendations.append("Enable multi-factor authentication immediately")
                score -= 50
            
            # Check MFA methods
            enabled_methods = mfa_status.get('methods', [])
            if len(enabled_methods) < 1:
                violations.append("No MFA methods configured")
                recommendations.append("Configure at least one MFA method (TOTP, SMS, or hardware token)")
                score -= 30
            
            # Check for backup methods
            if len(enabled_methods) < 2:
                violations.append("No backup MFA method configured")
                recommendations.append("Configure a backup MFA method for account recovery")
                score -= 20
            
            # Check MFA method strength
            weak_methods = {'sms', 'email'}
            if any(method in weak_methods for method in enabled_methods):
                violations.append("Weak MFA methods detected")
                recommendations.append("Use TOTP or hardware tokens instead of SMS/email")
                score -= 15
            
            # Check grace period compliance
            setup_date = mfa_status.get('setup_date')
            if setup_date:
                days_since_setup = (datetime.utcnow() - setup_date).days
                if days_since_setup > 30 and not mfa_status.get('enabled'):
                    violations.append("MFA setup grace period exceeded")
                    score -= 25
        
        # Check for regular users with elevated permissions
        elevated_permissions = mfa_status.get('elevated_permissions', [])
        if elevated_permissions and not mfa_status.get('enabled'):
            violations.append("MFA recommended for users with elevated permissions")
            recommendations.append("Consider enabling MFA for enhanced security")
            score -= 10
        
        # Determine compliance level
        if requires_mfa:
            if score >= 95:
                level = ComplianceLevel.COMPLIANT
            elif score >= 80:
                level = ComplianceLevel.WARNING
            elif score >= 60:
                level = ComplianceLevel.NON_COMPLIANT
            else:
                level = ComplianceLevel.CRITICAL
        else:
            level = ComplianceLevel.COMPLIANT if score >= 90 else ComplianceLevel.WARNING
        
        return ComplianceResult(
            standard="MFA for Administrative Accounts",
            level=level,
            passed=score >= 80 if requires_mfa else score >= 70,
            score=max(0, score),
            violations=violations,
            recommendations=recommendations,
            timestamp=datetime.utcnow(),
            details={
                "requires_mfa": requires_mfa,
                "user_role": user_role,
                "enabled_methods": enabled_methods,
                "elevated_permissions": elevated_permissions
            }
        )

    def generate_compliance_report(self, user_id: str, include_details: bool = True) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report for a user
        
        Args:
            user_id: User to generate report for
            include_details: Whether to include detailed findings
            
        Returns:
            Comprehensive compliance report
        """
        report = {
            "user_id": user_id,
            "generated_at": datetime.utcnow().isoformat(),
            "overall_compliance": ComplianceLevel.COMPLIANT.value,
            "compliance_score": 0,
            "checks_performed": [],
            "violations_summary": {},
            "recommendations": []
        }
        
        # This would integrate with actual user data in a real implementation
        # For now, we'll return the structure
        
        logger.info(f"Generated compliance report for user {user_id}")
        return report

    def _check_password_storage(self, config: Dict) -> float:
        """Check password storage compliance"""
        score = 100
        
        hash_algorithm = config.get('password_hash_algorithm', '').lower()
        if hash_algorithm not in ['bcrypt', 'scrypt', 'argon2', 'pbkdf2']:
            score -= 50
        
        if hash_algorithm == 'md5' or hash_algorithm == 'sha1':
            score -= 80  # Critical vulnerability
        
        rounds = config.get('hash_rounds', 0)
        if hash_algorithm == 'bcrypt' and rounds < 10:
            score -= 20
        elif hash_algorithm == 'pbkdf2' and rounds < 100000:
            score -= 20
        
        return max(0, score)

    def _check_session_management(self, config: Dict) -> float:
        """Check session management compliance"""
        score = 100
        
        if not config.get('secure_cookies', False):
            score -= 25
        
        if not config.get('httponly_cookies', False):
            score -= 25
        
        session_timeout = config.get('session_timeout_minutes', 0)
        if session_timeout > 480:  # 8 hours
            score -= 20
        elif session_timeout == 0:  # No timeout
            score -= 40
        
        if not config.get('csrf_protection', False):
            score -= 30
        
        return max(0, score)

    def _check_authentication_flow(self, config: Dict) -> float:
        """Check authentication flow compliance"""
        score = 100
        
        if not config.get('rate_limiting', False):
            score -= 30
        
        if not config.get('secure_error_messages', False):
            score -= 20
        
        if not config.get('login_attempt_logging', False):
            score -= 25
        
        if not config.get('https_only', False):
            score -= 25
        
        return max(0, score)

    def _check_account_lockout(self, config: Dict) -> float:
        """Check account lockout policy compliance"""
        score = 100
        
        max_attempts = config.get('max_login_attempts', 0)
        if max_attempts == 0 or max_attempts > 10:
            score -= 40
        
        lockout_duration = config.get('lockout_duration_minutes', 0)
        if lockout_duration < 15:
            score -= 30
        
        if not config.get('progressive_delays', False):
            score -= 30
        
        return max(0, score)

    def _check_credential_recovery(self, config: Dict) -> float:
        """Check credential recovery compliance"""
        score = 100
        
        if not config.get('secure_reset_tokens', False):
            score -= 40
        
        token_expiry = config.get('reset_token_expiry_minutes', 0)
        if token_expiry > 60 or token_expiry == 0:
            score -= 30
        
        if not config.get('rate_limit_reset_requests', False):
            score -= 30
        
        return max(0, score)

    def _contains_personal_info(self, password: str, user_info: Dict) -> bool:
        """Check if password contains personal information"""
        password_lower = password.lower()
        
        # Check common personal info fields
        personal_fields = ['name', 'email', 'username', 'company', 'phone']
        
        for field in personal_fields:
            value = user_info.get(field, '')
            if value and len(value) > 2 and value.lower() in password_lower:
                return True
        
        return False

    def _calculate_password_complexity(self, password: str) -> float:
        """Calculate password complexity score (0-100)"""
        score = 0
        
        # Length bonus
        score += min(len(password) * 2, 25)
        
        # Character variety
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            score += 15
        
        # Pattern diversity
        unique_chars = len(set(password))
        score += min(unique_chars * 2, 20)
        
        # Entropy bonus for randomness
        if not self._has_obvious_patterns(password):
            score += 10
        
        return min(score, 100)

    def _analyze_character_types(self, password: str) -> Dict[str, int]:
        """Analyze character types in password"""
        return {
            "uppercase": len(re.findall(r'[A-Z]', password)),
            "lowercase": len(re.findall(r'[a-z]', password)),
            "digits": len(re.findall(r'\d', password)),
            "special": len(re.findall(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password)),
            "unique_chars": len(set(password))
        }

    def _has_obvious_patterns(self, password: str) -> bool:
        """Check for obvious patterns in password"""
        # Check for sequential characters
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            return True
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            return True
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            return True
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1234', 'abcd']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                return True
        
        return False
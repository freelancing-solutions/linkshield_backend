#!/usr/bin/env python3
"""
LinkShield Security Validation Script

Comprehensive security validation tool that checks all security implementations
against the requirements and success criteria defined in the security specification.

This script performs:
- Configuration validation
- Security component testing
- Performance benchmarking
- Compliance checking
- Integration validation
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import argparse

import redis.asyncio as redis
import jwt
from pydantic import BaseModel, Field

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from config.settings import get_settings
    from security.jwt_blacklist import JWTBlacklistService
    from security.csrf_protection import CSRFProtectionService
    from security.rate_limiting import RateLimitService
    from security.session_security import SessionManager
    from security.api_key_security import APIKeyManager
    from security.performance_monitor import SecurityPerformanceMonitor
    from security.notification_system import NotificationSystem
except ImportError as e:
    print(f"Import error: {e}")
    print("Note: Some security modules may not be fully implemented yet.")
    print("This validation will check what's available and report on missing components.")
    
    # Create mock classes for missing components
    class MockService:
        def __init__(self, *args, **kwargs):
            pass
        
        async def __aenter__(self):
            return self
        
        async def __aexit__(self, *args):
            pass
    
    # Set defaults for missing imports
    try:
        from config.settings import get_settings
    except ImportError:
        def get_settings():
            return type('Settings', (), {
                'jwt_secret_key': 'test-secret',
                'redis_url': 'redis://localhost:6379',
                'csrf_secret_key': 'test-csrf-secret'
            })()
    
    try:
        from security.jwt_blacklist import JWTBlacklistService
    except ImportError:
        JWTBlacklistService = MockService
    
    try:
        from security.csrf_protection import CSRFProtectionService
    except ImportError:
        CSRFProtectionService = MockService
    
    try:
        from security.rate_limiting import RateLimitService
    except ImportError:
        RateLimitService = MockService
    
    try:
        from security.session_security import SessionManager
    except ImportError:
        SessionManager = MockService
    
    try:
        from security.api_key_security import APIKeyManager
    except ImportError:
        APIKeyManager = MockService
    
    try:
        from security.performance_monitor import SecurityPerformanceMonitor
    except ImportError:
        SecurityPerformanceMonitor = MockService
    
    try:
        from security.notification_system import NotificationSystem
    except ImportError:
        NotificationSystem = MockService
from security.security_event_logger import SecurityEventLogger


class ValidationResult(BaseModel):
    """Validation result model"""
    component: str
    test_name: str
    status: str  # "PASS", "FAIL", "WARNING", "SKIP"
    message: str
    duration_ms: float
    details: Optional[Dict[str, Any]] = None


class SecurityValidationReport(BaseModel):
    """Security validation report model"""
    timestamp: datetime
    environment: str
    total_tests: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    total_duration_ms: float
    results: List[ValidationResult]
    summary: Dict[str, Any]


class SecurityValidator:
    """Comprehensive security validation tool"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize security validator"""
        self.settings = get_settings()
        self.results: List[ValidationResult] = []
        self.start_time = time.time()
        
        # Initialize logger
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize Redis connection
        self.redis_client = None
        
        # Initialize security components
        self.jwt_blacklist = None
        self.csrf_service = None
        self.rate_limiter = None
        self.session_manager = None
        self.api_key_manager = None
        self.performance_monitor = None
        self.notification_system = None
        self.security_logger = None
    
    async def initialize_components(self):
        """Initialize security components for testing"""
        try:
            # Initialize Redis
            self.redis_client = redis.Redis.from_url(
                self.settings.REDIS_URL,
                decode_responses=True
            )
            await self.redis_client.ping()
            
            # Initialize security components
            self.security_logger = SecurityEventLogger()
            self.jwt_blacklist = JWTBlacklistService(self.redis_client, self.security_logger)
            self.csrf_service = CSRFProtectionService(secret_key=self.settings.CSRF_SECRET_KEY)
            self.rate_limiter = RateLimitService(self.redis_client)
            self.session_manager = SessionManager(self.redis_client, self.security_logger)
            self.api_key_manager = APIKeyManager(self.redis_client, self.security_logger)
            self.performance_monitor = SecurityPerformanceMonitor(self.redis_client)
            self.notification_system = NotificationSystem()
            
            self.logger.info("Security components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            raise
    
    async def cleanup_components(self):
        """Cleanup security components"""
        try:
            if self.redis_client:
                await self.redis_client.close()
            self.logger.info("Security components cleaned up successfully")
        except Exception as e:
            self.logger.error(f"Failed to cleanup components: {e}")
    
    def add_result(self, component: str, test_name: str, status: str, 
                   message: str, duration_ms: float, details: Optional[Dict] = None):
        """Add validation result"""
        result = ValidationResult(
            component=component,
            test_name=test_name,
            status=status,
            message=message,
            duration_ms=duration_ms,
            details=details
        )
        self.results.append(result)
        
        # Log result
        log_level = {
            "PASS": logging.INFO,
            "FAIL": logging.ERROR,
            "WARNING": logging.WARNING,
            "SKIP": logging.INFO
        }.get(status, logging.INFO)
        
        self.logger.log(log_level, f"{component}.{test_name}: {status} - {message}")
    
    async def validate_configuration(self):
        """Validate security configuration"""
        component = "Configuration"
        
        # Test 1: Environment Variables
        start_time = time.time()
        try:
            required_vars = [
                "JWT_SECRET_KEY",
                "CSRF_SECRET_KEY", 
                "SESSION_SECRET_KEY",
                "REDIS_URL"
            ]
            
            missing_vars = []
            for var in required_vars:
                if not getattr(self.settings, var, None):
                    missing_vars.append(var)
            
            if missing_vars:
                self.add_result(
                    component, "environment_variables", "FAIL",
                    f"Missing required environment variables: {missing_vars}",
                    (time.time() - start_time) * 1000,
                    {"missing_variables": missing_vars}
                )
            else:
                self.add_result(
                    component, "environment_variables", "PASS",
                    "All required environment variables are set",
                    (time.time() - start_time) * 1000
                )
        except Exception as e:
            self.add_result(
                component, "environment_variables", "FAIL",
                f"Configuration validation failed: {e}",
                (time.time() - start_time) * 1000
            )
        
        # Test 2: Secret Key Strength
        start_time = time.time()
        try:
            weak_keys = []
            
            # Check JWT secret key
            if len(self.settings.JWT_SECRET_KEY) < 32:
                weak_keys.append("JWT_SECRET_KEY")
            
            # Check CSRF secret key
            if len(self.settings.CSRF_SECRET_KEY) < 32:
                weak_keys.append("CSRF_SECRET_KEY")
            
            # Check session secret key
            if len(self.settings.SESSION_SECRET_KEY) < 32:
                weak_keys.append("SESSION_SECRET_KEY")
            
            if weak_keys:
                self.add_result(
                    component, "secret_key_strength", "WARNING",
                    f"Weak secret keys detected: {weak_keys}",
                    (time.time() - start_time) * 1000,
                    {"weak_keys": weak_keys}
                )
            else:
                self.add_result(
                    component, "secret_key_strength", "PASS",
                    "All secret keys meet minimum length requirements",
                    (time.time() - start_time) * 1000
                )
        except Exception as e:
            self.add_result(
                component, "secret_key_strength", "FAIL",
                f"Secret key validation failed: {e}",
                (time.time() - start_time) * 1000
            )
        
        # Test 3: Redis Connectivity
        start_time = time.time()
        try:
            await self.redis_client.ping()
            self.add_result(
                component, "redis_connectivity", "PASS",
                "Redis connection successful",
                (time.time() - start_time) * 1000
            )
        except Exception as e:
            self.add_result(
                component, "redis_connectivity", "FAIL",
                f"Redis connection failed: {e}",
                (time.time() - start_time) * 1000
            )
    
    async def validate_jwt_blacklist(self):
        """Validate JWT blacklist functionality"""
        component = "JWT_Blacklist"
        
        # Test 1: Token Revocation
        start_time = time.time()
        try:
            test_jti = f"test_jti_{int(time.time())}"
            await self.jwt_blacklist.revoke_token(
                token_jti=test_jti,
                user_id="test_user",
                reason="validation_test"
            )
            
            is_blacklisted = await self.jwt_blacklist.is_token_blacklisted(test_jti)
            
            if is_blacklisted:
                self.add_result(
                    component, "token_revocation", "PASS",
                    "Token revocation working correctly",
                    (time.time() - start_time) * 1000
                )
            else:
                self.add_result(
                    component, "token_revocation", "FAIL",
                    "Token revocation not working",
                    (time.time() - start_time) * 1000
                )
        except Exception as e:
            self.add_result(
                component, "token_revocation", "FAIL",
                f"Token revocation test failed: {e}",
                (time.time() - start_time) * 1000
            )
        
        # Test 2: Performance Benchmark
        start_time = time.time()
        try:
            # Test multiple token checks
            test_tokens = [f"perf_test_{i}" for i in range(100)]
            
            # Revoke tokens
            for token in test_tokens:
                await self.jwt_blacklist.revoke_token(
                    token_jti=token,
                    user_id="perf_test_user",
                    reason="performance_test"
                )
            
            # Benchmark token checking
            check_start = time.time()
            for token in test_tokens:
                await self.jwt_blacklist.is_token_blacklisted(token)
            check_duration = (time.time() - check_start) * 1000
            
            avg_check_time = check_duration / len(test_tokens)
            
            if avg_check_time < 10:  # Less than 10ms per check
                self.add_result(
                    component, "performance_benchmark", "PASS",
                    f"Average token check time: {avg_check_time:.2f}ms",
                    (time.time() - start_time) * 1000,
                    {"average_check_time_ms": avg_check_time}
                )
            else:
                self.add_result(
                    component, "performance_benchmark", "WARNING",
                    f"Token check time above threshold: {avg_check_time:.2f}ms",
                    (time.time() - start_time) * 1000,
                    {"average_check_time_ms": avg_check_time}
                )
        except Exception as e:
            self.add_result(
                component, "performance_benchmark", "FAIL",
                f"Performance benchmark failed: {e}",
                (time.time() - start_time) * 1000
            )
    
    async def validate_csrf_protection(self):
        """Validate CSRF protection functionality"""
        component = "CSRF_Protection"
        
        # Test 1: Token Generation and Validation
        start_time = time.time()
        try:
            token = await self.csrf_service.generate_token(
                session_id="test_session",
                user_id="test_user"
            )
            
            is_valid = await self.csrf_service.validate_token(
                token=token.token,
                session_id="test_session",
                user_id="test_user"
            )
            
            if is_valid:
                self.add_result(
                    component, "token_generation_validation", "PASS",
                    "CSRF token generation and validation working",
                    (time.time() - start_time) * 1000
                )
            else:
                self.add_result(
                    component, "token_generation_validation", "FAIL",
                    "CSRF token validation failed",
                    (time.time() - start_time) * 1000
                )
        except Exception as e:
            self.add_result(
                component, "token_generation_validation", "FAIL",
                f"CSRF token test failed: {e}",
                (time.time() - start_time) * 1000
            )
        
        # Test 2: Invalid Token Rejection
        start_time = time.time()
        try:
            is_valid = await self.csrf_service.validate_token(
                token="invalid_token",
                session_id="test_session",
                user_id="test_user"
            )
            
            if not is_valid:
                self.add_result(
                    component, "invalid_token_rejection", "PASS",
                    "Invalid CSRF tokens properly rejected",
                    (time.time() - start_time) * 1000
                )
            else:
                self.add_result(
                    component, "invalid_token_rejection", "FAIL",
                    "Invalid CSRF token was accepted",
                    (time.time() - start_time) * 1000
                )
        except Exception as e:
            self.add_result(
                component, "invalid_token_rejection", "FAIL",
                f"Invalid token rejection test failed: {e}",
                (time.time() - start_time) * 1000
            )
    
    async def validate_rate_limiting(self):
        """Validate rate limiting functionality"""
        component = "Rate_Limiting"
        
        # Test 1: Rate Limit Enforcement
        start_time = time.time()
        try:
            test_key = f"rate_test_{int(time.time())}"
            limit = 5
            window = 60
            
            # Make requests up to limit
            allowed_count = 0
            for i in range(limit + 2):
                result = await self.rate_limiter.check_rate_limit(
                    key=test_key,
                    limit=limit,
                    window=window,
                    algorithm="sliding_window"
                )
                if result.allowed:
                    allowed_count += 1
            
            if allowed_count == limit:
                self.add_result(
                    component, "rate_limit_enforcement", "PASS",
                    f"Rate limiting working correctly (allowed {allowed_count}/{limit})",
                    (time.time() - start_time) * 1000,
                    {"allowed_requests": allowed_count, "limit": limit}
                )
            else:
                self.add_result(
                    component, "rate_limit_enforcement", "FAIL",
                    f"Rate limiting not working (allowed {allowed_count}/{limit})",
                    (time.time() - start_time) * 1000,
                    {"allowed_requests": allowed_count, "limit": limit}
                )
        except Exception as e:
            self.add_result(
                component, "rate_limit_enforcement", "FAIL",
                f"Rate limiting test failed: {e}",
                (time.time() - start_time) * 1000
            )
        
        # Test 2: Performance Benchmark
        start_time = time.time()
        try:
            test_key = f"perf_test_{int(time.time())}"
            
            # Benchmark rate limit checks
            check_start = time.time()
            for i in range(100):
                await self.rate_limiter.check_rate_limit(
                    key=f"{test_key}_{i}",
                    limit=1000,
                    window=3600,
                    algorithm="sliding_window"
                )
            check_duration = (time.time() - check_start) * 1000
            
            avg_check_time = check_duration / 100
            
            if avg_check_time < 5:  # Less than 5ms per check
                self.add_result(
                    component, "performance_benchmark", "PASS",
                    f"Average rate limit check time: {avg_check_time:.2f}ms",
                    (time.time() - start_time) * 1000,
                    {"average_check_time_ms": avg_check_time}
                )
            else:
                self.add_result(
                    component, "performance_benchmark", "WARNING",
                    f"Rate limit check time above threshold: {avg_check_time:.2f}ms",
                    (time.time() - start_time) * 1000,
                    {"average_check_time_ms": avg_check_time}
                )
        except Exception as e:
            self.add_result(
                component, "performance_benchmark", "FAIL",
                f"Performance benchmark failed: {e}",
                (time.time() - start_time) * 1000
            )
    
    async def validate_session_security(self):
        """Validate session security functionality"""
        component = "Session_Security"
        
        # Test 1: Session Creation and Validation
        start_time = time.time()
        try:
            session = await self.session_manager.create_session(
                user_id="test_user",
                ip_address="192.168.1.100",
                user_agent="Test-Agent/1.0"
            )
            
            is_valid = await self.session_manager.validate_session(
                session_id=session.session_id,
                ip_address="192.168.1.100",
                user_agent="Test-Agent/1.0"
            )
            
            if is_valid:
                self.add_result(
                    component, "session_creation_validation", "PASS",
                    "Session creation and validation working",
                    (time.time() - start_time) * 1000
                )
            else:
                self.add_result(
                    component, "session_creation_validation", "FAIL",
                    "Session validation failed",
                    (time.time() - start_time) * 1000
                )
        except Exception as e:
            self.add_result(
                component, "session_creation_validation", "FAIL",
                f"Session test failed: {e}",
                (time.time() - start_time) * 1000
            )
        
        # Test 2: IP Address Validation
        start_time = time.time()
        try:
            session = await self.session_manager.create_session(
                user_id="test_user_ip",
                ip_address="192.168.1.100",
                user_agent="Test-Agent/1.0"
            )
            
            # Try to validate from different IP
            is_valid = await self.session_manager.validate_session(
                session_id=session.session_id,
                ip_address="192.168.1.200",  # Different IP
                user_agent="Test-Agent/1.0"
            )
            
            if not is_valid:
                self.add_result(
                    component, "ip_address_validation", "PASS",
                    "IP address validation working correctly",
                    (time.time() - start_time) * 1000
                )
            else:
                self.add_result(
                    component, "ip_address_validation", "FAIL",
                    "IP address validation not working",
                    (time.time() - start_time) * 1000
                )
        except Exception as e:
            self.add_result(
                component, "ip_address_validation", "FAIL",
                f"IP address validation test failed: {e}",
                (time.time() - start_time) * 1000
            )
    
    async def validate_api_key_security(self):
        """Validate API key security functionality"""
        component = "API_Key_Security"
        
        # Test 1: API Key Generation and Validation
        start_time = time.time()
        try:
            api_key = await self.api_key_manager.generate_api_key(
                user_id="test_user",
                name="validation_test_key",
                permissions=["read", "write"]
            )
            
            is_valid = await self.api_key_manager.validate_api_key(api_key.key)
            
            if is_valid:
                self.add_result(
                    component, "api_key_generation_validation", "PASS",
                    "API key generation and validation working",
                    (time.time() - start_time) * 1000
                )
            else:
                self.add_result(
                    component, "api_key_generation_validation", "FAIL",
                    "API key validation failed",
                    (time.time() - start_time) * 1000
                )
        except Exception as e:
            self.add_result(
                component, "api_key_generation_validation", "FAIL",
                f"API key test failed: {e}",
                (time.time() - start_time) * 1000
            )
        
        # Test 2: API Key Revocation
        start_time = time.time()
        try:
            api_key = await self.api_key_manager.generate_api_key(
                user_id="test_user_revoke",
                name="revocation_test_key",
                permissions=["read"]
            )
            
            # Revoke the key
            await self.api_key_manager.revoke_api_key(api_key.key_id)
            
            # Try to validate revoked key
            is_valid = await self.api_key_manager.validate_api_key(api_key.key)
            
            if not is_valid:
                self.add_result(
                    component, "api_key_revocation", "PASS",
                    "API key revocation working correctly",
                    (time.time() - start_time) * 1000
                )
            else:
                self.add_result(
                    component, "api_key_revocation", "FAIL",
                    "API key revocation not working",
                    (time.time() - start_time) * 1000
                )
        except Exception as e:
            self.add_result(
                component, "api_key_revocation", "FAIL",
                f"API key revocation test failed: {e}",
                (time.time() - start_time) * 1000
            )
    
    async def validate_performance_monitoring(self):
        """Validate performance monitoring functionality"""
        component = "Performance_Monitoring"
        
        # Test 1: Metric Collection
        start_time = time.time()
        try:
            # Record some test metrics
            await self.performance_monitor.record_jwt_validation_time(15.5)
            await self.performance_monitor.record_csrf_generation_time(8.2)
            await self.performance_monitor.record_rate_limit_check_time(3.1)
            
            # Get metrics
            metrics = await self.performance_monitor.get_performance_summary(hours=1)
            
            if metrics and len(metrics) > 0:
                self.add_result(
                    component, "metric_collection", "PASS",
                    "Performance metric collection working",
                    (time.time() - start_time) * 1000,
                    {"metrics_count": len(metrics)}
                )
            else:
                self.add_result(
                    component, "metric_collection", "FAIL",
                    "Performance metric collection not working",
                    (time.time() - start_time) * 1000
                )
        except Exception as e:
            self.add_result(
                component, "metric_collection", "FAIL",
                f"Performance monitoring test failed: {e}",
                (time.time() - start_time) * 1000
            )
    
    async def validate_notification_system(self):
        """Validate notification system functionality"""
        component = "Notification_System"
        
        # Test 1: Notification Creation
        start_time = time.time()
        try:
            await self.notification_system.send_security_alert(
                title="Validation Test Alert",
                message="This is a test security alert for validation",
                severity="medium",
                details={"test": True}
            )
            
            self.add_result(
                component, "notification_creation", "PASS",
                "Notification system working",
                (time.time() - start_time) * 1000
            )
        except Exception as e:
            self.add_result(
                component, "notification_creation", "WARNING",
                f"Notification system test failed (may be expected in test env): {e}",
                (time.time() - start_time) * 1000
            )
    
    async def validate_integration(self):
        """Validate cross-component integration"""
        component = "Integration"
        
        # Test 1: JWT + Session Integration
        start_time = time.time()
        try:
            # Create session
            session = await self.session_manager.create_session(
                user_id="integration_test_user",
                ip_address="192.168.1.100",
                user_agent="Integration-Test/1.0"
            )
            
            # Create JWT token
            test_jti = f"integration_test_{int(time.time())}"
            
            # Validate session
            session_valid = await self.session_manager.validate_session(
                session_id=session.session_id,
                ip_address="192.168.1.100",
                user_agent="Integration-Test/1.0"
            )
            
            # Check JWT blacklist
            jwt_blacklisted = await self.jwt_blacklist.is_token_blacklisted(test_jti)
            
            if session_valid and not jwt_blacklisted:
                self.add_result(
                    component, "jwt_session_integration", "PASS",
                    "JWT and session integration working",
                    (time.time() - start_time) * 1000
                )
            else:
                self.add_result(
                    component, "jwt_session_integration", "FAIL",
                    f"Integration test failed: session_valid={session_valid}, jwt_blacklisted={jwt_blacklisted}",
                    (time.time() - start_time) * 1000
                )
        except Exception as e:
            self.add_result(
                component, "jwt_session_integration", "FAIL",
                f"Integration test failed: {e}",
                (time.time() - start_time) * 1000
            )
    
    async def run_comprehensive_validation(self):
        """Run comprehensive security validation"""
        self.logger.info("Starting comprehensive security validation...")
        
        try:
            await self.initialize_components()
            
            # Run all validation tests
            await self.validate_configuration()
            await self.validate_jwt_blacklist()
            await self.validate_csrf_protection()
            await self.validate_rate_limiting()
            await self.validate_session_security()
            await self.validate_api_key_security()
            await self.validate_performance_monitoring()
            await self.validate_notification_system()
            await self.validate_integration()
            
        except Exception as e:
            self.logger.error(f"Validation failed: {e}")
            raise
        finally:
            await self.cleanup_components()
    
    async def run_quick_validation(self):
        """Run quick security validation (essential tests only)"""
        self.logger.info("Starting quick security validation...")
        
        try:
            await self.initialize_components()
            
            # Run essential validation tests
            await self.validate_configuration()
            await self.validate_jwt_blacklist()
            await self.validate_csrf_protection()
            await self.validate_rate_limiting()
            
        except Exception as e:
            self.logger.error(f"Quick validation failed: {e}")
            raise
        finally:
            await self.cleanup_components()
    
    def generate_report(self) -> SecurityValidationReport:
        """Generate validation report"""
        total_duration = (time.time() - self.start_time) * 1000
        
        # Count results by status
        passed = len([r for r in self.results if r.status == "PASS"])
        failed = len([r for r in self.results if r.status == "FAIL"])
        warnings = len([r for r in self.results if r.status == "WARNING"])
        skipped = len([r for r in self.results if r.status == "SKIP"])
        
        # Generate summary
        summary = {
            "overall_status": "PASS" if failed == 0 else "FAIL",
            "success_rate": (passed / len(self.results)) * 100 if self.results else 0,
            "components_tested": len(set(r.component for r in self.results)),
            "average_test_duration_ms": sum(r.duration_ms for r in self.results) / len(self.results) if self.results else 0,
            "critical_failures": [r for r in self.results if r.status == "FAIL"],
            "performance_warnings": [r for r in self.results if r.status == "WARNING" and "performance" in r.test_name.lower()]
        }
        
        return SecurityValidationReport(
            timestamp=datetime.utcnow(),
            environment=os.getenv("ENVIRONMENT", "development"),
            total_tests=len(self.results),
            passed=passed,
            failed=failed,
            warnings=warnings,
            skipped=skipped,
            total_duration_ms=total_duration,
            results=self.results,
            summary=summary
        )
    
    def print_report(self, report: SecurityValidationReport):
        """Print validation report to console"""
        print("\n" + "="*80)
        print("LINKSHIELD SECURITY VALIDATION REPORT")
        print("="*80)
        print(f"Timestamp: {report.timestamp}")
        print(f"Environment: {report.environment}")
        print(f"Total Duration: {report.total_duration_ms:.2f}ms")
        print()
        
        print("SUMMARY:")
        print(f"  Total Tests: {report.total_tests}")
        print(f"  Passed: {report.passed}")
        print(f"  Failed: {report.failed}")
        print(f"  Warnings: {report.warnings}")
        print(f"  Skipped: {report.skipped}")
        print(f"  Success Rate: {report.summary['success_rate']:.1f}%")
        print(f"  Overall Status: {report.summary['overall_status']}")
        print()
        
        # Group results by component
        components = {}
        for result in report.results:
            if result.component not in components:
                components[result.component] = []
            components[result.component].append(result)
        
        print("DETAILED RESULTS:")
        for component, results in components.items():
            print(f"\n{component}:")
            for result in results:
                status_symbol = {
                    "PASS": "✓",
                    "FAIL": "✗",
                    "WARNING": "⚠",
                    "SKIP": "○"
                }.get(result.status, "?")
                
                print(f"  {status_symbol} {result.test_name}: {result.message} ({result.duration_ms:.2f}ms)")
        
        # Print critical failures
        if report.summary["critical_failures"]:
            print("\nCRITICAL FAILURES:")
            for failure in report.summary["critical_failures"]:
                print(f"  ✗ {failure.component}.{failure.test_name}: {failure.message}")
        
        # Print performance warnings
        if report.summary["performance_warnings"]:
            print("\nPERFORMANCE WARNINGS:")
            for warning in report.summary["performance_warnings"]:
                print(f"  ⚠ {warning.component}.{warning.test_name}: {warning.message}")
        
        print("\n" + "="*80)
    
    def save_report(self, report: SecurityValidationReport, filename: str):
        """Save validation report to file"""
        with open(filename, 'w') as f:
            json.dump(report.dict(), f, indent=2, default=str)
        
        self.logger.info(f"Validation report saved to {filename}")


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="LinkShield Security Validation")
    parser.add_argument("--comprehensive", action="store_true", help="Run comprehensive validation")
    parser.add_argument("--quick", action="store_true", help="Run quick validation")
    parser.add_argument("--report", action="store_true", help="Generate detailed report")
    parser.add_argument("--output", help="Output file for report")
    
    args = parser.parse_args()
    
    # Default to comprehensive if no mode specified
    if not args.comprehensive and not args.quick:
        args.comprehensive = True
    
    validator = SecurityValidator()
    
    try:
        if args.comprehensive:
            await validator.run_comprehensive_validation()
        elif args.quick:
            await validator.run_quick_validation()
        
        # Generate and display report
        report = validator.generate_report()
        validator.print_report(report)
        
        # Save report if requested
        if args.output:
            validator.save_report(report, args.output)
        elif args.report:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_validation_report_{timestamp}.json"
            validator.save_report(report, filename)
        
        # Exit with appropriate code
        if report.failed > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except Exception as e:
        logging.error(f"Validation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
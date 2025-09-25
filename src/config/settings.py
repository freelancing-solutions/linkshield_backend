#!/usr/bin/env python3
"""
LinkShield Backend API Settings

Configuration management using Pydantic settings with environment variable support.
Handles all application configuration including database, security, and external services.
"""

import os
import json
from functools import lru_cache
from typing import List, Optional

from pydantic import Field, validator, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings with environment variable support.
    All settings can be overridden via environment variables with LINKSHIELD_ prefix.
    """
    
    # Application Settings
    APP_NAME: str = "LinkShield API"
    APP_URL: str  = "https://www.linkshield.site"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(default="development", env="LINKSHIELD_ENVIRONMENT")
    DEBUG: bool = Field(default=True, env="LINKSHIELD_DEBUG")
    LOG_LEVEL: str = Field(default="INFO", env="LINKSHIELD_LOG_LEVEL")
    
    # Server Settings
    HOST: str = Field(default="0.0.0.0", env="LINKSHIELD_HOST")
    PORT: int = Field(default=8000, env="LINKSHIELD_PORT")
    ALLOWED_HOSTS: List[str] = Field(default=["localhost", "127.0.0.1"], env="LINKSHIELD_ALLOWED_HOSTS")
    ALLOWED_ORIGINS: List[str] = Field(default=["http://localhost:3000"], env="LINKSHIELD_ALLOWED_ORIGINS")
    
    # Database Settings
    DATABASE_URL: str = Field(
        default="postgresql://linkshield:linkshield@localhost:5432/linkshield",
        env="LINKSHIELD_DATABASE_URL"
    )
    DATABASE_POOL_SIZE: int = Field(default=10, env="LINKSHIELD_DATABASE_POOL_SIZE")
    DATABASE_MAX_OVERFLOW: int = Field(default=20, env="LINKSHIELD_DATABASE_MAX_OVERFLOW")
    DATABASE_POOL_TIMEOUT: int = Field(default=30, env="LINKSHIELD_DATABASE_POOL_TIMEOUT")
    DATABASE_POOL_RECYCLE: int = Field(default=3600, env="LINKSHIELD_DATABASE_POOL_RECYCLE")
    
    # Redis Settings (for caching and rate limiting)
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="LINKSHIELD_REDIS_URL")
    REDIS_PASSWORD: Optional[str] = Field(default=None, env="LINKSHIELD_REDIS_PASSWORD")
    REDIS_DB: int = Field(default=0, env="LINKSHIELD_REDIS_DB")
    REDIS_POOL_SIZE: int = Field(default=10, env="LINKSHIELD_REDIS_POOL_SIZE")
    REDIS_MAX_CONNECTIONS: int = Field(default=10, env="LINKSHIELD_REDIS_MAX_CONNECTIONS")
    REDIS_CONNECTION_TIMEOUT: int = Field(default=5, env="LINKSHIELD_REDIS_CONNECTION_TIMEOUT")
    REDIS_SOCKET_TIMEOUT: int = Field(default=5, env="LINKSHIELD_REDIS_SOCKET_TIMEOUT")
    REDIS_SSL_ENABLED: bool = Field(default=False, env="LINKSHIELD_REDIS_SSL_ENABLED")
    REDIS_SSL_CERT_REQS: str = Field(default="required", env="LINKSHIELD_REDIS_SSL_CERT_REQS")
    
    # Security Settings
    SECRET_KEY: str = Field(
        default="your-secret-key-change-in-production",
        env="LINKSHIELD_SECRET_KEY"
    )
    JWT_SECRET_KEY: str = Field(
        default="your-jwt-secret-key-change-in-production",
        env="LINKSHIELD_JWT_SECRET_KEY"
    )
    JWT_ALGORITHM: str = Field(default="HS256", env="LINKSHIELD_JWT_ALGORITHM")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="LINKSHIELD_JWT_ACCESS_TOKEN_EXPIRE_MINUTES")
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, env="LINKSHIELD_JWT_REFRESH_TOKEN_EXPIRE_DAYS")
    PASSWORD_RESET_TOKEN_EXPIRE_HOURS: int = Field(default=1, env="LINKSHIELD_PASSWORD_RESET_TOKEN_EXPIRE_HOURS")
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = Field(default=24, env="LINKSHIELD_EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS")
    
    # Session Management Settings (Phase 2 Security Enhancement)
    # Addresses session duration mismatches and security policy enforcement
    SESSION_DURATION_DAYS: int = Field(default=7, env="LINKSHIELD_SESSION_DURATION_DAYS")
    SESSION_MAX_IDLE_HOURS: int = Field(default=24, env="LINKSHIELD_SESSION_MAX_IDLE_HOURS")
    SESSION_MAX_CONCURRENT_SESSIONS: int = Field(default=5, env="LINKSHIELD_SESSION_MAX_CONCURRENT_SESSIONS")
    SESSION_REQUIRE_FRESH_LOGIN_HOURS: int = Field(default=168, env="LINKSHIELD_SESSION_REQUIRE_FRESH_LOGIN_HOURS")  # 7 days
    SESSION_SECURE_COOKIE: bool = Field(default=True, env="LINKSHIELD_SESSION_SECURE_COOKIE")
    SESSION_HTTPONLY_COOKIE: bool = Field(default=True, env="LINKSHIELD_SESSION_HTTPONLY_COOKIE")
    SESSION_SAMESITE_COOKIE: str = Field(default="Strict", env="LINKSHIELD_SESSION_SAMESITE_COOKIE")
    SESSION_INVALIDATE_ON_PASSWORD_CHANGE: bool = Field(default=True, env="LINKSHIELD_SESSION_INVALIDATE_ON_PASSWORD_CHANGE")
    SESSION_TRACK_IP_CHANGES: bool = Field(default=True, env="LINKSHIELD_SESSION_TRACK_IP_CHANGES")
    SESSION_TRACK_USER_AGENT_CHANGES: bool = Field(default=True, env="LINKSHIELD_SESSION_TRACK_USER_AGENT_CHANGES")
    SESSION_CLEANUP_INTERVAL_HOURS: int = Field(default=1, env="LINKSHIELD_SESSION_CLEANUP_INTERVAL_HOURS")
    SESSION_EXTEND_ON_ACTIVITY: bool = Field(default=True, env="LINKSHIELD_SESSION_EXTEND_ON_ACTIVITY")
    SESSION_NOTIFICATION_ON_NEW_LOGIN: bool = Field(default=True, env="LINKSHIELD_SESSION_NOTIFICATION_ON_NEW_LOGIN")
    
    # Password Settings
    PASSWORD_MIN_LENGTH: int = Field(default=8, env="LINKSHIELD_PASSWORD_MIN_LENGTH")
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True, env="LINKSHIELD_PASSWORD_REQUIRE_UPPERCASE")
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True, env="LINKSHIELD_PASSWORD_REQUIRE_LOWERCASE")
    PASSWORD_REQUIRE_NUMBERS: bool = Field(default=True, env="LINKSHIELD_PASSWORD_REQUIRE_NUMBERS")
    PASSWORD_REQUIRE_SPECIAL: bool = Field(default=True, env="LINKSHIELD_PASSWORD_REQUIRE_SPECIAL")
    
    # Rate Limiting Settings
    RATE_LIMIT_ENABLED: bool = Field(default=True, env="LINKSHIELD_RATE_LIMIT_ENABLED")
    RATE_LIMIT_DEFAULT: str = Field(default="100/hour", env="LINKSHIELD_RATE_LIMIT_DEFAULT")
    RATE_LIMIT_AUTH: str = Field(default="1000/hour", env="LINKSHIELD_RATE_LIMIT_AUTH")
    RATE_LIMIT_CHECK: str = Field(default="50/hour", env="LINKSHIELD_RATE_LIMIT_CHECK")
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = Field(default=60, env="LINKSHIELD_RATE_LIMIT_REQUESTS_PER_MINUTE")
    RATE_LIMIT_BURST_SIZE: int = Field(default=10, env="LINKSHIELD_RATE_LIMIT_BURST_SIZE")
    
    # Distributed Rate Limiting Settings
    DISTRIBUTED_RATE_LIMIT_ENABLED: bool = Field(default=False, env="LINKSHIELD_DISTRIBUTED_RATE_LIMIT_ENABLED")
    DISTRIBUTED_RATE_LIMIT_WINDOW_SIZE: int = Field(default=60, env="LINKSHIELD_DISTRIBUTED_RATE_LIMIT_WINDOW_SIZE")
    DISTRIBUTED_RATE_LIMIT_MAX_REQUESTS: int = Field(default=1000, env="LINKSHIELD_DISTRIBUTED_RATE_LIMIT_MAX_REQUESTS")
    DISTRIBUTED_RATE_LIMIT_REDIS_KEY_PREFIX: str = Field(default="linkshield:rate_limit", env="LINKSHIELD_DISTRIBUTED_RATE_LIMIT_REDIS_KEY_PREFIX")
    DISTRIBUTED_RATE_LIMIT_CLEANUP_INTERVAL: int = Field(default=300, env="LINKSHIELD_DISTRIBUTED_RATE_LIMIT_CLEANUP_INTERVAL")
    DISTRIBUTED_RATE_LIMIT_SLIDING_WINDOW: bool = Field(default=True, env="LINKSHIELD_DISTRIBUTED_RATE_LIMIT_SLIDING_WINDOW")
    DISTRIBUTED_RATE_LIMIT_BURST_MULTIPLIER: float = Field(default=1.5, env="LINKSHIELD_DISTRIBUTED_RATE_LIMIT_BURST_MULTIPLIER")
    DISTRIBUTED_RATE_LIMIT_WHITELIST_IPS: List[str] = Field(default=[], env="LINKSHIELD_DISTRIBUTED_RATE_LIMIT_WHITELIST_IPS")
    DISTRIBUTED_RATE_LIMIT_BLACKLIST_IPS: List[str] = Field(default=[], env="LINKSHIELD_DISTRIBUTED_RATE_LIMIT_BLACKLIST_IPS")
    DISTRIBUTED_RATE_LIMIT_USER_SPECIFIC: bool = Field(default=True, env="LINKSHIELD_DISTRIBUTED_RATE_LIMIT_USER_SPECIFIC")
    DISTRIBUTED_RATE_LIMIT_ENDPOINT_SPECIFIC: bool = Field(default=True, env="LINKSHIELD_DISTRIBUTED_RATE_LIMIT_ENDPOINT_SPECIFIC")
    
    # SSRF Protection Settings
    SSRF_PROTECTION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SSRF_PROTECTION_ENABLED")
    SSRF_ALLOWED_DOMAINS: List[str] = Field(default=[], env="LINKSHIELD_SSRF_ALLOWED_DOMAINS")
    SSRF_BLOCKED_DOMAINS: List[str] = Field(default=["localhost", "127.0.0.1", "0.0.0.0"], env="LINKSHIELD_SSRF_BLOCKED_DOMAINS")
    SSRF_ALLOWED_PORTS: List[int] = Field(default=[80, 443], env="LINKSHIELD_SSRF_ALLOWED_PORTS")
    SSRF_BLOCKED_PORTS: List[int] = Field(default=[22, 23, 25, 53, 110, 143, 993, 995], env="LINKSHIELD_SSRF_BLOCKED_PORTS")
    SSRF_TIMEOUT: int = Field(default=10, env="LINKSHIELD_SSRF_TIMEOUT")
    SSRF_MAX_REDIRECTS: int = Field(default=3, env="LINKSHIELD_SSRF_MAX_REDIRECTS")
    SSRF_USER_AGENT: str = Field(default="LinkShield-Scanner/1.0", env="LINKSHIELD_SSRF_USER_AGENT")
    SSRF_VERIFY_SSL: bool = Field(default=True, env="LINKSHIELD_SSRF_VERIFY_SSL")
    
    # Error Message Standardization Settings
    ERROR_MESSAGES_STANDARDIZED: bool = Field(default=True, env="LINKSHIELD_ERROR_MESSAGES_STANDARDIZED")
    ERROR_MESSAGES_INCLUDE_DETAILS: bool = Field(default=False, env="LINKSHIELD_ERROR_MESSAGES_INCLUDE_DETAILS")
    ERROR_MESSAGES_LOG_LEVEL: str = Field(default="ERROR", env="LINKSHIELD_ERROR_MESSAGES_LOG_LEVEL")
    ERROR_MESSAGES_SANITIZE_SENSITIVE: bool = Field(default=True, env="LINKSHIELD_ERROR_MESSAGES_SANITIZE_SENSITIVE")
    
    # Security Policy Settings (Phase 2 Security Enhancement)
    # Addresses comprehensive security policy enforcement and compliance requirements
    SECURITY_POLICY_ENFORCEMENT: bool = Field(default=True, env="LINKSHIELD_SECURITY_POLICY_ENFORCEMENT")
    SECURITY_POLICY_STRICT_MODE: bool = Field(default=False, env="LINKSHIELD_SECURITY_POLICY_STRICT_MODE")
    SECURITY_POLICY_AUDIT_MODE: bool = Field(default=True, env="LINKSHIELD_SECURITY_POLICY_AUDIT_MODE")
    
    # Input Validation Policies
    INPUT_VALIDATION_STRICT: bool = Field(default=True, env="LINKSHIELD_INPUT_VALIDATION_STRICT")
    INPUT_VALIDATION_MAX_LENGTH: int = Field(default=10000, env="LINKSHIELD_INPUT_VALIDATION_MAX_LENGTH")
    INPUT_VALIDATION_ALLOW_HTML: bool = Field(default=False, env="LINKSHIELD_INPUT_VALIDATION_ALLOW_HTML")
    INPUT_VALIDATION_SANITIZE_SQL: bool = Field(default=True, env="LINKSHIELD_INPUT_VALIDATION_SANITIZE_SQL")
    INPUT_VALIDATION_BLOCK_SCRIPTS: bool = Field(default=True, env="LINKSHIELD_INPUT_VALIDATION_BLOCK_SCRIPTS")
    INPUT_VALIDATION_ENCODING_CHECK: bool = Field(default=True, env="LINKSHIELD_INPUT_VALIDATION_ENCODING_CHECK")
    
    # Content Security Policies
    CSP_ENABLED: bool = Field(default=True, env="LINKSHIELD_CSP_ENABLED")
    CSP_REPORT_ONLY: bool = Field(default=False, env="LINKSHIELD_CSP_REPORT_ONLY")
    CSP_REPORT_URI: Optional[str] = Field(default=None, env="LINKSHIELD_CSP_REPORT_URI")
    CSP_SCRIPT_SRC: str = Field(default="'self'", env="LINKSHIELD_CSP_SCRIPT_SRC")
    CSP_STYLE_SRC: str = Field(default="'self' 'unsafe-inline'", env="LINKSHIELD_CSP_STYLE_SRC")
    CSP_IMG_SRC: str = Field(default="'self' data: https:", env="LINKSHIELD_CSP_IMG_SRC")
    
    # Compliance and Regulatory Settings
    GDPR_COMPLIANCE_MODE: bool = Field(default=False, env="LINKSHIELD_GDPR_COMPLIANCE_MODE")
    CCPA_COMPLIANCE_MODE: bool = Field(default=False, env="LINKSHIELD_CCPA_COMPLIANCE_MODE")
    SOC2_COMPLIANCE_MODE: bool = Field(default=False, env="LINKSHIELD_SOC2_COMPLIANCE_MODE")
    DATA_RETENTION_POLICY_DAYS: int = Field(default=2555, env="LINKSHIELD_DATA_RETENTION_POLICY_DAYS")  # 7 years
    DATA_ANONYMIZATION_ENABLED: bool = Field(default=True, env="LINKSHIELD_DATA_ANONYMIZATION_ENABLED")
    DATA_EXPORT_ENCRYPTION: bool = Field(default=True, env="LINKSHIELD_DATA_EXPORT_ENCRYPTION")
    
    # Security Headers and Policies
    SECURITY_HEADERS_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_HEADERS_ENABLED")
    HSTS_ENABLED: bool = Field(default=True, env="LINKSHIELD_HSTS_ENABLED")
    HSTS_MAX_AGE: int = Field(default=31536000, env="LINKSHIELD_HSTS_MAX_AGE")  # 1 year
    HSTS_INCLUDE_SUBDOMAINS: bool = Field(default=True, env="LINKSHIELD_HSTS_INCLUDE_SUBDOMAINS")
    X_FRAME_OPTIONS: str = Field(default="DENY", env="LINKSHIELD_X_FRAME_OPTIONS")
    X_CONTENT_TYPE_OPTIONS: str = Field(default="nosniff", env="LINKSHIELD_X_CONTENT_TYPE_OPTIONS")
    REFERRER_POLICY: str = Field(default="strict-origin-when-cross-origin", env="LINKSHIELD_REFERRER_POLICY")
    
    # URL Analysis Settings
    URL_TIMEOUT: int = Field(default=10, env="LINKSHIELD_URL_TIMEOUT")
    MAX_REDIRECTS: int = Field(default=5, env="LINKSHIELD_MAX_REDIRECTS")
    USER_AGENT: str = Field(
        default="LinkShield-Bot/1.0 (+https://linkshield.com/bot)",
        env="LINKSHIELD_USER_AGENT"
    )
    
    # AI/ML Settings
    OPENAI_API_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_OPENAI_API_KEY")
    OPENAI_MODEL: str = Field(default="gpt-3.5-turbo", env="LINKSHIELD_OPENAI_MODEL")
    OPENAI_MAX_TOKENS: int = Field(default=1000, env="LINKSHIELD_OPENAI_MAX_TOKENS")
    
    # External API Keys
    VIRUSTOTAL_API_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_VIRUSTOTAL_API_KEY")
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_GOOGLE_SAFE_BROWSING_API_KEY")
    URLVOID_API_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_URLVOID_API_KEY")
    
    # Bot Configuration
    TWITTER_BOT_BEARER_TOKEN: Optional[str] = Field(default=None, env="LINKSHIELD_TWITTER_BOT_BEARER_TOKEN")
    TELEGRAM_BOT_TOKEN: Optional[str] = Field(default=None, env="LINKSHIELD_TELEGRAM_BOT_TOKEN")
    DISCORD_BOT_TOKEN: Optional[str] = Field(default=None, env="LINKSHIELD_DISCORD_BOT_TOKEN")
    QUICK_ANALYSIS_TIMEOUT_SECONDS: int = Field(default=3, env="LINKSHIELD_QUICK_ANALYSIS_TIMEOUT_SECONDS")
    BOT_RATE_LIMIT_PER_MINUTE: int = Field(default=30, env="LINKSHIELD_BOT_RATE_LIMIT_PER_MINUTE")
    BOT_SERVICE_ACCOUNT_ID: Optional[str] = Field(default=None, env="LINKSHIELD_BOT_SERVICE_ACCOUNT_ID")
    BOT_WEBHOOK_SECRET: Optional[str] = Field(default=None, env="LINKSHIELD_BOT_WEBHOOK_SECRET")
    BOT_CACHE_TTL_SECONDS: int = Field(default=300, env="LINKSHIELD_BOT_CACHE_TTL_SECONDS")
    BOT_MAX_RESPONSE_LENGTH: int = Field(default=2000, env="LINKSHIELD_BOT_MAX_RESPONSE_LENGTH")
    BOT_ENABLE_DEEP_ANALYSIS: bool = Field(default=False, env="LINKSHIELD_BOT_ENABLE_DEEP_ANALYSIS")
    
    # Platform-specific bot settings
    TWITTER_WEBHOOK_SECRET: Optional[str] = Field(default=None, env="LINKSHIELD_TWITTER_WEBHOOK_SECRET")
    TELEGRAM_WEBHOOK_SECRET: Optional[str] = Field(default=None, env="LINKSHIELD_TELEGRAM_WEBHOOK_SECRET")
    DISCORD_WEBHOOK_SECRET: Optional[str] = Field(default=None, env="LINKSHIELD_DISCORD_WEBHOOK_SECRET")
    
    # Bot feature flags
    BOT_ENABLE_TWITTER: bool = Field(default=True, env="LINKSHIELD_BOT_ENABLE_TWITTER")
    BOT_ENABLE_TELEGRAM: bool = Field(default=True, env="LINKSHIELD_BOT_ENABLE_TELEGRAM")
    BOT_ENABLE_DISCORD: bool = Field(default=True, env="LINKSHIELD_BOT_ENABLE_DISCORD")
    
    # Bot analytics and logging
    BOT_ENABLE_ANALYTICS: bool = Field(default=True, env="LINKSHIELD_BOT_ENABLE_ANALYTICS")
    BOT_LOG_INTERACTIONS: bool = Field(default=True, env="LINKSHIELD_BOT_LOG_INTERACTIONS")
    BOT_ANALYTICS_RETENTION_DAYS: int = Field(default=90, env="LINKSHIELD_BOT_ANALYTICS_RETENTION_DAYS")
    
    # Email Settings
    SMTP_HOST: Optional[str] = Field(default=None, env="LINKSHIELD_SMTP_HOST")
    SMTP_PORT: int = Field(default=587, env="LINKSHIELD_SMTP_PORT")
    SMTP_USERNAME: Optional[str] = Field(default=None, env="LINKSHIELD_SMTP_USERNAME")
    SMTP_PASSWORD: Optional[str] = Field(default=None, env="LINKSHIELD_SMTP_PASSWORD")
    SMTP_USE_TLS: bool = Field(default=True, env="LINKSHIELD_SMTP_USE_TLS")
    SMTP_SSL: bool = Field(default=False, env="LINKSHIELD_SMTP_SSL")
    FROM_EMAIL: str = Field(default="noreply@linkshield.com", env="LINKSHIELD_FROM_EMAIL")
    EMAIL_FROM_NAME: str = Field(default="LinkShield", env="LINKSHIELD_EMAIL_FROM_NAME")
    
    # Email Validation Settings (Phase 2 Security Enhancement)
    # Multi-layer email validation to address medium-severity validation issues
    EMAIL_VALIDATION_ENABLED: bool = Field(default=True, env="LINKSHIELD_EMAIL_VALIDATION_ENABLED")
    EMAIL_MX_CHECK_ENABLED: bool = Field(default=True, env="LINKSHIELD_EMAIL_MX_CHECK_ENABLED")
    EMAIL_MX_CHECK_TIMEOUT: int = Field(default=10, env="LINKSHIELD_EMAIL_MX_CHECK_TIMEOUT")
    EMAIL_DISPOSABLE_CHECK_ENABLED: bool = Field(default=True, env="LINKSHIELD_EMAIL_DISPOSABLE_CHECK_ENABLED")
    EMAIL_DISPOSABLE_API_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_EMAIL_DISPOSABLE_API_KEY")
    EMAIL_DISPOSABLE_API_URL: str = Field(default="https://api.disposable.email/check", env="LINKSHIELD_EMAIL_DISPOSABLE_API_URL")
    EMAIL_DOMAIN_WHITELIST: List[str] = Field(default=[], env="LINKSHIELD_EMAIL_DOMAIN_WHITELIST")
    EMAIL_DOMAIN_BLACKLIST: List[str] = Field(default=["tempmail.org", "10minutemail.com", "guerrillamail.com"], env="LINKSHIELD_EMAIL_DOMAIN_BLACKLIST")
    EMAIL_REPUTATION_CHECK_ENABLED: bool = Field(default=False, env="LINKSHIELD_EMAIL_REPUTATION_CHECK_ENABLED")
    EMAIL_REPUTATION_API_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_EMAIL_REPUTATION_API_KEY")
    EMAIL_VALIDATION_CACHE_TTL: int = Field(default=3600, env="LINKSHIELD_EMAIL_VALIDATION_CACHE_TTL")
    EMAIL_VALIDATION_MAX_RETRIES: int = Field(default=3, env="LINKSHIELD_EMAIL_VALIDATION_MAX_RETRIES")
    EMAIL_VALIDATION_STRICT_MODE: bool = Field(default=False, env="LINKSHIELD_EMAIL_VALIDATION_STRICT_MODE")
    
    # Resend API Settings
    RESEND_API_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_RESEND_API_KEY")
    EMAIL_PROVIDER: str = Field(default="resend")
    RESEND_FROM_DOMAIN: Optional[str] = Field(default="https://www.linkshield.site")
    
    # Stripe Settings (for billing)
    STRIPE_PUBLISHABLE_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_STRIPE_PUBLISHABLE_KEY")
    STRIPE_SECRET_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_STRIPE_SECRET_KEY")
    STRIPE_WEBHOOK_SECRET: Optional[str] = Field(default=None, env="LINKSHIELD_STRIPE_WEBHOOK_SECRET")
    
    # Webhook Settings
    WEBHOOK_SECRET: str = Field(default="your-webhook-secret-key", env="LINKSHIELD_WEBHOOK_SECRET")
    WEBHOOK_TIMEOUT: int = Field(default=30, env="LINKSHIELD_WEBHOOK_TIMEOUT")
    
    # Subscription Plans
    FREE_PLAN_DAILY_LIMIT: int = Field(default=10, env="LINKSHIELD_FREE_PLAN_DAILY_LIMIT")
    BASIC_PLAN_DAILY_LIMIT: int = Field(default=100, env="LINKSHIELD_BASIC_PLAN_DAILY_LIMIT")
    PRO_PLAN_DAILY_LIMIT: int = Field(default=1000, env="LINKSHIELD_PRO_PLAN_DAILY_LIMIT")
    ENTERPRISE_PLAN_DAILY_LIMIT: int = Field(default=10000, env="LINKSHIELD_ENTERPRISE_PLAN_DAILY_LIMIT")
    
    # Access Control Settings (Phase 2 Security Enhancement)
    # Addresses anonymous user limits and subscription tier enforcement
    ANONYMOUS_DAILY_LIMIT: int = Field(default=5, env="LINKSHIELD_ANONYMOUS_DAILY_LIMIT")
    ANONYMOUS_HOURLY_LIMIT: int = Field(default=2, env="LINKSHIELD_ANONYMOUS_HOURLY_LIMIT")
    ANONYMOUS_RATE_LIMIT_WINDOW: int = Field(default=3600, env="LINKSHIELD_ANONYMOUS_RATE_LIMIT_WINDOW")  # seconds
    ANONYMOUS_REQUIRE_CAPTCHA: bool = Field(default=True, env="LINKSHIELD_ANONYMOUS_REQUIRE_CAPTCHA")
    ANONYMOUS_BLOCK_AFTER_ATTEMPTS: int = Field(default=10, env="LINKSHIELD_ANONYMOUS_BLOCK_AFTER_ATTEMPTS")
    ANONYMOUS_BLOCK_DURATION_HOURS: int = Field(default=24, env="LINKSHIELD_ANONYMOUS_BLOCK_DURATION_HOURS")
    
    # Subscription Tier Access Control
    SUBSCRIPTION_TIER_ENFORCEMENT: bool = Field(default=True, env="LINKSHIELD_SUBSCRIPTION_TIER_ENFORCEMENT")
    SUBSCRIPTION_GRACE_PERIOD_DAYS: int = Field(default=3, env="LINKSHIELD_SUBSCRIPTION_GRACE_PERIOD_DAYS")
    SUBSCRIPTION_DOWNGRADE_IMMEDIATE: bool = Field(default=False, env="LINKSHIELD_SUBSCRIPTION_DOWNGRADE_IMMEDIATE")
    SUBSCRIPTION_USAGE_RESET_HOUR: int = Field(default=0, env="LINKSHIELD_SUBSCRIPTION_USAGE_RESET_HOUR")  # UTC hour
    SUBSCRIPTION_OVERAGE_ALLOWED: bool = Field(default=False, env="LINKSHIELD_SUBSCRIPTION_OVERAGE_ALLOWED")
    SUBSCRIPTION_OVERAGE_LIMIT_PERCENT: int = Field(default=10, env="LINKSHIELD_SUBSCRIPTION_OVERAGE_LIMIT_PERCENT")
    
    # API Access Control
    API_KEY_REQUIRED_FOR_ANONYMOUS: bool = Field(default=False, env="LINKSHIELD_API_KEY_REQUIRED_FOR_ANONYMOUS")
    API_KEY_RATE_LIMIT_MULTIPLIER: float = Field(default=2.0, env="LINKSHIELD_API_KEY_RATE_LIMIT_MULTIPLIER")
    API_ENDPOINT_ACCESS_CONTROL: bool = Field(default=True, env="LINKSHIELD_API_ENDPOINT_ACCESS_CONTROL")
    API_ADMIN_ENDPOINTS_REQUIRE_2FA: bool = Field(default=True, env="LINKSHIELD_API_ADMIN_ENDPOINTS_REQUIRE_2FA")
    
    # File Upload Settings
    MAX_FILE_SIZE: int = Field(default=10 * 1024 * 1024, env="LINKSHIELD_MAX_FILE_SIZE")  # 10MB
    ALLOWED_FILE_TYPES: List[str] = Field(
        default=[".txt", ".csv", ".json"],
        env="LINKSHIELD_ALLOWED_FILE_TYPES"
    )
    UPLOAD_DIR: str = Field(default="./uploads", env="LINKSHIELD_UPLOAD_DIR")
    
    # Logging Configuration
    LOG_FORMAT: str = Field(default="json", env="LINKSHIELD_LOG_FORMAT")
    LOG_FILE: str = Field(default="logs/linkshield.log", env="LINKSHIELD_LOG_FILE")
    LOG_ROTATION: str = Field(default="1 day", env="LINKSHIELD_LOG_ROTATION")
    LOG_RETENTION: str = Field(default="30 days", env="LINKSHIELD_LOG_RETENTION")
    
    # Audit Logging Configuration (Phase 2 Security Enhancement)
    # Addresses comprehensive audit trail requirements and log sanitization
    AUDIT_LOG_ENABLED: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_ENABLED")
    AUDIT_LOG_FILE: str = Field(default="logs/audit.log", env="LINKSHIELD_AUDIT_LOG_FILE")
    AUDIT_LOG_LEVEL: str = Field(default="INFO", env="LINKSHIELD_AUDIT_LOG_LEVEL")
    AUDIT_LOG_RETENTION_DAYS: int = Field(default=365, env="LINKSHIELD_AUDIT_LOG_RETENTION_DAYS")
    AUDIT_LOG_ROTATION_SIZE: str = Field(default="100MB", env="LINKSHIELD_AUDIT_LOG_ROTATION_SIZE")
    AUDIT_LOG_MAX_FILES: int = Field(default=10, env="LINKSHIELD_AUDIT_LOG_MAX_FILES")
    
    # Audit Event Configuration
    AUDIT_LOG_USER_ACTIONS: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_USER_ACTIONS")
    AUDIT_LOG_ADMIN_ACTIONS: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_ADMIN_ACTIONS")
    AUDIT_LOG_API_CALLS: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_API_CALLS")
    AUDIT_LOG_AUTHENTICATION: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_AUTHENTICATION")
    AUDIT_LOG_AUTHORIZATION_FAILURES: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_AUTHORIZATION_FAILURES")
    AUDIT_LOG_DATA_ACCESS: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_DATA_ACCESS")
    AUDIT_LOG_CONFIGURATION_CHANGES: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_CONFIGURATION_CHANGES")
    
    # Log Sanitization and Privacy
    AUDIT_LOG_SANITIZE_PII: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_SANITIZE_PII")
    AUDIT_LOG_MASK_SENSITIVE_DATA: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_MASK_SENSITIVE_DATA")
    AUDIT_LOG_INCLUDE_REQUEST_BODY: bool = Field(default=False, env="LINKSHIELD_AUDIT_LOG_INCLUDE_REQUEST_BODY")
    AUDIT_LOG_INCLUDE_RESPONSE_BODY: bool = Field(default=False, env="LINKSHIELD_AUDIT_LOG_INCLUDE_RESPONSE_BODY")
    AUDIT_LOG_IP_ANONYMIZATION: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_IP_ANONYMIZATION")
    
    # Compliance and Export
    AUDIT_LOG_COMPLIANCE_MODE: bool = Field(default=False, env="LINKSHIELD_AUDIT_LOG_COMPLIANCE_MODE")
    AUDIT_LOG_EXPORT_FORMAT: str = Field(default="json", env="LINKSHIELD_AUDIT_LOG_EXPORT_FORMAT")
    AUDIT_LOG_INTEGRITY_CHECK: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_INTEGRITY_CHECK")
    
    # Monitoring and Analytics
    SENTRY_DSN: Optional[str] = Field(default=None, env="LINKSHIELD_SENTRY_DSN")
    ANALYTICS_ENABLED: bool = Field(default=True, env="LINKSHIELD_ANALYTICS_ENABLED")
    METRICS_ENABLED: bool = Field(default=True, env="LINKSHIELD_METRICS_ENABLED")
    METRICS_PORT: int = Field(default=9090, env="LINKSHIELD_METRICS_PORT")
    HEALTH_CHECK_INTERVAL: int = Field(default=30, env="LINKSHIELD_HEALTH_CHECK_INTERVAL")
    
    # CORS Configuration
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True)
    CORS_ALLOW_METHODS: List[str] = Field(default=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    CORS_ALLOW_HEADERS: List[str] = Field(default=["*"])
    
    # Background Tasks Configuration
    # Using FastAPI BackgroundTasks instead of Celery
    
    # AI Analysis Configuration
    AI_ANALYSIS_ENABLED: bool = Field(default=True, env="LINKSHIELD_AI_ANALYSIS_ENABLED")
    AI_ANALYSIS_TIMEOUT: int = Field(default=30, env="LINKSHIELD_AI_ANALYSIS_TIMEOUT")
    AI_BATCH_SIZE: int = Field(default=10, env="LINKSHIELD_AI_BATCH_SIZE")
    AI_CONFIDENCE_THRESHOLD: float = Field(default=0.7, env="LINKSHIELD_AI_CONFIDENCE_THRESHOLD")
    
    # Security Scanning Configuration
    SCAN_TIMEOUT: int = Field(default=60, env="LINKSHIELD_SCAN_TIMEOUT")
    SCAN_MAX_RETRIES: int = Field(default=3, env="LINKSHIELD_SCAN_MAX_RETRIES")
    SCAN_BATCH_SIZE: int = Field(default=5, env="LINKSHIELD_SCAN_BATCH_SIZE")
    SCAN_PARALLEL_REQUESTS: int = Field(default=3, env="LINKSHIELD_SCAN_PARALLEL_REQUESTS")
    
    # Cache Configuration
    CACHE_TTL: int = Field(default=3600, env="LINKSHIELD_CACHE_TTL")
    CACHE_MAX_SIZE: int = Field(default=1000, env="LINKSHIELD_CACHE_MAX_SIZE")
    CACHE_ENABLED: bool = Field(default=True, env="LINKSHIELD_CACHE_ENABLED")
    
    # Background Task Configuration
    BACKGROUND_TASKS_ENABLED: bool = Field(default=True, env="LINKSHIELD_BACKGROUND_TASKS_ENABLED")
    BACKGROUND_TASK_TIMEOUT: int = Field(default=3600, env="LINKSHIELD_BACKGROUND_TASK_TIMEOUT")
    BACKGROUND_TASK_MAX_RETRIES: int = Field(default=3, env="LINKSHIELD_BACKGROUND_TASK_MAX_RETRIES")
    BACKGROUND_TASK_RETRY_DELAY: int = Field(default=60, env="LINKSHIELD_BACKGROUND_TASK_RETRY_DELAY")
    BACKGROUND_TASK_CLEANUP_DAYS: int = Field(default=30, env="LINKSHIELD_BACKGROUND_TASK_CLEANUP_DAYS")
    
    # Webhook Configuration
    WEBHOOK_ENABLED: bool = Field(default=True, env="LINKSHIELD_WEBHOOK_ENABLED")
    WEBHOOK_TIMEOUT: int = Field(default=30, env="LINKSHIELD_WEBHOOK_TIMEOUT")
    WEBHOOK_MAX_RETRIES: int = Field(default=3, env="LINKSHIELD_WEBHOOK_MAX_RETRIES")
    WEBHOOK_RETRY_DELAY: int = Field(default=60, env="LINKSHIELD_WEBHOOK_RETRY_DELAY")
    WEBHOOK_SECRET_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_WEBHOOK_SECRET_KEY")
    
    # Task Processing Configuration
    TASK_ASYNC_THRESHOLD: int = Field(default=1000, env="LINKSHIELD_TASK_ASYNC_THRESHOLD")
    TASK_BATCH_SIZE: int = Field(default=100, env="LINKSHIELD_TASK_BATCH_SIZE")
    TASK_PROGRESS_UPDATE_INTERVAL: int = Field(default=10, env="LINKSHIELD_TASK_PROGRESS_UPDATE_INTERVAL")
    
    # Development/Testing
    TEST_DATABASE_URL: str = Field(
        default="postgresql://linkshield_user:password@localhost:5432/linkshield_test_db",
        env="LINKSHIELD_TEST_DATABASE_URL"
    )
    TEST_MODE: bool = Field(default=False, env="LINKSHIELD_TEST_MODE")
    MOCK_EXTERNAL_APIS: bool = Field(default=False, env="LINKSHIELD_MOCK_EXTERNAL_APIS")
    
    # Social Protection Configuration
    # Core Social Protection Settings
    SOCIAL_PROTECTION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SOCIAL_PROTECTION_ENABLED")
    SOCIAL_PROTECTION_DEBUG_MODE: bool = Field(default=False, env="LINKSHIELD_SOCIAL_PROTECTION_DEBUG_MODE")
    SOCIAL_PROTECTION_LOG_LEVEL: str = Field(default="INFO", env="LINKSHIELD_SOCIAL_PROTECTION_LOG_LEVEL")
    
    # Extension Data Processing Configuration
    EXTENSION_DATA_PROCESSING_ENABLED: bool = Field(default=True, env="LINKSHIELD_EXTENSION_DATA_PROCESSING_ENABLED")
    EXTENSION_DATA_MAX_SIZE_MB: int = Field(default=10, env="LINKSHIELD_EXTENSION_DATA_MAX_SIZE_MB")
    EXTENSION_DATA_BATCH_SIZE: int = Field(default=100, env="LINKSHIELD_EXTENSION_DATA_BATCH_SIZE")
    EXTENSION_DATA_PROCESSING_TIMEOUT: int = Field(default=30, env="LINKSHIELD_EXTENSION_DATA_PROCESSING_TIMEOUT")
    EXTENSION_DATA_RETENTION_DAYS: int = Field(default=90, env="LINKSHIELD_EXTENSION_DATA_RETENTION_DAYS")
    EXTENSION_DATA_ENCRYPTION_ENABLED: bool = Field(default=True, env="LINKSHIELD_EXTENSION_DATA_ENCRYPTION_ENABLED")
    
    # Social Media Scanning Configuration
    SOCIAL_SCAN_ENABLED: bool = Field(default=True, env="LINKSHIELD_SOCIAL_SCAN_ENABLED")
    SOCIAL_SCAN_MAX_CONCURRENT_SCANS: int = Field(default=5, env="LINKSHIELD_SOCIAL_SCAN_MAX_CONCURRENT_SCANS")
    SOCIAL_SCAN_TIMEOUT_MINUTES: int = Field(default=30, env="LINKSHIELD_SOCIAL_SCAN_TIMEOUT_MINUTES")
    SOCIAL_SCAN_RETRY_ATTEMPTS: int = Field(default=3, env="LINKSHIELD_SOCIAL_SCAN_RETRY_ATTEMPTS")
    SOCIAL_SCAN_RETRY_DELAY_SECONDS: int = Field(default=60, env="LINKSHIELD_SOCIAL_SCAN_RETRY_DELAY_SECONDS")
    SOCIAL_SCAN_RATE_LIMIT_PER_HOUR: int = Field(default=100, env="LINKSHIELD_SOCIAL_SCAN_RATE_LIMIT_PER_HOUR")
    SOCIAL_SCAN_CACHE_TTL_HOURS: int = Field(default=24, env="LINKSHIELD_SOCIAL_SCAN_CACHE_TTL_HOURS")
    
    # Content Risk Assessment Configuration
    CONTENT_RISK_ASSESSMENT_ENABLED: bool = Field(default=True, env="LINKSHIELD_CONTENT_RISK_ASSESSMENT_ENABLED")
    CONTENT_RISK_AI_ANALYSIS_ENABLED: bool = Field(default=True, env="LINKSHIELD_CONTENT_RISK_AI_ANALYSIS_ENABLED")
    CONTENT_RISK_SEVERITY_THRESHOLD: float = Field(default=0.7, env="LINKSHIELD_CONTENT_RISK_SEVERITY_THRESHOLD")
    CONTENT_RISK_AUTO_QUARANTINE_ENABLED: bool = Field(default=False, env="LINKSHIELD_CONTENT_RISK_AUTO_QUARANTINE_ENABLED")
    CONTENT_RISK_NOTIFICATION_ENABLED: bool = Field(default=True, env="LINKSHIELD_CONTENT_RISK_NOTIFICATION_ENABLED")
    CONTENT_RISK_RETENTION_DAYS: int = Field(default=365, env="LINKSHIELD_CONTENT_RISK_RETENTION_DAYS")
    
    # Social Protection Analytics Configuration
    SOCIAL_PROTECTION_ANALYTICS_ENABLED: bool = Field(default=True, env="LINKSHIELD_SOCIAL_PROTECTION_ANALYTICS_ENABLED")
    SOCIAL_PROTECTION_METRICS_COLLECTION: bool = Field(default=True, env="LINKSHIELD_SOCIAL_PROTECTION_METRICS_COLLECTION")
    SOCIAL_PROTECTION_DASHBOARD_REFRESH_INTERVAL: int = Field(default=300, env="LINKSHIELD_SOCIAL_PROTECTION_DASHBOARD_REFRESH_INTERVAL")
    SOCIAL_PROTECTION_REPORT_GENERATION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SOCIAL_PROTECTION_REPORT_GENERATION_ENABLED")
    
    # Social Protection Security Settings
    SOCIAL_PROTECTION_AUDIT_LOGGING: bool = Field(default=True, env="LINKSHIELD_SOCIAL_PROTECTION_AUDIT_LOGGING")
    SOCIAL_PROTECTION_DATA_ANONYMIZATION: bool = Field(default=True, env="LINKSHIELD_SOCIAL_PROTECTION_DATA_ANONYMIZATION")
    SOCIAL_PROTECTION_GDPR_COMPLIANCE: bool = Field(default=True, env="LINKSHIELD_SOCIAL_PROTECTION_GDPR_COMPLIANCE")
    SOCIAL_PROTECTION_ACCESS_CONTROL_STRICT: bool = Field(default=True, env="LINKSHIELD_SOCIAL_PROTECTION_ACCESS_CONTROL_STRICT")
    
    # Social Protection Integration Settings
    SOCIAL_PROTECTION_WEBHOOK_ENABLED: bool = Field(default=False, env="LINKSHIELD_SOCIAL_PROTECTION_WEBHOOK_ENABLED")
    SOCIAL_PROTECTION_WEBHOOK_URL: Optional[str] = Field(default=None, env="LINKSHIELD_SOCIAL_PROTECTION_WEBHOOK_URL")
    SOCIAL_PROTECTION_WEBHOOK_SECRET: Optional[str] = Field(default=None, env="LINKSHIELD_SOCIAL_PROTECTION_WEBHOOK_SECRET")
    SOCIAL_PROTECTION_API_RATE_LIMIT: str = Field(default="1000/hour", env="LINKSHIELD_SOCIAL_PROTECTION_API_RATE_LIMIT")
    SOCIAL_PROTECTION_EXTERNAL_API_TIMEOUT: int = Field(default=30, env="LINKSHIELD_SOCIAL_PROTECTION_EXTERNAL_API_TIMEOUT")
    
    # Admin Dashboard Configuration
    ADMIN_SESSION_TIMEOUT_MINUTES: int = Field(default=60, env="LINKSHIELD_ADMIN_SESSION_TIMEOUT_MINUTES")
    ADMIN_MAX_CONCURRENT_SESSIONS: int = Field(default=3, env="LINKSHIELD_ADMIN_MAX_CONCURRENT_SESSIONS")
    ADMIN_AUDIT_LOG_RETENTION_DAYS: int = Field(default=90, env="LINKSHIELD_ADMIN_AUDIT_LOG_RETENTION_DAYS")
    ADMIN_DASHBOARD_REFRESH_INTERVAL_SECONDS: int = Field(default=30, env="LINKSHIELD_ADMIN_DASHBOARD_REFRESH_INTERVAL_SECONDS")
    ADMIN_SYSTEM_HEALTH_CHECK_INTERVAL_MINUTES: int = Field(default=5, env="LINKSHIELD_ADMIN_SYSTEM_HEALTH_CHECK_INTERVAL_MINUTES")
    ADMIN_ANALYTICS_DATA_RETENTION_DAYS: int = Field(default=365, env="LINKSHIELD_ADMIN_ANALYTICS_DATA_RETENTION_DAYS")
    ADMIN_CONFIG_BACKUP_ENABLED: bool = Field(default=True, env="LINKSHIELD_ADMIN_CONFIG_BACKUP_ENABLED")
    ADMIN_CONFIG_BACKUP_INTERVAL_HOURS: int = Field(default=24, env="LINKSHIELD_ADMIN_CONFIG_BACKUP_INTERVAL_HOURS")
    ADMIN_NOTIFICATION_EMAIL: Optional[str] = Field(default=None, env="LINKSHIELD_ADMIN_NOTIFICATION_EMAIL")
    ADMIN_CRITICAL_ALERT_THRESHOLD: float = Field(default=0.95, env="LINKSHIELD_ADMIN_CRITICAL_ALERT_THRESHOLD")
    ADMIN_WARNING_ALERT_THRESHOLD: float = Field(default=0.80, env="LINKSHIELD_ADMIN_WARNING_ALERT_THRESHOLD")
    ADMIN_MAX_EXPORT_RECORDS: int = Field(default=10000, env="LINKSHIELD_ADMIN_MAX_EXPORT_RECORDS")
    ADMIN_BULK_OPERATION_BATCH_SIZE: int = Field(default=100, env="LINKSHIELD_ADMIN_BULK_OPERATION_BATCH_SIZE")

    # Security Notification Settings (Phase 3 Security Enhancement)
    # SMTP Configuration for Security Emails
    SECURITY_SMTP_HOST: str = Field(default="localhost", env="LINKSHIELD_SECURITY_SMTP_HOST")
    SECURITY_SMTP_PORT: int = Field(default=587, env="LINKSHIELD_SECURITY_SMTP_PORT")
    SECURITY_SMTP_USERNAME: Optional[str] = Field(default=None, env="LINKSHIELD_SECURITY_SMTP_USERNAME")
    SECURITY_SMTP_PASSWORD: Optional[str] = Field(default=None, env="LINKSHIELD_SECURITY_SMTP_PASSWORD")
    SECURITY_SMTP_USE_TLS: bool = Field(default=True, env="LINKSHIELD_SECURITY_SMTP_USE_TLS")
    SECURITY_SMTP_USE_SSL: bool = Field(default=False, env="LINKSHIELD_SECURITY_SMTP_USE_SSL")
    SECURITY_SMTP_TIMEOUT: int = Field(default=30, env="LINKSHIELD_SECURITY_SMTP_TIMEOUT")
    SECURITY_SMTP_CONNECTION_POOL_SIZE: int = Field(default=5, env="LINKSHIELD_SECURITY_SMTP_CONNECTION_POOL_SIZE")
    
    # Security Email Configuration
    SECURITY_EMAIL_FROM_ADDRESS: str = Field(default="security@linkshield.com", env="LINKSHIELD_SECURITY_EMAIL_FROM_ADDRESS")
    SECURITY_EMAIL_FROM_NAME: str = Field(default="LinkShield Security", env="LINKSHIELD_SECURITY_EMAIL_FROM_NAME")
    SECURITY_EMAIL_REPLY_TO: Optional[str] = Field(default=None, env="LINKSHIELD_SECURITY_EMAIL_REPLY_TO")
    SECURITY_EMAIL_BCC_ADDRESSES: Optional[str] = Field(default=None, env="LINKSHIELD_SECURITY_EMAIL_BCC_ADDRESSES")
    SECURITY_EMAIL_TEMPLATE_PATH: str = Field(default="templates/security", env="LINKSHIELD_SECURITY_EMAIL_TEMPLATE_PATH")
    SECURITY_EMAIL_SUBJECT_PREFIX: str = Field(default="[SECURITY ALERT]", env="LINKSHIELD_SECURITY_EMAIL_SUBJECT_PREFIX")
    
    # Notification Rate Limits
    SECURITY_NOTIFICATION_RATE_LIMIT_PER_MINUTE: int = Field(default=10, env="LINKSHIELD_SECURITY_NOTIFICATION_RATE_LIMIT_PER_MINUTE")
    SECURITY_NOTIFICATION_RATE_LIMIT_PER_HOUR: int = Field(default=100, env="LINKSHIELD_SECURITY_NOTIFICATION_RATE_LIMIT_PER_HOUR")
    SECURITY_NOTIFICATION_RATE_LIMIT_PER_DAY: int = Field(default=500, env="LINKSHIELD_SECURITY_NOTIFICATION_RATE_LIMIT_PER_DAY")
    SECURITY_NOTIFICATION_BURST_LIMIT: int = Field(default=5, env="LINKSHIELD_SECURITY_NOTIFICATION_BURST_LIMIT")
    SECURITY_NOTIFICATION_COOLDOWN_MINUTES: int = Field(default=15, env="LINKSHIELD_SECURITY_NOTIFICATION_COOLDOWN_MINUTES")
    
    # Security Notification Channels
    SECURITY_NOTIFICATION_EMAIL_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_NOTIFICATION_EMAIL_ENABLED")
    SECURITY_NOTIFICATION_SLACK_ENABLED: bool = Field(default=False, env="LINKSHIELD_SECURITY_NOTIFICATION_SLACK_ENABLED")
    SECURITY_NOTIFICATION_WEBHOOK_ENABLED: bool = Field(default=False, env="LINKSHIELD_SECURITY_NOTIFICATION_WEBHOOK_ENABLED")
    SECURITY_NOTIFICATION_SLACK_WEBHOOK_URL: Optional[str] = Field(default=None, env="LINKSHIELD_SECURITY_NOTIFICATION_SLACK_WEBHOOK_URL")
    SECURITY_NOTIFICATION_WEBHOOK_URL: Optional[str] = Field(default=None, env="LINKSHIELD_SECURITY_NOTIFICATION_WEBHOOK_URL")
    SECURITY_NOTIFICATION_WEBHOOK_SECRET: Optional[str] = Field(default=None, env="LINKSHIELD_SECURITY_NOTIFICATION_WEBHOOK_SECRET")
    SECURITY_NOTIFICATION_WEBHOOK_TIMEOUT: int = Field(default=10, env="LINKSHIELD_SECURITY_NOTIFICATION_WEBHOOK_TIMEOUT")

    # Secure Logging Configuration (Phase 3 Security Enhancement)
    # Log Sanitization Rules
    SECURE_LOG_SANITIZATION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_SANITIZATION_ENABLED")
    SECURE_LOG_SANITIZE_PASSWORDS: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_SANITIZE_PASSWORDS")
    SECURE_LOG_SANITIZE_TOKENS: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_SANITIZE_TOKENS")
    SECURE_LOG_SANITIZE_API_KEYS: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_SANITIZE_API_KEYS")
    SECURE_LOG_SANITIZE_CREDIT_CARDS: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_SANITIZE_CREDIT_CARDS")
    SECURE_LOG_SANITIZE_SSN: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_SANITIZE_SSN")
    SECURE_LOG_SANITIZE_PHONE_NUMBERS: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_SANITIZE_PHONE_NUMBERS")
    SECURE_LOG_SANITIZE_IP_ADDRESSES: bool = Field(default=False, env="LINKSHIELD_SECURE_LOG_SANITIZE_IP_ADDRESSES")
    SECURE_LOG_SANITIZE_USER_AGENTS: bool = Field(default=False, env="LINKSHIELD_SECURE_LOG_SANITIZE_USER_AGENTS")
    SECURE_LOG_SANITIZE_CUSTOM_PATTERNS: Optional[str] = Field(default=None, env="LINKSHIELD_SECURE_LOG_SANITIZE_CUSTOM_PATTERNS")
    
    # PII Protection Settings
    SECURE_LOG_PII_DETECTION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_PII_DETECTION_ENABLED")
    SECURE_LOG_PII_DETECTION_CONFIDENCE_THRESHOLD: float = Field(default=0.8, env="LINKSHIELD_SECURE_LOG_PII_DETECTION_CONFIDENCE_THRESHOLD")
    SECURE_LOG_PII_REDACTION_STRATEGY: str = Field(default="mask", env="LINKSHIELD_SECURE_LOG_PII_REDACTION_STRATEGY")
    SECURE_LOG_PII_MASK_CHARACTER: str = Field(default="*", env="LINKSHIELD_SECURE_LOG_PII_MASK_CHARACTER")
    SECURE_LOG_PII_PRESERVE_LENGTH: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_PII_PRESERVE_LENGTH")
    SECURE_LOG_PII_PRESERVE_FORMAT: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_PII_PRESERVE_FORMAT")
    SECURE_LOG_PII_WHITELIST_DOMAINS: Optional[str] = Field(default=None, env="LINKSHIELD_SECURE_LOG_PII_WHITELIST_DOMAINS")
    SECURE_LOG_PII_BLACKLIST_PATTERNS: Optional[str] = Field(default=None, env="LINKSHIELD_SECURE_LOG_PII_BLACKLIST_PATTERNS")
    
    # Secure Log Storage and Encryption
    SECURE_LOG_ENCRYPTION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_ENCRYPTION_ENABLED")
    SECURE_LOG_ENCRYPTION_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_SECURE_LOG_ENCRYPTION_KEY")
    SECURE_LOG_ENCRYPTION_ALGORITHM: str = Field(default="AES-256-GCM", env="LINKSHIELD_SECURE_LOG_ENCRYPTION_ALGORITHM")
    SECURE_LOG_COMPRESSION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_COMPRESSION_ENABLED")
    SECURE_LOG_COMPRESSION_LEVEL: int = Field(default=6, env="LINKSHIELD_SECURE_LOG_COMPRESSION_LEVEL")
    SECURE_LOG_ROTATION_SIZE_MB: int = Field(default=100, env="LINKSHIELD_SECURE_LOG_ROTATION_SIZE_MB")
    SECURE_LOG_ROTATION_COUNT: int = Field(default=10, env="LINKSHIELD_SECURE_LOG_ROTATION_COUNT")
    SECURE_LOG_BACKUP_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURE_LOG_BACKUP_ENABLED")
    SECURE_LOG_BACKUP_LOCATION: Optional[str] = Field(default=None, env="LINKSHIELD_SECURE_LOG_BACKUP_LOCATION")
    SECURE_LOG_BACKUP_RETENTION_DAYS: int = Field(default=90, env="LINKSHIELD_SECURE_LOG_BACKUP_RETENTION_DAYS")

    # Audit Logging Storage Configuration (Phase 3 Security Enhancement)
    # Audit Log Retention and Storage
    AUDIT_LOG_STORAGE_TYPE: str = Field(default="database", env="LINKSHIELD_AUDIT_LOG_STORAGE_TYPE")
    AUDIT_LOG_DATABASE_TABLE: str = Field(default="audit_logs", env="LINKSHIELD_AUDIT_LOG_DATABASE_TABLE")
    AUDIT_LOG_FILE_STORAGE_PATH: Optional[str] = Field(default=None, env="LINKSHIELD_AUDIT_LOG_FILE_STORAGE_PATH")
    AUDIT_LOG_S3_BUCKET: Optional[str] = Field(default=None, env="LINKSHIELD_AUDIT_LOG_S3_BUCKET")
    AUDIT_LOG_S3_PREFIX: str = Field(default="audit-logs/", env="LINKSHIELD_AUDIT_LOG_S3_PREFIX")
    AUDIT_LOG_S3_REGION: Optional[str] = Field(default=None, env="LINKSHIELD_AUDIT_LOG_S3_REGION")
    AUDIT_LOG_S3_ACCESS_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_AUDIT_LOG_S3_ACCESS_KEY")
    AUDIT_LOG_S3_SECRET_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_AUDIT_LOG_S3_SECRET_KEY")
    AUDIT_LOG_S3_ENCRYPTION_ENABLED: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_S3_ENCRYPTION_ENABLED")
    
    # Audit Log Retention Policies
    AUDIT_LOG_RETENTION_POLICY_ENABLED: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_RETENTION_POLICY_ENABLED")
    AUDIT_LOG_RETENTION_DAYS_DEFAULT: int = Field(default=2555, env="LINKSHIELD_AUDIT_LOG_RETENTION_DAYS_DEFAULT")  # 7 years
    AUDIT_LOG_RETENTION_DAYS_AUTHENTICATION: int = Field(default=1095, env="LINKSHIELD_AUDIT_LOG_RETENTION_DAYS_AUTHENTICATION")  # 3 years
    AUDIT_LOG_RETENTION_DAYS_AUTHORIZATION: int = Field(default=1095, env="LINKSHIELD_AUDIT_LOG_RETENTION_DAYS_AUTHORIZATION")  # 3 years
    AUDIT_LOG_RETENTION_DAYS_DATA_ACCESS: int = Field(default=2555, env="LINKSHIELD_AUDIT_LOG_RETENTION_DAYS_DATA_ACCESS")  # 7 years
    AUDIT_LOG_RETENTION_DAYS_ADMIN_ACTIONS: int = Field(default=2555, env="LINKSHIELD_AUDIT_LOG_RETENTION_DAYS_ADMIN_ACTIONS")  # 7 years
    AUDIT_LOG_RETENTION_DAYS_SECURITY_EVENTS: int = Field(default=2555, env="LINKSHIELD_AUDIT_LOG_RETENTION_DAYS_SECURITY_EVENTS")  # 7 years
    AUDIT_LOG_RETENTION_DAYS_COMPLIANCE: int = Field(default=2555, env="LINKSHIELD_AUDIT_LOG_RETENTION_DAYS_COMPLIANCE")  # 7 years
    
    # Audit Log Archival and Cleanup
    AUDIT_LOG_ARCHIVAL_ENABLED: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_ARCHIVAL_ENABLED")
    AUDIT_LOG_ARCHIVAL_THRESHOLD_DAYS: int = Field(default=365, env="LINKSHIELD_AUDIT_LOG_ARCHIVAL_THRESHOLD_DAYS")
    AUDIT_LOG_ARCHIVAL_STORAGE_TYPE: str = Field(default="s3", env="LINKSHIELD_AUDIT_LOG_ARCHIVAL_STORAGE_TYPE")
    AUDIT_LOG_ARCHIVAL_COMPRESSION_ENABLED: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_ARCHIVAL_COMPRESSION_ENABLED")
    AUDIT_LOG_ARCHIVAL_ENCRYPTION_ENABLED: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_ARCHIVAL_ENCRYPTION_ENABLED")
    AUDIT_LOG_CLEANUP_ENABLED: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_CLEANUP_ENABLED")
    AUDIT_LOG_CLEANUP_BATCH_SIZE: int = Field(default=1000, env="LINKSHIELD_AUDIT_LOG_CLEANUP_BATCH_SIZE")
    AUDIT_LOG_CLEANUP_SCHEDULE_CRON: str = Field(default="0 2 * * 0", env="LINKSHIELD_AUDIT_LOG_CLEANUP_SCHEDULE_CRON")  # Weekly at 2 AM Sunday
    
    # Audit Log Performance and Indexing
    AUDIT_LOG_INDEXING_ENABLED: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_INDEXING_ENABLED")
    AUDIT_LOG_PARTITION_BY_DATE: bool = Field(default=True, env="LINKSHIELD_AUDIT_LOG_PARTITION_BY_DATE")
    AUDIT_LOG_PARTITION_INTERVAL_DAYS: int = Field(default=30, env="LINKSHIELD_AUDIT_LOG_PARTITION_INTERVAL_DAYS")
    AUDIT_LOG_QUERY_TIMEOUT_SECONDS: int = Field(default=30, env="LINKSHIELD_AUDIT_LOG_QUERY_TIMEOUT_SECONDS")
    AUDIT_LOG_BULK_INSERT_BATCH_SIZE: int = Field(default=100, env="LINKSHIELD_AUDIT_LOG_BULK_INSERT_BATCH_SIZE")

    # Error Handling Preferences (Phase 3 Security Enhancement)
    # Error Message Sanitization
    ERROR_HANDLING_SANITIZATION_ENABLED: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_SANITIZATION_ENABLED")
    ERROR_HANDLING_SANITIZATION_LEVEL: str = Field(default="strict", env="LINKSHIELD_ERROR_HANDLING_SANITIZATION_LEVEL")
    ERROR_HANDLING_SANITIZE_STACK_TRACES: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_SANITIZE_STACK_TRACES")
    ERROR_HANDLING_SANITIZE_FILE_PATHS: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_SANITIZE_FILE_PATHS")
    ERROR_HANDLING_SANITIZE_DATABASE_ERRORS: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_SANITIZE_DATABASE_ERRORS")
    ERROR_HANDLING_SANITIZE_NETWORK_ERRORS: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_SANITIZE_NETWORK_ERRORS")
    ERROR_HANDLING_SANITIZE_VALIDATION_ERRORS: bool = Field(default=False, env="LINKSHIELD_ERROR_HANDLING_SANITIZE_VALIDATION_ERRORS")
    ERROR_HANDLING_GENERIC_MESSAGE: str = Field(default="An error occurred while processing your request", env="LINKSHIELD_ERROR_HANDLING_GENERIC_MESSAGE")
    ERROR_HANDLING_INCLUDE_ERROR_ID: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_INCLUDE_ERROR_ID")
    ERROR_HANDLING_INCLUDE_TIMESTAMP: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_INCLUDE_TIMESTAMP")
    
    # Debug Mode Configuration
    ERROR_HANDLING_DEBUG_MODE_ENABLED: bool = Field(default=False, env="LINKSHIELD_ERROR_HANDLING_DEBUG_MODE_ENABLED")
    ERROR_HANDLING_DEBUG_ALLOWED_IPS: Optional[str] = Field(default=None, env="LINKSHIELD_ERROR_HANDLING_DEBUG_ALLOWED_IPS")
    ERROR_HANDLING_DEBUG_REQUIRE_AUTH: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_DEBUG_REQUIRE_AUTH")
    ERROR_HANDLING_DEBUG_ADMIN_ONLY: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_DEBUG_ADMIN_ONLY")
    ERROR_HANDLING_DEBUG_INCLUDE_ENVIRONMENT: bool = Field(default=False, env="LINKSHIELD_ERROR_HANDLING_DEBUG_INCLUDE_ENVIRONMENT")
    ERROR_HANDLING_DEBUG_INCLUDE_REQUEST_DATA: bool = Field(default=False, env="LINKSHIELD_ERROR_HANDLING_DEBUG_INCLUDE_REQUEST_DATA")
    ERROR_HANDLING_DEBUG_MAX_STACK_DEPTH: int = Field(default=10, env="LINKSHIELD_ERROR_HANDLING_DEBUG_MAX_STACK_DEPTH")
    
    # Error Logging and Reporting
    ERROR_HANDLING_LOG_ERRORS: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_LOG_ERRORS")
    ERROR_HANDLING_LOG_LEVEL: str = Field(default="ERROR", env="LINKSHIELD_ERROR_HANDLING_LOG_LEVEL")
    ERROR_HANDLING_LOG_INCLUDE_USER_CONTEXT: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_LOG_INCLUDE_USER_CONTEXT")
    ERROR_HANDLING_LOG_INCLUDE_REQUEST_ID: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_LOG_INCLUDE_REQUEST_ID")
    ERROR_HANDLING_EXTERNAL_REPORTING_ENABLED: bool = Field(default=False, env="LINKSHIELD_ERROR_HANDLING_EXTERNAL_REPORTING_ENABLED")
    ERROR_HANDLING_SENTRY_DSN: Optional[str] = Field(default=None, env="LINKSHIELD_ERROR_HANDLING_SENTRY_DSN")
    ERROR_HANDLING_SENTRY_ENVIRONMENT: Optional[str] = Field(default=None, env="LINKSHIELD_ERROR_HANDLING_SENTRY_ENVIRONMENT")
    ERROR_HANDLING_SENTRY_SAMPLE_RATE: float = Field(default=1.0, env="LINKSHIELD_ERROR_HANDLING_SENTRY_SAMPLE_RATE")
    
    # Error Rate Limiting and Circuit Breaker
    ERROR_HANDLING_RATE_LIMITING_ENABLED: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_RATE_LIMITING_ENABLED")
    ERROR_HANDLING_MAX_ERRORS_PER_MINUTE: int = Field(default=100, env="LINKSHIELD_ERROR_HANDLING_MAX_ERRORS_PER_MINUTE")
    ERROR_HANDLING_CIRCUIT_BREAKER_ENABLED: bool = Field(default=True, env="LINKSHIELD_ERROR_HANDLING_CIRCUIT_BREAKER_ENABLED")
    ERROR_HANDLING_CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = Field(default=50, env="LINKSHIELD_ERROR_HANDLING_CIRCUIT_BREAKER_FAILURE_THRESHOLD")
    ERROR_HANDLING_CIRCUIT_BREAKER_RECOVERY_TIMEOUT: int = Field(default=60, env="LINKSHIELD_ERROR_HANDLING_CIRCUIT_BREAKER_RECOVERY_TIMEOUT")

    # Security Event Configuration (Phase 3 Security Enhancement)
    # Event Detection Thresholds
    SECURITY_EVENT_FAILED_LOGIN_THRESHOLD: int = Field(default=5, env="LINKSHIELD_SECURITY_EVENT_FAILED_LOGIN_THRESHOLD")
    SECURITY_EVENT_FAILED_LOGIN_WINDOW_MINUTES: int = Field(default=15, env="LINKSHIELD_SECURITY_EVENT_FAILED_LOGIN_WINDOW_MINUTES")
    SECURITY_EVENT_SUSPICIOUS_IP_THRESHOLD: int = Field(default=10, env="LINKSHIELD_SECURITY_EVENT_SUSPICIOUS_IP_THRESHOLD")
    SECURITY_EVENT_RATE_LIMIT_THRESHOLD: int = Field(default=100, env="LINKSHIELD_SECURITY_EVENT_RATE_LIMIT_THRESHOLD")
    SECURITY_EVENT_PRIVILEGE_ESCALATION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_PRIVILEGE_ESCALATION_ENABLED")
    SECURITY_EVENT_DATA_BREACH_DETECTION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_DATA_BREACH_DETECTION_ENABLED")
    SECURITY_EVENT_MALWARE_DETECTION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_MALWARE_DETECTION_ENABLED")
    SECURITY_EVENT_ANOMALY_DETECTION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_ANOMALY_DETECTION_ENABLED")
    SECURITY_EVENT_GEOLOCATION_ANOMALY_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_GEOLOCATION_ANOMALY_ENABLED")
    SECURITY_EVENT_SESSION_HIJACKING_DETECTION: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_SESSION_HIJACKING_DETECTION")
    
    # Event Severity Levels and Classification
    SECURITY_EVENT_SEVERITY_LEVELS: str = Field(default="low,medium,high,critical", env="LINKSHIELD_SECURITY_EVENT_SEVERITY_LEVELS")
    SECURITY_EVENT_AUTO_ESCALATE_CRITICAL: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_AUTO_ESCALATE_CRITICAL")
    SECURITY_EVENT_AUTO_ESCALATE_HIGH: bool = Field(default=False, env="LINKSHIELD_SECURITY_EVENT_AUTO_ESCALATE_HIGH")
    SECURITY_EVENT_ESCALATION_DELAY_MINUTES: int = Field(default=30, env="LINKSHIELD_SECURITY_EVENT_ESCALATION_DELAY_MINUTES")
    SECURITY_EVENT_CORRELATION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_CORRELATION_ENABLED")
    SECURITY_EVENT_CORRELATION_WINDOW_MINUTES: int = Field(default=60, env="LINKSHIELD_SECURITY_EVENT_CORRELATION_WINDOW_MINUTES")
    SECURITY_EVENT_DEDUPLICATION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_DEDUPLICATION_ENABLED")
    SECURITY_EVENT_DEDUPLICATION_WINDOW_MINUTES: int = Field(default=10, env="LINKSHIELD_SECURITY_EVENT_DEDUPLICATION_WINDOW_MINUTES")
    
    # Notification and Response Configuration
    SECURITY_EVENT_NOTIFICATION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_NOTIFICATION_ENABLED")
    SECURITY_EVENT_EMAIL_NOTIFICATIONS: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_EMAIL_NOTIFICATIONS")
    SECURITY_EVENT_SMS_NOTIFICATIONS: bool = Field(default=False, env="LINKSHIELD_SECURITY_EVENT_SMS_NOTIFICATIONS")
    SECURITY_EVENT_WEBHOOK_NOTIFICATIONS: bool = Field(default=False, env="LINKSHIELD_SECURITY_EVENT_WEBHOOK_NOTIFICATIONS")
    SECURITY_EVENT_SLACK_NOTIFICATIONS: bool = Field(default=False, env="LINKSHIELD_SECURITY_EVENT_SLACK_NOTIFICATIONS")
    SECURITY_EVENT_NOTIFICATION_RATE_LIMIT: int = Field(default=10, env="LINKSHIELD_SECURITY_EVENT_NOTIFICATION_RATE_LIMIT")
    SECURITY_EVENT_NOTIFICATION_COOLDOWN_MINUTES: int = Field(default=5, env="LINKSHIELD_SECURITY_EVENT_NOTIFICATION_COOLDOWN_MINUTES")
    SECURITY_EVENT_EMERGENCY_CONTACT_LIST: Optional[str] = Field(default=None, env="LINKSHIELD_SECURITY_EVENT_EMERGENCY_CONTACT_LIST")
    SECURITY_EVENT_ESCALATION_CONTACT_LIST: Optional[str] = Field(default=None, env="LINKSHIELD_SECURITY_EVENT_ESCALATION_CONTACT_LIST")
    
    # Automated Response Actions
    SECURITY_EVENT_AUTO_BLOCK_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_AUTO_BLOCK_ENABLED")
    SECURITY_EVENT_AUTO_BLOCK_DURATION_MINUTES: int = Field(default=60, env="LINKSHIELD_SECURITY_EVENT_AUTO_BLOCK_DURATION_MINUTES")
    SECURITY_EVENT_AUTO_QUARANTINE_ENABLED: bool = Field(default=False, env="LINKSHIELD_SECURITY_EVENT_AUTO_QUARANTINE_ENABLED")
    SECURITY_EVENT_AUTO_LOGOUT_SUSPICIOUS_SESSIONS: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_AUTO_LOGOUT_SUSPICIOUS_SESSIONS")
    SECURITY_EVENT_AUTO_DISABLE_COMPROMISED_ACCOUNTS: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_AUTO_DISABLE_COMPROMISED_ACCOUNTS")
    SECURITY_EVENT_INCIDENT_CREATION_ENABLED: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_INCIDENT_CREATION_ENABLED")
    SECURITY_EVENT_FORENSIC_DATA_COLLECTION: bool = Field(default=True, env="LINKSHIELD_SECURITY_EVENT_FORENSIC_DATA_COLLECTION")
    SECURITY_EVENT_BACKUP_TRIGGER_ENABLED: bool = Field(default=False, env="LINKSHIELD_SECURITY_EVENT_BACKUP_TRIGGER_ENABLED")

    @validator("REDIS_SSL_CERT_REQS")
    def validate_redis_ssl_cert_reqs(cls, v):
        """Validate Redis SSL certificate requirements."""
        allowed_values = ["none", "optional", "required"]
        if v.lower() not in allowed_values:
            raise ValueError(f"REDIS_SSL_CERT_REQS must be one of: {allowed_values}")
        return v.lower()
    
    @validator("DISTRIBUTED_RATE_LIMIT_BURST_MULTIPLIER")
    def validate_burst_multiplier(cls, v):
        """Validate burst multiplier is positive."""
        if v <= 0:
            raise ValueError("DISTRIBUTED_RATE_LIMIT_BURST_MULTIPLIER must be positive")
        return v
    
    @validator("SSRF_TIMEOUT", "SSRF_MAX_REDIRECTS")
    def validate_positive_integers(cls, v):
        """Validate positive integer values."""
        if v <= 0:
            raise ValueError("Value must be positive")
        return v
    
    @validator("ERROR_MESSAGES_LOG_LEVEL")
    def validate_error_log_level(cls, v):
        """Validate error message log level."""
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed_levels:
            raise ValueError(f"ERROR_MESSAGES_LOG_LEVEL must be one of: {allowed_levels}")
        return v.upper()

    @validator("ENVIRONMENT")
    def validate_environment(cls, v):
        """Validate environment setting."""
        allowed_environments = ["development", "staging", "production"]
        if v not in allowed_environments:
            raise ValueError(f"Environment must be one of: {allowed_environments}")
        return v
    
    @validator("LOG_LEVEL")
    def validate_log_level(cls, v):
        """Validate log level setting."""
        allowed_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed_levels:
            raise ValueError(f"Log level must be one of: {allowed_levels}")
        return v.upper()
    
    @validator("DATABASE_URL", "TEST_DATABASE_URL")
    def validate_database_url(cls, v):
        """Validate database URL format."""
        if not v.startswith(("postgresql://", "postgresql+asyncpg://")):
            raise ValueError("Database URL must be a PostgreSQL connection string")
        return v
    
    @validator("REDIS_URL")
    def validate_redis_url(cls, v):
        """Validate Redis URL format."""
        if not v.startswith("redis://"):
            raise ValueError("Redis URL must be a valid Redis connection string")
        return v
    
    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"  # Ignore extra fields in .env that aren't in the model


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    Uses LRU cache to avoid re-reading environment variables on every call.
    """
    return Settings()


# Export settings instance for convenience
settings = get_settings()
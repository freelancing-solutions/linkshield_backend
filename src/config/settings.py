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
    
    # Email Settings
    SMTP_HOST: Optional[str] = Field(default=None, env="LINKSHIELD_SMTP_HOST")
    SMTP_PORT: int = Field(default=587, env="LINKSHIELD_SMTP_PORT")
    SMTP_USERNAME: Optional[str] = Field(default=None, env="LINKSHIELD_SMTP_USERNAME")
    SMTP_PASSWORD: Optional[str] = Field(default=None, env="LINKSHIELD_SMTP_PASSWORD")
    SMTP_USE_TLS: bool = Field(default=True, env="LINKSHIELD_SMTP_USE_TLS")
    SMTP_SSL: bool = Field(default=False, env="LINKSHIELD_SMTP_SSL")
    FROM_EMAIL: str = Field(default="noreply@linkshield.com", env="LINKSHIELD_FROM_EMAIL")
    EMAIL_FROM_NAME: str = Field(default="LinkShield", env="LINKSHIELD_EMAIL_FROM_NAME")
    
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
    
    # Celery Configuration
    CELERY_BROKER_URL: str = Field(default="redis://localhost:6379/1", env="LINKSHIELD_CELERY_BROKER_URL")
    CELERY_RESULT_BACKEND: str = Field(default="redis://localhost:6379/2", env="LINKSHIELD_CELERY_RESULT_BACKEND")
    CELERY_TASK_SERIALIZER: str = Field(default="json")
    CELERY_RESULT_SERIALIZER: str = Field(default="json")
    CELERY_ACCEPT_CONTENT: List[str] = Field(default=["json"])
    CELERY_TIMEZONE: str = Field(default="UTC")
    
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
    
    # Development/Testing
    TEST_DATABASE_URL: str = Field(
        default="postgresql://linkshield_user:password@localhost:5432/linkshield_test_db",
        env="LINKSHIELD_TEST_DATABASE_URL"
    )
    TEST_MODE: bool = Field(default=False, env="LINKSHIELD_TEST_MODE")
    MOCK_EXTERNAL_APIS: bool = Field(default=False, env="LINKSHIELD_MOCK_EXTERNAL_APIS")

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
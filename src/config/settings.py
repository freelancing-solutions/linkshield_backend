#!/usr/bin/env python3
"""
LinkShield Backend API Settings

Configuration management using Pydantic settings with environment variable support.
Handles all application configuration including database, security, and external services.
"""

import os
from functools import lru_cache
from typing import List, Optional

from pydantic import BaseSettings, Field, validator


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
    
    # Redis Settings (for caching and rate limiting)
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="LINKSHIELD_REDIS_URL")
    REDIS_POOL_SIZE: int = Field(default=10, env="LINKSHIELD_REDIS_POOL_SIZE")
    
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
    FROM_EMAIL: str = Field(default="noreply@linkshield.com", env="LINKSHIELD_FROM_EMAIL")
    
    # Stripe Settings (for billing)
    STRIPE_PUBLISHABLE_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_STRIPE_PUBLISHABLE_KEY")
    STRIPE_SECRET_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_STRIPE_SECRET_KEY")
    STRIPE_WEBHOOK_SECRET: Optional[str] = Field(default=None, env="LINKSHIELD_STRIPE_WEBHOOK_SECRET")
    
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
    
    # Monitoring and Analytics
    SENTRY_DSN: Optional[str] = Field(default=None, env="LINKSHIELD_SENTRY_DSN")
    ANALYTICS_ENABLED: bool = Field(default=True, env="LINKSHIELD_ANALYTICS_ENABLED")
    
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
    
    @validator("DATABASE_URL")
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
    
    @validator("ALLOWED_HOSTS", "ALLOWED_ORIGINS", "ALLOWED_FILE_TYPES", pre=True)
    def parse_list_from_string(cls, v):
        """Parse comma-separated string into list."""
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v
    
    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    Uses LRU cache to avoid re-reading environment variables on every call.
    """
    return Settings()


# Export settings instance for convenience
settings = get_settings()
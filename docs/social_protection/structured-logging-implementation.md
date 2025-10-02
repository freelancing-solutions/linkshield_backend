# Structured Logging Implementation for Social Protection

## Overview

This document describes the structured logging implementation for the social protection module. All services, controllers, analyzers, and platform adapters now use consistent structured logging with contextual information for better debugging, monitoring, and observability.

## Implementation Details

### Logging Utility (`src/social_protection/logging_utils.py`)

Created a `StructuredLogger` wrapper around `loguru` that provides:

- **Consistent Context**: All log messages include service name, timestamp, and optional context fields
- **Structured Fields**: Support for user_id, platform, operation, duration_ms, and custom fields
- **Error Context**: Automatic error type and message extraction for exceptions
- **Type Safety**: Proper typing for all parameters

### Key Features

1. **Service Identification**: Each logger is bound to a specific service name
2. **Contextual Logging**: All log messages can include:
   - `user_id`: UUID of the user performing the operation
   - `platform`: Social media platform (twitter, facebook, etc.)
   - `operation`: Name of the operation being performed
   - `duration_ms`: Operation duration in milliseconds
   - Custom fields via `**extra_fields`

3. **Error Handling**: Error and critical logs automatically capture:
   - Exception type
   - Exception message
   - Full stack trace (via `exc_info`)

### Usage Example

```python
from src.social_protection.logging_utils import get_logger

logger = get_logger("MyService")

# Info logging with context
logger.info(
    "Processing user request",
    user_id=user_id,
    platform="twitter",
    operation="scan_profile",
    duration_ms=123.45
)

# Error logging with exception
try:
    result = perform_operation()
except Exception as e:
    logger.error(
        "Operation failed",
        error=e,
        user_id=user_id,
        platform="twitter",
        operation="scan_profile"
    )
```

## Updated Components

### Services
- ✅ `SocialScanService` - Profile scanning and risk assessment
- ✅ `ExtensionDataProcessor` - Browser extension data processing

### Controllers
- ✅ `UserController` - User-facing social protection operations
- ✅ `BotController` - Bot integration operations
- ✅ `ExtensionController` - Browser extension integration

### Algorithm Health Analyzers
- ✅ `VisibilityScorer` - Platform visibility analysis
- ✅ `EngagementAnalyzer` - Engagement quality assessment
- ✅ `PenaltyDetector` - Algorithmic penalty detection
- ✅ `ShadowBanDetector` - Shadow ban detection

### Platform Adapters
- ✅ `TwitterProtectionAdapter` - Twitter/X specific protection
- ✅ `MetaProtectionAdapter` - Facebook/Instagram protection
- ✅ `TikTokProtectionAdapter` - TikTok specific protection
- ✅ `LinkedInProtectionAdapter` - LinkedIn specific protection
- ✅ `TelegramProtectionAdapter` - Telegram specific protection
- ✅ `DiscordProtectionAdapter` - Discord specific protection

### Supporting Components
- ✅ `PlatformAdapterRegistry` - Platform adapter registration
- ✅ `ReputationTracker` - Reputation monitoring

## Log Format

All structured logs include the following base fields:

```json
{
  "service": "ServiceName",
  "timestamp": "2025-10-02T17:55:25.123456Z",
  "level": "INFO",
  "message": "Log message",
  "user_id": "uuid-string",
  "platform": "twitter",
  "operation": "operation_name",
  "duration_ms": 123.45
}
```

Error logs additionally include:

```json
{
  "error_type": "ValueError",
  "error_message": "Error description"
}
```

## Benefits

1. **Improved Debugging**: Contextual information makes it easier to trace issues
2. **Better Monitoring**: Structured logs can be easily parsed by log aggregation tools
3. **Performance Tracking**: Duration tracking helps identify slow operations
4. **User Tracing**: User ID tracking enables user-specific issue investigation
5. **Platform Analysis**: Platform-specific logging helps identify platform-related issues
6. **Consistent Format**: All services use the same logging format

## Testing

Comprehensive tests verify:
- Logger initialization
- Context building
- All log levels (info, warning, error, debug, critical)
- Exception handling
- Multiple logger instances

Run tests with:
```bash
pytest tests/test_structured_logging.py -v
```

## Migration Notes

### Before
```python
import logging
logger = logging.getLogger(__name__)

logger.info(f"Processing user {user_id}")
logger.error(f"Error: {str(e)}", exc_info=True)
```

### After
```python
from src.social_protection.logging_utils import get_logger
logger = get_logger("ServiceName")

logger.info("Processing user", user_id=user_id, operation="process")
logger.error("Operation failed", error=e, user_id=user_id)
```

## Future Enhancements

1. **Log Sampling**: Implement sampling for high-volume operations
2. **Sensitive Data Masking**: Automatically mask PII in logs
3. **Performance Metrics**: Integrate with Prometheus metrics
4. **Distributed Tracing**: Add correlation IDs for distributed tracing
5. **Log Levels by Service**: Configure different log levels per service

## Compliance

This implementation satisfies:
- **Requirement 9.1**: Comprehensive error logging with context
- **Task 4.2**: Add structured logging to all services
- **Design Section**: Logging Strategy with structured logging

## Related Documentation

- [Error Handling Strategy](../error-handling.md)
- [Monitoring and Observability](../monitoring.md)
- [Social Protection Design](../../.kiro/specs/social-protection-production-readiness/design.md)

# Error Handling Documentation

## Overview

LinkShield backend implements a comprehensive error handling system with standardized error responses, custom exception classes, and proper HTTP status codes. This document covers all error handling patterns, exception types, and response formats.

## Error Response Format

All API errors follow a consistent JSON response format:

```json
{
  "success": false,
  "error": "Brief error description",
  "detail": "Detailed error message (optional)",
  "errors": [...], // Validation errors (optional)
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "uuid-string"
}
```

### Standard Fields

- **success**: Always `false` for error responses
- **error**: Brief, user-friendly error message
- **detail**: Detailed technical information (development mode only)
- **errors**: Array of validation errors (422 responses)
- **timestamp**: ISO 8601 timestamp of the error
- **request_id**: Unique identifier for request tracking

## HTTP Status Codes

### 4xx Client Errors

| Code | Description | Usage |
|------|-------------|-------|
| 400 | Bad Request | Invalid request format, malformed data |
| 401 | Unauthorized | Missing or invalid authentication |
| 403 | Forbidden | Valid auth but insufficient permissions |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | Resource already exists, duplicate data |
| 413 | Payload Too Large | Request exceeds size limits |
| 422 | Unprocessable Entity | Validation errors |
| 429 | Too Many Requests | Rate limit exceeded |

### 5xx Server Errors

| Code | Description | Usage |
|------|-------------|-------|
| 500 | Internal Server Error | Unhandled exceptions, system errors |
| 502 | Bad Gateway | External service failures |
| 503 | Service Unavailable | System maintenance, overload |
| 504 | Gateway Timeout | External service timeouts |

## Custom Exception Classes

### Authentication Exceptions

```python
# Base authentication error
class AuthenticationError(Exception):
    """Base exception for authentication failures"""

# Specific authentication errors
class InvalidCredentialsError(AuthenticationError):
    """Invalid email/password combination"""

class AccountLockedError(AuthenticationError):
    """Account is suspended or locked"""

class EmailNotVerifiedError(AuthenticationError):
    """Email address not verified"""

class TokenExpiredError(AuthenticationError):
    """JWT token has expired"""
```

### Authorization Exceptions

```python
class SecurityError(Exception):
    """Base exception for security violations"""

class AuthorizationError(SecurityError):
    """Insufficient permissions for operation"""
```

### Service-Specific Exceptions

```python
# AI Service Errors
class AIServiceError(Exception):
    """Base exception for AI service errors"""

class ModelLoadError(AIServiceError):
    """AI model loading failures"""

class AnalysisError(AIServiceError):
    """Content analysis failures"""

# URL Analysis Errors
class URLAnalysisError(Exception):
    """Base exception for URL analysis errors"""

class InvalidURLError(URLAnalysisError):
    """Invalid URL format or structure"""

class ScanTimeoutError(URLAnalysisError):
    """Analysis operation timed out"""

# Email Service Errors
class EmailServiceError(Exception):
    """Base exception for email service errors"""

class EmailProviderError(EmailServiceError):
    """Email provider API failures"""

class EmailValidationError(EmailServiceError):
    """Email template or content validation errors"""

# Background Task Errors
class EmailTaskError(Exception):
    """Base exception for email task errors"""
```

## Global Exception Handler

The application includes a global exception handler that catches unhandled exceptions:

```python
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    content = {"success": False, "error": "Internal server error"}
    if settings.ENVIRONMENT == "development":
        content["detail"] = str(exc)
    return JSONResponse(status_code=500, content=content)
```

### Features

- **Logging**: All unhandled exceptions are logged with full stack traces
- **Environment-aware**: Detailed error info only in development mode
- **Consistent format**: Maintains standard error response structure

## Controller Error Handling

### Base Controller Methods

All controllers inherit standardized error handling methods:

#### Database Error Handling

```python
def handle_database_error(self, error: SQLAlchemyError, operation: str) -> HTTPException:
    """Handle database errors with appropriate HTTP responses"""
    
    # Map specific database errors to HTTP status codes
    if "duplicate key" in str(error).lower():
        return HTTPException(
            status_code=409,
            detail=f"Resource already exists: {operation}"
        )
    elif "foreign key" in str(error).lower():
        return HTTPException(
            status_code=400,
            detail=f"Invalid reference in {operation}"
        )
    else:
        return HTTPException(
            status_code=500,
            detail=f"Database error during {operation}"
        )
```

#### Validation Error Handling

```python
def handle_validation_error(self, error: ValidationError, operation: str) -> HTTPException:
    """Handle validation errors with detailed error messages"""
    
    return HTTPException(
        status_code=422,
        detail={
            "message": f"Validation failed for {operation}",
            "errors": error.errors()
        }
    )
```

#### Access Control Validation

```python
def validate_user_access(
    self,
    user_id: int,
    resource_user_id: int,
    is_admin: bool = False,
    operation: str = "access resource"
) -> None:
    """Validate user access to resources"""
    
    if user_id != resource_user_id and not is_admin:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: cannot {operation}"
        )
```

## Security Middleware Error Handling

### Request Validation

The security middleware performs several validation checks:

```python
# Request size validation
if content_length and int(content_length) > settings.MAX_FILE_SIZE:
    return JSONResponse(
        status_code=413,
        content={
            "success": False,
            "error": "Request entity too large",
            "detail": f"Maximum allowed size is {settings.MAX_FILE_SIZE} bytes"
        }
    )

# Suspicious request detection
if self._is_suspicious_request(request):
    logger.warning(f"Suspicious request detected: {request.url.path}")
    return JSONResponse(
        status_code=400,
        content={
            "success": False,
            "error": "Bad request",
        }
    )
```

### Suspicious Pattern Detection

The middleware detects common attack patterns:

- Path traversal attempts (`../`, `..%2f`)
- XSS attempts (`<script`, `javascript:`)
- SQL injection (`union select`, `drop table`)
- Command injection (`exec(`, `system(`)
- Excessively long paths (>2048 characters)
- Too many query parameters (>50)

## Rate Limiting Errors

Rate limiting is handled by the SlowAPI library with custom error responses:

```python
# Rate limit exceeded response
{
    "success": false,
    "error": "Rate limit exceeded",
    "detail": "Too many requests. Please try again later.",
    "retry_after": 60
}
```

### Rate Limit Headers

Rate-limited responses include headers:

- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Requests remaining in window
- `X-RateLimit-Reset`: Timestamp when limit resets
- `Retry-After`: Seconds to wait before retrying

## Endpoint-Specific Error Codes

### User Management Errors

| Code | Error | Description |
|------|-------|-------------|
| 4001 | EMAIL_ALREADY_EXISTS | Email address already registered |
| 4002 | INVALID_CREDENTIALS | Invalid email/password combination |
| 4003 | EMAIL_NOT_VERIFIED | Email verification required |
| 4004 | ACCOUNT_SUSPENDED | Account has been suspended |
| 4005 | PASSWORD_TOO_WEAK | Password doesn't meet requirements |
| 4006 | INVALID_TOKEN | JWT token is invalid or expired |
| 4007 | SESSION_EXPIRED | User session has expired |

### URL Check Errors

| Code | Error | Description |
|------|-------|-------------|
| 4101 | INVALID_URL_FORMAT | URL format is invalid |
| 4102 | URL_TOO_LONG | URL exceeds maximum length |
| 4103 | UNSUPPORTED_PROTOCOL | Protocol not supported |
| 4104 | SCAN_TIMEOUT | URL analysis timed out |
| 4105 | SCAN_FAILED | Analysis could not be completed |
| 4106 | DAILY_LIMIT_EXCEEDED | Daily scan limit reached |

### Report Errors

| Code | Error | Description |
|------|-------|-------------|
| 4201 | REPORT_NOT_FOUND | Report does not exist |
| 4202 | DUPLICATE_REPORT | Report already exists for URL |
| 4203 | INVALID_REPORT_TYPE | Report type not supported |
| 4204 | INSUFFICIENT_EVIDENCE | Report lacks required evidence |
| 4205 | REPORT_ALREADY_RESOLVED | Report has already been resolved |

### AI Analysis Errors

| Code | Error | Description |
|------|-------|-------------|
| 4301 | AI_SERVICE_UNAVAILABLE | AI analysis service is down |
| 4302 | MODEL_LOAD_FAILED | AI model could not be loaded |
| 4303 | ANALYSIS_FAILED | Content analysis failed |
| 4304 | INSUFFICIENT_CONTENT | Not enough content to analyze |
| 4305 | ANALYSIS_TIMEOUT | Analysis operation timed out |
| 4306 | RETRY_LIMIT_EXCEEDED | Maximum retry attempts reached |

### Subscription Errors

| Code | Error | Description |
|------|-------|-------------|
| 4401 | SUBSCRIPTION_REQUIRED | Feature requires active subscription |
| 4402 | PLAN_LIMIT_EXCEEDED | Usage limit for plan exceeded |
| 4403 | PAYMENT_FAILED | Payment processing failed |
| 4404 | SUBSCRIPTION_EXPIRED | Subscription has expired |
| 4405 | INVALID_PLAN | Subscription plan not found |

## Error Logging

### Log Levels

- **ERROR**: Unhandled exceptions, system failures
- **WARNING**: Authentication failures, suspicious requests
- **INFO**: Normal operation events, successful requests
- **DEBUG**: Detailed request/response information (development only)

### Log Format

```
{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}
```

### Log Destinations

- **Console**: All environments with color coding
- **File**: `logs/linkshield.log` with rotation (10MB, 30 days retention)
- **Structured**: JSON format for production log aggregation

## Error Recovery Strategies

### Automatic Retry

Some operations support automatic retry with exponential backoff:

```python
# AI Analysis retry mechanism
async def retry_analysis(analysis_id: str, max_retries: int = 3):
    for attempt in range(max_retries):
        try:
            return await perform_analysis(analysis_id)
        except AnalysisError as e:
            if attempt == max_retries - 1:
                raise
            await asyncio.sleep(2 ** attempt)  # Exponential backoff
```

### Circuit Breaker Pattern

External service calls implement circuit breaker pattern:

- **Closed**: Normal operation
- **Open**: Service unavailable, fail fast
- **Half-Open**: Testing service recovery

### Graceful Degradation

When non-critical services fail:

- Return partial results with warnings
- Use cached data when available
- Provide alternative functionality

## Development Guidelines

### Error Handling Best Practices

1. **Use specific exception types** for different error conditions
2. **Log errors with context** including user ID, operation, and parameters
3. **Return consistent error formats** across all endpoints
4. **Validate input early** to catch errors before processing
5. **Handle database errors gracefully** with appropriate HTTP status codes
6. **Implement proper cleanup** in finally blocks or context managers

### Testing Error Conditions

```python
# Example error condition test
def test_invalid_url_format():
    response = client.post("/api/url-check", json={"url": "invalid-url"})
    assert response.status_code == 422
    assert response.json()["success"] is False
    assert "Invalid URL format" in response.json()["error"]
```

### Error Monitoring

- **Sentry Integration**: Automatic error reporting and alerting
- **Health Checks**: Monitor service availability and performance
- **Metrics Collection**: Track error rates and response times
- **Log Analysis**: Automated log parsing and alerting

## Security Considerations

### Error Information Disclosure

- **Production**: Minimal error details to prevent information leakage
- **Development**: Full error details for debugging
- **Logging**: Sensitive data is never logged (passwords, tokens)

### Attack Prevention

- **Rate Limiting**: Prevent brute force attacks
- **Input Validation**: Sanitize all user input
- **SQL Injection**: Use parameterized queries
- **XSS Prevention**: Escape output and validate input
- **CSRF Protection**: Validate request origins

### Audit Trail

All security-related errors are logged with:

- Client IP address
- User agent string
- Request timestamp
- Attempted operation
- Authentication status

This comprehensive error handling system ensures robust, secure, and maintainable API operations while providing clear feedback to clients and detailed logging for system administrators.
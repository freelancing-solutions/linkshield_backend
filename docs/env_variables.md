# Environment Variables

This document lists all environment variables required for running the LinkShield application. These variables should be stored in a `.env.local` file in the project root for local development.

## 🔧 General Configuration

### `NODE_ENV`
- **Description:** Specifies the application environment
- **Values:** `development`, `production`, or `test`
- **Usage:** Controls framework behaviors, logging levels, caching strategies, and database connection pooling
- **Default:** `development`

### `PORT`
- **Description:** Port number for the application server
- **Usage:** Defines which port the Next.js server will listen on
- **Default:** `3000`
- **Example:** `3000`

## 🌐 Application URLs

### `NEXT_PUBLIC_APP_URL`
- **Description:** The full public URL of the application
- **Usage:** Used for generating absolute URLs, redirects, Open Graph images, and shareable links
- **Required:** Yes
- **Example:** `https://app.linkshield.com` or `http://localhost:3000`

### `NEXT_PUBLIC_BASE_URL`
- **Description:** Alternative base URL for shareable reports
- **Usage:** Used by the shareable report service when `NEXT_PUBLIC_APP_URL` is not available
- **Default:** Falls back to `https://linkshield.site`
- **Example:** `https://linkshield.site`

### `NEXT_PUBLIC_SOCKET_URL`
- **Description:** WebSocket server URL for real-time features
- **Usage:** Used by client-side Socket.IO for real-time report updates and notifications
- **Default:** Falls back to `http://localhost:3001`
- **Example:** `https://ws.linkshield.com`

## 🗄️ Database

### `DATABASE_URL`
- **Description:** PostgreSQL database connection string
- **Usage:** Required by Prisma ORM for all database operations
- **Required:** Yes
- **Format:** `postgresql://username:password@host:port/database?sslmode=require`
- **Example:** `postgresql://user:password@localhost:5432/linkshield`

## 🔐 Authentication (NextAuth.js)

### `NEXTAUTH_URL`
- **Description:** Canonical URL of the Next.js application
- **Usage:** Required by NextAuth.js for generating callback URLs and secure redirects
- **Required:** Yes
- **Development:** `http://localhost:3000`
- **Production:** Should match `NEXT_PUBLIC_APP_URL`
- **Example:** `https://app.linkshield.com`

### `NEXTAUTH_SECRET`
- **Description:** Secret key for signing and encrypting JWTs, cookies, and security tokens
- **Usage:** Critical for session security - must be a long, random, private string
- **Required:** Yes
- **Generation:** `openssl rand -base64 32`
- **Example:** `your-super-secret-key-here`

## 💳 Payment Processing

### Stripe Configuration

#### `STRIPE_SECRET_KEY`
- **Description:** Stripe secret API key
- **Usage:** Server-side Stripe operations (creating customers, checkout sessions)
- **Required:** Yes (for payment features)
- **Format:** `sk_test_...` (test) or `sk_live_...` (production)
- **Example:** `sk_test_51234567890abcdef...`

#### `STRIPE_PUBLISHABLE_KEY`
- **Description:** Stripe publishable API key
- **Usage:** Client-side Stripe integration
- **Required:** Yes (for payment features)
- **Format:** `pk_test_...` (test) or `pk_live_...` (production)
- **Example:** `pk_test_51234567890abcdef...`

#### `STRIPE_WEBHOOK_SECRET`
- **Description:** Webhook endpoint secret for verifying Stripe webhooks
- **Usage:** Ensures webhook requests are genuinely from Stripe
- **Required:** Yes (for payment webhooks)
- **Format:** `whsec_...`
- **Example:** `whsec_1234567890abcdef...`

### PayPal Configuration

#### `PAYPAL_CLIENT_ID`
- **Description:** PayPal application client ID
- **Usage:** PayPal API authentication and order creation
- **Required:** Yes (for PayPal payments)
- **Example:** `your_paypal_client_id`

#### `PAYPAL_CLIENT_SECRET` / `PAYPAL_SECRET`
- **Description:** PayPal application client secret
- **Usage:** PayPal API authentication (server-side)
- **Required:** Yes (for PayPal payments)
- **Note:** Code checks for both `PAYPAL_SECRET` and `PAYPAL_CLIENT_SECRET`
- **Example:** `your_paypal_client_secret`

#### `PAYPAL_WEBHOOK_ID`
- **Description:** PayPal webhook ID for signature verification
- **Usage:** Verifies incoming PayPal webhook requests
- **Required:** Yes (for PayPal webhooks)
- **Example:** `your_webhook_id`

#### `PAYPAL_API_BASE`
- **Description:** PayPal API base URL
- **Usage:** Determines PayPal environment (sandbox vs production)
- **Default:** `https://api-m.sandbox.paypal.com` (sandbox)
- **Production:** `https://api-m.paypal.com`
- **Example:** `https://api-m.sandbox.paypal.com`

#### `PAYPAL_RETURN_URL`
- **Description:** URL to redirect users after successful PayPal payment
- **Usage:** PayPal checkout flow completion
- **Default:** Falls back to `{NEXT_PUBLIC_APP_URL}/pricing`
- **Example:** `https://app.linkshield.com/dashboard?success=true`

#### `PAYPAL_CANCEL_URL`
- **Description:** URL to redirect users when PayPal payment is cancelled
- **Usage:** PayPal checkout flow cancellation
- **Default:** Falls back to `{NEXT_PUBLIC_APP_URL}/pricing`
- **Example:** `https://app.linkshield.com/pricing`

## 🧠 AI Services (Optional)

### `OPENAI_API_KEY`
- **Description:** OpenAI API key for AI-powered content analysis
- **Usage:** Content quality scoring, summarization, and topic categorization
- **Required:** No (AI features will be disabled without it)
- **Format:** `sk-...`
- **Example:** `sk-1234567890abcdef...`

## 🚀 Caching & Performance

### Redis Configuration

#### `REDIS_URL`
- **Description:** Redis connection string for caching and distributed rate limiting
- **Usage:** Caches report data, user sessions, analytics, and provides distributed rate limiting storage
- **Required:** No (caching will be disabled without it, rate limiting will use in-memory storage)
- **Format:** `redis://:password@host:port/db`
- **Example:** `redis://:password@localhost:6379/0`
- **Security:** Ensure Redis is properly secured with authentication and network isolation

#### `REDIS_PASSWORD`
- **Description:** Redis authentication password
- **Usage:** Authenticates connections to Redis server
- **Required:** Yes (if Redis requires authentication)
- **Security:** Use strong passwords and change default passwords in production
- **Example:** `your-redis-password-change-in-production`

#### `REDIS_DB`
- **Description:** Redis database number to use
- **Usage:** Isolates LinkShield data from other applications using the same Redis instance
- **Default:** `0`
- **Range:** `0-15` (depending on Redis configuration)
- **Example:** `0`

#### `REDIS_MAX_CONNECTIONS`
- **Description:** Maximum number of connections in the Redis connection pool
- **Usage:** Controls resource usage and connection limits
- **Default:** `10`
- **Tuning:** Increase for high-traffic applications
- **Example:** `10`

#### `REDIS_CONNECTION_TIMEOUT`
- **Description:** Connection timeout for Redis operations (seconds)
- **Usage:** Prevents hanging connections during Redis connectivity issues
- **Default:** `5`
- **Security:** Prevents resource exhaustion from hanging connections
- **Example:** `5`

#### `REDIS_SOCKET_TIMEOUT`
- **Description:** Socket timeout for Redis operations (seconds)
- **Usage:** Prevents slow operations from blocking the application
- **Default:** `5`
- **Performance:** Balance between reliability and responsiveness
- **Example:** `5`

#### `REDIS_SSL_ENABLED`
- **Description:** Enable SSL/TLS encryption for Redis connections
- **Usage:** Encrypts data in transit to Redis server
- **Default:** `false`
- **Security:** **CRITICAL** - Enable for production deployments
- **Example:** `true`

#### `REDIS_SSL_CERT_REQS`
- **Description:** SSL certificate verification requirements
- **Usage:** Controls SSL certificate validation strictness
- **Values:** `required`, `optional`, `none`
- **Default:** `required`
- **Security:** Use `required` for production
- **Example:** `required`

## 📊 Analytics & Monitoring (Optional)

Currently, LinkShield uses built-in analytics. External analytics services can be integrated by adding their respective environment variables.

## 🛡️ Security Configuration

### Distributed Rate Limiting

#### `RATE_LIMIT_ENABLED`
- **Description:** Enable/disable rate limiting globally
- **Usage:** Master switch for all rate limiting functionality
- **Default:** `true`
- **Security:** **CRITICAL** - Should always be enabled in production
- **Example:** `true`

#### `RATE_LIMIT_REQUESTS_PER_MINUTE`
- **Description:** Global rate limit for requests per minute per IP address
- **Usage:** Prevents abuse and DoS attacks from individual IP addresses
- **Default:** `60`
- **Tuning:** Adjust based on expected legitimate traffic patterns
- **Example:** `60`

#### `RATE_LIMIT_BURST_SIZE`
- **Description:** Burst allowance for legitimate traffic spikes
- **Usage:** Allows temporary traffic bursts above the base rate limit
- **Default:** `10`
- **Balance:** Higher values allow more flexibility but reduce protection
- **Example:** `10`

#### `RATE_LIMIT_STORAGE_BACKEND`
- **Description:** Storage backend for rate limiting data
- **Usage:** Determines where rate limiting counters are stored
- **Values:** `redis` (distributed), `memory` (single instance)
- **Default:** `redis`
- **Production:** Use `redis` for multi-instance deployments
- **Example:** `redis`

#### `RATE_LIMIT_KEY_PREFIX`
- **Description:** Prefix for rate limiting keys in storage
- **Usage:** Prevents collisions with other applications using the same storage
- **Default:** `linkshield:ratelimit:`
- **Format:** Should end with a colon for clarity
- **Example:** `linkshield:ratelimit:`

#### `RATE_LIMIT_SLIDING_WINDOW`
- **Description:** Use sliding window vs fixed window rate limiting
- **Usage:** Controls rate limiting algorithm behavior
- **Default:** `true`
- **Security:** Sliding windows provide more consistent protection
- **Example:** `true`

#### `RATE_LIMIT_AUTHENTICATED_MULTIPLIER`
- **Description:** Rate limit multiplier for authenticated users
- **Usage:** Allows higher limits for authenticated users vs anonymous
- **Default:** `5`
- **Balance:** Higher values improve UX but may allow more abuse
- **Example:** `5`

#### `RATE_LIMIT_API_KEY_REQUESTS_PER_MINUTE`
- **Description:** Separate rate limit for API key requests
- **Usage:** Controls API usage for programmatic access
- **Default:** `300`
- **Business:** Align with API pricing tiers and usage expectations
- **Example:** `300`

### SSRF Protection

#### `SSRF_PROTECTION_ENABLED`
- **Description:** Enable Server-Side Request Forgery protection
- **Usage:** Master switch for SSRF protection mechanisms
- **Default:** `true`
- **Security:** **CRITICAL** - Should always be enabled
- **Example:** `true`

#### `SSRF_BLOCK_PRIVATE_IPS`
- **Description:** Block requests to private IP address ranges
- **Usage:** Prevents access to internal network resources
- **Default:** `true`
- **Security:** **CRITICAL** - Blocks RFC 1918, RFC 3927, etc.
- **Example:** `true`

#### `SSRF_BLOCK_LOCALHOST`
- **Description:** Block requests to localhost and loopback addresses
- **Usage:** Prevents access to local services and metadata endpoints
- **Default:** `true`
- **Security:** **CRITICAL** - Prevents local service enumeration
- **Example:** `true`

#### `SSRF_BLOCK_METADATA_SERVICES`
- **Description:** Block requests to cloud metadata services
- **Usage:** Prevents access to AWS, GCP, Azure metadata endpoints
- **Default:** `true`
- **Security:** **CRITICAL** - Prevents credential theft in cloud environments
- **Example:** `true`

#### `SSRF_ALLOWED_PROTOCOLS`
- **Description:** Allowed protocols for URL validation
- **Usage:** Restricts which protocols can be used in URL requests
- **Default:** `http,https`
- **Security:** Limit to necessary protocols only
- **Example:** `http,https`

#### `SSRF_MAX_REDIRECTS`
- **Description:** Maximum number of redirects to follow
- **Usage:** Prevents redirect loops and limits redirect chains
- **Default:** `5`
- **Security:** Lower values reduce attack surface
- **Example:** `5`

#### `SSRF_REQUEST_TIMEOUT`
- **Description:** Timeout for external URL requests (seconds)
- **Usage:** Prevents hanging requests and resource exhaustion
- **Default:** `30`
- **Performance:** Balance between reliability and resource usage
- **Example:** `30`

#### `SSRF_USER_AGENT`
- **Description:** User agent string for external requests
- **Usage:** Identifies LinkShield in server logs and helps with rate limiting
- **Default:** `LinkShield-Scanner/1.0`
- **Compliance:** Some services require specific user agents
- **Example:** `LinkShield-Scanner/1.0`

#### `SSRF_BLOCKED_DOMAINS`
- **Description:** Custom blocked domains (comma-separated)
- **Usage:** Block specific domains beyond default protections
- **Format:** Supports wildcards (*.example.com)
- **Example:** `internal.company.com,*.local`

#### `SSRF_ALLOWED_DOMAINS`
- **Description:** Custom allowed domains (if set, only these are allowed)
- **Usage:** Whitelist mode - only specified domains are accessible
- **Security:** Most restrictive option, use for high-security environments
- **Example:** `example.com,trusted-site.org`

### Error Message Standardization

#### `ERROR_STANDARDIZATION_ENABLED`
- **Description:** Enable standardized error messages
- **Usage:** Prevents information disclosure through error message variations
- **Default:** `true`
- **Security:** **CRITICAL** - Prevents user enumeration and information leakage
- **Example:** `true`

#### `ERROR_AUTH_GENERIC_MESSAGE`
- **Description:** Generic error message for authentication failures
- **Usage:** Prevents user enumeration through different error messages
- **Default:** `Invalid credentials provided`
- **Security:** Should not reveal whether username or password is incorrect
- **Example:** `Invalid credentials provided`

#### `ERROR_AUTHZ_GENERIC_MESSAGE`
- **Description:** Generic error message for authorization failures
- **Usage:** Standardizes access denied messages
- **Default:** `Access denied`
- **Security:** Should not reveal specific permission details
- **Example:** `Access denied`

#### `ERROR_VALIDATION_GENERIC_MESSAGE`
- **Description:** Generic error message for validation failures
- **Usage:** Prevents information disclosure through validation details
- **Default:** `Invalid input provided`
- **Security:** Should not reveal specific validation rules
- **Example:** `Invalid input provided`

#### `ERROR_RATE_LIMIT_MESSAGE`
- **Description:** Error message for rate limiting
- **Usage:** Informs users about rate limiting without revealing specifics
- **Default:** `Too many requests. Please try again later`
- **UX:** Should be user-friendly while maintaining security
- **Example:** `Too many requests. Please try again later`

#### `ERROR_DETAILED_LOGGING`
- **Description:** Log detailed errors server-side while showing generic messages
- **Usage:** Enables debugging while maintaining security
- **Default:** `true`
- **Balance:** Helps with troubleshooting without exposing details to users
- **Example:** `true`

#### `ERROR_INCLUDE_CODES`
- **Description:** Include error codes in responses
- **Usage:** Provides structured error identification for client debugging
- **Default:** `true`
- **Development:** Useful for API integration and debugging
- **Example:** `true`

#### `ERROR_INCLUDE_REQUEST_ID`
- **Description:** Include request IDs in error responses
- **Usage:** Enables correlation between client errors and server logs
- **Default:** `true`
- **Support:** Essential for customer support and debugging
- **Example:** `true`

## 🔒 Security Considerations

### Required for Production
- `NEXTAUTH_SECRET` - Must be cryptographically secure
- `DATABASE_URL` - Should use SSL in production
- `STRIPE_WEBHOOK_SECRET` - Required for payment security
- `PAYPAL_WEBHOOK_ID` - Required for PayPal webhook verification

### Environment-Specific Values
- **Development:** Use test/sandbox keys for all payment providers
- **Production:** Use live/production keys and enable SSL
- **Testing:** Use test database and mock payment providers

## 📝 Example Configuration

### Development (.env.local)
```bash
# Application
NODE_ENV=development
PORT=3000
NEXT_PUBLIC_APP_URL=http://localhost:3000
NEXT_PUBLIC_BASE_URL=http://localhost:3000
NEXT_PUBLIC_SOCKET_URL=http://localhost:3001

# Database
DATABASE_URL=postgresql://username:password@localhost:5432/linkshield

# Authentication
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=your-super-secret-development-key

# Stripe (Test Mode)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# PayPal (Sandbox)
PAYPAL_CLIENT_ID=your_sandbox_client_id
PAYPAL_CLIENT_SECRET=your_sandbox_client_secret
PAYPAL_WEBHOOK_ID=your_sandbox_webhook_id
PAYPAL_API_BASE=https://api-m.sandbox.paypal.com

# AI Services (Optional)
OPENAI_API_KEY=sk-...

# Caching (Optional)
REDIS_URL=redis://localhost:6379
```

### Production
```bash
# Application
NODE_ENV=production
PORT=3000
NEXT_PUBLIC_APP_URL=https://app.linkshield.com
NEXT_PUBLIC_BASE_URL=https://linkshield.site
NEXT_PUBLIC_SOCKET_URL=https://ws.linkshield.com

# Database
DATABASE_URL=postgresql://user:password@prod-host:5432/linkshield?sslmode=require

# Authentication
NEXTAUTH_URL=https://app.linkshield.com
NEXTAUTH_SECRET=your-super-secure-production-key

# Stripe (Live Mode)
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...

# PayPal (Production)
PAYPAL_CLIENT_ID=your_production_client_id
PAYPAL_CLIENT_SECRET=your_production_client_secret
PAYPAL_WEBHOOK_ID=your_production_webhook_id
PAYPAL_API_BASE=https://api-m.paypal.com
PAYPAL_RETURN_URL=https://app.linkshield.com/dashboard?success=true
PAYPAL_CANCEL_URL=https://app.linkshield.com/pricing

# AI Services
OPENAI_API_KEY=sk-...

# Caching
REDIS_URL=redis://:password@prod-redis:6379
```

## 🚨 Common Issues

### Missing Required Variables
- Application will fail to start without `DATABASE_URL`
- Authentication will not work without `NEXTAUTH_SECRET`
- Payment features will be disabled without payment provider keys

### URL Mismatches
- Ensure `NEXTAUTH_URL` matches your actual domain in production
- `NEXT_PUBLIC_APP_URL` should be accessible from client browsers
- PayPal return/cancel URLs should be valid and accessible

### Development vs Production
- Always use test/sandbox keys in development
- Never commit production secrets to version control
- Use different database instances for different environments

## 🔄 Environment Variable Validation

The application performs runtime validation of critical environment variables. Missing required variables will cause startup failures with descriptive error messages.

## 🛡️ Phase 2 Security Configuration

The following environment variables provide enhanced security features including email validation, session management, access control, audit logging, and security policy enforcement.

### Email Validation Settings

#### `LINKSHIELD_EMAIL_VALIDATION_ENABLED`
- **Description:** Enables comprehensive email validation system
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Prevents abuse through invalid or malicious email addresses

#### `LINKSHIELD_EMAIL_MX_CHECK_ENABLED`
- **Description:** Enables MX record validation for email domains
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Verifies email domain has valid mail servers

#### `LINKSHIELD_EMAIL_MX_CHECK_TIMEOUT`
- **Description:** Timeout in seconds for MX record lookups
- **Default:** `10`
- **Recommended:** `5-30` seconds depending on network conditions

#### `LINKSHIELD_EMAIL_DISPOSABLE_CHECK_ENABLED`
- **Description:** Enables detection of disposable/temporary email services
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Prevents abuse from temporary email services

#### `LINKSHIELD_EMAIL_DOMAIN_BLACKLIST`
- **Description:** Comma-separated list of blocked email domains
- **Example:** `example.com,spam-domain.net`
- **Security Impact:** Blocks known problematic domains

#### `LINKSHIELD_EMAIL_DOMAIN_WHITELIST`
- **Description:** Comma-separated list of allowed email domains (if set, only these are allowed)
- **Example:** `company.com,partner.org`
- **Security Impact:** Restricts registration to approved domains

### Session Management Settings

#### `LINKSHIELD_SESSION_DURATION_DAYS`
- **Description:** Maximum session duration in days
- **Default:** `7`
- **Security Impact:** Limits session lifetime to reduce exposure risk

#### `LINKSHIELD_SESSION_MAX_IDLE_HOURS`
- **Description:** Maximum idle time before session expires
- **Default:** `24`
- **Security Impact:** Automatically logs out inactive users

#### `LINKSHIELD_SESSION_MAX_CONCURRENT_SESSIONS`
- **Description:** Maximum concurrent sessions per user
- **Default:** `5`
- **Security Impact:** Prevents session hijacking and account sharing

#### `LINKSHIELD_SESSION_SECURE_COOKIE`
- **Description:** Requires HTTPS for session cookies
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Prevents cookie interception over HTTP

#### `LINKSHIELD_SESSION_TRACK_IP_CHANGES`
- **Description:** Monitors IP address changes during sessions
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Detects potential session hijacking

### Access Control Settings

#### `LINKSHIELD_ANONYMOUS_DAILY_LIMIT`
- **Description:** Daily request limit for anonymous users
- **Default:** `5`
- **Security Impact:** Prevents abuse from unauthenticated users

#### `LINKSHIELD_ANONYMOUS_HOURLY_LIMIT`
- **Description:** Hourly request limit for anonymous users
- **Default:** `2`
- **Security Impact:** Provides fine-grained rate limiting

#### `LINKSHIELD_SUBSCRIPTION_TIER_ENFORCEMENT`
- **Description:** Enforces subscription plan limits
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Prevents unauthorized access to premium features

#### `LINKSHIELD_API_ADMIN_ENDPOINTS_REQUIRE_2FA`
- **Description:** Requires two-factor authentication for admin endpoints
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Adds extra protection for sensitive operations

### Audit Logging Configuration

#### `LINKSHIELD_AUDIT_LOG_ENABLED`
- **Description:** Enables comprehensive audit logging
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Provides audit trail for compliance and security monitoring

#### `LINKSHIELD_AUDIT_LOG_RETENTION_DAYS`
- **Description:** Number of days to retain audit logs
- **Default:** `365`
- **Compliance:** Required for SOC2, GDPR, and other regulations

#### `LINKSHIELD_AUDIT_LOG_SANITIZE_PII`
- **Description:** Removes personally identifiable information from logs
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Protects user privacy in log files

#### `LINKSHIELD_AUDIT_LOG_INTEGRITY_CHECK`
- **Description:** Enables log integrity verification
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Detects log tampering attempts

### Security Policy Settings

#### `LINKSHIELD_SECURITY_POLICY_ENFORCEMENT`
- **Description:** Enables comprehensive security policy enforcement
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Activates all security validation and protection mechanisms

#### `LINKSHIELD_INPUT_VALIDATION_STRICT`
- **Description:** Enables strict input validation
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Prevents injection attacks and malformed data

#### `LINKSHIELD_CSP_ENABLED`
- **Description:** Enables Content Security Policy headers
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Prevents XSS and code injection attacks

#### `LINKSHIELD_GDPR_COMPLIANCE_MODE`
- **Description:** Enables GDPR compliance features
- **Values:** `true`, `false`
- **Default:** `false`
- **Compliance:** Required for EU data processing

#### `LINKSHIELD_HSTS_ENABLED`
- **Description:** Enables HTTP Strict Transport Security
- **Values:** `true`, `false`
- **Default:** `true`
- **Security Impact:** Forces HTTPS connections and prevents downgrade attacks

### Security Recommendations

1. **Production Settings:**
   - Enable all validation and security features
   - Set strict session timeouts
   - Enable audit logging with appropriate retention
   - Use compliance modes as required by regulations

2. **Development Settings:**
   - Can disable some validation for testing
   - Use shorter session timeouts for testing
   - Enable audit logging for debugging

3. **Monitoring:**
   - Monitor audit logs for suspicious activity
   - Set up alerts for security policy violations
   - Regularly review access control settings

---

## Phase 3 Security Configuration

Phase 3 introduces advanced security features including comprehensive notification systems, secure logging with PII protection, enhanced audit storage capabilities, sophisticated error handling, and automated security event management.

### Security Notification Settings

These variables configure the security notification system for sending alerts about security events, failed logins, and other critical security incidents.

| Variable | Description | Default | Security Impact |
|----------|-------------|---------|-----------------|
| `LINKSHIELD_SECURITY_NOTIFICATION_SMTP_HOST` | SMTP server hostname for security notifications | `smtp.gmail.com` | **CRITICAL** - Must be secure, trusted SMTP provider |
| `LINKSHIELD_SECURITY_NOTIFICATION_SMTP_PORT` | SMTP server port | `587` | Use 587 (TLS) or 465 (SSL) for security |
| `LINKSHIELD_SECURITY_NOTIFICATION_SMTP_USERNAME` | SMTP authentication username | `""` | **SENSITIVE** - Store securely, never commit |
| `LINKSHIELD_SECURITY_NOTIFICATION_SMTP_PASSWORD` | SMTP authentication password | `""` | **CRITICAL** - Use app passwords, store securely |
| `LINKSHIELD_SECURITY_NOTIFICATION_SMTP_USE_TLS` | Enable TLS encryption for SMTP | `true` | **CRITICAL** - Always enable for security |
| `LINKSHIELD_SECURITY_NOTIFICATION_SMTP_USE_SSL` | Enable SSL encryption for SMTP | `false` | Use TLS instead of SSL for modern security |
| `LINKSHIELD_SECURITY_NOTIFICATION_FROM_EMAIL` | From email address for notifications | `security@linkshield.com` | Should be recognizable security address |
| `LINKSHIELD_SECURITY_NOTIFICATION_ADMIN_EMAIL` | Primary admin email for alerts | `admin@linkshield.com` | **CRITICAL** - Must be monitored 24/7 |
| `LINKSHIELD_SECURITY_NOTIFICATION_ENABLED` | Enable security notifications | `true` | **CRITICAL** - Disable only for testing |
| `LINKSHIELD_SECURITY_NOTIFICATION_RATE_LIMIT_PER_HOUR` | Max notifications per hour | `50` | Prevents notification spam |
| `LINKSHIELD_SECURITY_NOTIFICATION_ENCRYPT_SENSITIVE_DATA` | Encrypt sensitive data in notifications | `true` | **CRITICAL** - Protects PII in transit |

**Security Recommendations:**
- Use dedicated security email accounts with strong authentication
- Configure rate limiting to prevent notification flooding
- Enable encryption for all sensitive notification data
- Monitor notification delivery and failure rates

### Secure Logging Configuration

These variables control log sanitization, PII protection, and secure storage of application logs.

| Variable | Description | Default | Security Impact |
|----------|-------------|---------|-----------------|
| `LINKSHIELD_SECURE_LOG_SANITIZATION_ENABLED` | Enable log sanitization | `true` | **CRITICAL** - Prevents sensitive data leakage |
| `LINKSHIELD_SECURE_LOG_SANITIZATION_LEVEL` | Sanitization strictness level | `strict` | Options: `strict`, `moderate`, `minimal` |
| `LINKSHIELD_SECURE_LOG_PII_DETECTION_ENABLED` | Enable PII pattern detection | `true` | **CRITICAL** - GDPR/CCPA compliance requirement |
| `LINKSHIELD_SECURE_LOG_PII_PATTERNS` | PII patterns to detect | `email,phone,ssn,credit_card` | Customize based on data types |
| `LINKSHIELD_SECURE_LOG_REDACT_PASSWORDS` | Redact passwords from logs | `true` | **CRITICAL** - Never log passwords |
| `LINKSHIELD_SECURE_LOG_REDACT_TOKENS` | Redact authentication tokens | `true` | **CRITICAL** - Prevents token theft |
| `LINKSHIELD_SECURE_LOG_REDACT_API_KEYS` | Redact API keys from logs | `true` | **CRITICAL** - Prevents API key exposure |
| `LINKSHIELD_SECURE_LOG_ENCRYPTION_ENABLED` | Enable log file encryption | `false` | **HIGH** - Enable for sensitive environments |
| `LINKSHIELD_SECURE_LOG_ROTATION_ENABLED` | Enable log rotation | `true` | Prevents disk space issues |
| `LINKSHIELD_SECURE_LOG_COMPRESSION_ENABLED` | Enable log compression | `true` | Reduces storage costs |
| `LINKSHIELD_SECURE_LOG_BACKUP_ENABLED` | Enable log backups | `true` | **HIGH** - Required for audit compliance |

**Security Recommendations:**
- Always enable PII detection and redaction
- Use strict sanitization in production environments
- Enable encryption for logs containing sensitive data
- Implement secure backup and retention policies

### Audit Logging Storage Configuration

These variables manage audit log retention, archival, and performance optimization.

| Variable | Description | Default | Security Impact |
|----------|-------------|---------|-----------------|
| `LINKSHIELD_AUDIT_LOG_RETENTION_POLICY_ENABLED` | Enable retention policy | `true` | **CRITICAL** - Required for compliance |
| `LINKSHIELD_AUDIT_LOG_RETENTION_DAYS` | Default retention period | `2555` | 7 years - meets most compliance requirements |
| `LINKSHIELD_AUDIT_LOG_RETENTION_CRITICAL_DAYS` | Critical event retention | `3650` | 10 years for critical security events |
| `LINKSHIELD_AUDIT_LOG_ARCHIVAL_ENABLED` | Enable log archival | `true` | **HIGH** - Reduces active storage costs |
| `LINKSHIELD_AUDIT_LOG_ARCHIVAL_ENCRYPTION_ENABLED` | Encrypt archived logs | `true` | **CRITICAL** - Protects historical data |
| `LINKSHIELD_AUDIT_LOG_CLEANUP_ENABLED` | Enable automatic cleanup | `true` | Prevents storage overflow |
| `LINKSHIELD_AUDIT_LOG_STORAGE_QUOTA_GB` | Storage quota in GB | `100` | Adjust based on audit volume |
| `LINKSHIELD_AUDIT_LOG_PERFORMANCE_MONITORING` | Monitor performance metrics | `true` | **HIGH** - Prevents audit system degradation |
| `LINKSHIELD_AUDIT_LOG_INDEXING_ENABLED` | Enable search indexing | `true` | **HIGH** - Required for compliance searches |
| `LINKSHIELD_AUDIT_LOG_EXPORT_ENABLED` | Enable audit log export | `true` | **CRITICAL** - Required for compliance reporting |

**Security Recommendations:**
- Set retention periods based on regulatory requirements
- Enable encryption for all archived audit logs
- Monitor storage quotas to prevent audit log loss
- Regularly test export functionality for compliance

### Error Handling Preferences

These variables control error message sanitization and debug mode security.

| Variable | Description | Default | Security Impact |
|----------|-------------|---------|-----------------|
| `LINKSHIELD_ERROR_HANDLING_SANITIZATION_ENABLED` | Enable error sanitization | `true` | **CRITICAL** - Prevents information disclosure |
| `LINKSHIELD_ERROR_HANDLING_SANITIZATION_LEVEL` | Sanitization strictness | `strict` | Options: `strict`, `moderate`, `minimal` |
| `LINKSHIELD_ERROR_HANDLING_SANITIZE_STACK_TRACES` | Sanitize stack traces | `true` | **CRITICAL** - Prevents path disclosure |
| `LINKSHIELD_ERROR_HANDLING_SANITIZE_DATABASE_ERRORS` | Sanitize DB errors | `true` | **CRITICAL** - Prevents schema disclosure |
| `LINKSHIELD_ERROR_HANDLING_DEBUG_MODE_ENABLED` | Enable debug mode | `false` | **CRITICAL** - Never enable in production |
| `LINKSHIELD_ERROR_HANDLING_DEBUG_ADMIN_ONLY` | Restrict debug to admins | `true` | **CRITICAL** - Limits debug access |
| `LINKSHIELD_ERROR_HANDLING_EXTERNAL_REPORTING_ENABLED` | Enable external error reporting | `false` | Consider privacy implications |
| `LINKSHIELD_ERROR_HANDLING_SENTRY_DSN` | Sentry DSN for error tracking | `""` | **SENSITIVE** - Store securely |
| `LINKSHIELD_ERROR_HANDLING_RATE_LIMITING_ENABLED` | Enable error rate limiting | `true` | Prevents error-based DoS attacks |
| `LINKSHIELD_ERROR_HANDLING_CIRCUIT_BREAKER_ENABLED` | Enable circuit breaker | `true` | **HIGH** - Prevents cascade failures |

**Security Recommendations:**
- Always use strict sanitization in production
- Never enable debug mode in production environments
- Implement rate limiting to prevent error-based attacks
- Carefully configure external error reporting to avoid data leaks

### Security Event Configuration

These variables control automated security event detection, escalation, and response.

| Variable | Description | Default | Security Impact |
|----------|-------------|---------|-----------------|
| `LINKSHIELD_SECURITY_EVENT_FAILED_LOGIN_THRESHOLD` | Failed login attempts before alert | `5` | **CRITICAL** - Detects brute force attacks |
| `LINKSHIELD_SECURITY_EVENT_FAILED_LOGIN_WINDOW_MINUTES` | Time window for failed login tracking | `15` | Balances security vs usability |
| `LINKSHIELD_SECURITY_EVENT_SUSPICIOUS_IP_THRESHOLD` | Suspicious activity threshold per IP | `10` | **HIGH** - Detects distributed attacks |
| `LINKSHIELD_SECURITY_EVENT_PRIVILEGE_ESCALATION_ENABLED` | Detect privilege escalation | `true` | **CRITICAL** - Prevents unauthorized access |
| `LINKSHIELD_SECURITY_EVENT_DATA_BREACH_DETECTION_ENABLED` | Enable breach detection | `true` | **CRITICAL** - Required for compliance |
| `LINKSHIELD_SECURITY_EVENT_ANOMALY_DETECTION_ENABLED` | Enable anomaly detection | `true` | **HIGH** - Detects unusual patterns |
| `LINKSHIELD_SECURITY_EVENT_AUTO_ESCALATE_CRITICAL` | Auto-escalate critical events | `true` | **CRITICAL** - Ensures rapid response |
| `LINKSHIELD_SECURITY_EVENT_CORRELATION_ENABLED` | Enable event correlation | `true` | **HIGH** - Improves threat detection |
| `LINKSHIELD_SECURITY_EVENT_NOTIFICATION_ENABLED` | Enable event notifications | `true` | **CRITICAL** - Required for incident response |
| `LINKSHIELD_SECURITY_EVENT_AUTO_BLOCK_ENABLED` | Enable automatic blocking | `true` | **HIGH** - Prevents ongoing attacks |
| `LINKSHIELD_SECURITY_EVENT_AUTO_LOGOUT_SUSPICIOUS_SESSIONS` | Auto-logout suspicious sessions | `true` | **CRITICAL** - Prevents session hijacking |
| `LINKSHIELD_SECURITY_EVENT_INCIDENT_CREATION_ENABLED` | Auto-create security incidents | `true` | **HIGH** - Ensures proper tracking |
| `LINKSHIELD_SECURITY_EVENT_FORENSIC_DATA_COLLECTION` | Collect forensic data | `true` | **HIGH** - Required for investigation |

**Security Recommendations:**
- Configure thresholds based on your application's normal usage patterns
- Enable all critical detection mechanisms in production
- Set up proper escalation procedures for different event types
- Regularly review and tune detection parameters
- Ensure incident response procedures are documented and tested

### Phase 3 Compliance Considerations

**GDPR Compliance:**
- PII detection and redaction in logs
- Audit log retention and deletion policies
- Data breach detection and notification
- Forensic data collection with privacy controls

**SOC 2 Compliance:**
- Comprehensive audit logging and retention
- Security event monitoring and response
- Access control and session management
- Incident management and forensic capabilities

**HIPAA Compliance (if applicable):**
- Enhanced encryption for sensitive logs
- Strict access controls for debug modes
- Comprehensive audit trails
- Automated security event detection

### Phase 3 Production Deployment Checklist

1. **Security Notifications:**
   - Configure secure SMTP with strong authentication
   - Set appropriate rate limits for notifications
   - Test notification delivery and escalation procedures

2. **Secure Logging:**
   - Enable strict sanitization and PII detection
   - Configure log encryption for sensitive environments
   - Set up secure log rotation and backup procedures

3. **Audit Storage:**
   - Configure retention periods per regulatory requirements
   - Enable archival and encryption for long-term storage
   - Set up monitoring for storage quotas and performance

4. **Error Handling:**
   - Ensure debug mode is disabled in production
   - Configure strict error sanitization
   - Set up external error reporting with privacy controls

5. **Security Events:**
   - Tune detection thresholds for your environment
   - Configure escalation and notification procedures
   - Test automated response mechanisms
   - Set up forensic data collection procedures

---

**Note:** Keep your `.env.local` file secure and never commit it to version control. Use your deployment platform's environment variable management for production deployments.

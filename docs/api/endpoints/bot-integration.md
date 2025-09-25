# Bot Integration API

The LinkShield Bot Integration API provides webhook endpoints and services for social media platform bots (Twitter, Telegram, Discord) to perform URL analysis and interact with users.

## Overview

The bot integration system allows LinkShield to:
- Receive webhook events from social media platforms
- Process URL analysis requests from bot interactions
- Provide quick analysis results optimized for bot responses
- Track user interactions and analytics across platforms
- Manage rate limiting and user preferences per platform

## Authentication

Bot webhooks use platform-specific signature verification:

### Twitter
```http
X-Twitter-Webhooks-Signature: sha256=<signature>
```

### Telegram
```http
X-Telegram-Bot-Api-Secret-Token: <secret_token>
```

### Discord
```http
X-Signature-Ed25519: <signature>
X-Signature-Timestamp: <timestamp>
```

## Endpoints

### Twitter Bot Webhook

**POST** `/api/v1/bots/twitter/webhook`

Receives Twitter webhook events for mentions, direct messages, and interactions.

#### Request Headers
```http
Content-Type: application/json
X-Twitter-Webhooks-Signature: sha256=<signature>
```

#### Request Body
```json
{
  "tweet_create_events": [
    {
      "id_str": "1234567890",
      "text": "@linkshield_bot check https://suspicious-site.com",
      "user": {
        "id_str": "987654321",
        "screen_name": "user123"
      }
    }
  ]
}
```

#### Response
```json
{
  "status": "processed",
  "events_handled": 1
}
```

### Telegram Bot Webhook

**POST** `/api/v1/bots/telegram/webhook`

Receives Telegram webhook events for messages and commands.

#### Request Headers
```http
Content-Type: application/json
X-Telegram-Bot-Api-Secret-Token: <secret_token>
```

#### Request Body
```json
{
  "update_id": 123456789,
  "message": {
    "message_id": 1234,
    "from": {
      "id": 987654321,
      "username": "user123"
    },
    "chat": {
      "id": -1001234567890,
      "type": "group"
    },
    "text": "/analyze https://suspicious-site.com"
  }
}
```

#### Response
```json
{
  "status": "processed"
}
```

### Discord Bot Webhook

**POST** `/api/v1/bots/discord/webhook`

Receives Discord interaction events for slash commands and components.

#### Request Headers
```http
Content-Type: application/json
X-Signature-Ed25519: <signature>
X-Signature-Timestamp: <timestamp>
```

#### Request Body
```json
{
  "type": 2,
  "data": {
    "name": "analyze",
    "options": [
      {
        "name": "url",
        "value": "https://suspicious-site.com"
      }
    ]
  },
  "user": {
    "id": "123456789012345678",
    "username": "user123"
  }
}
```

#### Response
```json
{
  "type": 4,
  "data": {
    "content": "Analysis complete!",
    "embeds": [
      {
        "title": "URL Analysis Result",
        "description": "The URL appears to be safe",
        "color": 65280
      }
    ]
  }
}
```

## Bot Analysis Service

### Quick Analysis

**POST** `/api/v1/bots/analyze/quick`

Performs optimized URL analysis for bot responses with reduced timeout and simplified results.

#### Request Headers
```http
Content-Type: application/json
Authorization: Bearer <service_token>
```

#### Request Body
```json
{
  "url": "https://example.com",
  "platform": "discord",
  "user_id": "123456789012345678",
  "context": {
    "guild_id": "987654321098765432",
    "channel_id": "456789012345678901"
  }
}
```

#### Response
```json
{
  "analysis_id": "uuid-string",
  "url": "https://example.com",
  "risk_level": "low",
  "risk_score": 15,
  "is_safe": true,
  "threats_detected": [],
  "summary": "This URL appears to be safe with no detected threats.",
  "analysis_time": "2024-01-15T10:30:00Z",
  "cached": false,
  "quick_analysis": true
}
```

### User Statistics

**GET** `/api/v1/bots/users/{platform}/{user_id}/stats`

Retrieves user statistics and interaction history for a specific platform.

#### Parameters
- `platform`: Platform identifier (twitter, telegram, discord)
- `user_id`: Platform-specific user ID

#### Response
```json
{
  "user_id": "123456789012345678",
  "platform": "discord",
  "total_requests": 45,
  "safe_urls": 38,
  "risky_urls": 7,
  "blocked_urls": 0,
  "first_interaction": "2024-01-01T00:00:00Z",
  "last_interaction": "2024-01-15T10:30:00Z",
  "rate_limit_status": {
    "requests_remaining": 8,
    "reset_time": "2024-01-15T11:00:00Z"
  }
}
```

## Rate Limiting

Bot endpoints implement platform-specific rate limiting:

### Default Limits
- **Per User**: 10 requests/minute, 100 requests/hour, 500 requests/day
- **Per Platform**: 1000 requests/minute globally
- **Quick Analysis**: 3-second timeout for bot-optimized responses

### Rate Limit Headers
```http
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1642248600
X-RateLimit-Platform: discord
```

## Error Responses

### Common Error Codes

#### 400 Bad Request
```json
{
  "error": "invalid_request",
  "message": "Invalid URL format",
  "details": {
    "url": "Not a valid URL"
  }
}
```

#### 401 Unauthorized
```json
{
  "error": "unauthorized",
  "message": "Invalid webhook signature"
}
```

#### 429 Too Many Requests
```json
{
  "error": "rate_limit_exceeded",
  "message": "Rate limit exceeded for user",
  "retry_after": 60
}
```

#### 503 Service Unavailable
```json
{
  "error": "service_unavailable",
  "message": "Analysis service temporarily unavailable"
}
```

## Bot Commands

### Supported Commands

#### Universal Commands
- `/analyze <url>` - Analyze a URL for threats
- `/help` - Display help information
- `/stats` - Show user statistics

#### Platform-Specific Features

##### Discord
- Slash commands with autocomplete
- Interactive buttons for re-analysis
- Embed responses with color-coded risk levels

##### Telegram
- Inline keyboard responses
- Group chat support with mention detection
- Private message fallback for sensitive results

##### Twitter
- Mention-based interaction
- Thread replies for detailed analysis
- Direct message support for private results

## Configuration

### Environment Variables

```bash
# Bot Service Configuration
BOT_SERVICE_ACCOUNT_ID=linkshield-bot-service
BOT_WEBHOOK_SECRET=your-webhook-secret
BOT_CACHE_TTL_SECONDS=300
BOT_MAX_RESPONSE_LENGTH=2000

# Platform Tokens
TWITTER_BOT_BEARER_TOKEN=your-twitter-token
TELEGRAM_BOT_TOKEN=your-telegram-token
DISCORD_BOT_TOKEN=your-discord-token

# Rate Limiting
BOT_RATE_LIMIT_PER_MINUTE=10
BOT_RATE_LIMIT_PER_HOUR=100
BOT_RATE_LIMIT_PER_DAY=500

# Analysis Configuration
QUICK_ANALYSIS_TIMEOUT_SECONDS=3
BOT_ANALYSIS_CACHE_ENABLED=true
BOT_ANALYSIS_RETRY_ATTEMPTS=2
```

## Security Considerations

1. **Webhook Verification**: All webhooks must pass signature verification
2. **Rate Limiting**: Strict rate limits prevent abuse
3. **User Privacy**: Sensitive analysis results sent via private channels
4. **Data Retention**: Bot interaction data follows platform-specific retention policies
5. **Access Control**: Service tokens required for internal API access

## Monitoring and Analytics

The bot integration system tracks:
- Request volume per platform
- Response times and success rates
- User engagement metrics
- Error rates and failure patterns
- Cache hit rates for performance optimization

Analytics data is available through the admin dashboard and can be exported for further analysis.
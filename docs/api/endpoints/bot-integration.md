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

#### CRC Verification

Twitter requires CRC challenge verification for webhook setup.

**GET** `/api/v1/bots/twitter/webhook?crc_token=<token>`

**Response:**
```json
{
  "response_token": "sha256=<signature>"
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

#### Verification

Some setups may perform a GET verification.

**GET** `/api/v1/bots/telegram/webhook`

**Response:**
```json
{
  "message": "Telegram webhook endpoint active"
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

#### Verification

Some setups may perform a GET verification.

**GET** `/api/v1/bots/discord/webhook`

**Response:**
```json
{
  "message": "Discord webhook endpoint active"
}
```

## Bot Management and Status

The bot service exposes endpoints for status, health, command registration, and platform management.

### Service Status

**GET** `/api/v1/bots/status`

Returns comprehensive status information for all bot platforms.

**Response:**
```json
{
  "platform_statuses": {
    "discord": "running",
    "telegram": "running",
    "twitter": "running"
  },
  "platform_health": {
    "discord": {"healthy": true},
    "telegram": {"healthy": true},
    "twitter": {"healthy": true}
  }
}
```

### Service Health

**GET** `/api/v1/bots/health`

Returns health information suitable for monitoring systems.

**Response:**
```json
{
  "healthy": true,
  "platforms": {
    "discord": {"healthy": true},
    "telegram": {"healthy": true},
    "twitter": {"healthy": true}
  }
}
```

### Register Bot Commands

**POST** `/api/v1/bots/commands/register`

Triggers command registration across platforms.

**Response:**
```json
{
  "message": "Command registration completed",
  "results": {
    "discord": "ok",
    "telegram": "ok",
    "twitter": "ok"
  }
}
```

### Restart Platform

**POST** `/api/v1/bots/platforms/{platform}/restart`

Restarts a specific platform (discord, telegram, twitter).

**Response:**
```json
{
  "message": "Platform discord restart initiated"
}
```

### Platform Info

**GET** `/api/v1/bots/platforms/{platform}/info`

Returns platform configuration, status, and health.

**Response:**
```json
{
  "platform": "discord",
  "status": "running",
  "bot_info": {"id": "bot-123"},
  "config": {
    "enabled": true,
    "features": {},
    "limits": {}
  },
  "health": {"healthy": true}
}
```

## Related API: Social Protection Bot

For content analysis services optimized for bot integrations (analyze, account safety, compliance, followers, batch analysis), see the Social Protection Bot API documentation under `/api/v1/social-protection/bot`.

## Rate Limiting

Bot endpoints implement platform-specific rate limiting:

### Default Limits
- **Per user per platform**: 50 requests/hour (sliding window) enforced via BotRateLimit
- **Platform throttling**: Provider-side limits apply (Discord, Telegram, Twitter)
- **Quick Analysis**: 3-second timeout for bot-optimized responses

### Rate Limit Headers
```http
X-RateLimit-Limit: 50
X-RateLimit-Remaining: 47
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
# Rate Limiting
# Enforced per user per platform via BotRateLimit (sliding window)
BOT_RATE_LIMIT_PER_HOUR=50

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
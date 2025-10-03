# Bot Integration Implementation Guide

## Overview

This guide provides step-by-step instructions for implementing and deploying the LinkShield bot integration system across Twitter, Telegram, and Discord platforms.

## Prerequisites

### Development Environment

- Python 3.9+
- PostgreSQL 12+
- Redis 6+
- FastAPI application running
- Access to social media platform developer accounts

### Platform Requirements

1. **Twitter Developer Account**
   - Twitter API v2 access
   - App with read/write permissions
   - Webhook environment configured

2. **Telegram Bot**
   - Bot created via @BotFather
   - Bot token obtained
   - Webhook URL configured

3. **Discord Application**
   - Discord Developer Portal application
   - Bot user created with necessary permissions
   - Slash commands registered

## Implementation Steps

### Step 1: Environment Configuration

1. **Copy environment template**
   ```bash
   cp .env.example .env
   ```

2. **Configure bot credentials**
   ```bash
   # Twitter Bot Configuration
   TWITTER_BOT_BEARER_TOKEN=your-twitter-bearer-token
   TWITTER_BOT_API_KEY=your-twitter-api-key
   TWITTER_BOT_API_SECRET=your-twitter-api-secret
   TWITTER_BOT_ACCESS_TOKEN=your-twitter-access-token
   TWITTER_BOT_ACCESS_TOKEN_SECRET=your-twitter-access-token-secret

   # Telegram Bot Configuration
   TELEGRAM_BOT_TOKEN=your-telegram-bot-token
   TELEGRAM_BOT_WEBHOOK_URL=https://your-domain.com/api/v1/bots/telegram/webhook

   # Discord Bot Configuration
   DISCORD_BOT_TOKEN=your-discord-bot-token
   DISCORD_BOT_CLIENT_ID=your-discord-client-id
   DISCORD_BOT_CLIENT_SECRET=your-discord-client-secret
   ```

3. **Configure service settings**
   ```bash
   BOT_SERVICE_ACCOUNT_ID=linkshield-bot-service
   BOT_WEBHOOK_SECRET=generate-secure-random-string
   BOT_CACHE_TTL_SECONDS=300
   BOT_MAX_RESPONSE_LENGTH=2000
   ```

### Step 2: Database Setup

1. **Run database migration**
   ```bash
   alembic upgrade head
   ```

2. **Verify tables created**
   ```sql
   \dt bot_*
   ```

   Expected tables:
   - `bot_users`
   - `bot_analysis_requests`
   - `bot_rate_limits`
   - `bot_sessions`
   - `bot_configurations`
   - `bot_analytics_events`

### Step 3: Platform Setup

#### Twitter Setup

1. **Create Twitter App**
   - Go to [Twitter Developer Portal](https://developer.twitter.com/)
   - Create new app with read/write permissions
   - Generate API keys and access tokens

2. **Configure Webhook**
   ```bash
   # Set webhook URL (replace with your domain)
   curl -X POST "https://api.twitter.com/1.1/account_activity/all/dev/webhooks.json" \
     -H "Authorization: OAuth ..." \
     -d "url=https://your-domain.com/api/v1/bots/twitter/webhook"
   ```

3. **Subscribe to events**
   ```bash
   curl -X POST "https://api.twitter.com/1.1/account_activity/all/dev/subscriptions.json" \
     -H "Authorization: OAuth ..."
   ```

#### Telegram Setup

1. **Create Bot**
   - Message @BotFather on Telegram
   - Use `/newbot` command
   - Save the bot token

2. **Set Webhook**
   ```bash
   curl -X POST "https://api.telegram.org/bot<BOT_TOKEN>/setWebhook" \
     -H "Content-Type: application/json" \
     -d '{
       "url": "https://your-domain.com/api/v1/bots/telegram/webhook",
       "secret_token": "your-webhook-secret"
     }'
   ```

3. **Configure Commands**
   ```bash
   curl -X POST "https://api.telegram.org/bot<BOT_TOKEN>/setMyCommands" \
     -H "Content-Type: application/json" \
     -d '{
       "commands": [
         {"command": "analyze", "description": "Analyze a URL for threats"},
         {"command": "help", "description": "Show help information"},
         {"command": "stats", "description": "Show your usage statistics"}
       ]
     }'
   ```

#### Discord Setup

1. **Create Discord Application**
   - Go to [Discord Developer Portal](https://discord.com/developers/applications)
   - Create new application
   - Create bot user and copy token

2. **Register Slash Commands**
   ```python
   # Run this script to register commands
   import requests
   
   APPLICATION_ID = "your-application-id"
   BOT_TOKEN = "your-bot-token"
   
   commands = [
       {
           "name": "analyze",
           "description": "Analyze a URL for security threats",
           "options": [
               {
                   "name": "url",
                   "description": "The URL to analyze",
                   "type": 3,  # STRING
                   "required": True
               }
           ]
       },
       {
           "name": "help",
           "description": "Show help information"
       },
       {
           "name": "stats",
           "description": "Show your usage statistics"
       }
   ]
   
   for command in commands:
       response = requests.post(
           f"https://discord.com/api/v10/applications/{APPLICATION_ID}/commands",
           headers={"Authorization": f"Bot {BOT_TOKEN}"},
           json=command
       )
       print(f"Registered command: {command['name']}")
   ```

3. **Set Interaction Endpoint**
   - In Discord Developer Portal, set Interactions Endpoint URL
   - URL: `https://your-domain.com/api/v1/bots/discord/webhook`

### Step 4: Service Deployment

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start application**
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000
   ```

3. **Verify bot gateway initialization**
   ```bash
   # Check logs for successful initialization
   tail -f app.log | grep "Bot gateway"
   ```

### Step 5: Testing

#### Unit Tests

```bash
# Run bot-specific tests
pytest tests/test_bots/ -v

# Run authentication tests
pytest tests/test_auth/test_bot_auth.py -v

# Run controller tests
pytest tests/test_controllers/test_bot_controller.py -v
```

#### Integration Tests

```bash
# Test webhook endpoints
curl -X POST "https://www.linkshield.site/api/v1/bots/telegram/webhook" \
  -H "Content-Type: application/json" \
  -H "X-Telegram-Bot-Api-Secret-Token: your-secret" \
  -d '{
    "update_id": 123,
    "message": {
      "message_id": 1,
      "from": {"id": 123, "username": "test"},
      "chat": {"id": 123, "type": "private"},
      "text": "/analyze https://example.com"
    }
  }'
```

#### End-to-End Tests

1. **Twitter**: Send mention to bot account
2. **Telegram**: Send `/analyze` command to bot
3. **Discord**: Use slash command in server

### Step 6: Monitoring Setup

1. **Configure logging**
   ```python
   # In app.py or logging configuration
   import logging
   
   logging.basicConfig(
       level=logging.INFO,
       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
       handlers=[
           logging.FileHandler('bot.log'),
           logging.StreamHandler()
       ]
   )
   ```

2. **Set up metrics collection**
   ```bash
   # Install monitoring dependencies
   pip install prometheus-client

   # Configure metrics endpoint
   # Metrics available at /metrics
   ```

3. **Health check endpoints**
   ```bash
   # Check bot service health
curl https://www.linkshield.site/health/bots
   ```

## Configuration Management

### Environment-Specific Settings

#### Development
```bash
BOT_ENABLE_DEEP_ANALYSIS=false
BOT_RATE_LIMIT_STRICT_MODE=false
BOT_LOG_ALL_INTERACTIONS=true
```

#### Production
```bash
BOT_ENABLE_DEEP_ANALYSIS=true
BOT_RATE_LIMIT_STRICT_MODE=true
BOT_LOG_ALL_INTERACTIONS=false
BOT_WEBHOOK_SIGNATURE_VERIFICATION=true
```

### Feature Flags

```bash
# Enable/disable platforms
BOT_TWITTER_ENABLED=true
BOT_TELEGRAM_ENABLED=true
BOT_DISCORD_ENABLED=true

# Enable/disable features
BOT_ANALYTICS_ENABLED=true
BOT_USER_PREFERENCES_ENABLED=true
BOT_ANALYSIS_CACHE_ENABLED=true
```

## Troubleshooting

### Common Issues

#### Webhook Verification Failures

**Symptoms**: 401 Unauthorized responses to webhooks

**Solutions**:
1. Verify webhook secrets match platform configuration
2. Check signature generation algorithm
3. Ensure proper header names and formats

```python
# Debug webhook signatures
import hmac
import hashlib

def verify_signature(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

#### Rate Limit Issues

**Symptoms**: 429 Too Many Requests responses

**Solutions**:
1. Check Redis connection and rate limit storage
2. Verify rate limit configuration
3. Monitor user request patterns

```bash
# Check rate limit status
redis-cli keys "rate_limit:*"
redis-cli get "rate_limit:discord:123456789"
```

#### Bot Command Registration

**Symptoms**: Commands not appearing in platform interfaces

**Solutions**:
1. Re-register commands with updated permissions
2. Check bot permissions in servers/groups
3. Verify application configuration

### Performance Optimization

#### Caching Strategy

```python
# Optimize cache usage
BOT_ANALYSIS_CACHE_TTL_MINUTES=15
BOT_CACHE_TTL_SECONDS=300

# Monitor cache hit rates
redis-cli info stats | grep keyspace_hits
```

#### Database Optimization

```sql
-- Add indexes for performance
CREATE INDEX CONCURRENTLY idx_bot_users_platform_user_id 
ON bot_users(platform, platform_user_id);

CREATE INDEX CONCURRENTLY idx_bot_analysis_requests_created_at 
ON bot_analysis_requests(created_at);
```

## Security Considerations

### Webhook Security

1. **Always verify signatures** for all incoming webhooks
2. **Use HTTPS** for all webhook endpoints
3. **Rotate secrets** regularly
4. **Log security events** for audit trails

### Data Protection

1. **Minimize data collection** - only store necessary information
2. **Implement data retention** policies
3. **Encrypt sensitive data** at rest
4. **Use secure communication** channels

### Access Control

1. **Service tokens** for internal API access
2. **Rate limiting** to prevent abuse
3. **User blocking** for suspicious activity
4. **Audit logging** for all operations

## Maintenance

### Regular Tasks

1. **Monitor error rates** and response times
2. **Review rate limit** effectiveness
3. **Update platform APIs** as needed
4. **Clean up old data** according to retention policies

### Updates and Patches

1. **Test in staging** environment first
2. **Monitor deployment** for issues
3. **Rollback plan** for critical failures
4. **Update documentation** as needed

## Support and Documentation

### Internal Documentation

- API documentation: `/docs/api/endpoints/bot-integration.md`
- Database schema: `/docs/database/bot-schema.md`
- Security guide: `/docs/security/bot-security.md`

### External Resources

- [Twitter API Documentation](https://developer.twitter.com/en/docs)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [Discord Developer Documentation](https://discord.com/developers/docs)

### Getting Help

1. Check application logs for error details
2. Review platform-specific documentation
3. Test with minimal examples
4. Contact platform support if needed
I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

I can see that the current social protection implementation is missing Telegram and Discord platform adapters. The PlatformType enum in types.py only includes TWITTER, META_FACEBOOK, META_INSTAGRAM, TIKTOK, and LINKEDIN - but not TELEGRAM and DISCORD. The platform_adapters directory has adapters for Twitter, Meta, TikTok, and LinkedIn, but is missing Telegram and Discord adapters. The user wants complete social media protection services and endpoints for these missing platforms.

### Approach

I'll add comprehensive social media protection support for Telegram and Discord by: 1) Adding TELEGRAM and DISCORD to the PlatformType enum, 2) Creating TelegramProtectionAdapter and DiscordProtectionAdapter following the same pattern as existing adapters, 3) Updating the platform registry and imports, 4) Adding platform-specific configuration, and 5) Updating documentation. The adapters will implement the full SocialPlatformAdapter interface with platform-specific risk analysis, content scanning, algorithm health monitoring, and crisis detection capabilities.

### Reasoning

I examined the social protection types, registry, and platform adapters directory to understand the current implementation. I found that Telegram and Discord are completely missing from the platform types enum and have no corresponding adapter implementations, despite the infrastructure being ready to support them through the existing base adapter pattern and registry system.

## Proposed File Changes

### src\social_protection\types.py(MODIFY)

Add TELEGRAM and DISCORD to the PlatformType enum. Update the enum to include:
```python
TELEGRAM = "telegram"
DISCORD = "discord"
```
These additions will enable the social protection system to recognize and handle Telegram and Discord platforms alongside the existing platforms.

### src\social_protection\platform_adapters\telegram_adapter.py(NEW)

References: 

- src\social_protection\platform_adapters\base_adapter.py
- src\social_protection\platform_adapters\twitter_adapter.py

Create comprehensive TelegramProtectionAdapter class that implements the SocialPlatformAdapter interface. Include Telegram-specific risk analysis for:

**Profile Analysis:**
- Bot detection and verification status
- Channel/group authenticity assessment
- Subscriber count validation
- Profile completeness and suspicious indicators

**Content Analysis:**
- Message spam detection
- Malicious link identification
- Scam pattern recognition
- Forward chain analysis
- Media content safety assessment

**Algorithm Health:**
- Message delivery rates
- Engagement patterns
- Channel/group visibility metrics
- Search discoverability

**Crisis Detection:**
- Viral negative content spread
- Mass reporting campaigns
- Coordinated harassment detection
- Misinformation propagation

Implement all abstract methods from `SocialPlatformAdapter` with Telegram-specific logic, rate limits, and risk thresholds.

### src\social_protection\platform_adapters\discord_adapter.py(NEW)

References: 

- src\social_protection\platform_adapters\base_adapter.py
- src\social_protection\platform_adapters\twitter_adapter.py

Create comprehensive DiscordProtectionAdapter class that implements the SocialPlatformAdapter interface. Include Discord-specific risk analysis for:

**Profile Analysis:**
- User verification and badge status
- Server membership patterns
- Account age and activity validation
- Suspicious behavior indicators
- Bot account detection

**Content Analysis:**
- Message content safety scanning
- Embed and attachment analysis
- Invite link validation
- Spam and raid detection
- Voice/video content monitoring

**Algorithm Health:**
- Message visibility and engagement
- Server discovery metrics
- Role and permission effectiveness
- Community growth patterns

**Crisis Detection:**
- Server raids and coordinated attacks
- Harassment campaign detection
- Doxxing and privacy violations
- Malicious bot infiltration
- Community toxicity escalation

Implement all abstract methods from `SocialPlatformAdapter` with Discord-specific logic, API integration patterns, and community safety features.

### src\social_protection\platform_adapters\__init__.py(MODIFY)

References: 

- src\social_protection\platform_adapters\telegram_adapter.py(NEW)
- src\social_protection\platform_adapters\discord_adapter.py(NEW)

Add imports and exports for the new Telegram and Discord adapters:

```python
from .telegram_adapter import TelegramProtectionAdapter
from .discord_adapter import DiscordProtectionAdapter
```

Update the `__all__` list to include:
```python
"TelegramProtectionAdapter",
"DiscordProtectionAdapter",
```

Update the module docstring to mention Telegram and Discord protection adapters alongside the existing platforms.

### src\social_protection\data_models\telegram_models.py(NEW)

References: 

- src\social_protection\data_models\assessment_models.py

Create Telegram-specific data models for social protection including:

**TelegramProfileData:**
- User/channel/group information
- Subscriber counts and verification status
- Bio and description content
- Profile photo and media

**TelegramContentData:**
- Message content and metadata
- Forward chain information
- Media attachments and files
- Reaction and engagement data

**TelegramRiskFactors:**
- Bot detection indicators
- Spam pattern markers
- Scam content flags
- Malicious link indicators

**TelegramAnalysisRequest/Response:**
- Platform-specific request parameters
- Telegram API integration data
- Risk assessment results
- Recommendation actions

All models should inherit from appropriate base classes and include proper validation, serialization, and documentation.

### src\social_protection\data_models\discord_models.py(NEW)

References: 

- src\social_protection\data_models\assessment_models.py

Create Discord-specific data models for social protection including:

**DiscordProfileData:**
- User profile information and badges
- Server membership and roles
- Activity status and presence
- Account creation and verification data

**DiscordContentData:**
- Message content and embeds
- Attachment and media files
- Reaction and interaction data
- Thread and reply context

**DiscordServerData:**
- Server information and settings
- Member count and activity metrics
- Channel structure and permissions
- Moderation and safety features

**DiscordRiskFactors:**
- Raid and spam indicators
- Harassment pattern markers
- Malicious bot detection
- Community toxicity signals

**DiscordAnalysisRequest/Response:**
- Platform-specific request parameters
- Discord API integration data
- Risk assessment results
- Moderation recommendations

Include proper validation, type hints, and integration with existing data model patterns.

### src\social_protection\data_models\__init__.py(MODIFY)

References: 

- src\social_protection\data_models\telegram_models.py(NEW)
- src\social_protection\data_models\discord_models.py(NEW)

Add imports and exports for the new Telegram and Discord data models:

```python
from .telegram_models import (
    TelegramProfileData,
    TelegramContentData,
    TelegramRiskFactors,
    TelegramAnalysisRequest,
    TelegramAnalysisResponse
)
from .discord_models import (
    DiscordProfileData,
    DiscordContentData,
    DiscordServerData,
    DiscordRiskFactors,
    DiscordAnalysisRequest,
    DiscordAnalysisResponse
)
```

Update the `__all__` list to include all the new model classes. This ensures the models are properly exposed for use by the adapters and other components.

### src\config\social_protection_config.yaml(MODIFY)

Add configuration sections for Telegram and Discord platforms including:

**Telegram Configuration:**
```yaml
telegram:
  enabled: true
  api_credentials:
    bot_token: ${TELEGRAM_BOT_TOKEN}
    api_id: ${TELEGRAM_API_ID}
    api_hash: ${TELEGRAM_API_HASH}
  rate_limits:
    profile_scans_per_hour: 100
    content_analyses_per_hour: 500
    api_requests_per_minute: 30
  risk_thresholds:
    bot_detection: 0.7
    spam_content: 0.6
    malicious_links: 0.8
    scam_patterns: 0.75
```

**Discord Configuration:**
```yaml
discord:
  enabled: true
  api_credentials:
    bot_token: ${DISCORD_BOT_TOKEN}
    client_id: ${DISCORD_CLIENT_ID}
    client_secret: ${DISCORD_CLIENT_SECRET}
  rate_limits:
    profile_scans_per_hour: 150
    content_analyses_per_hour: 600
    api_requests_per_minute: 50
  risk_thresholds:
    raid_detection: 0.8
    harassment_patterns: 0.7
    malicious_bots: 0.85
    toxicity_levels: 0.6
```

### src\social_protection\controllers\social_protection_controller.py(MODIFY)

References: 

- src\social_protection\types.py(MODIFY)

Update the `_is_valid_profile_url()` method to include validation for Telegram and Discord URLs. Add to the `platform_domains` dictionary:

```python
PlatformType.TELEGRAM: ["t.me", "telegram.me", "telegram.org"],
PlatformType.DISCORD: ["discord.com", "discord.gg", "discordapp.com"],
```

This ensures that the social protection controller can properly validate URLs for Telegram channels/groups and Discord servers/users when initiating scans.

### requirements.txt(MODIFY)

Add dependencies required for Telegram and Discord API integration:

```
# Telegram API integration
pyrogram
tgcrypto
telethon

# Discord API integration
discord.py
aiohttp

# Additional utilities for social media analysis
python-telegram-bot
discord-webhook
```

These libraries provide comprehensive API access for both platforms, enabling the adapters to fetch profile data, analyze content, and monitor platform-specific metrics.

### .env.example(MODIFY)

Add environment variable examples for Telegram and Discord API credentials:

```bash
# Telegram API Configuration
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
TELEGRAM_API_ID=your_telegram_api_id
TELEGRAM_API_HASH=your_telegram_api_hash

# Discord API Configuration
DISCORD_BOT_TOKEN=your_discord_bot_token_here
DISCORD_CLIENT_ID=your_discord_client_id
DISCORD_CLIENT_SECRET=your_discord_client_secret

# Platform-specific settings
TELEGRAM_RATE_LIMIT_PER_MINUTE=30
DISCORD_RATE_LIMIT_PER_MINUTE=50
```

Include comments explaining how to obtain these credentials from Telegram BotFather and Discord Developer Portal.

### src\config\settings.py(MODIFY)

Add configuration settings for Telegram and Discord platforms to the Settings class:

```python
# Telegram Configuration
TELEGRAM_BOT_TOKEN: Optional[str] = None
TELEGRAM_API_ID: Optional[str] = None
TELEGRAM_API_HASH: Optional[str] = None
TELEGRAM_RATE_LIMIT_PER_MINUTE: int = 30

# Discord Configuration
DISCORD_BOT_TOKEN: Optional[str] = None
DISCORD_CLIENT_ID: Optional[str] = None
DISCORD_CLIENT_SECRET: Optional[str] = None
DISCORD_RATE_LIMIT_PER_MINUTE: int = 50
```

Add validation methods to ensure required credentials are provided when the respective platforms are enabled. Include proper type hints and default values.

### docs\social_media_shield\telegram.md(NEW)

References: 

- docs\social_media_shield\twitter.md

Create comprehensive documentation for Telegram social protection features including:

**Overview:**
- Telegram platform protection capabilities
- Supported analysis types and features
- Integration with LinkShield ecosystem

**Setup and Configuration:**
- Telegram Bot API setup instructions
- Required credentials and permissions
- Rate limiting and API quotas

**Protection Features:**
- Profile and channel analysis
- Content safety scanning
- Bot detection and verification
- Scam and spam identification
- Forward chain analysis

**API Endpoints:**
- Available endpoints for Telegram analysis
- Request/response examples
- Error handling and status codes

**Best Practices:**
- Optimal scanning strategies
- Privacy and compliance considerations
- Performance optimization tips

Include code examples, troubleshooting guides, and integration patterns.

### docs\social_media_shield\discord.md(NEW)

References: 

- docs\social_media_shield\twitter.md

Create comprehensive documentation for Discord social protection features including:

**Overview:**
- Discord platform protection capabilities
- Server and user analysis features
- Community safety and moderation tools

**Setup and Configuration:**
- Discord Bot setup and permissions
- OAuth2 application configuration
- Required scopes and intents

**Protection Features:**
- User profile and behavior analysis
- Server health and safety assessment
- Content moderation and filtering
- Raid and harassment detection
- Bot and automation analysis

**API Endpoints:**
- Available endpoints for Discord analysis
- Request/response examples
- Webhook integration options

**Community Safety:**
- Toxicity detection algorithms
- Moderation recommendation system
- Crisis response procedures
- Privacy and data protection

**Integration Examples:**
- Bot integration patterns
- Webhook configuration
- Real-time monitoring setup

Include detailed examples, security considerations, and compliance guidelines.

### src\alembic\versions\009_add_telegram_discord_support.py(NEW)

References: 

- src\alembic\versions\007_add_social_protection_models.py
- src\models\social_protection.py

Create Alembic migration to update the database schema for Telegram and Discord support:

**Update PlatformType enum:**
- Add 'telegram' and 'discord' values to the platform_type enum in the database
- Ensure existing data remains intact

**Update existing tables:**
- Modify any tables that reference platform types to support the new values
- Update constraints and indexes as needed

**Add platform-specific columns:**
- Add any Telegram/Discord-specific fields to relevant tables
- Include proper data types and constraints

**Migration structure:**
```python
def upgrade():
    # Add new platform types to enum
    op.execute("ALTER TYPE platformtype ADD VALUE 'telegram'")
    op.execute("ALTER TYPE platformtype ADD VALUE 'discord'")
    
    # Update any platform-specific configurations
    # Add indexes for new platform types
    
def downgrade():
    # Remove new platform types (with data cleanup)
    # Restore previous schema state
```

Include proper error handling and data migration procedures.
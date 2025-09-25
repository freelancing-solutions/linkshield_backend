I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

I've thoroughly analyzed the LinkShield backend codebase and understand the comprehensive social protection infrastructure already in place. The system has mature FastAPI architecture with social media scanning, platform adapters, authentication, and database models. The user wants to add bot functionality for Twitter, Telegram, and Discord that provides quick-access (≤3 second) responses using existing analysis capabilities. The current `SocialScanService` performs comprehensive multi-minute scans, so we need a lightweight "quick analysis" path that reuses existing logic with timeouts and caching.

### Approach

The implementation will add a new bot layer on top of the existing social protection infrastructure. We'll create platform-specific bot handlers (Twitter, Telegram, Discord) that connect to a unified `QuickAccessBotGateway`. This gateway will use a new `QuickAnalysisService` that wraps existing platform adapters with 3-second timeouts and caching. Bot webhooks will be handled through new FastAPI routes with bot-specific authentication. The design reuses existing models, services, and database infrastructure while adding the minimal components needed for real-time bot interactions.

### Reasoning

I explored the codebase structure starting with the main application entry point and social protection module. I examined the existing platform adapters, services, controllers, routes, and authentication system to understand integration patterns. I reviewed the data models to understand request/response structures and checked the requirements.txt for available dependencies. This gave me a complete picture of the current architecture and how bot functionality should integrate.

## Mermaid Diagram

sequenceDiagram
    participant User as Platform User
    participant Bot as Bot Handler
    participant Gateway as QuickAccessBotGateway
    participant QuickService as QuickAnalysisService
    participant Adapter as Platform Adapter
    participant DB as Database

    User->>Bot: Send command (DM/mention)
    Bot->>Bot: Parse command & validate
    Bot->>Gateway: handle_quick_request(command, user_context)
    Gateway->>Gateway: classify_request(command)
    
    alt Profile Analysis
        Gateway->>QuickService: quick_profile_analysis(username)
        QuickService->>Adapter: scan_profile(minimal_data, timeout=3s)
        Adapter-->>QuickService: risk_assessment
        QuickService->>DB: Cache result
    else Content Analysis
        Gateway->>QuickService: quick_content_analysis(content)
        QuickService->>Adapter: analyze_content(content, timeout=3s)
        Adapter-->>QuickService: content_risk
        QuickService->>DB: Cache result
    end
    
    QuickService-->>Gateway: analysis_result
    Gateway->>Gateway: format_platform_response(result, platform)
    Gateway-->>Bot: formatted_response
    Bot->>User: Send response (DM/reply)
    
    opt Background Deep Analysis
        Bot->>QuickService: schedule_deep_analysis(scan_id)
        QuickService->>DB: Create full scan record
        Note over QuickService: Async full analysis using existing SocialScanService
    end

## Proposed File Changes

### src\config\settings.py(MODIFY)

Add new environment variables for bot configuration including `TWITTER_BOT_BEARER_TOKEN`, `TELEGRAM_BOT_TOKEN`, `DISCORD_BOT_TOKEN`, `QUICK_ANALYSIS_TIMEOUT_SECONDS`, `BOT_RATE_LIMIT_PER_MINUTE`, and `BOT_SERVICE_ACCOUNT_ID`. Update the `Settings` class to include these new configuration options with appropriate defaults and validation.

### src\bots(NEW)

Create new directory for bot-related modules and services.

### src\bots\__init__.py(NEW)

Initialize the bots package with exports for the main bot components including `QuickAccessBotGateway`, `TwitterBotHandler`, `TelegramBotHandler`, and `DiscordBotHandler`.

### src\bots\gateway.py(NEW)

References: 

- src\social_protection\services\social_scan_service.py
- src\social_protection\platform_adapters\base_adapter.py

Implement the `QuickAccessBotGateway` class that serves as the central coordinator for all bot platforms. This class will handle command parsing, route requests to the appropriate quick analysis service, and format responses for each platform. Include methods for `handle_quick_request()`, `classify_request()`, and `format_platform_response()`. The gateway will integrate with the existing `SocialScanService` and platform adapters but with strict 3-second timeouts.

### src\bots\handlers(NEW)

Create directory for platform-specific bot handlers.

### src\bots\handlers\__init__.py(NEW)

Initialize handlers package with exports for all bot handler classes.

### src\bots\handlers\twitter_bot_handler.py(NEW)

References: 

- src\bots\gateway.py(NEW)

Implement `TwitterBotHandler` class that handles Twitter webhook events, parses DMs and mentions, extracts commands, and sends responses via Twitter API. Include methods for `process_webhook()`, `parse_dm_command()`, `parse_mention_command()`, `send_dm_response()`, and `send_mention_reply()`. The handler will validate Twitter webhook signatures and handle rate limiting according to Twitter's API limits.

### src\bots\handlers\telegram_bot_handler.py(NEW)

References: 

- src\bots\gateway.py(NEW)

Implement `TelegramBotHandler` class that processes Telegram webhook updates, handles both direct messages and inline queries, parses bot commands, and sends responses. Include methods for `process_webhook()`, `handle_message()`, `handle_inline_query()`, `send_message()`, and `answer_inline_query()`. Support Telegram's custom keyboards for quick actions and handle file uploads for content analysis.

### src\bots\handlers\discord_bot_handler.py(NEW)

References: 

- src\bots\gateway.py(NEW)

Implement `DiscordBotHandler` class that processes Discord webhook interactions, handles slash commands and direct messages, and sends responses with Discord's embed formatting. Include methods for `process_webhook()`, `handle_slash_command()`, `handle_dm()`, `send_response()`, and `create_embed_response()`. Support Discord's interaction responses and follow-up messages for longer analyses.

### src\services\quick_analysis_service.py(NEW)

References: 

- src\social_protection\services\social_scan_service.py
- src\social_protection\platform_adapters\twitter_adapter.py
- src\social_protection\platform_adapters\base_adapter.py

Create `QuickAnalysisService` class that provides fast, lightweight analysis by wrapping existing social protection services with strict timeouts and caching. Implement methods for `quick_profile_analysis()`, `quick_content_analysis()`, and `quick_risk_assessment()` that reuse logic from `SocialScanService` and platform adapters but with 3-second limits. Include caching mechanisms to store recent analysis results and fallback responses for timeout scenarios.

### src\models\bot.py(NEW)

References: 

- src\models\user.py

Create database models for bot operations including `BotCommand` for logging bot interactions, `BotUser` for mapping external platform users to LinkShield users, and `BotSession` for tracking conversation state. Include fields for platform, external_user_id, command_type, response_time, and success status. These models will help with analytics, debugging, and user mapping.

### src\routes\bot_webhooks.py(NEW)

References: 

- src\routes\social_protection.py
- src\bots\handlers\twitter_bot_handler.py(NEW)
- src\bots\handlers\telegram_bot_handler.py(NEW)
- src\bots\handlers\discord_bot_handler.py(NEW)

Create FastAPI router for bot webhook endpoints including `/api/v1/bots/twitter/webhook`, `/api/v1/bots/telegram/webhook`, and `/api/v1/bots/discord/webhook`. Each endpoint will validate platform-specific webhook signatures, parse incoming requests, and delegate to the appropriate bot handler. Include proper error handling, rate limiting, and logging for all webhook interactions.

### src\controllers\bot_controller.py(NEW)

References: 

- src\controllers\base_controller.py
- src\social_protection\controllers\social_protection_controller.py

Implement `BotController` class that handles business logic for bot operations including user mapping, command validation, rate limiting, and analytics. Include methods for `map_external_user()`, `validate_bot_command()`, `log_bot_interaction()`, and `get_bot_analytics()`. The controller will integrate with existing authentication and rate limiting systems while providing bot-specific functionality.

### src\controllers\depends.py(MODIFY)

References: 

- src\controllers\bot_controller.py(NEW)

Add dependency injection function `get_bot_controller()` that creates and returns a `BotController` instance with all required services. Follow the same pattern as `get_social_protection_controller()` to ensure consistent dependency management across the application.

### src\authentication\dependencies.py(MODIFY)

References: 

- src\models\user.py

Add new authentication dependency `get_bot_service_user()` that returns a service account user for bot operations. This allows bots to perform analysis without requiring individual user authentication while still maintaining audit trails. Include validation for bot-specific tokens and rate limiting.

### app.py(MODIFY)

References: 

- src\routes\bot_webhooks.py(NEW)

Import and include the new bot webhooks router in the FastAPI application. Add `from src.routes.bot_webhooks import router as bot_webhooks_router` and `app.include_router(bot_webhooks_router)` to register the bot endpoints with the main application.

### requirements.txt(MODIFY)

Add new dependencies for bot functionality including `python-telegram-bot` for Telegram bot API, `tweepy` for Twitter API v2 integration, `discord.py` for Discord bot functionality, and `cachetools` for response caching (if not already present). These libraries will handle platform-specific API interactions and webhook processing.

### .env.example(MODIFY)

Add example environment variables for bot configuration including `TWITTER_BOT_BEARER_TOKEN=your_twitter_bearer_token`, `TELEGRAM_BOT_TOKEN=your_telegram_bot_token`, `DISCORD_BOT_TOKEN=your_discord_bot_token`, `QUICK_ANALYSIS_TIMEOUT_SECONDS=3`, `BOT_RATE_LIMIT_PER_MINUTE=60`, and `BOT_SERVICE_ACCOUNT_ID=bot_service_account_uuid`. Include comments explaining how to obtain these tokens from each platform.

### src\alembic\versions\008_add_bot_models.py(NEW)

References: 

- src\models\bot.py(NEW)
- src\alembic\versions\007_add_social_protection_models.py

Create Alembic migration to add bot-related database tables including `bot_commands`, `bot_users`, and `bot_sessions`. The migration will create tables with appropriate indexes, foreign key constraints, and follow the same patterns as existing social protection models. Include proper rollback functionality for the migration.

### docs\social_media_shield\bots.md(NEW)

References: 

- docs\social_media_shield\twitter.md

Create comprehensive documentation for the bot functionality including setup instructions for each platform, webhook configuration, command reference, rate limiting details, and troubleshooting guide. Include examples of bot interactions and integration with existing LinkShield features. Document the architecture and how bots integrate with the social protection system.

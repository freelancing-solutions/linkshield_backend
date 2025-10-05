I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

## Current State Analysis

The codebase has a **disconnected bot architecture** where:

1. **BotUser Model** (`src/models/bot.py`) tracks platform-specific bot users (Twitter, Telegram, Discord) with `platform_user_id` but has **NO link to the main User model**
2. **User Model** (`src/models/user.py`) has subscription management and authentication but **NO relationship to BotUser**
3. **Bot handlers** (Twitter, Telegram, Discord) create BotUser records independently without verifying User existence or subscription status
4. **Bot controllers** (`src/social_protection/controllers/bot_controller.py`) receive authenticated User objects but don't enforce subscription requirements for bot operations
5. **Subscription service** has well-defined plan tiers (free, basic, pro, enterprise) with feature flags like `api_access_enabled`
6. **Bot authentication** (`src/auth/bot_auth.py`) verifies webhook signatures but doesn't link platform users to application Users

## Key Issues Identified

- **No subscription gating**: Anyone can use bot features regardless of subscription status
- **Orphaned bot data**: BotUser records exist without corresponding User accounts
- **No unified rate limiting**: Rate limits are per BotUser, not per User (allowing abuse via multiple platform accounts)
- **Missing audit trail**: Can't track which User performed which bot actions
- **Inconsistent access control**: API routes require User authentication, but bot webhooks bypass this

## Business Rules to Implement

Based on subscription plans analysis:
- **FREE plan**: `api_access_enabled: False` - should NOT have bot access
- **BASIC+ plans**: `api_access_enabled: True` - should have bot access
- **Subscription must be active**: `status in [ACTIVE, TRIAL]` and not expired


### Approach

## Implementation Strategy

### Phase 1: Database Schema Migration
Add `user_id` foreign key to `BotUser` model linking to `users.id`, making it **nullable initially** to handle existing data. Create migration with data backfill strategy for orphaned records.

### Phase 2: Model Relationship Updates
Update both User and BotUser models to establish bidirectional relationship. Add validation methods to enforce subscription requirements.

### Phase 3: Bot User Creation Flow
Modify `get_or_create_bot_user()` and all bot handlers to require a valid, subscribed User. Implement linking mechanism for platform users to application users.

### Phase 4: Subscription Enforcement
Add subscription validation layer that checks before any bot operation. Create helper functions to verify `api_access_enabled` and active subscription status.

### Phase 5: Code Refactoring
Update all bot controllers, services, handlers, and routes to use the new User → BotUser relationship chain. Ensure proper error handling for subscription failures.

### Phase 6: Testing & Documentation
Update tests to create linked User/BotUser pairs. Document the new authentication and subscription flow for bot integrations.


### Reasoning

I explored the codebase systematically to understand the bot architecture:

1. **Listed the project structure** to identify key directories and files
2. **Read User and BotUser models** to understand current data relationships (found no FK between them)
3. **Searched for BotRateLimit and BotUser usage** across the codebase to identify integration points
4. **Examined bot-related models** in `social_media_bot.py` to see additional relationships
5. **Reviewed bot registration and authentication** to understand how bot users are created
6. **Analyzed subscription service** to understand plan tiers and feature flags
7. **Checked existing Alembic migration** (008) to see current bot schema
8. **Reviewed bot handlers** (Twitter) to understand webhook processing flow

This revealed that the current architecture treats bot users as completely separate entities from application users, with no subscription enforcement or proper linking mechanism.


## Mermaid Diagram

sequenceDiagram
    participant PlatformUser as Platform User<br/>(Twitter/Telegram/Discord)
    participant Bot as Bot Handler
    participant BotAuth as Bot Auth Service
    participant User as User Model
    participant BotUser as BotUser Model
    participant SubValidator as Subscription Validator
    participant BotController as Bot Controller

    PlatformUser->>Bot: Send command (e.g., @bot analyze @account)
    Bot->>BotUser: Check if platform_user_id exists
    
    alt BotUser not found or not linked
        Bot->>PlatformUser: Send authentication URL
        PlatformUser->>BotAuth: Click auth URL & login
        BotAuth->>User: Verify user logged in
        BotAuth->>SubValidator: Validate subscription
        
        alt Has valid subscription
            SubValidator-->>BotAuth: ✅ Subscription valid
            BotAuth->>BotUser: Create/link BotUser with user_id
            BotAuth->>PlatformUser: ✅ Authentication complete
        else No subscription or expired
            SubValidator-->>BotAuth: ❌ Subscription required
            BotAuth->>PlatformUser: ❌ Upgrade required
        end
    else BotUser exists and linked
        Bot->>BotUser: Load linked User
        Bot->>SubValidator: Validate subscription
        
        alt Subscription valid
            SubValidator-->>Bot: ✅ Access granted
            Bot->>BotController: Process command with User context
            BotController->>BotController: Execute analysis
            BotController-->>Bot: Return result
            Bot->>PlatformUser: Send formatted response
        else Subscription invalid
            SubValidator-->>Bot: ❌ Subscription expired/invalid
            Bot->>PlatformUser: ❌ Subscription renewal required
        end
    end

## Proposed File Changes

### src\models\bot.py(MODIFY)

References: 

- src\models\user.py(MODIFY)

## Add User Relationship to BotUser Model

### Import Changes
Add UUID import: `from sqlalchemy.dialects.postgresql import UUID`

### Schema Changes to BotUser Class
1. **Add user_id foreign key column** after the `id` column:
   - Type: `UUID(as_uuid=True)`
   - Foreign key to `users.id` with `ondelete="CASCADE"`
   - **Make it nullable=True initially** for migration compatibility
   - Add index for performance
   - This links each BotUser to a parent User account

2. **Add user relationship** in the relationships section:
   - `user = relationship("User", back_populates="bot_users")`
   - This creates bidirectional navigation between User and BotUser

3. **Add subscription validation method**:
   - Create `can_use_bot_features(self, db_session) -> Tuple[bool, str]` method
   - Check if linked user exists and has active subscription
   - Verify subscription plan has `api_access_enabled=True`
   - Return tuple of (is_allowed, reason_if_not)
   - This centralizes subscription checking logic

4. **Add helper method** `get_user_subscription_plan(self, db_session) -> Optional[str]`:
   - Returns the subscription plan name of the linked user
   - Returns None if no user linked or no subscription

### Update get_or_create_bot_user Function
**BREAKING CHANGE**: Add required `user_id` parameter:
- Signature: `get_or_create_bot_user(db_session, user_id: uuid.UUID, platform: str, platform_user_id: str, username: Optional[str] = None, display_name: Optional[str] = None) -> BotUser`
- **Validate user exists** before creating BotUser
- **Validate user has active subscription** with api_access_enabled
- Raise `ValueError` with clear message if validation fails
- When creating new BotUser, set the `user_id` field
- When updating existing BotUser, verify it belongs to the same user (security check)
- Add logging for subscription validation failures

### Update check_rate_limit Function
Modify to consider both BotUser and User-level limits:
- Keep existing per-BotUser rate limiting
- Add optional check for aggregate User-level limits across all their BotUsers
- This prevents abuse via multiple platform accounts

### Add New Utility Function
Create `link_existing_bot_user_to_user(db_session, bot_user_id: int, user_id: uuid.UUID) -> BotUser`:
- For migrating orphaned BotUser records
- Validates user exists and has subscription
- Updates bot_user.user_id
- Returns updated BotUser
- Useful for admin tools and migration scripts

### src\models\user.py(MODIFY)

References: 

- src\models\bot.py(MODIFY)

## Add BotUser Relationship to User Model

### Add Relationship in Relationships Section
After the existing relationships (around line 125), add:
- `bot_users = relationship("BotUser", back_populates="user", cascade="all, delete-orphan")`
- This creates the parent side of the User → BotUser relationship
- Cascade delete ensures BotUser records are removed when User is deleted
- Maintains referential integrity

### Add Bot Access Validation Method
Create new method `can_access_bot_features(self) -> Tuple[bool, str]`:
- Check if subscription is active using existing `is_subscription_active()` method
- Check if subscription plan is not FREE (or explicitly check api_access_enabled from plan config)
- Return tuple: (True, "success") or (False, "reason message")
- Possible reasons: "No active subscription", "Subscription expired", "Plan does not include bot access", "Free plan users cannot access bot features"
- This provides user-friendly error messages for UI/API responses

### Add Bot User Count Method
Create `get_bot_user_count(self) -> int`:
- Returns `len(self.bot_users)` if relationship is loaded
- Useful for admin dashboards and usage analytics
- Shows how many platform accounts are linked to this user

### Update to_dict Method
Add bot-related information when `include_sensitive=True`:
- `"bot_users_count": len(self.bot_users)` if relationship loaded
- `"can_access_bots": self.can_access_bot_features()[0]`
- This provides complete user profile information including bot access status

### src\alembic\versions\010_link_bot_users_to_users.py(NEW)

References: 

- src\models\bot.py(MODIFY)
- src\models\user.py(MODIFY)
- src\alembic\versions\008_add_bot_models.py

## Create New Alembic Migration for User-BotUser Linking

### Migration Metadata
- Revision ID: `010_link_bot_users_to_users`
- Revises: `009_add_crisis_and_extension_models` (or latest migration)
- Create Date: Current timestamp
- Description: "Link BotUser records to User accounts with subscription validation"

### Upgrade Function

#### Step 1: Add user_id Column (Nullable)
```python
op.add_column('bot_users', 
    sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True)
)
```
- Initially nullable to allow existing records to remain valid

#### Step 2: Create Index
```python
op.create_index('ix_bot_users_user_id', 'bot_users', ['user_id'])
```
- Improves query performance for User → BotUser lookups

#### Step 3: Add Foreign Key Constraint
```python
op.create_foreign_key(
    'fk_bot_users_user_id_users',
    'bot_users', 'users',
    ['user_id'], ['id'],
    ondelete='CASCADE'
)
```
- Enforces referential integrity
- CASCADE delete ensures cleanup when User is deleted

#### Step 4: Data Migration Strategy (IMPORTANT)
Add comment explaining manual data migration required:
```python
# NOTE: Existing bot_users records have user_id=NULL
# Run the data migration script BEFORE making user_id non-nullable:
# python scripts/migrate_bot_users_to_users.py
# 
# This script should:
# 1. Identify orphaned bot_users (user_id IS NULL)
# 2. Attempt to match by email/username if possible
# 3. Create default User accounts for unmatched bot_users
# 4. OR delete orphaned records if business rules allow
```

#### Step 5: Make user_id Non-Nullable (Optional - Commented Out)
Include commented-out code for future execution after data migration:
```python
# After data migration is complete, uncomment and run:
# op.alter_column('bot_users', 'user_id', nullable=False)
```

### Downgrade Function
- Drop foreign key constraint: `op.drop_constraint('fk_bot_users_user_id_users', 'bot_users')`
- Drop index: `op.drop_index('ix_bot_users_user_id', 'bot_users')`
- Drop column: `op.drop_column('bot_users', 'user_id')`

### Migration Notes
Add detailed docstring explaining:
- Why user_id is nullable initially
- Data migration requirements
- How to handle orphaned records
- When to make user_id non-nullable

### scripts\migrate_bot_users_to_users.py(NEW)

References: 

- src\models\bot.py(MODIFY)
- src\models\user.py(MODIFY)
- src\config\database.py

## Create Data Migration Script for Orphaned BotUsers

### Script Purpose
Migrate existing BotUser records (with user_id=NULL) to be linked to User accounts.

### Script Structure

#### Import Required Modules
- SQLAlchemy session management
- User and BotUser models
- UUID generation
- Logging
- argparse for CLI options

#### Main Migration Function
`migrate_orphaned_bot_users(db_session, strategy='create_users', dry_run=False)`:

**Strategy 1: 'create_users'** (Default)
- For each orphaned BotUser:
  - Create a new User account with email: `bot_{platform}_{platform_user_id}@linkshield.internal`
  - Set username: `{platform}_{username}`
  - Set subscription_plan to FREE (they can upgrade later)
  - Set status to ACTIVE
  - Link BotUser.user_id to new User.id
  - Log creation details

**Strategy 2: 'match_by_username'**
- Attempt to match BotUser.username to existing User.username
- If match found and user has api_access_enabled subscription, link them
- If no match or user lacks subscription, fall back to 'create_users' strategy
- Log match success/failure

**Strategy 3: 'delete_orphaned'**
- Delete all BotUser records where user_id IS NULL
- Log deletion count
- Require explicit confirmation flag

#### Dry Run Mode
- When `dry_run=True`, print what would be done without making changes
- Show statistics: orphaned count, would-be created users, would-be matches, would-be deletions

#### CLI Interface
```
python scripts/migrate_bot_users_to_users.py \
  --strategy create_users \
  --dry-run
```

Options:
- `--strategy`: choose migration strategy
- `--dry-run`: preview changes without applying
- `--confirm-delete`: required for delete_orphaned strategy

#### Logging and Reporting
- Log to both console and file: `logs/bot_user_migration.log`
- Generate summary report:
  - Total orphaned BotUsers found
  - Successfully migrated count
  - Failed migrations with reasons
  - New Users created
  - Execution time

#### Error Handling
- Wrap in try/except with rollback on failure
- Continue processing remaining records if one fails
- Collect and report all errors at end

### Post-Migration Validation
Create `validate_migration()` function:
- Check no BotUsers have user_id=NULL
- Verify all linked Users have valid subscriptions
- Report any anomalies

### src\services\bot_subscription_validator.py(NEW)

References: 

- src\models\user.py(MODIFY)
- src\models\bot.py(MODIFY)
- src\services\subscription_service.py(MODIFY)

## Create Centralized Bot Subscription Validation Service

### Service Purpose
Provide reusable subscription validation logic for all bot operations.

### Class: BotSubscriptionValidator

#### Method: `validate_user_can_use_bots(user: User, db_session: Session) -> Tuple[bool, Optional[str]]`
**Validation Steps:**
1. Check if user exists (should always be true if passed in, but defensive check)
2. Check if user.is_active is True
3. Call `user.is_subscription_active()` to verify subscription not expired
4. Get user's subscription plan from `SUBSCRIPTION_PLANS` config
5. Check if plan has `api_access_enabled: True`
6. Return (True, None) if all checks pass
7. Return (False, error_message) with specific reason if any check fails

**Error Messages:**
- "User account is not active"
- "No active subscription found"
- "Subscription has expired"
- "Your subscription plan does not include bot access. Please upgrade to Basic or higher."
- "Free plan users cannot access bot features"

#### Method: `validate_bot_user_access(bot_user: BotUser, db_session: Session) -> Tuple[bool, Optional[str]]`
**Validation Steps:**
1. Check if bot_user.user_id is not None
2. Load the linked User if not already loaded
3. Call `validate_user_can_use_bots()` with the linked user
4. Return result

**Error Messages:**
- "Bot user is not linked to an application user"
- Plus all messages from `validate_user_can_use_bots()`

#### Method: `get_bot_feature_limits(user: User) -> Dict[str, Any]`
Return bot-specific limits based on subscription plan:
- `max_bot_requests_per_hour`: varies by plan (Basic: 100, Pro: 500, Enterprise: 2000)
- `max_platforms`: how many platform accounts can be linked (Basic: 2, Pro: 5, Enterprise: unlimited)
- `deep_analysis_enabled`: boolean from plan config
- `priority_support`: boolean from plan config

#### Method: `check_platform_limit(user: User, db_session: Session) -> Tuple[bool, Optional[str]]`
Validate if user can add another platform account:
1. Count existing bot_users for this user
2. Get max_platforms from plan limits
3. Return (True, None) if under limit
4. Return (False, "Platform limit reached. Upgrade to add more accounts.") if at limit

#### Decorator: `@require_bot_subscription`
Create decorator for route/controller methods:
```python
def require_bot_subscription(func):
    async def wrapper(user: User, *args, **kwargs):
        is_valid, error = BotSubscriptionValidator.validate_user_can_use_bots(user, db_session)
        if not is_valid:
            raise HTTPException(status_code=403, detail=error)
        return await func(user, *args, **kwargs)
    return wrapper
```

### Integration Points
- Import in all bot controllers
- Import in bot handlers
- Import in bot routes
- Use before any bot operation

### src\bots\handlers\twitter_bot_handler.py(MODIFY)

References: 

- src\models\bot.py(MODIFY)
- src\models\user.py(MODIFY)
- src\services\bot_subscription_validator.py(NEW)

## Update Twitter Bot Handler to Require User Linking

### Import Additions
- Import `BotSubscriptionValidator` from `src.services.bot_subscription_validator`
- Import `User` model from `src.models.user`
- Import `get_or_create_bot_user` from `src.models.bot`

### Add User Resolution Method
Create new method `async def _resolve_user_from_platform_id(self, platform_user_id: str, db_session) -> Optional[User]`:
**Purpose:** Link platform user ID to application User

**Implementation Strategy:**
1. Query BotUser table for existing record with this platform_user_id and platform=TWITTER
2. If found and has user_id, return the linked User
3. If not found, this is a new bot user - they need to authenticate first
4. Return None if no User can be resolved

**Authentication Flow for New Users:**
- Bot should respond with: "Welcome! To use this bot, please authenticate at: https://app.linkshield.com/bot-auth?platform=twitter&user_id={platform_user_id}"
- This URL would be a web page where user logs in and authorizes the bot
- After authorization, BotUser record is created with proper user_id link

### Update _handle_tweet_event Method
**Add User Resolution Step** (after extracting user_id from event):
1. Call `_resolve_user_from_platform_id(user_id, db_session)`
2. If User is None, send authentication required message and return early
3. Validate subscription using `BotSubscriptionValidator.validate_user_can_use_bots(user, db_session)`
4. If validation fails, send subscription upgrade message and return early
5. Get or create BotUser using `get_or_create_bot_user(db_session, user.id, 'twitter', user_id, user_screen_name, display_name)`
6. Continue with existing command processing

### Update _handle_direct_message_event Method
Apply same User resolution and validation logic as tweet events.

### Add Subscription Error Response Method
Create `_create_subscription_error_response(self, error_message: str) -> BotResponse`:
- Format user-friendly message about subscription requirements
- Include link to upgrade page
- Return BotResponse with error type

### Add Authentication Required Response Method
Create `_create_auth_required_response(self, platform_user_id: str) -> BotResponse`:
- Generate authentication URL with platform and user_id parameters
- Format friendly message explaining authentication requirement
- Return BotResponse with instructions

### Update _process_bot_command Method
Add user parameter: `async def _process_bot_command(self, bot_command: BotCommand, user: User, bot_user: BotUser) -> BotResponse`:
- Pass user context to command processing
- This allows command handlers to access subscription limits
- Enables user-specific rate limiting and feature gating

### Error Handling Updates
- Catch subscription validation errors and return friendly messages
- Log subscription failures for analytics
- Track authentication required events for conversion metrics

### src\bots\handlers\telegram_bot_handler.py(MODIFY)

References: 

- src\bots\handlers\twitter_bot_handler.py(MODIFY)
- src\models\bot.py(MODIFY)
- src\services\bot_subscription_validator.py(NEW)

## Update Telegram Bot Handler (Similar to Twitter)

### Apply Same Pattern as Twitter Handler
Implement identical changes as described for `twitter_bot_handler.py`:

1. **Import additions**: BotSubscriptionValidator, User model, get_or_create_bot_user

2. **Add `_resolve_user_from_platform_id()` method** for Telegram platform
   - Query BotUser with platform='telegram'
   - Return linked User or None

3. **Update webhook event handlers** to:
   - Resolve User from Telegram user_id
   - Validate subscription before processing
   - Create/get BotUser with proper user_id link
   - Handle authentication required and subscription errors

4. **Add response methods**:
   - `_create_subscription_error_response()`
   - `_create_auth_required_response()`

5. **Update command processing** to accept User and BotUser parameters

### Telegram-Specific Considerations
- Telegram uses numeric user IDs (convert to string for platform_user_id)
- Telegram supports inline keyboards - use them for authentication/upgrade CTAs
- Format authentication URL as clickable button in Telegram message

### Authentication Flow for Telegram
- Send message with inline keyboard button: "🔐 Authenticate with LinkShield"
- Button URL: `https://app.linkshield.com/bot-auth?platform=telegram&user_id={telegram_user_id}`
- After authentication, send confirmation message

### src\bots\handlers\discord_bot_handler.py(MODIFY)

References: 

- src\bots\handlers\twitter_bot_handler.py(MODIFY)
- src\models\bot.py(MODIFY)
- src\services\bot_subscription_validator.py(NEW)

## Update Discord Bot Handler (Similar to Twitter/Telegram)

### Apply Same Pattern as Other Handlers
Implement identical changes as described for `twitter_bot_handler.py` and `telegram_bot_handler.py`:

1. **Import additions**: BotSubscriptionValidator, User model, get_or_create_bot_user

2. **Add `_resolve_user_from_platform_id()` method** for Discord platform
   - Query BotUser with platform='discord'
   - Return linked User or None

3. **Update interaction handlers** (Discord uses interactions, not webhooks) to:
   - Resolve User from Discord user_id
   - Validate subscription before processing
   - Create/get BotUser with proper user_id link
   - Handle authentication required and subscription errors

4. **Add response methods**:
   - `_create_subscription_error_response()`
   - `_create_auth_required_response()`

5. **Update command processing** to accept User and BotUser parameters

### Discord-Specific Considerations
- Discord uses snowflake IDs (large integers as strings)
- Discord supports embeds and components - use them for rich authentication messages
- Discord slash commands can be responded to with ephemeral messages (only visible to user)
- Use ephemeral responses for authentication/subscription error messages

### Authentication Flow for Discord
- Respond to slash command with ephemeral message containing:
  - Embed with title: "🔐 Authentication Required"
  - Description explaining why authentication is needed
  - Button component: "Authenticate with LinkShield"
  - Button URL: `https://app.linkshield.com/bot-auth?platform=discord&user_id={discord_user_id}`

### src\social_protection\controllers\bot_controller.py(MODIFY)

References: 

- src\services\bot_subscription_validator.py(NEW)
- src\models\user.py(MODIFY)
- src\models\bot.py(MODIFY)

## Update Social Protection Bot Controller

### Import Additions
- Import `BotSubscriptionValidator` from `src.services.bot_subscription_validator`
- Import `get_or_create_bot_user` from `src.models.bot`

### Add Subscription Validation to __init__
Store validator instance:
```python
self.subscription_validator = BotSubscriptionValidator()
```

### Update All Public Methods to Validate Subscription

#### analyze_account_safety Method
**Add validation at start** (before rate limit check):
1. Call `self.subscription_validator.validate_user_can_use_bots(user, db_session)`
2. If validation fails, raise HTTPException with status 403 and error message
3. Log subscription validation failure with user_id for analytics

#### check_content_compliance Method
**Add same validation** as analyze_account_safety

#### analyze_verified_followers Method
**Add same validation** as analyze_account_safety

#### quick_content_analysis Method
**Add same validation** as analyze_account_safety

### Update Rate Limiting Logic
**Enhance check_rate_limit calls** to consider user-level limits:
- Current implementation checks per-request rate limits
- Add check for user's subscription plan limits using `subscription_validator.get_bot_feature_limits(user)`
- Adjust rate limits based on plan tier (Basic: 100/min, Pro: 200/min, Enterprise: 500/min)
- This ensures fair usage across all users

### Add Method: get_user_bot_status
Create new method `async def get_user_bot_status(self, user: User, db_session: Session) -> Dict[str, Any]`:
**Returns:**
```python
{
    "can_use_bots": bool,
    "subscription_plan": str,
    "bot_features_enabled": bool,
    "linked_platforms": List[str],  # ['twitter', 'telegram']
    "platform_limit": int,
    "platform_limit_reached": bool,
    "rate_limits": {
        "requests_per_hour": int,
        "deep_analysis_enabled": bool
    },
    "error_message": Optional[str]
}
```
**Purpose:** Provide frontend with user's bot access status and limits

### Update Error Responses
- Use consistent error format for subscription failures
- Include upgrade CTA in error responses
- Provide specific error codes: `BOT_SUBSCRIPTION_REQUIRED`, `BOT_PLAN_UPGRADE_REQUIRED`, `BOT_PLATFORM_LIMIT_REACHED`

### Add Logging for Subscription Events
- Log when users attempt bot operations without subscription
- Log when users hit platform limits
- Track conversion funnel: authentication → subscription → bot usage

### src\controllers\bot_controller.py(MODIFY)

References: 

- src\services\bot_subscription_validator.py(NEW)
- src\models\user.py(MODIFY)
- src\models\bot.py(MODIFY)

## Update Root Bot Controller

### Import Additions
- Import `BotSubscriptionValidator` from `src.services.bot_subscription_validator`
- Import `User` model from `src.models.user`

### Update get_bot_analytics Method
**Add user parameter** if not already present:
- Signature: `async def get_bot_analytics(self, user: User, platform: Optional[str] = None, time_range: str = "24h", db_session: Session = None) -> Dict[str, Any]`
- Filter analytics by user's bot_users only
- Don't show analytics for other users' bot activity
- This enforces data isolation

### Update get_bot_statistics Method
**Filter by user**:
- Only return statistics for BotUsers linked to the requesting User
- Query: `db_session.query(BotUser).filter(BotUser.user_id == user.id)`
- Aggregate stats across user's platforms

### Update get_platform_statistics Method
**Add user filtering**:
- Filter by both platform AND user_id
- Prevents users from seeing other users' platform stats

### Add Subscription Validation
**For all analytics/stats methods**:
- Validate user has bot access before returning data
- Return empty/default stats if no subscription
- Include subscription status in response metadata

### Update Bot User Management Methods
**If controller has methods like create_bot_user, update_bot_user, delete_bot_user**:
- Add subscription validation
- Verify user owns the BotUser being modified (security check)
- Check platform limits before creating new BotUser
- Use `get_or_create_bot_user()` with user_id parameter

### src\routes\social_protection_bot.py(MODIFY)

References: 

- src\services\bot_subscription_validator.py(NEW)
- src\authentication\dependencies.py
- src\social_protection\controllers\bot_controller.py(MODIFY)

## Update Social Protection Bot Routes

### Import Additions
- Import `BotSubscriptionValidator` from `src.services.bot_subscription_validator`
- Import `HTTPException` from `fastapi`

### Add Subscription Validation Dependency
Create new dependency function:
```python
async def verify_bot_subscription(current_user: User = Depends(get_current_user)):
    validator = BotSubscriptionValidator()
    is_valid, error = validator.validate_user_can_use_bots(current_user, db_session)
    if not is_valid:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "bot_subscription_required",
                "message": error,
                "upgrade_url": "/subscription/plans"
            }
        )
    return current_user
```

### Update All Bot Route Endpoints
**Replace `current_user: User = Depends(get_current_user)` with `current_user: User = Depends(verify_bot_subscription)`**:

- `/analyze` endpoint
- `/account-safety` endpoint
- `/compliance` endpoint
- `/followers` endpoint
- `/batch-analyze` endpoint
- `/webhook` endpoint (keep current_user for webhook auth, but add validation inside handler)
- `/stats` endpoint

**Keep `/health` endpoint without subscription check** - it should be publicly accessible

### Add New Route: GET /bot-status
Create endpoint to check user's bot access status:
```python
@router.get("/bot-status")
async def get_bot_access_status(
    current_user: User = Depends(get_current_user),
    controller: BotController = Depends(get_bot_controller)
):
    return await controller.get_user_bot_status(current_user, db_session)
```
**Purpose:** Frontend can check if user has bot access before showing bot features

### Update Error Responses
- Return structured error responses with error codes
- Include upgrade URLs in error responses
- Provide user-friendly messages

### Add Rate Limit Headers
**For successful bot requests**, add response headers:
- `X-RateLimit-Limit`: user's hourly limit
- `X-RateLimit-Remaining`: remaining requests
- `X-RateLimit-Reset`: timestamp when limit resets
- This helps clients implement client-side rate limiting

### src\routes\bot_auth.py(NEW)

References: 

- src\models\bot.py(MODIFY)
- src\models\user.py(MODIFY)
- src\services\bot_subscription_validator.py(NEW)
- src\authentication\dependencies.py

## Create Bot Authentication Routes

### Purpose
Provide web endpoints for users to authenticate and link their platform accounts to their User account.

### Router Setup
```python
router = APIRouter(prefix="/api/v1/bot-auth", tags=["Bot Authentication"])
```

### Endpoint: GET /bot-auth/initiate
**Query Parameters:**
- `platform`: Platform name (twitter, telegram, discord)
- `platform_user_id`: Platform-specific user ID
- `redirect_url`: Optional URL to redirect after authentication

**Flow:**
1. Validate platform is supported
2. Check if platform_user_id is already linked to a User
3. If linked, return status: "already_linked"
4. If not linked, generate authentication token (JWT with short expiry)
5. Store token in cache/database with platform and platform_user_id
6. Return authentication URL for frontend

**Response:**
```json
{
    "auth_token": "jwt_token_here",
    "auth_url": "/bot-auth/complete?token=jwt_token_here",
    "expires_in": 600,
    "platform": "twitter",
    "status": "pending"
}
```

### Endpoint: POST /bot-auth/complete
**Request Body:**
```json
{
    "auth_token": "jwt_token_from_initiate",
    "platform": "twitter",
    "platform_user_id": "123456789",
    "username": "optional_username",
    "display_name": "optional_display_name"
}
```

**Authentication Required:** Yes (user must be logged in)

**Flow:**
1. Validate auth_token is valid and not expired
2. Verify token matches platform and platform_user_id
3. Get current authenticated User
4. Validate user has bot access subscription
5. Check platform limit not exceeded
6. Create or update BotUser record with user_id link
7. Delete auth_token from cache
8. Return success with BotUser details

**Response:**
```json
{
    "success": true,
    "message": "Platform account linked successfully",
    "bot_user": {
        "id": 123,
        "platform": "twitter",
        "username": "user123",
        "linked_at": "2024-01-20T10:30:00Z"
    },
    "linked_platforms": ["twitter", "telegram"],
    "platform_limit": 5,
    "platform_limit_reached": false
}
```

### Endpoint: GET /bot-auth/status
**Query Parameters:**
- `auth_token`: Token from initiate endpoint

**Purpose:** Check authentication status (for polling from platform bot)

**Response:**
```json
{
    "status": "pending" | "completed" | "expired",
    "linked": false,
    "message": "Waiting for user authentication"
}
```

### Endpoint: DELETE /bot-auth/unlink
**Request Body:**
```json
{
    "platform": "twitter",
    "platform_user_id": "123456789"
}
```

**Authentication Required:** Yes

**Flow:**
1. Get current authenticated User
2. Find BotUser with matching platform, platform_user_id, and user_id
3. Verify user owns this BotUser
4. Delete BotUser record (or set is_active=False)
5. Return success

**Response:**
```json
{
    "success": true,
    "message": "Platform account unlinked successfully",
    "remaining_platforms": ["telegram"]
}
```

### Endpoint: GET /bot-auth/linked-platforms
**Authentication Required:** Yes

**Purpose:** List all platform accounts linked to current user

**Response:**
```json
{
    "linked_platforms": [
        {
            "platform": "twitter",
            "username": "user123",
            "linked_at": "2024-01-15T10:00:00Z",
            "last_used": "2024-01-20T09:30:00Z",
            "total_analyses": 45
        },
        {
            "platform": "telegram",
            "username": "user123",
            "linked_at": "2024-01-18T14:00:00Z",
            "last_used": "2024-01-20T10:15:00Z",
            "total_analyses": 12
        }
    ],
    "platform_limit": 5,
    "can_add_more": true
}
```

### Security Considerations
- Auth tokens should expire in 10 minutes
- Validate user owns the BotUser before any modifications
- Rate limit authentication attempts
- Log all authentication events for audit trail
- Use HTTPS only for authentication endpoints

### src\services\social_media_bot_service.py(MODIFY)

References: 

- src\models\user.py(MODIFY)
- src\models\bot.py(MODIFY)
- src\services\bot_subscription_validator.py(NEW)
- src\services\subscription_service.py(MODIFY)

## Update Social Media Bot Service

### Import Additions
- Import `User` model from `src.models.user`
- Import `BotSubscriptionValidator` from `src.services.bot_subscription_validator`

### Update Method Signatures

#### analyze_account_safety Method
**Add user parameter** as first parameter after self:
- Signature: `async def analyze_account_safety(self, user: User, platform: PlatformType, account_identifier: str, bot_user: BotUser) -> AccountSafetyResult`
- Add subscription validation at start of method
- Pass user context to underlying analysis services

#### check_content_compliance Method
**Add user parameter**:
- Signature: `async def check_content_compliance(self, user: User, platform: PlatformType, content: str, bot_user: BotUser) -> ComplianceResult`
- Add subscription validation

#### analyze_verified_followers Method
**Add user parameter**:
- Signature: `async def analyze_verified_followers(self, user: User, platform: PlatformType, account_identifier: str, bot_user: BotUser) -> VerifiedFollowerResult`
- Add subscription validation

#### perform_risk_assessment Method
**Add user parameter**:
- Signature: `async def perform_risk_assessment(self, user: User, platform: PlatformType, content_or_account: str, assessment_type: str, bot_user: BotUser) -> RiskAssessmentResult`
- Add subscription validation
- Check if user's plan allows deep analysis if assessment_type is 'deep'

### Add Subscription Validation Helper
Create private method `_validate_subscription(self, user: User) -> None`:
- Call `BotSubscriptionValidator.validate_user_can_use_bots(user, db_session)`
- Raise appropriate exception if validation fails
- Reusable across all public methods

### Add Feature Gating
Create private method `_check_feature_access(self, user: User, feature: str) -> bool`:
- Check if user's subscription plan includes specific feature
- Features: 'deep_analysis', 'priority_support', 'bulk_checking'
- Return True if feature is available, False otherwise
- Use this to gate premium features

### Update Error Handling
- Catch subscription validation errors
- Return user-friendly error messages
- Include upgrade suggestions in error responses

### Add Usage Tracking
**After successful operations**, increment usage counters:
- Call `subscription_service.increment_usage(user.id, UsageType.BOT_ANALYSIS)`
- This tracks bot usage against subscription limits
- Enables usage-based billing in future

### src\services\subscription_service.py(MODIFY)

References: 

- src\models\subscription.py
- src\models\user.py(MODIFY)
- src\models\bot.py(MODIFY)

## Update Subscription Service for Bot Features

### Update SUBSCRIPTION_PLANS Configuration

#### Add Bot-Specific Limits to Each Plan

**FREE Plan:**
- Add: `"bot_access_enabled": False`
- Add: `"max_bot_platforms": 0`
- Add: `"bot_requests_per_hour": 0`
- Add: `"bot_deep_analysis_enabled": False`

**BASIC Plan:**
- Add: `"bot_access_enabled": True`
- Add: `"max_bot_platforms": 2`
- Add: `"bot_requests_per_hour": 100`
- Add: `"bot_deep_analysis_enabled": False`

**PRO Plan:**
- Add: `"bot_access_enabled": True`
- Add: `"max_bot_platforms": 5`
- Add: `"bot_requests_per_hour": 500`
- Add: `"bot_deep_analysis_enabled": True`

**ENTERPRISE Plan:**
- Add: `"bot_access_enabled": True`
- Add: `"max_bot_platforms": -1`  # Unlimited
- Add: `"bot_requests_per_hour": 2000`
- Add: `"bot_deep_analysis_enabled": True`

### Add New Method: get_bot_limits
Create method `async def get_bot_limits(self, user_id: uuid.UUID) -> Dict[str, Any]`:
**Returns:**
```python
{
    "bot_access_enabled": bool,
    "max_bot_platforms": int,
    "bot_requests_per_hour": int,
    "bot_deep_analysis_enabled": bool,
    "current_platform_count": int,  # Query from BotUser table
    "platform_limit_reached": bool
}
```
**Purpose:** Provide bot-specific limits for a user

### Add New Method: can_add_bot_platform
Create method `async def can_add_bot_platform(self, user_id: uuid.UUID) -> Tuple[bool, Optional[str]]`:
1. Get user's subscription and plan limits
2. Count existing BotUser records for this user
3. Check if count < max_bot_platforms (or unlimited)
4. Return (True, None) if can add, (False, error_message) if cannot

### Update get_subscription_plans Method
**Include bot limits in returned plan data**:
- Add bot_access_enabled, max_bot_platforms, bot_requests_per_hour to each plan dict
- This allows frontend to display bot features in pricing table

### Add Usage Type for Bot Operations
**In UsageType enum** (if not already present):
- Add `BOT_ANALYSIS = "bot_analysis"`
- This allows tracking bot-specific usage separately from regular API usage

### Update increment_usage Method
**Support bot usage tracking**:
- When usage_type is BOT_ANALYSIS, increment bot-specific counters
- Consider adding separate daily_bot_checks_used counter to UserSubscription model
- This enables bot-specific rate limiting independent of regular API usage

### tests\test_bot_user_subscription.py(NEW)

References: 

- src\models\user.py(MODIFY)
- src\models\bot.py(MODIFY)
- src\services\bot_subscription_validator.py(NEW)
- src\routes\bot_auth.py(NEW)

## Create Comprehensive Tests for Bot-User Subscription Integration

### Test Class: TestBotUserSubscriptionIntegration

#### Test Fixtures

**Fixture: `test_user_with_subscription`**
- Create User with BASIC subscription (api_access_enabled=True)
- Ensure subscription is active and not expired
- Return User instance

**Fixture: `test_user_free_plan`**
- Create User with FREE subscription
- Return User instance

**Fixture: `test_user_expired_subscription`**
- Create User with PRO subscription but expired
- Set subscription_expires_at to past date
- Return User instance

**Fixture: `test_bot_user_linked`**
- Create BotUser linked to test_user_with_subscription
- Platform: twitter
- Return BotUser instance

#### Test Cases

**Test: `test_create_bot_user_with_valid_subscription`**
- Given: User with active BASIC subscription
- When: Call get_or_create_bot_user with user_id
- Then: BotUser is created successfully with user_id link
- Assert: bot_user.user_id == user.id

**Test: `test_create_bot_user_without_subscription_fails`**
- Given: User with FREE plan
- When: Call get_or_create_bot_user with user_id
- Then: Raises ValueError with message about subscription required
- Assert: No BotUser record created

**Test: `test_create_bot_user_with_expired_subscription_fails`**
- Given: User with expired subscription
- When: Call get_or_create_bot_user with user_id
- Then: Raises ValueError with message about expired subscription
- Assert: No BotUser record created

**Test: `test_bot_user_can_use_features_with_active_subscription`**
- Given: BotUser linked to user with active subscription
- When: Call bot_user.can_use_bot_features(db_session)
- Then: Returns (True, None)

**Test: `test_bot_user_cannot_use_features_without_subscription`**
- Given: BotUser with user_id=None (orphaned)
- When: Call bot_user.can_use_bot_features(db_session)
- Then: Returns (False, error_message)

**Test: `test_user_bot_relationship_cascade_delete`**
- Given: User with linked BotUser
- When: Delete User
- Then: BotUser is also deleted (cascade)
- Assert: BotUser no longer exists in database

**Test: `test_platform_limit_enforcement`**
- Given: User with BASIC plan (max 2 platforms)
- When: Create 2 BotUsers successfully
- Then: Attempt to create 3rd BotUser fails
- Assert: Error message about platform limit reached

**Test: `test_subscription_validator_with_valid_user`**
- Given: User with active PRO subscription
- When: Call BotSubscriptionValidator.validate_user_can_use_bots(user)
- Then: Returns (True, None)

**Test: `test_subscription_validator_with_free_user`**
- Given: User with FREE plan
- When: Call BotSubscriptionValidator.validate_user_can_use_bots(user)
- Then: Returns (False, "Free plan users cannot access bot features")

**Test: `test_bot_controller_rejects_unsubscribed_user`**
- Given: User with FREE plan
- When: Call bot_controller.analyze_account_safety(user, ...)
- Then: Raises HTTPException with status 403
- Assert: Error detail contains subscription upgrade message

**Test: `test_bot_route_requires_subscription`**
- Given: Authenticated user with FREE plan
- When: POST to /api/v1/social-protection/bot/analyze
- Then: Returns 403 Forbidden
- Assert: Response contains upgrade URL

**Test: `test_get_or_create_bot_user_updates_existing`**
- Given: Existing BotUser with user_id=None
- When: Call get_or_create_bot_user with valid user_id
- Then: Updates existing BotUser with user_id
- Assert: bot_user.user_id is set correctly

**Test: `test_bot_user_statistics_filtered_by_user`**
- Given: Multiple users with BotUsers
- When: User A requests bot statistics
- Then: Only sees their own BotUser statistics
- Assert: No data leakage from other users

### Test Class: TestBotAuthenticationFlow

**Test: `test_initiate_bot_auth`**
- When: GET /api/v1/bot-auth/initiate?platform=twitter&platform_user_id=123
- Then: Returns auth_token and auth_url
- Assert: Token is valid JWT

**Test: `test_complete_bot_auth_with_subscription`**
- Given: User with BASIC subscription logged in
- When: POST /api/v1/bot-auth/complete with auth_token
- Then: BotUser is created and linked
- Assert: Response contains linked_platforms list

**Test: `test_complete_bot_auth_without_subscription_fails`**
- Given: User with FREE plan logged in
- When: POST /api/v1/bot-auth/complete with auth_token
- Then: Returns 403 with subscription required message

**Test: `test_unlink_bot_platform`**
- Given: User with linked Twitter BotUser
- When: DELETE /api/v1/bot-auth/unlink with platform=twitter
- Then: BotUser is deleted/deactivated
- Assert: User's bot_users list no longer contains Twitter

### Test Utilities

**Helper: `create_test_user_with_plan(plan_name: str) -> User`**
- Creates User with specified subscription plan
- Sets appropriate subscription dates
- Returns User instance

**Helper: `create_test_bot_user(user: User, platform: str) -> BotUser`**
- Creates BotUser linked to user
- Uses get_or_create_bot_user function
- Returns BotUser instance

### docs\bot-subscription-integration.md(NEW)

References: 

- src\models\user.py(MODIFY)
- src\models\bot.py(MODIFY)
- src\services\bot_subscription_validator.py(NEW)
- src\routes\bot_auth.py(NEW)

## Create Comprehensive Documentation

### Document Title: Bot-User Subscription Integration Guide

### Section 1: Overview
**Content:**
- Explain the new User → BotUser relationship
- Why subscription gating is necessary for bot features
- Benefits: security, revenue protection, fair usage
- Architecture diagram showing User → BotUser → BotRateLimit chain

### Section 2: Subscription Requirements
**Content:**
- Table showing which plans have bot access:
  - FREE: ❌ No bot access
  - BASIC: ✅ Bot access (2 platforms, 100 req/hr)
  - PRO: ✅ Bot access (5 platforms, 500 req/hr, deep analysis)
  - ENTERPRISE: ✅ Bot access (unlimited platforms, 2000 req/hr)
- Explanation of `api_access_enabled` flag
- How subscription expiration affects bot access

### Section 3: Bot Authentication Flow
**Content:**
- Step-by-step flow diagram:
  1. User interacts with bot on platform (Twitter/Telegram/Discord)
  2. Bot checks if platform user is linked to application User
  3. If not linked, bot sends authentication URL
  4. User clicks URL and logs into web application
  5. User authorizes bot access
  6. BotUser record created with user_id link
  7. User can now use bot features
- Code examples for each step
- Security considerations

### Section 4: Database Schema Changes
**Content:**
- ERD diagram showing User ↔ BotUser relationship
- Migration steps:
  1. Run migration 010 to add user_id column
  2. Run data migration script
  3. Verify all BotUsers are linked
  4. Make user_id non-nullable (optional)
- Rollback procedures

### Section 5: API Changes
**Content:**
- List of affected endpoints
- New authentication requirements
- Error response formats
- Example requests/responses
- Rate limit headers

### Section 6: Developer Guide
**Content:**
- How to use BotSubscriptionValidator
- How to create bot-aware controllers
- How to handle subscription errors
- Code examples:
  ```python
  # Validate subscription before bot operation
  validator = BotSubscriptionValidator()
  is_valid, error = validator.validate_user_can_use_bots(user, db)
  if not is_valid:
      raise HTTPException(status_code=403, detail=error)
  ```

### Section 7: Migration Guide
**Content:**
- Pre-migration checklist
- Step-by-step migration instructions
- How to handle orphaned BotUser records
- Testing procedures
- Rollback plan

### Section 8: Troubleshooting
**Content:**
- Common issues and solutions:
  - "Bot user not linked" error
  - "Subscription required" error
  - "Platform limit reached" error
- How to manually link BotUser to User
- How to check subscription status
- Support contact information

### Section 9: Frontend Integration
**Content:**
- How to check bot access status: `GET /api/v1/bot-auth/bot-status`
- How to display subscription upgrade prompts
- How to show linked platforms
- UI/UX recommendations

### Section 10: Testing
**Content:**
- How to run bot subscription tests
- Test data setup
- Integration test scenarios
- Performance testing considerations

### README.md(MODIFY)

References: 

- docs\bot-subscription-integration.md(NEW)

## Update Main README

### Add Section: Bot Integration
**After the existing features section**, add:

#### Bot Integration Features
- Multi-platform bot support (Twitter, Telegram, Discord)
- Subscription-gated bot access
- User-linked bot accounts for security and billing
- Platform-specific rate limiting
- Bot authentication flow

#### Bot Setup
Add instructions:
1. Configure bot tokens in `.env` file
2. Run database migrations: `alembic upgrade head`
3. Run bot user migration script: `python scripts/migrate_bot_users_to_users.py`
4. Register bot commands: `python scripts/register_bot_commands.py`
5. Start bot services: `python -m src.bots.startup`

#### Bot Authentication
Add link to detailed documentation:
- See `docs/bot-subscription-integration.md` for complete guide
- Bot authentication endpoint: `/api/v1/bot-auth`
- Subscription requirements: BASIC plan or higher

### Update Environment Variables Section
Add bot-related environment variables:
```
# Bot Configuration
BOT_ENABLE_TWITTER=true
BOT_ENABLE_TELEGRAM=true
BOT_ENABLE_DISCORD=true

TWITTER_BOT_BEARER_TOKEN=your_token
TELEGRAM_BOT_TOKEN=your_token
DISCORD_BOT_TOKEN=your_token

BOT_WEBHOOK_SECRET=your_secret
```

### Update Migration Section
Add note about bot user migration:
- After running `alembic upgrade head`, run bot user migration script
- This links existing bot users to application users
- See migration guide in docs for details
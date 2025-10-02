I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

I've analyzed the Paddle configuration across the codebase and identified several issues:

1. **Missing Property**: `src/services/paddle_client.py` (line 47) tries to access `self.settings.paddle_api_secret_key`, but this property doesn't exist in the Settings class
2. **Inconsistent Naming**: The Settings class has `PADDLE_API_KEY` and `PADDLE_SECRET_KEY`, but Paddle's modern Billing API uses `PADDLE_API_SECRET_KEY` as the authentication key
3. **Missing Documentation**: `.env.example` has NO Paddle configuration section at all
4. **Active Usage**: Paddle is actively used in `paddle_client.py`, `subscription_service.py`, `paddle_webhooks.py`, and subscription models

The Paddle Billing SDK expects `PADDLE_API_SECRET_KEY` for authentication, which is the industry-standard naming for Paddle's current API.

### Approach

This plan adds the missing `paddle_api_secret_key` property to the Settings class and creates comprehensive Paddle configuration documentation in `.env.example`.

**Approach:**
1. **Add the missing property** to `src/config/settings.py` in the Paddle Settings section
2. **Create a complete Paddle configuration section** in `.env.example` with all necessary environment variables
3. **Verify compatibility** with `src/services/paddle_client.py` to ensure it can properly access the new setting
4. **Document all Paddle settings** including the webhook secret and environment configuration

The implementation maintains backward compatibility with existing Paddle fields while adding the critical missing `paddle_api_secret_key` property that the Paddle client service requires.

### Reasoning

I started by reading the three files mentioned in the user's task: `src/config/settings.py`, `.env.example`, and `src/services/paddle_client.py`. 

I discovered that `paddle_client.py` line 47 tries to access `self.settings.paddle_api_secret_key`, but this property doesn't exist in the Settings class. I then read the Paddle Settings section of `settings.py` (lines 240-260) and found it has `PADDLE_API_KEY`, `PADDLE_SECRET_KEY`, and other fields, but not `paddle_api_secret_key`.

I performed a grep search for "PADDLE" in `.env.example` and found NO matches, meaning there's no Paddle configuration section at all. I then searched for all "paddle" references across Python files to understand how Paddle is being used throughout the codebase, confirming that it's actively integrated in subscription services, webhooks, and models.

## Mermaid Diagram

sequenceDiagram
    participant PC as PaddleClientService
    participant Settings as Settings Class
    participant ENV as Environment Variables
    
    Note over PC,ENV: Initialization Flow
    
    PC->>ENV: Check PADDLE_API_SECRET_KEY
    alt Environment Variable Exists
        ENV-->>PC: Return API Secret Key
    else Environment Variable Missing
        PC->>Settings: Access paddle_api_secret_key property
        alt Property Exists (After Fix)
            Settings-->>PC: Return API Secret Key
        else Property Missing (Current State)
            Settings-->>PC: AttributeError
            PC->>PC: Raise ValueError
        end
    end
    
    PC->>PC: Initialize Paddle Client
    Note over PC: Client ready for API calls
    
    Note over PC,ENV: Webhook Verification Flow
    
    PC->>ENV: Check PADDLE_WEBHOOK_SECRET
    alt Environment Variable Exists
        ENV-->>PC: Return Webhook Secret
    else Environment Variable Missing
        PC->>Settings: Access paddle_webhook_secret
        Settings-->>PC: Return Webhook Secret
    end
    
    PC->>PC: Verify Webhook Signature

## Proposed File Changes

### src\config\settings.py(MODIFY)

References: 

- src\services\paddle_client.py(MODIFY)

Add the missing `paddle_api_secret_key` property to the Paddle Settings section (after line 253, before line 254):

**Add new field after `PADDLE_WEBHOOK_SECRET` (line 253):**
```python
PADDLE_API_SECRET_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_PADDLE_API_SECRET_KEY")
```

This property is required by `src/services/paddle_client.py` line 47, which attempts to access `self.settings.paddle_api_secret_key`. The Paddle Billing API uses `PADDLE_API_SECRET_KEY` as the primary authentication key for API requests.

**Note:** The existing `PADDLE_API_KEY` and `PADDLE_SECRET_KEY` fields (lines 251-252) should remain for backward compatibility, but `PADDLE_API_SECRET_KEY` is the correct field name for Paddle's modern Billing API.

The final Paddle Settings section should have these fields in order:
1. PADDLE_API_KEY (line 251)
2. PADDLE_SECRET_KEY (line 252)
3. PADDLE_WEBHOOK_SECRET (line 253)
4. **PADDLE_API_SECRET_KEY (NEW - add after line 253)**
5. PADDLE_ENVIRONMENT (line 254)
6. PADDLE_VENDOR_ID (line 255)
7. PADDLE_VENDOR_AUTH_CODE (line 256)
8. PADDLE_WEBHOOK_URL (line 257)

### .env.example(MODIFY)

References: 

- src\config\settings.py(MODIFY)
- src\services\paddle_client.py(MODIFY)

Add a complete Paddle Configuration section after the Webhook Configuration section (after line 191, before line 192):

**Insert new section:**
```bash
# Paddle Configuration (for billing and subscriptions)
# SECURITY CRITICAL: Paddle Billing API integration for subscription management
PADDLE_API_KEY=your-paddle-api-key
PADDLE_SECRET_KEY=your-paddle-secret-key
PADDLE_API_SECRET_KEY=your-paddle-api-secret-key
PADDLE_WEBHOOK_SECRET=your-paddle-webhook-secret
PADDLE_ENVIRONMENT=sandbox
PADDLE_VENDOR_ID=your-paddle-vendor-id
PADDLE_VENDOR_AUTH_CODE=your-paddle-vendor-auth-code
PADDLE_WEBHOOK_URL=https://your-domain.com/api/v1/webhooks/paddle
```

**Important Notes:**
- `PADDLE_API_SECRET_KEY` is the primary authentication key for Paddle Billing API (required by `src/services/paddle_client.py`)
- `PADDLE_ENVIRONMENT` should be set to `sandbox` for development/testing and `production` for live environments
- `PADDLE_WEBHOOK_SECRET` is used to verify webhook signatures from Paddle
- `PADDLE_WEBHOOK_URL` should be your publicly accessible webhook endpoint
- All values should be prefixed with `LINKSHIELD_` when used in the application (e.g., `LINKSHIELD_PADDLE_API_SECRET_KEY`), but the example shows the base names for clarity

This section should be inserted between the Webhook Configuration (lines 188-191) and File Upload Configuration (lines 192-195) sections.

### src\services\paddle_client.py(MODIFY)

References: 

- src\config\settings.py(MODIFY)

Verify that the Paddle client can properly access the new `paddle_api_secret_key` setting (this is a verification step, no code changes needed):

**Verification checklist:**

1. **Line 47 - API Key Access**: Confirm that the code `api_key = os.getenv('PADDLE_API_SECRET_KEY') or self.settings.paddle_api_secret_key` will now work correctly with the new Settings property

2. **Line 266 - Webhook Secret Access**: Confirm that `secret = webhook_secret or os.getenv('PADDLE_WEBHOOK_SECRET') or self.settings.paddle_webhook_secret` can access the existing `PADDLE_WEBHOOK_SECRET` setting

3. **Line 42 - Settings Import**: Verify that `self.settings = get_settings()` properly loads the Settings instance with all Paddle configuration

4. **Environment Variable Priority**: The code correctly prioritizes environment variables over settings properties (using `os.getenv()` first), which is a good practice

**Expected Behavior After Changes:**
- The `_initialize_client()` method (lines 45-55) will successfully retrieve the API key from either:
  - Environment variable `PADDLE_API_SECRET_KEY` (first priority)
  - Settings property `paddle_api_secret_key` (fallback)
- If neither is set, it will raise a `ValueError` with a clear error message (line 50)

**No code changes are required** in this file - the implementation is correct and will work once the Settings class has the `paddle_api_secret_key` property added.
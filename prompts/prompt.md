I have created the following plan after thorough exploration and analysis of the codebase. Follow the below plan verbatim. Trust the files and references. Do not re-verify what's written in the plan. Explore only when absolutely necessary. First implement all the proposed file changes and then I'll review all the changes together at the end.

### Observations

I've analyzed the codebase and identified all Stripe-related code that needs to be removed. The good news is that Stripe was never fully integrated—there are no actual Stripe imports or service implementations. The references are limited to:

1. **Database model fields** in `src/models/subscription.py` for `SubscriptionPlan`, `UserSubscription`, and `Payment` models
2. **Configuration settings** in `src/config/settings.py` 
3. **Environment variables** in `.env.example`
4. **Health check** reference in `src/controllers/health_controller.py`
5. **Documentation** references in various markdown files

The system is already using Paddle for payment processing, so this is primarily a cleanup task to remove legacy Stripe references that were never implemented.


### Approach

This plan focuses on systematically removing all Stripe-related code and configuration from the LinkShield backend. Since Stripe was never fully integrated (no imports or service implementations exist), this is a straightforward cleanup operation.

The approach involves:
1. **Removing database model fields** from subscription-related models
2. **Removing configuration settings** from the Settings class
3. **Updating environment examples** to remove Stripe variables
4. **Removing health check references** to Stripe
5. **Updating documentation** to reflect Paddle-only billing

Each change will be carefully documented to ensure no breaking changes occur, as the system already relies on Paddle for payment processing.


### Reasoning

I started by examining the files mentioned in the user's task. I read `src/models/subscription.py` to identify all Stripe-related fields across the `SubscriptionPlan`, `UserSubscription`, and `Payment` models. I then read portions of `src/config/settings.py` to locate Stripe configuration settings, and reviewed `.env.example` to find Stripe environment variables.

I performed grep searches across the codebase to find all occurrences of "stripe" (case-insensitive) in Python files and markdown documentation. This revealed additional references in `src/controllers/health_controller.py` and various documentation files. I also searched for Stripe imports to confirm that Stripe was never actually integrated into the codebase—no imports were found.

Finally, I read the `src/services/subscription_service.py` file to verify that it uses Paddle exclusively for payment processing, confirming that removing Stripe references won't break any existing functionality.


## Proposed File Changes

### src\models\subscription.py(MODIFY)

Remove all Stripe-related fields and methods from the subscription models:

**In `SubscriptionPlan` class (lines 78-307):**
- Remove the comment `# External IDs for payment processors` at line 124 and replace with `# Paddle Billing integration` to be consistent with `UserSubscription` model
- Remove field `stripe_price_id_monthly` at line 125
- Remove field `stripe_price_id_yearly` at line 126
- Remove field `stripe_product_id` at line 127
- Remove the entire method `get_stripe_price_id()` at lines 150-158, including its docstring

**In `UserSubscription` class (lines 309-505):**
- Remove the comment `# External IDs for payment processors` at line 341
- Remove field `stripe_subscription_id` at line 342
- Remove field `stripe_customer_id` at line 343
- In the `to_dict()` method (lines 467-504), remove the Stripe-related fields from the `include_sensitive` block:
  - Remove line 492: `"stripe_subscription_id": self.stripe_subscription_id,`
  - Remove line 493: `"stripe_customer_id": self.stripe_customer_id,`

**In `Payment` class (lines 507-623):**
- Remove the comment `# External payment processor information` at line 529
- Remove field `stripe_payment_intent_id` at line 530
- Remove field `stripe_charge_id` at line 531
- In the `to_dict()` method (lines 587-622), remove the Stripe-related fields from the `include_sensitive` block:
  - Remove line 611: `"stripe_payment_intent_id": self.stripe_payment_intent_id,`
  - Remove line 612: `"stripe_charge_id": self.stripe_charge_id,`

After these removals, ensure proper spacing and formatting is maintained. The models should only contain Paddle-related payment processor fields.

### src\config\settings.py(MODIFY)

Remove all Stripe-related configuration settings from the `Settings` class:

**Remove the Stripe Settings section (lines 250-253):**
- Remove the comment line 250: `# Stripe Settings (for billing)`
- Remove field at line 251: `STRIPE_PUBLISHABLE_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_STRIPE_PUBLISHABLE_KEY")`
- Remove field at line 252: `STRIPE_SECRET_KEY: Optional[str] = Field(default=None, env="LINKSHIELD_STRIPE_SECRET_KEY")`
- Remove field at line 253: `STRIPE_WEBHOOK_SECRET: Optional[str] = Field(default=None, env="LINKSHIELD_STRIPE_WEBHOOK_SECRET")`
- Remove the blank line at line 254

The Paddle Settings section (starting at line 255) should remain unchanged and move up to replace the removed Stripe section. This ensures that the billing configuration only references Paddle, which is the active payment processor.

### .env.example(MODIFY)

Remove all Stripe-related environment variable examples:

**Remove the Stripe Configuration section (lines 188-191):**
- Remove the comment line 188: `# Stripe Configuration (for subscriptions)`
- Remove line 189: `STRIPE_PUBLISHABLE_KEY=pk_test_your-stripe-publishable-key`
- Remove line 190: `STRIPE_SECRET_KEY=sk_test_your-stripe-secret-key`
- Remove line 191: `STRIPE_WEBHOOK_SECRET=whsec_your-stripe-webhook-secret`
- Remove the blank line at line 192

The Webhook Configuration section (starting at line 193) should remain and move up to replace the removed Stripe section. This ensures that the environment variable examples only show Paddle configuration, which is the active payment processor being used in the application.

### src\controllers\health_controller.py(MODIFY)

References: 

- src\config\settings.py(MODIFY)

Remove the Stripe reference from the external services health check:

**In the `_check_external_services()` method (lines 278-294):**
- In the `external_services` dictionary (lines 279-285), remove line 284: `"stripe": self.settings.STRIPE_SECRET_KEY is not None,`

This method checks which external API services are configured. Since Stripe is being removed and Paddle is the active payment processor, the Stripe check should be removed. The method will continue to check for OpenAI, VirusTotal, Google Safe Browsing, and URLVoid API configurations.

Note: If desired, a Paddle check could be added in the future (e.g., `"paddle": self.settings.PADDLE_API_KEY is not None`), but that's outside the scope of this Stripe removal task.

### src\services\subscription_service.py(MODIFY)

References: 

- src\services\paddle_client.py

Verify that no Stripe-related code exists in the subscription service (this is a verification step, no changes needed):

**Verification checklist:**
- Confirm that the service only imports and uses `PaddleClientService` from `src/services/paddle_client.py` (line 31)
- Confirm that all subscription creation, upgrade, and cancellation methods use Paddle exclusively
- Confirm that there are no Stripe imports or references in the file

Based on my analysis, this file is already Paddle-only and requires no modifications. This verification step ensures that the subscription service will continue to function correctly after Stripe references are removed from the models and configuration.
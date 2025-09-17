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

### `REDIS_URL`
- **Description:** Redis connection string for caching
- **Usage:** Caches report data, user sessions, and analytics for improved performance
- **Required:** No (caching will be disabled without it)
- **Format:** `redis://:password@host:port`
- **Example:** `redis://:password@localhost:6379`
- **Note:** Only used in production environment

## 📊 Analytics & Monitoring (Optional)

Currently, LinkShield uses built-in analytics. External analytics services can be integrated by adding their respective environment variables.

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

---

**Note:** Keep your `.env.local` file secure and never commit it to version control. Use your deployment platform's environment variable management for production deployments.

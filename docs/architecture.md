nom# 🏗️ System Architecture

**LinkShield System Architecture Overview**

LinkShield is built as a modern, scalable web application using Next.js 15 with a comprehensive tech stack designed for performance, security, and maintainability. This document provides a detailed overview of the system architecture, component interactions, and technical decisions.

## 🎯 Architecture Overview

LinkShield follows a **modern full-stack architecture** with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend Layer                           │
│  Next.js 15 App Router + TypeScript + Tailwind CSS        │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                  API Layer (Next.js)                       │
│     /api/check  /api/reports  /api/auth  /api/dashboard     │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                 Business Logic Layer                       │
│   Services • Repositories • Middleware • Utilities         │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────────────┐
│                   Data Layer                               │
│    PostgreSQL + Prisma ORM + Redis Cache                   │
└─────────────────────────────────────────────────────────────┘
```

## 🛠️ Technology Stack

### **Frontend Technologies**

| Technology | Version | Purpose | Justification |
|------------|---------|---------|---------------|
| **Next.js** | 15.x | React Framework | App Router, SSR/SSG, API routes, optimized performance |
| **TypeScript** | 5.x | Type Safety | Enhanced developer experience, compile-time error detection |
| **Tailwind CSS** | 4.x | Styling | Utility-first, consistent design system, small bundle size |
| **shadcn/ui** | Latest | UI Components | Accessible, customizable, built on Radix UI primitives |
| **Framer Motion** | Latest | Animations | Smooth micro-interactions and page transitions |
| **Lucide React** | Latest | Icons | Consistent, lightweight icon library |

### **Backend Technologies**

| Technology | Version | Purpose | Justification |
|------------|---------|---------|---------------|
| **PostgreSQL** | 14+ | Primary Database | ACID compliance, complex queries, JSON support |
| **Prisma** | 5.x | ORM | Type-safe database access, migrations, schema management |
| **NextAuth.js** | 4.x | Authentication | OAuth providers, session management, security best practices |
| **Redis** | 7.x | Caching/Rate Limiting | Fast in-memory storage, session caching, rate limiting |
| **Socket.io** | 4.x | Real-time Updates | Live notifications, real-time analytics |

### **External Integrations**

| Service | Purpose | Implementation |
|---------|---------|----------------|
| **Stripe** | Payment Processing | Subscription management, webhooks, secure payments |
| **PayPal** | Alternative Payments | Secondary payment option, international support |
| **AI Services** | Content Analysis | Quality scoring, topic categorization, SEO analysis |
| **Email Service** | Notifications | Transactional emails, reports, alerts |

## 🏛️ System Components

### **1. Frontend Architecture**

```
src/app/
├── (auth)/                 # Authentication pages
├── (dashboard)/            # User dashboard
├── (public)/              # Public pages
├── admin/                 # Admin panel
├── api/                   # API routes
├── report/[id]/           # Public report pages
└── globals.css            # Global styles

src/components/
├── ui/                    # shadcn/ui components
├── layout/                # Layout components
├── forms/                 # Form components
├── charts/                # Data visualization
└── projects/              # Feature-specific components

src/lib/
├── services/              # Business logic services
├── repositories/          # Data access layer
├── middleware/            # Custom middleware
├── utils/                 # Utility functions
└── types/                 # TypeScript definitions
```

### **2. API Architecture**

LinkShield uses **Next.js API Routes** with a RESTful design:

#### **Core API Endpoints**

```
/api/
├── check/                 # URL analysis endpoint
│   └── POST /api/check    # Analyze URL, return security & AI data
├── reports/               # Report management
│   ├── GET /api/reports   # List user reports
│   └── POST /api/reports  # Create shareable report
├── dashboard/             # User dashboard data
│   ├── GET /api/dashboard/stats    # Usage statistics
│   └── GET /api/dashboard/history  # Analysis history
├── admin/                 # Admin panel APIs
│   ├── GET /api/admin/users        # User management
│   └── GET /api/admin/analytics    # System analytics
├── auth/                  # NextAuth.js endpoints
├── stripe/                # Stripe webhooks
└── paypal/                # PayPal integration
```

#### **API Request/Response Flow**

```
1. Client Request → Rate Limiting Middleware
2. Authentication Check → Session Validation
3. Input Validation → Zod Schema Validation
4. Business Logic → Service Layer
5. Data Access → Repository Layer
6. Response → JSON with proper HTTP status
```

### **3. Database Architecture**

#### **Core Data Models**

```sql
-- User Management
User {
  id: String (UUID)
  email: String (unique)
  role: UserRole (USER, ADMIN)
  plan: PlanType (FREE, PRO, ENTERPRISE)
  createdAt: DateTime
  updatedAt: DateTime
}

-- URL Analysis Results
Check {
  id: String (UUID)
  url: String
  urlHash: String (indexed)
  statusCode: Int
  responseTime: Int
  sslValid: Boolean
  securityScore: Int
  userId: String (foreign key)
  createdAt: DateTime
}

-- AI Analysis Results
AIAnalysis {
  id: String (UUID)
  contentHash: String (indexed)
  qualityScore: Int
  readabilityScore: Int
  seoScore: Int
  topicCategories: String[]
  checkId: String (foreign key)
  userId: String (foreign key)
  createdAt: DateTime
}

-- Shareable Reports
ShareableReport {
  id: String (UUID)
  checkId: String (foreign key)
  isPublic: Boolean
  customTitle: String?
  customDescription: String?
  viewCount: Int
  createdAt: DateTime
}
```

#### **Database Relationships**

```
User (1) ←→ (N) Check
User (1) ←→ (N) AIAnalysis
Check (1) ←→ (1) AIAnalysis
Check (1) ←→ (1) ShareableReport
User (1) ←→ (N) Project
Project (1) ←→ (N) ProjectUrl
```

### **4. Service Layer Architecture**

#### **Core Services**

```typescript
// URL Analysis Service
class UrlAnalysisService {
  async analyzeUrl(url: string): Promise<AnalysisResult>
  async validateSsl(url: string): Promise<SslResult>
  async extractMetadata(url: string): Promise<Metadata>
  async checkRedirects(url: string): Promise<RedirectChain>
}

// AI Analysis Service
class AiAnalysisService {
  async analyzeContent(content: string): Promise<AiAnalysis>
  async scoreQuality(content: string): Promise<QualityMetrics>
  async categorizeTopics(content: string): Promise<string[]>
  async findSimilarPages(contentHash: string): Promise<SimilarPage[]>
}

// Report Service
class ShareableReportService {
  async createReport(checkId: string, options: ReportOptions): Promise<ShareableReport>
  async getPublicReport(reportId: string): Promise<PublicReport>
  async trackView(reportId: string, metadata: ViewMetadata): Promise<void>
}

// Subscription Service
class SubscriptionService {
  async checkUsageLimits(userId: string, planType: PlanType): Promise<UsageLimits>
  async incrementUsage(userId: string, usageType: UsageType): Promise<void>
  async handleStripeWebhook(event: StripeEvent): Promise<void>
}
```

## 🔄 Data Flow Architecture

### **URL Analysis Flow**

```
1. User submits URL → Frontend validation
2. API request → Rate limiting & authentication
3. Check existing analysis → Database lookup by URL hash
4. If not exists → Perform new analysis
   ├── Security analysis → SSL, status, performance
   ├── Metadata extraction → Title, description, OG data
   └── Store results → Database with user association
5. If AI analysis requested → Content analysis
   ├── Fetch page content → Content extraction
   ├── Generate content hash → Deduplication check
   ├── AI processing → Quality, topics, SEO analysis
   └── Store AI results → Link to original check
6. Create shareable report → Generate public URL
7. Return results → JSON response to frontend
```

### **Authentication Flow**

```
1. User login attempt → NextAuth.js providers
2. OAuth flow → Google, GitHub, etc.
3. User creation/lookup → Database operations
4. Session creation → JWT token generation
5. Session storage → Database + HTTP-only cookies
6. Request authentication → Middleware validation
7. Session refresh → Automatic token renewal
```

### **Payment Flow**

```
1. Plan selection → Frontend pricing page
2. Payment method → Stripe/PayPal integration
3. Payment processing → External payment provider
4. Webhook handling → Subscription activation
5. Database update → User plan upgrade
6. Usage limits → Real-time enforcement
7. Billing cycle → Automated recurring payments
```

## 🚀 Performance Architecture

### **Caching Strategy**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Browser       │    │   Redis Cache   │    │   Database      │
│   Cache         │    │   (Server)      │    │   (PostgreSQL)  │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • Static assets │    │ • URL analysis  │    │ • User data     │
│ • API responses │    │ • AI results    │    │ • Check history │
│ • User sessions │    │ • Rate limits   │    │ • Reports       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### **Optimization Strategies**

1. **Database Optimization**
   - Indexed queries on frequently accessed fields
   - Connection pooling with Prisma
   - Query optimization and N+1 prevention

2. **API Optimization**
   - Response caching for repeated URL analyses
   - Pagination for large datasets
   - Compression for API responses

3. **Frontend Optimization**
   - Code splitting with Next.js
   - Image optimization with next/image
   - Static generation for public pages

## 🔒 Security Architecture

### **Security Layers**

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Security                     │
├─────────────────────────────────────────────────────────────┤
│ • Input validation (Zod schemas)                            │
│ • SQL injection prevention (Prisma ORM)                    │
│ • XSS protection (Content sanitization)                    │
│ • CSRF protection (Next.js built-in)                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                  Authentication Security                    │
├─────────────────────────────────────────────────────────────┤
│ • OAuth 2.0 providers (Google, GitHub)                     │
│ • JWT tokens with secure storage                            │
│ • Session management with NextAuth.js                      │
│ • Rate limiting per user/IP                                │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     Data Security                           │
├─────────────────────────────────────────────────────────────┤
│ • Encrypted database connections                            │
│ • Environment variable protection                           │
│ • API key rotation and management                           │
│ • Secure payment processing (PCI compliance)               │
└─────────────────────────────────────────────────────────────┘
```

## 📊 Monitoring & Analytics

### **System Monitoring**

- **Performance Metrics** - Response times, error rates, uptime
- **Usage Analytics** - API calls, feature adoption, user engagement
- **Business Metrics** - Conversion rates, subscription growth, churn
- **Security Monitoring** - Failed login attempts, suspicious activity

### **Logging Strategy**

```typescript
// Structured logging with different levels
logger.info('URL analysis completed', {
  userId: user.id,
  url: analysisUrl,
  duration: responseTime,
  securityScore: result.securityScore
});

logger.error('AI analysis failed', {
  userId: user.id,
  error: error.message,
  contentHash: contentHash
});
```

## 🔄 Deployment Architecture

### **Production Environment**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CDN/Edge      │    │   Application   │    │   Database      │
│   (Vercel)      │    │   (Next.js)     │    │   (PostgreSQL)  │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • Static assets │    │ • API routes    │    │ • Primary data  │
│ • Global cache  │    │ • SSR/SSG       │    │ • Backups       │
│ • Edge functions│    │ • Serverless    │    │ • Replication   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### **Scalability Considerations**

1. **Horizontal Scaling**
   - Serverless functions auto-scale with demand
   - Database connection pooling
   - Redis cluster for high availability

2. **Vertical Scaling**
   - Database performance optimization
   - Memory-efficient data structures
   - Efficient algorithm implementations

---

## 🔧 Development Guidelines

### **Code Organization**
- **Feature-based structure** - Group related components and logic
- **Separation of concerns** - Clear boundaries between layers
- **Type safety** - Comprehensive TypeScript usage
- **Testing strategy** - Unit, integration, and E2E tests

### **API Design Principles**
- **RESTful conventions** - Consistent endpoint naming
- **Error handling** - Standardized error responses
- **Validation** - Input validation with Zod schemas
- **Documentation** - Comprehensive API documentation

### **Database Design**
- **Normalized structure** - Efficient data relationships
- **Indexing strategy** - Optimized query performance
- **Migration management** - Version-controlled schema changes
- **Data integrity** - Foreign key constraints and validation

---

**Last Updated:** January 2025  
**Architecture Version:** 1.0.0  
**Next Review:** Q2 2025

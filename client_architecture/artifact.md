# LinkShield Client Application - Comprehensive Development Specification

## Project Overview

Develop a **modern, production-ready client application** for LinkShield - a URL security analysis platform. This is a **standalone client application** (separate from the admin dashboard) that integrates with the LinkShield Backend API to provide URL threat detection, AI-powered analysis, and subscription-based features.

## Technology Stack

### Core Framework
- **Next.js 14+** (App Router)
- **TypeScript** (strict mode)
- **React 18+**

### UI & Styling
- **shadcn/ui** (primary component library)
- **Tailwind CSS** (utility-first styling)
- **Radix UI** (accessible primitives)
- **Lucide React** (icons)
- **Framer Motion** (animations)

### State Management & Data Fetching
- **TanStack Query (React Query)** (server state)
- **Zustand** (client state)
- **SWR** (real-time updates, optional)

### Forms & Validation
- **React Hook Form** (form management)
- **Zod** (schema validation)

### API Integration
- **Axios** (HTTP client with interceptors)
- **API client service layer** (typed interfaces)

### Authentication
- **JWT tokens** (primary)
- **API keys** (programmatic access)
- **Secure cookie storage** (httpOnly)

### Additional Libraries
- **date-fns** (date formatting)
- **recharts** (data visualization)
- **react-hot-toast** (notifications)
- **clsx + tailwind-merge** (conditional classes)

## Architecture Requirements

### Project Structure

```
linkshield-client/
├── src/
│   ├── app/                      # Next.js App Router
│   │   ├── (auth)/              # Auth routes group
│   │   │   ├── login/
│   │   │   ├── register/
│   │   │   └── verify-email/
│   │   ├── (dashboard)/         # Protected routes group
│   │   │   ├── dashboard/
│   │   │   ├── url-checks/
│   │   │   ├── reports/
│   │   │   ├── ai-analysis/
│   │   │   ├── settings/
│   │   │   └── api-keys/
│   │   ├── (marketing)/         # Public routes
│   │   │   ├── page.tsx         # Homepage with URL checker
│   │   │   ├── pricing/
│   │   │   ├── features/
│   │   │   └── docs/
│   │   ├── api/                 # API routes (if needed)
│   │   ├── layout.tsx
│   │   └── providers.tsx
│   ├── components/
│   │   ├── ui/                  # shadcn/ui components
│   │   ├── forms/               # Form components
│   │   ├── layouts/             # Layout components
│   │   ├── dashboard/           # Dashboard-specific
│   │   ├── url-checker/         # URL checking components
│   │   ├── reports/             # Report components
│   │   └── shared/              # Shared components
│   ├── lib/
│   │   ├── api/                 # API client
│   │   │   ├── client.ts        # Axios instance
│   │   │   ├── auth.ts          # Auth endpoints
│   │   │   ├── url-check.ts     # URL check endpoints
│   │   │   ├── reports.ts       # Report endpoints
│   │   │   ├── ai-analysis.ts   # AI endpoints
│   │   │   └── types.ts         # API types
│   │   ├── hooks/               # Custom hooks
│   │   ├── utils/               # Utility functions
│   │   ├── validations/         # Zod schemas
│   │   └── constants.ts         # App constants
│   ├── store/                   # Zustand stores
│   ├── types/                   # TypeScript types
│   └── styles/                  # Global styles
├── public/
├── next.config.js
├── tailwind.config.ts
└── tsconfig.json
```

## Core Features & Implementation

### 1. Homepage - URL Checker (Landing Page)

**Primary Feature**: Prominent URL security checker on the homepage

#### Requirements:
- **Hero Section** with URL input (large, centered)
- **Scan Types** (visible based on user plan):
  - Quick Scan (free users)
  - Comprehensive Scan (authenticated users)
  - Deep Analysis with AI (Pro+ users)
- **Real-time Validation**: URL format validation before submission
- **Instant Results**: Display scan results inline without navigation
- **Anonymous Scanning**: Allow unauthenticated users (rate-limited by IP)
- **CTA for Registration**: Encourage sign-up for more features

#### UI Components:
```typescript
// components/url-checker/HeroURLChecker.tsx
- Large search-style input with scan button
- Scan type selector (tabs/radio)
- Loading state with progress indicator
- Result card with risk score visualization
- Quick actions (Save, Report, Analyze with AI)

// components/url-checker/ScanResults.tsx
- Risk score gauge (0-100)
- Threat indicators (badges)
- Provider results (VirusTotal, Google Safe Browsing, URLVoid)
- Detailed analysis accordion
- Action buttons
```

#### API Integration:
```typescript
// Endpoint: POST /api/v1/url-check/check
interface URLCheckRequest {
  url: string;
  scan_type: 'quick' | 'comprehensive' | 'deep';
  include_ai_analysis?: boolean;
}

// Rate Limits (from docs):
// - Anonymous: 30/minute by IP
// - Authenticated: Based on subscription plan
// - Free: 10/day, 100/month
// - Basic: 100/day, 1,000/month
// - Pro: 500/day, 10,000/month
```

### 2. Authentication System

#### Registration Flow:
1. **Registration Page** (`/register`)
   - Email, password, full name, company (optional)
   - Terms acceptance, marketing consent
   - Password strength indicator
   - Email verification notice

2. **Email Verification** (`/verify-email/[token]`)
   - Auto-verify on page load
   - Success/error states
   - Redirect to dashboard

3. **Login Page** (`/login`)
   - Email/password form
   - Remember me checkbox
   - Forgot password link
   - Social login (future)

#### Implementation Details:
```typescript
// lib/api/auth.ts
export const authAPI = {
  register: (data: RegisterRequest) => 
    api.post('/api/v1/user/register', data),
  
  login: (data: LoginRequest) => 
    api.post('/api/v1/user/login', data),
  
  logout: () => 
    api.post('/api/v1/user/logout'),
  
  verifyEmail: (token: string) => 
    api.post(`/api/v1/user/verify-email/${token}`),
  
  resendVerification: () => 
    api.post('/api/v1/user/resend-verification'),
};

// Password Requirements (from docs):
// - Minimum 8 characters
// - At least one uppercase letter
// - At least one lowercase letter
// - At least one digit
// - At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
```

#### Session Management:
- JWT token storage (httpOnly cookies recommended)
- Automatic token refresh
- Session duration: 7 days (default) or 30 days (remember me)
- Logout across all devices option

### 3. Dashboard Layout

#### Main Dashboard (`/dashboard`)
- **Overview Cards**:
  - Total URLs checked (this month)
  - Threats detected
  - AI analyses used
  - Subscription status
- **Recent Scans** (table)
- **Threat Summary** (chart)
- **Quick Actions**: Check URL, Generate Report, View API Keys

#### Navigation Structure:
```typescript
const dashboardNavigation = [
  {
    label: 'Dashboard',
    href: '/dashboard',
    icon: LayoutDashboard,
  },
  {
    label: 'URL Checks',
    href: '/dashboard/url-checks',
    icon: Link,
  },
  {
    label: 'Reports',
    href: '/dashboard/reports',
    icon: Flag,
  },
  {
    label: 'AI Analysis',
    href: '/dashboard/ai-analysis',
    icon: Brain,
    badge: 'Pro',
  },
  {
    label: 'API Keys',
    href: '/dashboard/api-keys',
    icon: Key,
  },
  {
    label: 'Settings',
    href: '/dashboard/settings',
    icon: Settings,
  },
];
```

### 4. URL Checks History (`/dashboard/url-checks`)

#### Features:
- **Table View** with columns:
  - URL (truncated with tooltip)
  - Domain
  - Risk Score (visual indicator)
  - Status (badge)
  - Scan Type
  - Date/Time
  - Actions (View, Analyze, Report)
- **Filters**:
  - Date range
  - Risk level (Safe, Low, Medium, High, Critical)
  - Scan type
  - Status
- **Sorting**: By date, risk score, domain
- **Pagination**: Cursor-based (recommended) or offset
- **Search**: By URL or domain
- **Bulk Actions**: Export, Delete

#### API Integration:
```typescript
// Endpoint: GET /api/v1/url-check/history
interface URLCheckHistoryParams {
  page?: number;
  limit?: number;
  status?: 'completed' | 'pending' | 'failed';
  start_date?: string;
  end_date?: string;
  risk_level?: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}
```

### 5. Community Reports (`/dashboard/reports`)

#### Create Report Feature:
- **Report Form**:
  - URL (auto-filled if from scan)
  - Report type: Phishing, Malware, Scam, Spam, Inappropriate, Copyright, Other
  - Title (optional)
  - Description (required, rich text)
  - Evidence (optional, JSON or file upload)
  - Priority indicator

#### Reports List:
- **My Reports** tab
- **Community Reports** tab (view others)
- **Status Filters**: Pending, Under Review, Resolved, Rejected
- **Priority Badges**: Low, Medium, High, Critical
- **Voting System**: Upvote/downvote reports
- **Report Details Modal**:
  - Full report information
  - Vote count and distribution
  - Review status and notes
  - Resolution details

#### API Integration:
```typescript
// Endpoints:
// POST /api/v1/reports/ - Create report
// GET /api/v1/reports/ - List reports
// GET /api/v1/reports/{report_id} - Get report details
// POST /api/v1/reports/{report_id}/vote - Vote on report
// GET /api/v1/reports/stats - Report statistics

interface ReportCreateRequest {
  reported_url: string;
  report_type: 'PHISHING' | 'MALWARE' | 'SCAM' | 'SPAM' | 'INAPPROPRIATE' | 'COPYRIGHT' | 'OTHER';
  title?: string;
  description: string;
  evidence?: Record<string, any>;
  url_check_id?: string;
}
```

### 6. AI Analysis (`/dashboard/ai-analysis`)

**Pro+ Feature** - Requires active subscription

#### Features:
- **Content Analysis Dashboard**:
  - Recent AI analyses
  - Analysis types: Phishing Detection, Malware Scan, Content Classification, Sentiment Analysis
  - Confidence scores
  - Quality scores
  - Processing status
- **New Analysis**:
  - Select URL from history
  - Choose analysis type
  - View real-time processing status
- **Analysis Results**:
  - Detailed findings
  - Risk breakdown
  - Recommendations
  - Similar content matches
- **Domain Statistics**:
  - Domain-level insights
  - Historical analysis trends

#### API Integration:
```typescript
// Endpoints:
// POST /api/v1/ai-analysis/ - Request analysis
// GET /api/v1/ai-analysis/{analysis_id} - Get results
// GET /api/v1/ai-analysis/history - Analysis history
// GET /api/v1/ai-analysis/domain-stats/{domain} - Domain statistics

interface AIAnalysisRequest {
  url_check_id: string;
  analysis_type: 'PHISHING_DETECTION' | 'MALWARE_SCAN' | 'CONTENT_CLASSIFICATION' | 'SENTIMENT_ANALYSIS';
}

// Rate Limits:
// Free: 10/minute
// Basic: 50/minute (if enabled)
// Pro+: Higher limits
```

### 7. API Keys Management (`/dashboard/api-keys`)

#### Features:
- **API Keys List**:
  - Name/description
  - Key prefix (last 8 chars hidden)
  - Permissions badges
  - Status (active/inactive)
  - Created date
  - Last used
  - Expiration date
  - Actions (View, Revoke, Delete)
- **Create API Key**:
  - Name (required)
  - Description (optional)
  - Permissions (checkboxes):
    - url_check
    - ai_analysis
    - reports
    - profile
  - Expiration date (optional)
- **Security Features**:
  - Show key only once on creation
  - Copy to clipboard
  - Regenerate key
  - Usage statistics

#### API Integration:
```typescript
// Endpoints:
// POST /api/v1/user/api-keys - Create key
// GET /api/v1/user/api-keys - List keys
// DELETE /api/v1/user/api-keys/{key_id} - Delete key

interface APIKeyCreateRequest {
  name: string;
  description?: string;
  expires_at?: string;
  permissions: ('url_check' | 'ai_analysis' | 'reports' | 'profile')[];
}

// Response includes full key only on creation:
// api_key: "lsk_live_1234567890abcdef1234567890abcdef12345678"
```

### 8. Settings & Profile (`/dashboard/settings`)

#### Tabs:
1. **Profile**:
   - Full name
   - Email (verified badge)
   - Company
   - Avatar upload
   - Account creation date

2. **Subscription**:
   - Current plan card
   - Usage statistics (progress bars):
     - Daily checks used/limit
     - Monthly checks used/limit
     - AI analysis used/limit
   - Plan features list
   - Upgrade/Downgrade buttons
   - Billing history

3. **Security**:
   - Change password
   - Two-factor authentication (future)
   - Active sessions list:
     - Device info
     - IP address
     - Last active
     - Revoke session
   - Terminate all sessions button

4. **Notifications**:
   - Email preferences
   - Security alerts
   - Report updates
   - Marketing emails

5. **Developer**:
   - API documentation link
   - Webhook configuration (future)
   - API usage statistics

#### API Integration:
```typescript
// Profile:
// GET /api/v1/user/profile
// PUT /api/v1/user/profile

// Password:
// POST /api/v1/user/change-password

// Sessions:
// GET /api/v1/user/sessions
// DELETE /api/v1/user/sessions/{session_id}
// DELETE /api/v1/user/sessions (all)

// Subscription:
// GET /api/v1/subscriptions/current
// GET /api/v1/subscriptions/usage
```

## UI/UX Requirements

### Design System

#### Color Palette:
```typescript
// Primary: Blue (trust, security)
primary: 'hsl(221, 83%, 53%)',      // #2463EB
primary-foreground: 'hsl(0, 0%, 100%)',

// Destructive: Red (threats, danger)
destructive: 'hsl(0, 84%, 60%)',    // #EF4444

// Success: Green (safe URLs)
success: 'hsl(142, 71%, 45%)',      // #10B981

// Warning: Orange (medium risk)
warning: 'hsl(38, 92%, 50%)',       // #F59E0B

// Muted: Gray (backgrounds)
muted: 'hsl(210, 40%, 96%)',        // #F3F4F6
```

#### Risk Score Visualization:
```typescript
const getRiskColor = (score: number) => {
  if (score >= 80) return 'destructive';  // Critical
  if (score >= 60) return 'warning';      // High
  if (score >= 40) return 'warning';      // Medium
  if (score >= 20) return 'success';      // Low
  return 'success';                        // Safe
};

// Visual indicators:
// - Gauge chart (radial progress)
// - Color-coded badges
// - Icons (Shield, AlertTriangle, CheckCircle)
```

#### Typography:
- **Headings**: Inter or Geist font
- **Body**: System font stack
- **Code**: Geist Mono

#### Components to Build:

1. **Risk Score Card**:
   - Large score display (0-100)
   - Radial progress indicator
   - Risk level label
   - Color-coded border

2. **URL Display Component**:
   - Truncate long URLs
   - Show full URL on hover (tooltip)
   - Copy button
   - External link icon

3. **Scan Status Badge**:
   - Completed (green)
   - Pending (blue)
   - Failed (red)
   - Processing (yellow, animated)

4. **Provider Results Grid**:
   - Cards for each provider
   - Provider logo
   - Detection status
   - Details link

5. **Usage Progress Bar**:
   - Current/limit display
   - Color changes based on percentage
   - Tooltip with reset date

6. **Empty States**:
   - No URL checks yet
   - No reports
   - No AI analyses
   - Clear CTAs

7. **Loading States**:
   - Skeleton loaders
   - Progress indicators
   - Animated spinners

### Responsive Design:
- **Mobile-first** approach
- Breakpoints:
  - sm: 640px
  - md: 768px
  - lg: 1024px
  - xl: 1280px
  - 2xl: 1536px
- **Mobile Navigation**: Hamburger menu
- **Touch-friendly**: Larger tap targets (min 44px)

### Accessibility:
- WCAG 2.1 AA compliance
- Keyboard navigation
- Screen reader support
- Focus indicators
- ARIA labels
- Semantic HTML

## State Management

### Global State (Zustand):
```typescript
// store/auth.ts
interface AuthStore {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (token: string, user: User) => void;
  logout: () => void;
  updateUser: (user: Partial<User>) => void;
}

// store/subscription.ts
interface SubscriptionStore {
  plan: SubscriptionPlan | null;
  usage: UsageStats | null;
  isLoading: boolean;
  fetchSubscription: () => Promise<void>;
  checkLimit: (type: 'daily' | 'monthly') => boolean;
}

// store/ui.ts
interface UIStore {
  sidebarOpen: boolean;
  toggleSidebar: () => void;
  theme: 'light' | 'dark' | 'system';
  setTheme: (theme: string) => void;
}
```

### Server State (TanStack Query):
```typescript
// hooks/useURLChecks.ts
export const useURLChecks = (params: URLCheckHistoryParams) => {
  return useQuery({
    queryKey: ['url-checks', params],
    queryFn: () => urlCheckAPI.getHistory(params),
    staleTime: 30000, // 30 seconds
  });
};

// hooks/useCreateURLCheck.ts
export const useCreateURLCheck = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: urlCheckAPI.check,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['url-checks'] });
      toast.success('URL scan completed');
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });
};
```

## API Client Implementation

### Axios Instance with Interceptors:
```typescript
// lib/api/client.ts
import axios from 'axios';
import { useAuthStore } from '@/store/auth';

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Include cookies
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().token;
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor
api.interceptors.response.use(
  (response) => response.data,
  async (error) => {
    const originalRequest = error.config;

    // Handle 401 errors (token expired)
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      useAuthStore.getState().logout();
      window.location.href = '/login';
      return Promise.reject(error);
    }

    // Handle rate limiting
    if (error.response?.status === 429) {
      const retryAfter = error.response.headers['retry-after'];
      toast.error(`Rate limit exceeded. Retry after ${retryAfter} seconds.`);
    }

    // Handle subscription limits
    if (error.response?.status === 402) {
      toast.error('Subscription limit reached. Please upgrade your plan.');
    }

    return Promise.reject(error);
  }
);

export default api;
```

### Type-Safe API Client:
```typescript
// lib/api/types.ts
export interface User {
  id: string;
  email: string;
  full_name: string;
  company?: string;
  role: 'USER' | 'MODERATOR' | 'ADMIN';
  is_active: boolean;
  is_verified: boolean;
  subscription_plan: SubscriptionPlan;
  created_at: string;
}

export interface URLCheckResult {
  id: string;
  url: string;
  domain: string;
  scan_type: 'quick' | 'comprehensive' | 'deep';
  status: 'completed' | 'pending' | 'failed';
  is_safe: boolean;
  risk_score: number;
  scan_results: {
    virustotal?: ProviderResult;
    google_safe_browsing?: ProviderResult;
    urlvoid?: ProviderResult;
  };
  metadata?: Record<string, any>;
  created_at: string;
  completed_at?: string;
}

export interface ProviderResult {
  detected: boolean;
  categories?: string[];
  details?: Record<string, any>;
}

// ... more types based on data-models.md
```

## Error Handling

### Global Error Handler:
```typescript
// lib/utils/error-handler.ts
export const handleAPIError = (error: any) => {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status;
    const message = error.response?.data?.error || error.message;

    switch (status) {
      case 400:
        return 'Invalid request. Please check your input.';
      case 401:
        return 'Authentication required. Please log in.';
      case 403:
        return 'Access denied. Insufficient permissions.';
      case 404:
        return 'Resource not found.';
      case 409:
        return 'Resource already exists.';
      case 422:
        return 'Validation error. Please check your input.';
      case 429:
        return 'Too many requests. Please try again later.';
      case 500:
        return 'Server error. Please try again later.';
      default:
        return message || 'An unexpected error occurred.';
    }
  }

  return 'An unexpected error occurred.';
};
```

### Form Validation (Zod):
```typescript
// lib/validations/url-check.ts
import { z } from 'zod';

export const urlCheckSchema = z.object({
  url: z.string()
    .url('Invalid URL format')
    .max(2048, 'URL too long')
    .refine(
      (url) => url.startsWith('http://') || url.startsWith('https://'),
      'URL must start with http:// or https://'
    ),
  scan_type: z.enum(['quick', 'comprehensive', 'deep']),
  include_ai_analysis: z.boolean().optional(),
});

export const reportSchema = z.object({
  reported_url: z.string().url('Invalid URL'),
  report_type: z.enum([
    'PHISHING',
    'MALWARE',
    'SCAM',
    'SPAM',
    'INAPPROPRIATE',
    'COPYRIGHT',
    'OTHER'
  ]),
  title: z.string().max(200).optional(),
  description: z.string()
    .min(10, 'Description must be at least 10 characters')
    .max(5000, 'Description too long'),
  evidence: z.record(z.any()).optional(),
});
```

## Security Implementation

### Authentication Guards:
```typescript
// middleware.ts (Next.js middleware)
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('auth_token')?.value;
  const isAuthPage = request.nextUrl.pathname.startsWith('/login') ||
                     request.nextUrl.pathname.startsWith('/register');
  const isDashboard = request.nextUrl.pathname.startsWith('/dashboard');

  // Redirect authenticated users away from auth pages
  if (isAuthPage && token) {
    return NextResponse.redirect(new URL('/dashboard', request.url));
  }

  // Protect dashboard routes
  if (isDashboard && !token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*', '/login', '/register'],
};
```

### Protected Route Component:
```typescript
// components/layouts/ProtectedRoute.tsx
'use client';

import { useAuthStore } from '@/store/auth';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';

export default function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuthStore();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push('/login');
    }
  }, [isAuthenticated, isLoading, router]);

  if (isLoading) {
    return <LoadingSpinner />;
  }

  if (!isAuthenticated) {
    return null;
  }

  return <>{children}</>;
}
```

### XSS Prevention:
- Sanitize user input (DOMPurify)
- Use `dangerouslySetInnerHTML` sparingly
- Validate all URLs before rendering

### CSRF Protection:
- Use httpOnly cookies for tokens
- Implement CSRF tokens for sensitive operations
- Verify origin headers

## Performance Optimization

### Code Splitting:
```typescript
// Dynamic imports for heavy components
const AIAnalysisDashboard = dynamic(
  () => import('@/components/dashboard/AIAnalysisDashboard'),
  { loading: () => <LoadingSkeleton /> }
);
```

### Image Optimization:
```typescript
// Use Next.js Image component
import Image from 'next/image';

<Image
  src="/logo.svg"
  alt="LinkShield"
  width={120}
  height={40}
  priority
/>
```

### API Caching:
```typescript
// TanStack Query cache configuration
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60 * 1000, // 1 minute
      cacheTime: 5 * 60 * 1000, // 5 minutes
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});
```

### Bundle Optimization:
- Tree shaking
- Remove unused dependencies
- Analyze bundle size (`@next/bundle-analyzer`)
- Use dynamic imports for large components

## Testing Strategy

### Unit Tests (Jest + React Testing Library):
```typescript
// __tests__/components/URLChecker.test.tsx
describe('URLChecker', () => {
  it('validates URL format', () => {
    // Test implementation
  });

  it('displays scan results', () => {
    // Test implementation
  });

  it('handles rate limiting', () => {
    // Test implementation
  });
});
```

### Integration Tests:
- API client functions
- Authentication flow
- Form submissions

### E2E Tests (Playwright):
- User registration and login
- URL checking flow
- Report creation
- Subscription upgrade

## Deployment

### Environment Variables:
```bash
# .env.local
NEXT_PUBLIC_API_URL=https://api.linkshield.com
NEXT_PUBLIC_APP_URL=https://linkshield.com
NEXT_PUBLIC_ENVIRONMENT=production
```

### Build Configuration:
```javascript
// next.config.js
module.exports = {
  reactStrictMode: true,
  images: {
    domains: ['api.linkshield.com'],
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.NEXT_PUBLIC_API_URL}/api/:path*`,
      },
    ];
  },
};
```

### Deployment Platforms:
- **Vercel** (recommended for Next.js)
- **Netlify**
- **AWS Amplify**
- **Docker + Kubernetes**

## Documentation Requirements

### README.md:
- Project overview
- Setup instructions
- Environment variables
- Scripts (dev, build, test)
- Deployment guide

### Component Documentation:
- Storybook for UI components
- JSDoc comments
- Usage examples

### API Integration Guide:
- Authentication examples
- Endpoint usage
- Error handling
- Rate limiting

## Social Media Protection Features

### Overview
LinkShield provides comprehensive social media security analysis across multiple platforms including Twitter, Facebook, Instagram, TikTok, LinkedIn, Telegram, and Discord. The client application must integrate these features prominently.

### Architecture Integration

```
src/
├── app/
│   ├── (dashboard)/
│   │   ├── social-protection/
│   │   │   ├── page.tsx                    # Main dashboard
│   │   │   ├── profile-scan/
│   │   │   │   └── page.tsx                # Profile scanning
│   │   │   ├── content-analysis/
│   │   │   │   └── page.tsx                # Content analysis
│   │   │   ├── crisis-detection/
│   │   │   │   └── page.tsx                # Crisis monitoring
│   │   │   ├── bot-analysis/
│   │   │   │   └── page.tsx                # Bot detection
│   │   │   └── reports/
│   │   │       └── page.tsx                # Social protection reports
│   ├── (marketing)/
│   │   ├── page.tsx                        # Homepage (add social protection hero)
│   │   └── social-protection/
│   │       └── page.tsx                    # Social protection landing
├── components/
│   ├── social-protection/
│   │   ├── ProfileScanner.tsx
│   │   ├── ContentAnalyzer.tsx
│   │   ├── CrisisMonitor.tsx
│   │   ├── BotDetector.tsx
│   │   ├── PlatformSelector.tsx
│   │   ├── RiskScoreCard.tsx
│   │   ├── AnalyzerResults.tsx
│   │   └── SocialHealthCheck.tsx
```

### 1. Homepage Integration - Social Media Protection

**Add to Hero Section** (alongside URL checker):

```typescript
// components/home/HeroSection.tsx
- Tabbed interface:
  - Tab 1: URL Security Check (existing)
  - Tab 2: Social Profile Scan (NEW)
  - Tab 3: Content Analysis (NEW)

// Social Profile Scanner Component
interface ProfileScannerProps {
  defaultPlatform?: Platform;
}

// Features:
- Platform selector (Twitter, Facebook, Instagram, TikTok, LinkedIn, Telegram, Discord)
- Profile URL/username input
- Scan type selector:
  - Quick Scan (free) - Basic risk assessment
  - Comprehensive Scan (authenticated) - Full analysis with all analyzers
  - Deep Scan with AI (Pro+) - AI-powered insights + crisis detection
- Real-time scan results
- Visual risk indicators
```

#### Platform Support Display:
```typescript
const SUPPORTED_PLATFORMS = [
  { name: 'Twitter', icon: Twitter, color: '#1DA1F2' },
  { name: 'Facebook', icon: Facebook, color: '#4267B2' },
  { name: 'Instagram', icon: Instagram, color: '#E4405F' },
  { name: 'TikTok', icon: Music, color: '#000000' },
  { name: 'LinkedIn', icon: Linkedin, color: '#0077B5' },
  { name: 'Telegram', icon: Send, color: '#0088cc' },
  { name: 'Discord', icon: MessageSquare, color: '#5865F2' },
];
```

### 2. Social Protection Dashboard (`/dashboard/social-protection`)

#### Main Dashboard Layout:

**Overview Cards:**
```typescript
interface SocialProtectionOverview {
  total_scans: number;
  threats_detected: number;
  profiles_monitored: number;
  crisis_alerts: number;
  bot_accounts_detected: number;
  content_analyzed: number;
}
```

**Dashboard Sections:**

1. **Quick Actions Panel**:
   - Scan Profile button
   - Analyze Content button
   - Check Bot Activity button
   - View Crisis Alerts button

2. **Recent Scans Table**:
   - Platform icon
   - Profile/Username
   - Risk score (gauge)
   - Threat types detected (badges)
   - Scan date
   - Actions (View details, Re-scan, Monitor)

3. **Threat Summary Charts**:
   - Risk distribution by platform (pie chart)
   - Threats over time (line chart)
   - Top threat categories (bar chart)

4. **Active Monitoring**:
   - List of monitored profiles
   - Real-time status indicators
   - Crisis alerts
   - Auto-scan frequency settings

### 3. Profile Scanning (`/dashboard/social-protection/profile-scan`)

#### Features:

**Input Section:**
```typescript
interface ProfileScanRequest {
  platform: Platform;
  profile_url: string;
  username?: string;
  scan_depth?: 'quick' | 'standard' | 'deep';
  include_followers?: boolean;
  analyze_content?: boolean;
  check_crisis_indicators?: boolean;
}

// Platforms enum
type Platform = 
  | 'twitter' 
  | 'facebook' 
  | 'instagram' 
  | 'tiktok' 
  | 'linkedin' 
  | 'telegram' 
  | 'discord';
```

**Analyzer Categories Display:**

```typescript
// 8 Core Analyzers (from backend)
const ANALYZERS = [
  {
    id: 'content_risk',
    name: 'Content Risk Analyzer',
    description: 'Evaluates content for harmful or risky material',
    icon: AlertTriangle,
    metrics: ['risk_score', 'threat_categories', 'flagged_posts'],
  },
  {
    id: 'link_penalty',
    name: 'Link Penalty Detector',
    description: 'Detects malicious URLs and link-based penalties',
    icon: Link,
    metrics: ['malicious_links', 'suspicious_domains', 'penalty_score'],
  },
  {
    id: 'spam_pattern',
    name: 'Spam Pattern Detector',
    description: 'Identifies spam and repetitive content patterns',
    icon: MessageCircle,
    metrics: ['spam_score', 'repetitive_content', 'bot_like_behavior'],
  },
  {
    id: 'community_notes',
    name: 'Community Notes Analyzer',
    description: 'Analyzes community feedback and fact-checks',
    icon: Users,
    metrics: ['notes_count', 'misleading_claims', 'fact_check_status'],
  },
  {
    id: 'visibility',
    name: 'Visibility Scorer',
    description: 'Measures content reach and visibility metrics',
    icon: Eye,
    metrics: ['visibility_score', 'reach_estimate', 'engagement_rate'],
  },
  {
    id: 'engagement',
    name: 'Engagement Analyzer',
    description: 'Analyzes engagement patterns and authenticity',
    icon: Heart,
    metrics: ['engagement_rate', 'authentic_engagement', 'bot_interactions'],
  },
  {
    id: 'penalty',
    name: 'Penalty Detector',
    description: 'Detects platform penalties and restrictions',
    icon: Ban,
    metrics: ['penalty_status', 'restriction_type', 'severity'],
  },
  {
    id: 'shadow_ban',
    name: 'Shadow Ban Detector',
    description: 'Identifies shadow banning and content suppression',
    icon: EyeOff,
    metrics: ['shadow_ban_probability', 'suppression_indicators', 'reach_impact'],
  },
];
```

**Results Display:**

```typescript
interface ProfileScanResult {
  profile_id: string;
  platform: Platform;
  username: string;
  display_name: string;
  bio: string;
  profile_image_url: string;
  verified: boolean;
  created_at: string;
  
  // Overall Risk Assessment
  overall_risk_score: number;        // 0-100
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  threats_detected: string[];
  
  // Analyzer Results
  content_risk: ContentRiskAnalysis;
  link_penalty: LinkPenaltyAnalysis;
  spam_pattern: SpamPatternAnalysis;
  community_notes: CommunityNotesAnalysis;
  visibility: VisibilityAnalysis;
  engagement: EngagementAnalysis;
  penalty: PenaltyAnalysis;
  shadow_ban: ShadowBanAnalysis;
  
  // Additional Insights
  follower_analysis?: FollowerAnalysis;
  content_samples: ContentSample[];
  recommendations: string[];
  
  // Metadata
  scan_timestamp: string;
  scan_duration_ms: number;
  data_sources: string[];
}
```

**UI Components:**

1. **Risk Score Dashboard**:
   - Large circular gauge (0-100)
   - Risk level badge (color-coded)
   - Threat categories list
   - Severity indicators

2. **Analyzer Results Grid**:
   - 8 cards (one per analyzer)
   - Each card shows:
     - Analyzer name and icon
     - Status (healthy, warning, critical)
     - Key metrics
     - Expand for details

3. **Profile Overview Card**:
   - Profile picture
   - Display name, username
   - Verification badge
   - Platform icon
   - Account age
   - Follower count

4. **Content Analysis Section**:
   - Recent posts/content samples
   - Flagged content highlights
   - Sentiment distribution
   - Language analysis

5. **Timeline Visualization**:
   - Activity patterns over time
   - Anomaly detection
   - Peak activity times
   - Content frequency

6. **Recommendations Panel**:
   - Action items
   - Risk mitigation steps
   - Monitoring suggestions

### 4. Content Analysis (`/dashboard/social-protection/content-analysis`)

**Features:**

```typescript
interface ContentAnalysisRequest {
  content_type: 'post' | 'comment' | 'message' | 'bio' | 'url';
  platform: Platform;
  content_text?: string;
  content_url?: string;
  media_urls?: string[];
  analyze_sentiment?: boolean;
  detect_toxicity?: boolean;
  check_misinformation?: boolean;
}

interface ContentAnalysisResult {
  content_id: string;
  analysis_timestamp: string;
  
  // Risk Assessment
  risk_score: number;
  risk_factors: string[];
  
  // Content Classification
  categories: string[];
  topics: string[];
  
  // Sentiment Analysis
  sentiment: {
    score: number;           // -1 (negative) to 1 (positive)
    label: 'positive' | 'negative' | 'neutral';
    confidence: number;
  };
  
  // Toxicity Detection
  toxicity: {
    is_toxic: boolean;
    severity: 'low' | 'medium' | 'high';
    categories: string[];    // hate_speech, harassment, threats, etc.
    confidence: number;
  };
  
  // Misinformation Check
  misinformation: {
    likelihood: number;
    fact_check_sources: FactCheckSource[];
    credibility_score: number;
  };
  
  // Link Analysis
  links_detected: LinkAnalysis[];
  
  // Language Detection
  language: string;
  is_multi_lingual: boolean;
  
  // Recommendations
  warnings: string[];
  suggestions: string[];
}
```

**UI Components:**

1. **Content Input Area**:
   - Rich text editor / textarea
   - URL input for existing content
   - Platform selector
   - Analysis options checkboxes

2. **Real-time Analysis**:
   - Live sentiment indicator
   - Toxicity gauge (updates as typing)
   - Risk meter
   - Language detection

3. **Detailed Results Panel**:
   - Sentiment visualization (emoji + score)
   - Toxicity breakdown by category
   - Misinformation probability
   - Link safety status
   - Category tags

4. **Content Comparison**:
   - Compare multiple versions
   - Before/after analysis
   - Historical trends

### 5. Crisis Detection & Monitoring (`/dashboard/social-protection/crisis-detection`)

**Features:**

```typescript
interface CrisisDetectionConfig {
  monitored_profiles: string[];
  keywords: string[];
  platforms: Platform[];
  alert_threshold: number;
  notification_channels: ('email' | 'sms' | 'webhook')[];
}

interface CrisisAlert {
  alert_id: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detected_at: string;
  
  // Crisis Details
  crisis_type: string;
  description: string;
  affected_profiles: string[];
  affected_platforms: Platform[];
  
  // Metrics
  threat_score: number;
  velocity: number;           // How fast it's spreading
  reach_estimate: number;
  engagement_volume: number;
  
  // Evidence
  trigger_events: TriggerEvent[];
  related_content: ContentSample[];
  sentiment_shift: SentimentTrend;
  
  // Response
  status: 'active' | 'monitoring' | 'resolved' | 'false_positive';
  response_actions: string[];
  assigned_to?: string;
}
```

**UI Components:**

1. **Crisis Dashboard**:
   - Active alerts count (with severity colors)
   - Alert timeline
   - Severity distribution chart
   - Platform breakdown

2. **Alert Cards**:
   - Color-coded by severity
   - Crisis type icon
   - Timestamp and duration
   - Affected profiles/platforms
   - Quick actions (View, Acknowledge, Resolve)

3. **Crisis Details Modal**:
   - Full alert information
   - Evidence gallery
   - Sentiment trends chart
   - Recommended actions
   - Response history

4. **Monitoring Configuration**:
   - Add/remove monitored profiles
   - Keyword management
   - Alert threshold settings
   - Notification preferences

5. **Historical Analysis**:
   - Past crises log
   - Response effectiveness
   - Lessons learned
   - Pattern recognition

### 6. Bot Analysis (`/dashboard/social-protection/bot-analysis`)

**Features:**

```typescript
interface BotAnalysisRequest {
  target_type: 'profile' | 'follower_list' | 'engagement_list';
  platform: Platform;
  profile_url?: string;
  account_ids?: string[];
}

interface BotAnalysisResult {
  analysis_id: string;
  target_account: string;
  platform: Platform;
  
  // Bot Detection
  is_likely_bot: boolean;
  bot_probability: number;        // 0-1
  confidence_score: number;
  
  // Bot Indicators
  indicators: {
    account_age: BotIndicator;
    posting_frequency: BotIndicator;
    content_diversity: BotIndicator;
    engagement_patterns: BotIndicator;
    profile_completeness: BotIndicator;
    follower_ratio: BotIndicator;
    automated_behavior: BotIndicator;
  };
  
  // Behavioral Analysis
  behavior: {
    posting_schedule: PostingPattern;
    content_sources: string[];
    interaction_style: string;
    response_time_avg: number;
  };
  
  // Network Analysis
  network: {
    bot_follower_percentage: number;
    suspicious_connections: number;
    coordination_detected: boolean;
  };
  
  // Classification
  bot_type?: 'spam' | 'amplification' | 'impersonation' | 'scraper' | 'benign';
  
  // Recommendations
  risk_assessment: string;
  recommended_actions: string[];
}
```

**UI Components:**

1. **Bot Scanner Input**:
   - Profile URL input
   - Bulk analysis (CSV upload)
   - Platform selector
   - Scan depth options

2. **Bot Probability Gauge**:
   - Large circular indicator (0-100%)
   - Confidence level
   - Bot type label
   - Risk classification

3. **Indicator Breakdown**:
   - Grid of 7 indicator cards
   - Each shows:
     - Indicator name
     - Score/status
     - Visual meter
     - Explanation

4. **Behavioral Patterns**:
   - Activity timeline
   - Posting frequency chart
   - Engagement distribution
   - Response time analysis

5. **Bulk Analysis Results**:
   - Table view with sortable columns
   - Bot probability column
   - Export functionality
   - Filter by bot likelihood

### 7. Social Protection Reports

**Report Types:**

```typescript
type SocialReportType = 
  | 'harmful_content'
  | 'impersonation'
  | 'bot_network'
  | 'coordinated_harassment'
  | 'misinformation'
  | 'spam_campaign'
  | 'crisis_event';

interface SocialProtectionReport {
  report_id: string;
  report_type: SocialReportType;
  platform: Platform;
  
  // Target Information
  reported_profile?: string;
  reported_content_url?: string;
  
  // Report Details
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  evidence: {
    screenshots?: string[];
    content_samples?: string[];
    timeline?: TimelineEvent[];
    related_accounts?: string[];
  };
  
  // Analysis Results
  automated_analysis?: {
    risk_score: number;
    detected_violations: string[];
    confidence: number;
  };
  
  // Status
  status: 'submitted' | 'under_review' | 'verified' | 'resolved' | 'dismissed';
  submitted_at: string;
  reviewed_at?: string;
  resolution?: string;
}
```

### 8. API Integration

#### Social Protection Endpoints:

```typescript
// lib/api/social-protection.ts

export const socialProtectionAPI = {
  // Health Check
  healthCheck: () => 
    api.get('/api/v1/social-protection/health'),
  
  // Profile Scanning
  scanProfile: (data: ProfileScanRequest) => 
    api.post('/api/v1/social-protection/scan/profile', data),
  
  getScanResult: (scanId: string) => 
    api.get(`/api/v1/social-protection/scan/${scanId}`),
  
  getScanHistory: (params: HistoryParams) => 
    api.get('/api/v1/social-protection/scan/history', { params }),
  
  // Content Analysis
  analyzeContent: (data: ContentAnalysisRequest) => 
    api.post('/api/v1/social-protection/content/analyze', data),
  
  getContentAnalysis: (analysisId: string) => 
    api.get(`/api/v1/social-protection/content/${analysisId}`),
  
  // Bot Detection
  analyzeBots: (data: BotAnalysisRequest) => 
    api.post('/api/v1/social-protection/bot/analyze', data),
  
  getBotAnalysis: (analysisId: string) => 
    api.get(`/api/v1/social-protection/bot/${analysisId}`),
  
  // Crisis Detection
  getCrisisAlerts: (params: AlertParams) => 
    api.get('/api/v1/social-protection/crisis/alerts', { params }),
  
  getCrisisAlert: (alertId: string) => 
    api.get(`/api/v1/social-protection/crisis/alerts/${alertId}`),
  
  updateCrisisStatus: (alertId: string, status: string) => 
    api.put(`/api/v1/social-protection/crisis/alerts/${alertId}/status`, { status }),
  
  configureCrisisMonitoring: (config: CrisisDetectionConfig) => 
    api.post('/api/v1/social-protection/crisis/configure', config),
  
  // Reports
  createReport: (data: SocialProtectionReport) => 
    api.post('/api/v1/social-protection/reports', data),
  
  getReports: (params: ReportParams) => 
    api.get('/api/v1/social-protection/reports', { params }),
  
  getReport: (reportId: string) => 
    api.get(`/api/v1/social-protection/reports/${reportId}`),
  
  // Monitoring
  addMonitoredProfile: (data: MonitorProfileRequest) => 
    api.post('/api/v1/social-protection/monitor/profiles', data),
  
  getMonitoredProfiles: () => 
    api.get('/api/v1/social-protection/monitor/profiles'),
  
  removeMonitoredProfile: (profileId: string) => 
    api.delete(`/api/v1/social-protection/monitor/profiles/${profileId}`),
};
```

### 9. Extension Integration Endpoints

**Browser Extension Data Processing:**

```typescript
// Extension endpoints (from docs/api/rate-limiting.md)
export const extensionAPI = {
  // Quick URL Check (anonymous allowed)
  quickCheck: (data: { url: string }) => 
    api.post('/api/v1/extension/url/check', data),
  // Rate limit: 12/minute (free), scales with tier
  
  // Bulk URL Check (JWT required)
  bulkCheck: (data: { urls: string[] }) => 
    api.post('/api/v1/extension/url/bulk-check', data),
  // Rate limit: 6/minute (free), scales with tier
  
  // Content Analysis (JWT required)
  analyzeContent: (data: ContentAnalysisRequest) => 
    api.post('/api/v1/extension/content/analyze', data),
  // Rate limit: 12/minute (free), scales with tier
};
```

### 10. React Hooks for Social Protection

```typescript
// hooks/useSocialProtection.ts
export const useSocialProtection = () => {
  return {
    useProfileScan: () => useMutation({
      mutationFn: socialProtectionAPI.scanProfile,
      onSuccess: (data) => {
        queryClient.invalidateQueries(['profile-scans']);
        toast.success('Profile scan completed');
      },
    }),
    
    useContentAnalysis: () => useMutation({
      mutationFn: socialProtectionAPI.analyzeContent,
    }),
    
    useBotAnalysis: () => useMutation({
      mutationFn: socialProtectionAPI.analyzeBots,
    }),
    
    useCrisisAlerts: (params: AlertParams) => useQuery({
      queryKey: ['crisis-alerts', params],
      queryFn: () => socialProtectionAPI.getCrisisAlerts(params),
      refetchInterval: 30000, // Refresh every 30 seconds
    }),
    
    useScanHistory: (params: HistoryParams) => useQuery({
      queryKey: ['social-scans', params],
      queryFn: () => socialProtectionAPI.getScanHistory(params),
    }),
  };
};
```

### 11. Social Protection Components

**Platform Selector Component:**
```typescript
// components/social-protection/PlatformSelector.tsx
interface PlatformSelectorProps {
  value: Platform;
  onChange: (platform: Platform) => void;
  disabled?: boolean;
}

// Features:
- Icon grid or dropdown
- Platform availability indicators
- Premium platform badges
- Tooltip with platform features
```

**Risk Score Visualization:**
```typescript
// components/social-protection/RiskScoreCard.tsx
interface RiskScoreCardProps {
  score: number;              // 0-100
  level: RiskLevel;
  threats: string[];
  recommendations: string[];
  size?: 'sm' | 'md' | 'lg';
}

// Visual elements:
- Radial progress gauge
- Color gradient (green → yellow → red)
- Threat badges
- Animated transitions
```

**Analyzer Results Grid:**
```typescript
// components/social-protection/AnalyzerResults.tsx
interface AnalyzerResultsProps {
  analyzers: AnalyzerResult[];
  expandable?: boolean;
}

// Features:
- Grid layout (responsive)
- Status indicators (healthy, warning, critical)
- Expand/collapse details
- Export functionality
```

### 12. Navigation Updates

**Main Navigation (add to dashboard):**
```typescript
const navigationItems = [
  // ... existing items
  {
    label: 'Social Protection',
    icon: Shield,
    href: '/dashboard/social-protection',
    badge: 'New',
    children: [
      {
        label: 'Dashboard',
        href: '/dashboard/social-protection',
        icon: LayoutDashboard,
      },
      {
        label: 'Profile Scan',
        href: '/dashboard/social-protection/profile-scan',
        icon: UserCheck,
      },
      {
        label: 'Content Analysis',
        href: '/dashboard/social-protection/content-analysis',
        icon: FileText,
      },
      {
        label: 'Crisis Monitor',
        href: '/dashboard/social-protection/crisis-detection',
        icon: AlertTriangle,
        badge: 'alerts',
      },
      {
        label: 'Bot Detection',
        href: '/dashboard/social-protection/bot-analysis',
        icon: Bot,
      },
      {
        label: 'Reports',
        href: '/dashboard/social-protection/reports',
        icon: Flag,
      },
    ],
  },
];
```

### 13. Subscription Plan Features

**Update subscription limits to include social protection:**

```typescript
interface SubscriptionPlanFeatures {
  // ... existing features
  
  // Social Protection Features
  social_protection: {
    profile_scans_daily: number;
    content_analysis_daily: number;
    bot_analysis_daily: number;
    crisis_monitoring: boolean;
    monitored_profiles_limit: number;
    platforms: Platform[];
    real_time_alerts: boolean;
    historical_data_days: number;
  };
}

// Plan examples:
const planFeatures = {
  free: {
    profile_scans_daily: 5,
    content_analysis_daily: 10,
    bot_analysis_daily: 3,
    crisis_monitoring: false,
    monitored_profiles_limit: 0,
    platforms: ['twitter', 'facebook'],
    real_time_alerts: false,
    historical_data_days: 7,
  },
  basic: {
    profile_scans_daily: 25,
    content_analysis_daily: 50,
    bot_analysis_daily: 15,
    crisis_monitoring: false,
    monitored_profiles_limit: 3,
    platforms: ['twitter', 'facebook', 'instagram', 'linkedin'],
    real_time_alerts: false,
    historical_data_days: 30,
  },
  pro: {
    profile_scans_daily: 100,
    content_analysis_daily: 200,
    bot_analysis_daily: 50,
    crisis_monitoring: true,
    monitored_profiles_limit: 15,
    platforms: ['all'],
    real_time_alerts: true,
    historical_data_days: 90,
  },
  enterprise: {
    profile_scans_daily: -1, // unlimited
    content_analysis_daily: -1,
    bot_analysis_daily: -1,
    crisis_monitoring: true,
    monitored_profiles_limit: -1,
    platforms: ['all'],
    real_time_alerts: true,
    historical_data_days: 365,
  },
};
```

### 14. Health Check Integration

**System Health Monitoring:**
```typescript
// hooks/useSystemHealth.ts
export const useSystemHealth = () => {
  return useQuery({
    queryKey: ['social-protection-health'],
    queryFn: socialProtectionAPI.healthCheck,
    refetchInterval: 60000, // Check every minute
  });
};

// Display in dashboard
// Show status indicators for:
// - Extension data processor
// - Social scan service
// - Database connectivity
// - All 8 analyzers
// - All 7 platform adapters
// - Crisis detection system
```

### 15. Feature Highlights

**Homepage Features Section:**
```typescript
const socialProtectionFeatures = [
  {
    icon: Shield,
    title: 'Multi-Platform Protection',
    description: '7 platforms supported: Twitter, Facebook, Instagram, TikTok, LinkedIn, Telegram, Discord',
    image: '/features/platforms.png',
  },
  {
    icon: Brain,
    title: '8 Advanced Analyzers',
    description: 'Content risk, link penalties, spam detection, community notes, visibility, engagement, penalties, shadow bans',
    image: '/features/analyzers.png',
  },
  {
    icon: AlertTriangle,
    title: 'Crisis Detection',
    description: 'Real-time monitoring and alerts for emerging threats and rapid response',
    image: '/features/crisis.png',
  },
  {
    icon: Bot,
    title: 'Bot Detection',
    description: 'Identify fake accounts, automation, and coordinated inauthentic behavior',
    image: '/features/bots.png',
  },
  {
    icon: Eye,
    title: 'Shadow Ban Detection',
    description: 'Detect content suppression and visibility restrictions across platforms',
    image: '/features/shadowban.png',
  },
  {
    icon: TrendingUp,
    title: 'Engagement Analysis',
    description: 'Measure authentic engagement and identify manipulation',
    image: '/features/engagement.png',
  },
];
```

### 16. Notification System

**Real-time Alerts:**
```typescript
// lib/notifications/social-alerts.ts
export const SocialAlertTypes = {
  CRISIS_DETECTED: 'crisis_detected',
  HIGH_RISK_PROFILE: 'high_risk_profile',
  BOT_ACTIVITY: 'bot_activity',
  SHADOW_BAN_DETECTED: 'shadow_ban_detected',
  HARMFUL_CONTENT: 'harmful_content',
  MONITORING_ALERT: 'monitoring_alert',
};

// WebSocket integration for real-time alerts
// Toast notifications
// Email notifications (based on preferences)
// Browser notifications (with permission)
```

### 17. Data Visualization

**Charts and Graphs:**
```typescript
// Using recharts
import { LineChart, BarChart, PieChart, RadarChart } from 'recharts';

// Visualizations needed:
// 1. Risk score trends over time (line chart)
// 2. Threat distribution by category (pie chart)
// 3. Platform comparison (bar chart)
// 4. Analyzer performance radar (radar chart)
// 5. Engagement patterns (area chart)
// 6. Bot detection confidence (gauge chart)
// 7. Crisis severity timeline (timeline chart)
```

### 18. Export Functionality

**Report Export:**
```typescript
interface ExportOptions {
  format: 'pdf' | 'csv' | 'json' | 'html';
  include_charts: boolean;
  include_evidence: boolean;
  date_range?: { start: string; end: string };
}

// Export features:
// - Profile scan reports
// - Bot analysis reports
// - Crisis summaries
// - Historical data
// - Bulk analysis results
```

## Deliverables

1. **Fully functional Next.js application**
2. **Responsive UI** (mobile, tablet, desktop)
3. **Complete authentication system**
4. **Dashboard with all features** including:
   - URL security checking
   - Social media protection (all 8 analyzers)
   - Crisis detection and monitoring
   - Bot analysis
   - Content analysis
5. **API integration** for all documente
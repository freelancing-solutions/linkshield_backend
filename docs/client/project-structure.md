# Project Structure

## Overview

This document defines the directory structure and file organization for the LinkShield client application. Following these conventions ensures consistency, maintainability, and makes it easy for developers to find and modify code.

## Root Directory

```
linkshield-client/
├── public/                      # Static assets served directly
│   ├── favicon.ico             # Browser favicon
│   ├── logo.svg                # Application logo
│   ├── robots.txt              # Search engine crawler instructions
│   └── manifest.json           # PWA manifest (if applicable)
├── src/                         # Source code
├── docs/                        # Documentation
├── tests/                       # Test files (mirrors src structure)
├── .env.example                 # Environment variables template
├── .eslintrc.json              # ESLint configuration
├── .prettierrc                 # Prettier configuration
├── .gitignore                  # Git ignore rules
├── index.html                  # HTML entry point
├── package.json                # Dependencies and scripts
├── package-lock.json           # Locked dependency versions
├── tsconfig.json               # TypeScript configuration
├── tsconfig.node.json          # TypeScript config for Node scripts
├── vite.config.ts              # Vite build tool configuration
├── tailwind.config.js          # Tailwind CSS configuration
├── postcss.config.js           # PostCSS configuration
├── playwright.config.ts        # Playwright E2E test configuration
├── vitest.config.ts            # Vitest unit test configuration
└── README.md                   # Project documentation
```

## Source Directory Structure

```
src/
├── main.tsx                    # Application entry point
├── App.tsx                     # Root component with router
├── vite-env.d.ts              # Vite type definitions
│
├── pages/                      # Page components (one per route)
│   ├── HomePage.tsx
│   ├── LoginPage.tsx
│   ├── RegisterPage.tsx
│   ├── VerifyEmailPage.tsx
│   ├── ForgotPasswordPage.tsx
│   ├── ResetPasswordPage.tsx
│   ├── DashboardPage.tsx
│   ├── UrlAnalysisPage.tsx
│   ├── CheckDetailPage.tsx
│   ├── AiAnalysisPage.tsx
│   ├── ReportsPage.tsx
│   ├── ReportDetailPage.tsx
│   ├── ApiKeysPage.tsx
│   ├── ProfilePage.tsx
│   ├── SessionsPage.tsx
│   ├── SubscriptionsPage.tsx
│   ├── PrivacyPage.tsx
│   ├── TermsPage.tsx
│   └── NotFoundPage.tsx
│
├── components/                 # Reusable components
│   ├── ui/                     # Base UI components (shadcn/ui)
│   │   ├── button.tsx
│   │   ├── input.tsx
│   │   ├── label.tsx
│   │   ├── form.tsx
│   │   ├── dialog.tsx
│   │   ├── sheet.tsx
│   │   ├── popover.tsx
│   │   ├── dropdown-menu.tsx
│   │   ├── select.tsx
│   │   ├── checkbox.tsx
│   │   ├── radio-group.tsx
│   │   ├── table.tsx
│   │   ├── tabs.tsx
│   │   ├── accordion.tsx
│   │   ├── toast.tsx
│   │   ├── toaster.tsx
│   │   ├── alert.tsx
│   │   ├── badge.tsx
│   │   ├── card.tsx
│   │   ├── separator.tsx
│   │   ├── avatar.tsx
│   │   ├── skeleton.tsx
│   │   └── ...
│   │
│   ├── layout/                 # Layout components
│   │   ├── PageLayout.tsx      # Main page wrapper
│   │   ├── Header.tsx          # Top navigation header
│   │   ├── Sidebar.tsx         # Side navigation
│   │   ├── Footer.tsx          # Page footer
│   │   ├── DashboardLayout.tsx # Dashboard-specific layout
│   │   └── AuthLayout.tsx      # Authentication pages layout
│   │
│   ├── auth/                   # Authentication components
│   │   ├── LoginForm.tsx
│   │   ├── RegisterForm.tsx
│   │   ├── ForgotPasswordForm.tsx
│   │   ├── ResetPasswordForm.tsx
│   │   ├── RequireAuth.tsx     # Protected route wrapper
│   │   └── PasswordStrengthIndicator.tsx
│   │
│   ├── url-analysis/           # URL analysis feature components
│   │   ├── UrlCheckForm.tsx
│   │   ├── UrlHistoryTable.tsx
│   │   ├── UrlHistoryFilters.tsx
│   │   ├── CheckDetailView.tsx
│   │   ├── ProviderResults.tsx
│   │   ├── BrokenLinksTable.tsx
│   │   ├── BulkAnalysisForm.tsx
│   │   ├── ReputationPanel.tsx
│   │   └── StatsCharts.tsx
│   │
│   ├── ai-analysis/            # AI analysis feature components
│   │   ├── AnalysisForm.tsx
│   │   ├── AnalysisResults.tsx
│   │   ├── SimilarContentList.tsx
│   │   ├── AnalysisHistoryTable.tsx
│   │   └── DomainStatsPanel.tsx
│   │
│   ├── reports/                # Community reports components
│   │   ├── ReportForm.tsx
│   │   ├── ReportsTable.tsx
│   │   ├── ReportsFilters.tsx
│   │   ├── ReportDetailView.tsx
│   │   ├── VoteButtons.tsx
│   │   └── ReportTemplateSelector.tsx
│   │
│   ├── dashboard/              # Dashboard components
│   │   ├── DashboardOverview.tsx
│   │   ├── StatCard.tsx
│   │   ├── StatsGrid.tsx
│   │   ├── ProjectsList.tsx
│   │   ├── ProjectCard.tsx
│   │   ├── ProjectDetailView.tsx
│   │   ├── AlertsList.tsx
│   │   ├── AlertCard.tsx
│   │   ├── TeamMembersList.tsx
│   │   └── SocialProtectionPanel.tsx
│   │
│   ├── subscriptions/          # Subscription components
│   │   ├── PlanCard.tsx
│   │   ├── PlanComparison.tsx
│   │   ├── UsagePanel.tsx
│   │   ├── UpgradeDialog.tsx
│   │   └── CancelSubscriptionDialog.tsx
│   │
│   └── shared/                 # Shared utility components
│       ├── LoadingSpinner.tsx
│       ├── LoadingSkeleton.tsx
│       ├── ErrorBoundary.tsx
│       ├── ErrorMessage.tsx
│       ├── EmptyState.tsx
│       ├── ConfirmDialog.tsx
│       ├── ThreatBadge.tsx
│       ├── StatusBadge.tsx
│       ├── DateDisplay.tsx
│       └── CopyToClipboard.tsx
│
├── hooks/                      # Custom React hooks
│   ├── auth/
│   │   ├── useAuth.ts
│   │   ├── useLogin.ts
│   │   ├── useRegister.ts
│   │   ├── useProfile.ts
│   │   └── useSessions.ts
│   ├── url-check/
│   │   ├── useUrlCheck.ts
│   │   ├── useUrlHistory.ts
│   │   ├── useBulkCheck.ts
│   │   └── useReputation.ts
│   ├── ai-analysis/
│   │   ├── useAiAnalysis.ts
│   │   ├── useAnalysisHistory.ts
│   │   └── useDomainStats.ts
│   ├── reports/
│   │   ├── useReports.ts
│   │   ├── useCreateReport.ts
│   │   ├── useVoteReport.ts
│   │   └── useReportTemplates.ts
│   ├── dashboard/
│   │   ├── useDashboardStats.ts
│   │   ├── useProjects.ts
│   │   └── useAlerts.ts
│   ├── subscriptions/
│   │   ├── useSubscription.ts
│   │   ├── usePlans.ts
│   │   └── useUsage.ts
│   └── utils/
│       ├── useDebounce.ts
│       ├── useLocalStorage.ts
│       ├── useMediaQuery.ts
│       ├── useOnClickOutside.ts
│       └── useCopyToClipboard.ts
│
├── services/                   # API client modules
│   ├── api.ts                  # Axios instance configuration
│   ├── auth.service.ts         # Authentication API calls
│   ├── url-check.service.ts    # URL checking API calls
│   ├── ai-analysis.service.ts  # AI analysis API calls
│   ├── reports.service.ts      # Reports API calls
│   ├── dashboard.service.ts    # Dashboard API calls
│   ├── subscriptions.service.ts # Subscriptions API calls
│   ├── api-keys.service.ts     # API keys management
│   └── social-protection.service.ts # Social protection API calls
│
├── stores/                     # Zustand stores
│   ├── authStore.ts            # Authentication state
│   ├── uiStore.ts              # UI preferences (theme, sidebar)
│   └── notificationStore.ts    # Global notifications
│
├── types/                      # TypeScript types and interfaces
│   ├── user.types.ts
│   ├── url-check.types.ts
│   ├── ai-analysis.types.ts
│   ├── reports.types.ts
│   ├── dashboard.types.ts
│   ├── subscriptions.types.ts
│   ├── api.types.ts            # Common API types
│   └── index.ts                # Re-export all types
│
├── utils/                      # Utility functions
│   ├── formatters.ts           # Date, number, string formatting
│   ├── validators.ts           # Validation functions
│   ├── constants.ts            # Application constants
│   ├── errorMessages.ts        # Error message mapping
│   ├── deviceInfo.ts           # Device information detection
│   └── cn.ts                   # Tailwind class name utility
│
├── config/                     # Configuration files
│   ├── env.ts                  # Environment variables with validation
│   ├── routes.ts               # Route path constants
│   └── queryClient.ts          # React Query configuration
│
├── lib/                        # Third-party library configurations
│   └── utils.ts                # shadcn/ui utilities
│
└── styles/                     # Global styles
    ├── globals.css             # Global CSS and Tailwind directives
    └── themes/                 # Theme variables (if applicable)
        ├── light.css
        └── dark.css
```

## File Naming Conventions

### Components

**Format**: PascalCase with `.tsx` extension

```
✅ Good:
- UserCard.tsx
- UrlHistoryTable.tsx
- DashboardOverview.tsx

❌ Bad:
- userCard.tsx
- url-history-table.tsx
- dashboard_overview.tsx
```

### Hooks

**Format**: camelCase with `use` prefix and `.ts` extension

```
✅ Good:
- useAuth.ts
- useUrlHistory.ts
- useDebounce.ts

❌ Bad:
- Auth.ts
- url-history.ts
- UseDebounce.ts
```

### Services

**Format**: camelCase with `.service.ts` suffix

```
✅ Good:
- auth.service.ts
- url-check.service.ts
- ai-analysis.service.ts

❌ Bad:
- authService.ts
- UrlCheckService.ts
- ai_analysis_service.ts
```

### Types

**Format**: camelCase with `.types.ts` suffix

```
✅ Good:
- user.types.ts
- url-check.types.ts
- api.types.ts

❌ Bad:
- userTypes.ts
- UrlCheckTypes.ts
- api_types.ts
```

### Utilities

**Format**: camelCase with `.ts` extension

```
✅ Good:
- formatters.ts
- validators.ts
- constants.ts

❌ Bad:
- Formatters.ts
- Validators.ts
- CONSTANTS.ts
```

### Stores

**Format**: camelCase with `Store` suffix and `.ts` extension

```
✅ Good:
- authStore.ts
- uiStore.ts
- notificationStore.ts

❌ Bad:
- auth-store.ts
- UIStore.ts
- notification_store.ts
```

## Feature-Based Organization

For large features with many related files, use feature folders:

```
src/features/
├── url-analysis/
│   ├── components/
│   │   ├── UrlHistoryTable.tsx
│   │   ├── CheckDetailView.tsx
│   │   ├── BulkAnalysisForm.tsx
│   │   └── index.ts            # Re-export components
│   ├── hooks/
│   │   ├── useUrlCheck.ts
│   │   ├── useUrlHistory.ts
│   │   └── index.ts
│   ├── types/
│   │   └── url-check.types.ts
│   ├── services/
│   │   └── url-check.service.ts
│   ├── pages/
│   │   ├── UrlAnalysisPage.tsx
│   │   └── CheckDetailPage.tsx
│   └── index.ts                # Re-export public API
│
└── dashboard/
    ├── components/
    ├── hooks/
    ├── types/
    ├── services/
    ├── pages/
    └── index.ts
```

**Benefits**:
- Co-location of related code
- Clear feature boundaries
- Easier to find and modify feature code
- Can be extracted into separate packages if needed
- Reduces cognitive load when working on a feature

**When to Use**:
- Feature has 5+ related components
- Feature has its own data models and API calls
- Feature is relatively independent from other features
- Team wants to work on feature in isolation

**When Not to Use**:
- Small features with 1-2 components
- Highly interconnected features
- Shared components used across many features

## Testing Structure

Tests mirror the source structure:

```
tests/
├── unit/                       # Unit tests
│   ├── components/
│   │   ├── auth/
│   │   │   └── LoginForm.test.tsx
│   │   └── shared/
│   │       └── LoadingSpinner.test.tsx
│   ├── hooks/
│   │   └── useDebounce.test.ts
│   └── utils/
│       └── formatters.test.ts
│
├── integration/                # Integration tests
│   ├── auth-flow.test.tsx
│   ├── url-check-flow.test.tsx
│   └── dashboard-flow.test.tsx
│
└── e2e/                        # End-to-end tests (Playwright)
    ├── auth.spec.ts
    ├── url-analysis.spec.ts
    ├── reports.spec.ts
    └── subscriptions.spec.ts
```

**Test File Naming**:
- Unit/Integration: `*.test.tsx` or `*.test.ts`
- E2E: `*.spec.ts`

## Configuration Files

### tsconfig.json

TypeScript configuration with strict mode and path aliases:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"],
      "@/components/*": ["./src/components/*"],
      "@/hooks/*": ["./src/hooks/*"],
      "@/services/*": ["./src/services/*"],
      "@/types/*": ["./src/types/*"],
      "@/utils/*": ["./src/utils/*"],
      "@/stores/*": ["./src/stores/*"]
    }
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

### vite.config.ts

Vite configuration with path aliases:

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@/components': path.resolve(__dirname, './src/components'),
      '@/hooks': path.resolve(__dirname, './src/hooks'),
      '@/services': path.resolve(__dirname, './src/services'),
      '@/types': path.resolve(__dirname, './src/types'),
      '@/utils': path.resolve(__dirname, './src/utils'),
      '@/stores': path.resolve(__dirname, './src/stores'),
    },
  },
});
```

### tailwind.config.js

Tailwind CSS configuration with custom theme:

```javascript
/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: [
    './pages/**/*.{ts,tsx}',
    './components/**/*.{ts,tsx}',
    './app/**/*.{ts,tsx}',
    './src/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        // ... more colors
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
};
```

## Import Organization

Organize imports in this order:

```typescript
// 1. External dependencies
import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';

// 2. Internal absolute imports (using @ alias)
import { Button } from '@/components/ui/button';
import { useAuth } from '@/hooks/auth/useAuth';
import { urlCheckService } from '@/services/url-check.service';
import { UrlCheck } from '@/types/url-check.types';
import { formatDate } from '@/utils/formatters';

// 3. Relative imports
import { UrlHistoryTable } from './UrlHistoryTable';
import { UrlHistoryFilters } from './UrlHistoryFilters';

// 4. Styles (if any)
import './styles.css';
```

## Index Files

Use `index.ts` files to re-export public APIs:

```typescript
// src/components/url-analysis/index.ts
export { UrlCheckForm } from './UrlCheckForm';
export { UrlHistoryTable } from './UrlHistoryTable';
export { CheckDetailView } from './CheckDetailView';
export { BulkAnalysisForm } from './BulkAnalysisForm';

// Usage in other files
import { UrlCheckForm, UrlHistoryTable } from '@/components/url-analysis';
```

## Environment Files

```
.env.example          # Template with all variables (committed)
.env.local            # Local development overrides (not committed)
.env.development      # Development environment (not committed)
.env.production       # Production environment (not committed)
```

**Example .env.example**:
```bash
# API Configuration
VITE_API_BASE_URL=https://www.linkshield.site/api/v1

# Feature Flags
VITE_ENABLE_ANALYTICS=true
VITE_ENABLE_SOCIAL_PROTECTION=true

# Environment
VITE_ENV=development
```

## Summary

Following this project structure ensures:

- **Consistency**: Everyone knows where to find and place files
- **Scalability**: Structure supports growth without reorganization
- **Maintainability**: Related code is co-located and easy to find
- **Clarity**: Clear separation between different types of code
- **Flexibility**: Can use flat or feature-based structure as needed

When in doubt, follow these principles:
1. Co-locate related files
2. Use clear, descriptive names
3. Follow established naming conventions
4. Keep the structure flat until complexity demands nesting
5. Prefer feature folders for large, independent features

---

**Last Updated**: January 2025
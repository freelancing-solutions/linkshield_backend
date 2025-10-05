# Technology Stack

## Overview

This document provides a comprehensive list of all technologies, frameworks, libraries, and tools used in the LinkShield client application. Each technology is documented with its purpose, version, rationale for selection, and links to official documentation.

## Core Framework & Language

### React 18.2+

- **Purpose**: UI library for building component-based user interfaces
- **Why**: Industry standard with excellent ecosystem, modern hooks API, concurrent features, and strong community support
- **Key Features**: 
  - Functional components with hooks
  - Concurrent rendering for better UX
  - Automatic batching for performance
  - Server components support (future)
- **Documentation**: https://react.dev

### TypeScript 5.0+

- **Purpose**: Type-safe JavaScript superset for building robust applications
- **Why**: Catch errors at compile time, better IDE support with IntelliSense, self-documenting code, improved refactoring
- **Configuration**: Strict mode enabled for maximum type safety
- **Key Features**:
  - Static type checking
  - Interface and type definitions
  - Generics for reusable code
  - Enum and union types
- **Documentation**: https://www.typescriptlang.org

## State Management

### Zustand 4.4+

- **Purpose**: Lightweight global UI state management
- **Why**: Simple API with minimal boilerplate, no context providers needed, excellent TypeScript support, small bundle size (~1KB)
- **Use Cases**: 
  - Authentication state (user, token, isAuthenticated)
  - UI preferences (theme, language, sidebar state)
  - Global notifications and toasts
  - Temporary UI state shared across components
- **Key Features**:
  - No providers or wrappers needed
  - Hooks-based API
  - Middleware support (persist, devtools)
  - Minimal re-renders
- **Documentation**: https://github.com/pmndrs/zustand

### TanStack Query (React Query) 5.0+

- **Purpose**: Powerful server state management and data fetching library
- **Why**: Automatic caching, background updates, optimistic updates, request deduplication, built-in loading/error states
- **Use Cases**: 
  - All API data fetching (GET requests)
  - All API mutations (POST, PUT, DELETE)
  - Paginated and infinite queries
  - Real-time data with polling
- **Key Features**:
  - Automatic caching with configurable stale time
  - Background refetching
  - Optimistic updates
  - Query invalidation
  - Infinite queries for pagination
  - Request cancellation
- **Documentation**: https://tanstack.com/query

**State Management Philosophy**: We use two separate solutions for different concerns:
- **Zustand** for client-side UI state that doesn't come from the server
- **React Query** for server state that comes from API calls

This separation provides clear boundaries and optimal performance for each use case.

## Routing

### React Router 6.20+

- **Purpose**: Declarative client-side routing for single-page applications
- **Why**: Industry standard, nested routes support, data loading, lazy loading, excellent TypeScript support
- **Key Features**:
  - Declarative route configuration
  - Nested routes and layouts
  - Route protection and guards
  - URL parameters and query strings
  - Programmatic navigation
  - Lazy loading with code splitting
- **Documentation**: https://reactrouter.com

## Forms & Validation

### React Hook Form 7.48+

- **Purpose**: Performant form state management with minimal re-renders
- **Why**: Excellent performance, easy integration with validation libraries, minimal boilerplate, great TypeScript support
- **Key Features**:
  - Uncontrolled components for performance
  - Built-in validation
  - Easy error handling
  - Field arrays for dynamic forms
  - Integration with UI libraries
- **Documentation**: https://react-hook-form.com

### Zod 3.22+

- **Purpose**: TypeScript-first schema validation library
- **Why**: Type inference from schemas, composable validators, runtime validation, excellent error messages
- **Integration**: Used with React Hook Form via `@hookform/resolvers/zod` for form validation
- **Key Features**:
  - TypeScript type inference
  - Composable schemas
  - Custom error messages
  - Transform and refine methods
  - Parse and safeParse for validation
- **Documentation**: https://zod.dev

**Example Integration**:
```typescript
import { z } from 'zod';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

type LoginFormData = z.infer<typeof loginSchema>;

const { register, handleSubmit } = useForm<LoginFormData>({
  resolver: zodResolver(loginSchema),
});
```

## UI Component Library

### shadcn/ui (Radix UI + Tailwind)

- **Purpose**: Accessible, customizable component primitives built on Radix UI
- **Why**: Copy-paste components (not npm package), full control over code, accessible by default (WCAG AA), excellent TypeScript support
- **Key Components**: 
  - Button, Input, Select, Checkbox, Radio
  - Dialog, Sheet, Popover, Dropdown Menu
  - Form, Label, Error Message
  - Table, Tabs, Accordion
  - Toast, Alert, Badge
  - Card, Separator, Avatar
- **Accessibility**: Built on Radix UI primitives with ARIA attributes and keyboard navigation
- **Documentation**: https://ui.shadcn.com

### Tailwind CSS 3.4+

- **Purpose**: Utility-first CSS framework for rapid UI development
- **Why**: Fast development, consistent design system, small production bundle, excellent IDE support, no CSS naming conflicts
- **Configuration**: Custom theme with LinkShield brand colors, spacing, and typography
- **Key Features**:
  - Utility classes for all CSS properties
  - Responsive design with breakpoint prefixes
  - Dark mode support
  - Custom theme configuration
  - JIT (Just-In-Time) compiler
  - PurgeCSS for production optimization
- **Documentation**: https://tailwindcss.com

**Tailwind Configuration Example**:
```javascript
// tailwind.config.js
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f0f9ff',
          500: '#0ea5e9',
          900: '#0c4a6e',
        },
      },
    },
  },
};
```

## HTTP Client

### Axios 1.6+

- **Purpose**: Promise-based HTTP client for making API requests
- **Why**: Request/response interceptors, automatic JSON parsing, request cancellation, better error handling than fetch
- **Configuration**: 
  - Base URL: `https://www.linkshield.site/api/v1`
  - Request interceptor for auth token injection
  - Response interceptor for error handling
  - Timeout configuration
- **Key Features**:
  - Interceptors for request/response transformation
  - Automatic JSON data transformation
  - Request cancellation with AbortController
  - Progress tracking for uploads
  - XSRF protection
- **Documentation**: https://axios-http.com

**Axios Configuration Example**:
```typescript
import axios from 'axios';

export const apiClient = axios.create({
  baseURL: 'https://www.linkshield.site/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
apiClient.interceptors.request.use((config) => {
  const token = authStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});
```

## Development Tools

### Vite 5.0+

- **Purpose**: Next-generation frontend build tool and dev server
- **Why**: Lightning-fast HMR (Hot Module Replacement), optimized builds, native ESM support, excellent plugin ecosystem
- **Key Features**:
  - Instant server start
  - Lightning-fast HMR
  - Optimized production builds with Rollup
  - TypeScript support out of the box
  - CSS pre-processor support
  - Plugin API for extensibility
- **Documentation**: https://vitejs.dev

### ESLint 8.54+

- **Purpose**: Pluggable JavaScript and TypeScript linter
- **Why**: Catch errors and enforce code quality standards, customizable rules, excellent IDE integration
- **Configuration**: 
  - React plugin for React-specific rules
  - TypeScript plugin for type-aware linting
  - Accessibility plugin (eslint-plugin-jsx-a11y)
  - Import plugin for import/export validation
- **Key Rules**:
  - No unused variables
  - Consistent code style
  - React hooks rules
  - Accessibility checks
- **Documentation**: https://eslint.org

### Prettier 3.1+

- **Purpose**: Opinionated code formatter
- **Why**: Consistent code formatting across team, no debates about style, automatic formatting on save
- **Configuration**: 
  - Single quotes
  - 2-space indentation
  - Trailing commas
  - Line width: 100 characters
- **Integration**: Works with ESLint via `eslint-config-prettier`
- **Documentation**: https://prettier.io

## Testing Framework

### Vitest 1.0+

- **Purpose**: Blazing-fast unit and integration testing framework
- **Why**: Vite-native for consistency, Jest-compatible API, fast execution, excellent TypeScript support
- **Key Features**:
  - Jest-compatible API
  - Native ESM support
  - TypeScript support
  - Watch mode with HMR
  - Coverage reports with c8
  - Snapshot testing
- **Documentation**: https://vitest.dev

### React Testing Library 14.1+

- **Purpose**: Testing library for React components
- **Why**: Tests user behavior not implementation details, encourages accessible components, simple API
- **Key Features**:
  - Query by accessible attributes (role, label, text)
  - User event simulation
  - Async utilities for testing async behavior
  - Custom render with providers
- **Philosophy**: "The more your tests resemble the way your software is used, the more confidence they can give you"
- **Documentation**: https://testing-library.com/react

### Playwright 1.40+

- **Purpose**: End-to-end testing framework
- **Why**: Cross-browser testing (Chromium, Firefox, WebKit), reliable and fast, great debugging tools, auto-wait
- **Key Features**:
  - Cross-browser testing
  - Auto-wait for elements
  - Network interception
  - Screenshots and videos
  - Parallel test execution
  - Trace viewer for debugging
- **Documentation**: https://playwright.dev

**Testing Strategy**:
- **Unit Tests** (Vitest): Test individual functions, hooks, and utilities
- **Integration Tests** (Vitest + React Testing Library): Test component interactions
- **E2E Tests** (Playwright): Test complete user flows

## Additional Libraries

### date-fns 3.0+

- **Purpose**: Modern JavaScript date utility library
- **Why**: Lightweight, immutable, tree-shakeable, comprehensive date manipulation
- **Use Cases**: Date formatting, parsing, comparison, manipulation
- **Documentation**: https://date-fns.org

### react-hot-toast 2.4+

- **Purpose**: Lightweight toast notification library
- **Why**: Simple API, customizable, accessible, small bundle size (~5KB)
- **Use Cases**: Success messages, error notifications, loading states
- **Documentation**: https://react-hot-toast.com

### lucide-react 0.294+

- **Purpose**: Beautiful and consistent icon library
- **Why**: Tree-shakeable, React components, consistent design, large icon set (1000+)
- **Use Cases**: UI icons throughout the application
- **Documentation**: https://lucide.dev

### recharts 2.10+

- **Purpose**: Composable charting library built on React components
- **Why**: React-native API, responsive, customizable, good documentation
- **Use Cases**: Dashboard charts, analytics visualization, usage statistics
- **Documentation**: https://recharts.org

## Development Dependencies

### TypeScript ESLint

- **Package**: `@typescript-eslint/parser` and `@typescript-eslint/eslint-plugin`
- **Purpose**: TypeScript support for ESLint
- **Documentation**: https://typescript-eslint.io

### Vite Plugins

- **@vitejs/plugin-react**: React support for Vite with Fast Refresh
- **vite-tsconfig-paths**: Support for TypeScript path mapping in Vite

### Testing Utilities

- **@testing-library/jest-dom**: Custom matchers for DOM testing
- **@testing-library/user-event**: User interaction simulation
- **@vitest/ui**: UI for Vitest test results

## Version Management

### Node.js

- **Required Version**: 18.0.0 or higher
- **Recommended**: 20.x LTS
- **Why**: Modern JavaScript features, native ESM support, performance improvements

### Package Manager

- **Recommended**: npm 9+ or yarn 1.22+
- **Lock File**: package-lock.json (npm) or yarn.lock (yarn)
- **Why**: Consistent dependency resolution across environments

## Environment Variables

The application uses environment variables for configuration:

```bash
# API Configuration
VITE_API_BASE_URL=https://www.linkshield.site/api/v1

# Feature Flags
VITE_ENABLE_ANALYTICS=true
VITE_ENABLE_SOCIAL_PROTECTION=true

# Environment
VITE_ENV=development
```

**Note**: Vite requires environment variables to be prefixed with `VITE_` to be exposed to the client.

## Browser Support

- **Modern Browsers**: Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- **Mobile**: iOS Safari 14+, Chrome Android 90+
- **No IE11 Support**: Modern JavaScript features and ESM modules

## Bundle Size Targets

- **Initial Bundle**: < 200KB gzipped
- **Route Chunks**: < 50KB gzipped each
- **Vendor Chunk**: < 150KB gzipped

## Performance Targets

- **First Contentful Paint (FCP)**: < 1.5s
- **Largest Contentful Paint (LCP)**: < 2.5s
- **Time to Interactive (TTI)**: < 3.5s
- **Cumulative Layout Shift (CLS)**: < 0.1

---

**Last Updated**: January 2025

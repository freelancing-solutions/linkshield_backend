# Routing and Navigation

## Overview

The LinkShield client uses React Router v6+ for client-side routing and navigation. This document explains how to implement routes, protect authenticated pages, and handle navigation patterns.

## React Router Setup

### Router Configuration

```typescript
// src/main.tsx
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import { routes } from './config/routes';

const router = createBrowserRouter(routes);

root.render(
  <QueryClientProvider client={queryClient}>
    <RouterProvider router={router} />
  </QueryClientProvider>
);
```

### Route Definitions

```typescript
// src/config/routes.tsx
import { lazy, Suspense } from 'react';
import { RouteObject } from 'react-router-dom';
import { RootLayout } from '@/components/layout/RootLayout';
import { RequireAuth } from '@/components/auth/RequireAuth';
import { LoadingSpinner } from '@/components/shared/LoadingSpinner';

// Lazy load pages for code splitting
const HomePage = lazy(() => import('@/pages/HomePage'));
const LoginPage = lazy(() => import('@/pages/LoginPage'));
const RegisterPage = lazy(() => import('@/pages/RegisterPage'));
const DashboardPage = lazy(() => import('@/pages/DashboardPage'));
const UrlAnalysisPage = lazy(() => import('@/pages/UrlAnalysisPage'));
const NotFoundPage = lazy(() => import('@/pages/NotFoundPage'));

// Wrapper for lazy-loaded components
const LazyPage = ({ children }: { children: React.ReactNode }) => (
  <Suspense fallback={<LoadingSpinner />}>
    {children}
  </Suspense>
);

export const routes: RouteObject[] = [
  {
    path: '/',
    element: <RootLayout />,
    errorElement: <NotFoundPage />,
    children: [
      // Public Routes
      {
        index: true,
        element: <LazyPage><HomePage /></LazyPage>,
      },
      {
        path: 'login',
        element: <LazyPage><LoginPage /></LazyPage>,
      },
      {
        path: 'register',
        element: <LazyPage><RegisterPage /></LazyPage>,
      },
      {
        path: 'verify-email/:token',
        element: <LazyPage><VerifyEmailPage /></LazyPage>,
      },
      {
        path: 'forgot-password',
        element: <LazyPage><ForgotPasswordPage /></LazyPage>,
      },
      {
        path: 'reset-password/:token',
        element: <LazyPage><ResetPasswordPage /></LazyPage>,
      },
      {
        path: 'privacy',
        element: <LazyPage><PrivacyPage /></LazyPage>,
      },
      {
        path: 'terms',
        element: <LazyPage><TermsPage /></LazyPage>,
      },
      
      // Protected Routes
      {
        path: 'dashboard',
        element: (
          <RequireAuth>
            <LazyPage><DashboardPage /></LazyPage>
          </RequireAuth>
        ),
      },
      {
        path: 'url-analysis',
        element: (
          <RequireAuth>
            <LazyPage><UrlAnalysisPage /></LazyPage>
          </RequireAuth>
        ),
      },
      {
        path: 'url-analysis/:checkId',
        element: (
          <RequireAuth>
            <LazyPage><CheckDetailPage /></LazyPage>
          </RequireAuth>
        ),
      },
      {
        path: 'ai-analysis',
        element: (
          <RequireAuth>
            <LazyPage><AiAnalysisPage /></LazyPage>
          </RequireAuth>
        ),
      },
      {
        path: 'reports',
        element: (
          <RequireAuth>
            <LazyPage><ReportsPage /></LazyPage>
          </RequireAuth>
        ),
      },
      {
        path: 'reports/:reportId',
        element: (
          <RequireAuth>
            <LazyPage><ReportDetailPage /></LazyPage>
          </RequireAuth>
        ),
      },
      {
        path: 'api-keys',
        element: (
          <RequireAuth>
            <LazyPage><ApiKeysPage /></LazyPage>
          </RequireAuth>
        ),
      },
      {
        path: 'profile',
        element: (
          <RequireAuth>
            <LazyPage><ProfilePage /></LazyPage>
          </RequireAuth>
        ),
      },
      {
        path: 'sessions',
        element: (
          <RequireAuth>
            <LazyPage><SessionsPage /></LazyPage>
          </RequireAuth>
        ),
      },
      {
        path: 'subscriptions',
        element: (
          <RequireAuth>
            <LazyPage><SubscriptionsPage /></LazyPage>
          </RequireAuth>
        ),
      },
      
      // 404 Catch-all
      {
        path: '*',
        element: <NotFoundPage />,
      },
    ],
  },
];
```

## Route Structure

### Public Routes

Routes accessible without authentication:

| Path | Component | Description |
|------|-----------|-------------|
| `/` | HomePage | Homepage with URL checker |
| `/login` | LoginPage | User login |
| `/register` | RegisterPage | User registration |
| `/verify-email/:token` | VerifyEmailPage | Email verification |
| `/forgot-password` | ForgotPasswordPage | Password reset request |
| `/reset-password/:token` | ResetPasswordPage | Password reset with token |
| `/privacy` | PrivacyPage | Privacy policy |
| `/terms` | TermsPage | Terms of service |

### Protected Routes

Routes requiring authentication:

| Path | Component | Description |
|------|-----------|-------------|
| `/dashboard` | DashboardPage | User dashboard |
| `/url-analysis` | UrlAnalysisPage | URL checking history |
| `/url-analysis/:checkId` | CheckDetailPage | URL check details |
| `/ai-analysis` | AiAnalysisPage | AI content analysis |
| `/reports` | ReportsPage | Community reports |
| `/reports/:reportId` | ReportDetailPage | Report details |
| `/api-keys` | ApiKeysPage | API key management |
| `/profile` | ProfilePage | User profile |
| `/sessions` | SessionsPage | Active sessions |
| `/subscriptions` | SubscriptionsPage | Subscription management |

## Route Protection

### RequireAuth Component

Protect routes by wrapping them with RequireAuth:

```typescript
// src/components/auth/RequireAuth.tsx
import { Navigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '@/stores/authStore';
import { LoadingSpinner } from '@/components/shared/LoadingSpinner';

interface RequireAuthProps {
  children: React.ReactNode;
  redirectTo?: string;
}

export const RequireAuth: React.FC<RequireAuthProps> = ({ 
  children, 
  redirectTo = '/login' 
}) => {
  const { isAuthenticated, isLoading } = useAuthStore();
  const location = useLocation();
  
  // Show loading while checking authentication
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <LoadingSpinner />
      </div>
    );
  }
  
  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    // Save the location they were trying to access
    return <Navigate to={redirectTo} state={{ from: location }} replace />;
  }
  
  // Render children if authenticated
  return <>{children}</>;
};
```

### Redirect After Login

Redirect users to their intended destination after login:

```typescript
// src/pages/LoginPage.tsx
import { useNavigate, useLocation } from 'react-router-dom';

export const LoginPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const login = useLogin();
  
  const handleLogin = async (data: LoginFormData) => {
    try {
      await login.mutateAsync(data);
      
      // Get the page they were trying to access
      const from = location.state?.from?.pathname || '/dashboard';
      navigate(from, { replace: true });
    } catch (error) {
      // Error handled by mutation
    }
  };
  
  return <LoginForm onSubmit={handleLogin} />;
};
```

**Important**: Route protection is a UX feature, not a security measure. The backend enforces actual access control.

## Navigation Patterns

### Programmatic Navigation

Use `useNavigate` hook for programmatic navigation:

```typescript
import { useNavigate } from 'react-router-dom';

const MyComponent = () => {
  const navigate = useNavigate();
  
  // Navigate to a route
  const handleClick = () => {
    navigate('/dashboard');
  };
  
  // Navigate with state
  const handleNavigateWithState = () => {
    navigate('/url-analysis', { 
      state: { fromHome: true } 
    });
  };
  
  // Navigate back
  const handleBack = () => {
    navigate(-1);
  };
  
  // Navigate forward
  const handleForward = () => {
    navigate(1);
  };
  
  // Replace current entry
  const handleReplace = () => {
    navigate('/dashboard', { replace: true });
  };
  
  return (
    <div>
      <button onClick={handleClick}>Go to Dashboard</button>
      <button onClick={handleBack}>Go Back</button>
    </div>
  );
};
```

### Declarative Navigation

Use `Link` component for declarative navigation:

```typescript
import { Link } from 'react-router-dom';

const Navigation = () => {
  return (
    <nav>
      <Link to="/">Home</Link>
      <Link to="/dashboard">Dashboard</Link>
      <Link to="/url-analysis">URL Analysis</Link>
      
      {/* Link with state */}
      <Link to="/reports" state={{ filter: 'recent' }}>
        Reports
      </Link>
      
      {/* Replace history entry */}
      <Link to="/login" replace>
        Login
      </Link>
      
      {/* External link */}
      <a href="https://docs.linkshield.site" target="_blank" rel="noopener noreferrer">
        Documentation
      </a>
    </nav>
  );
};
```

### NavLink for Active Styling

Use `NavLink` for navigation with active state:

```typescript
import { NavLink } from 'react-router-dom';

const Sidebar = () => {
  return (
    <nav>
      <NavLink
        to="/dashboard"
        className={({ isActive }) =>
          isActive ? 'nav-link active' : 'nav-link'
        }
      >
        Dashboard
      </NavLink>
      
      <NavLink
        to="/url-analysis"
        className={({ isActive }) =>
          `nav-link ${isActive ? 'active' : ''}`
        }
      >
        URL Analysis
      </NavLink>
      
      {/* With custom styling */}
      <NavLink
        to="/reports"
        style={({ isActive }) => ({
          color: isActive ? '#0ea5e9' : '#64748b',
          fontWeight: isActive ? 'bold' : 'normal',
        })}
      >
        Reports
      </NavLink>
    </nav>
  );
};
```

## Route Parameters

### URL Parameters

Access URL parameters with `useParams`:

```typescript
import { useParams } from 'react-router-dom';

const CheckDetailPage = () => {
  const { checkId } = useParams<{ checkId: string }>();
  const { data, isLoading } = useUrlCheckDetail(checkId!);
  
  if (isLoading) return <LoadingSkeleton />;
  
  return (
    <div>
      <h1>Check Details</h1>
      <CheckDetailView check={data} />
    </div>
  );
};
```

### Query Parameters

Access and manage query parameters with `useSearchParams`:

```typescript
import { useSearchParams } from 'react-router-dom';

const UrlAnalysisPage = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  
  // Get query parameter
  const page = searchParams.get('page') || '1';
  const filter = searchParams.get('filter') || 'all';
  
  // Set query parameter
  const handlePageChange = (newPage: number) => {
    setSearchParams({ page: newPage.toString(), filter });
  };
  
  const handleFilterChange = (newFilter: string) => {
    setSearchParams({ page: '1', filter: newFilter });
  };
  
  // Get all parameters as object
  const params = Object.fromEntries(searchParams.entries());
  
  return (
    <div>
      <UrlHistoryFilters 
        filter={filter} 
        onFilterChange={handleFilterChange} 
      />
      <UrlHistoryTable page={parseInt(page)} />
      <Pagination 
        currentPage={parseInt(page)} 
        onPageChange={handlePageChange} 
      />
    </div>
  );
};
```

### Reading Location State

Access state passed via navigation:

```typescript
import { useLocation } from 'react-router-dom';

const UrlAnalysisPage = () => {
  const location = useLocation();
  const fromHome = location.state?.fromHome;
  
  return (
    <div>
      {fromHome && (
        <Alert>Welcome! Here's your URL analysis history.</Alert>
      )}
      <UrlHistoryTable />
    </div>
  );
};
```

## Nested Routes and Layouts

### Nested Route Structure

```typescript
// Dashboard with nested routes
{
  path: 'dashboard',
  element: (
    <RequireAuth>
      <DashboardLayout />
    </RequireAuth>
  ),
  children: [
    {
      index: true,
      element: <DashboardOverview />,
    },
    {
      path: 'projects',
      element: <ProjectsPage />,
    },
    {
      path: 'projects/:projectId',
      element: <ProjectDetailPage />,
      children: [
        {
          index: true,
          element: <ProjectOverview />,
        },
        {
          path: 'team',
          element: <ProjectTeam />,
        },
        {
          path: 'alerts',
          element: <ProjectAlerts />,
        },
        {
          path: 'settings',
          element: <ProjectSettings />,
        },
      ],
    },
  ],
}
```

### Layout Component with Outlet

```typescript
// src/components/layout/DashboardLayout.tsx
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';

export const DashboardLayout = () => {
  return (
    <div className="dashboard-layout">
      <Header />
      <div className="dashboard-content">
        <Sidebar />
        <main className="dashboard-main">
          {/* Child routes render here */}
          <Outlet />
        </main>
      </div>
    </div>
  );
};
```

## Code Splitting and Lazy Loading

### Lazy Load Routes

```typescript
import { lazy, Suspense } from 'react';

// Lazy load page components
const DashboardPage = lazy(() => import('@/pages/DashboardPage'));
const UrlAnalysisPage = lazy(() => import('@/pages/UrlAnalysisPage'));

// Use with Suspense
<Suspense fallback={<LoadingSpinner />}>
  <DashboardPage />
</Suspense>
```

### Route-Based Code Splitting

```typescript
// Each route gets its own chunk
const routes = [
  {
    path: '/dashboard',
    element: (
      <Suspense fallback={<LoadingSpinner />}>
        <DashboardPage />
      </Suspense>
    ),
  },
  {
    path: '/url-analysis',
    element: (
      <Suspense fallback={<LoadingSpinner />}>
        <UrlAnalysisPage />
      </Suspense>
    ),
  },
];
```

### Loading Component

```typescript
// src/components/shared/LoadingSpinner.tsx
export const LoadingSpinner = () => {
  return (
    <div className="flex items-center justify-center min-h-[400px]">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
    </div>
  );
};
```

## Breadcrumbs

### Breadcrumb Component

```typescript
// src/components/shared/Breadcrumbs.tsx
import { Link, useLocation } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';

export const Breadcrumbs = () => {
  const location = useLocation();
  
  const pathnames = location.pathname.split('/').filter((x) => x);
  
  return (
    <nav className="flex items-center space-x-2 text-sm">
      <Link to="/" className="text-gray-600 hover:text-gray-900">
        Home
      </Link>
      
      {pathnames.map((name, index) => {
        const routeTo = `/${pathnames.slice(0, index + 1).join('/')}`;
        const isLast = index === pathnames.length - 1;
        
        return (
          <div key={name} className="flex items-center space-x-2">
            <ChevronRight className="h-4 w-4 text-gray-400" />
            {isLast ? (
              <span className="text-gray-900 font-medium">
                {formatBreadcrumb(name)}
              </span>
            ) : (
              <Link to={routeTo} className="text-gray-600 hover:text-gray-900">
                {formatBreadcrumb(name)}
              </Link>
            )}
          </div>
        );
      })}
    </nav>
  );
};

function formatBreadcrumb(str: string): string {
  return str
    .split('-')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}
```

## Error Handling

### Error Boundary for Routes

```typescript
// src/pages/NotFoundPage.tsx
import { Link } from 'react-router-dom';

export const NotFoundPage = () => {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen">
      <h1 className="text-6xl font-bold text-gray-900">404</h1>
      <p className="text-xl text-gray-600 mt-4">Page not found</p>
      <Link to="/" className="mt-8 btn btn-primary">
        Go Home
      </Link>
    </div>
  );
};
```

### Route Error Element

```typescript
// In route configuration
{
  path: '/',
  element: <RootLayout />,
  errorElement: <ErrorPage />,
  children: [
    // ... routes
  ],
}

// src/pages/ErrorPage.tsx
import { useRouteError, Link } from 'react-router-dom';

export const ErrorPage = () => {
  const error = useRouteError() as any;
  
  return (
    <div className="flex flex-col items-center justify-center min-h-screen">
      <h1 className="text-4xl font-bold text-gray-900">Oops!</h1>
      <p className="text-xl text-gray-600 mt-4">
        Sorry, an unexpected error has occurred.
      </p>
      <p className="text-gray-500 mt-2">
        {error?.statusText || error?.message}
      </p>
      <Link to="/" className="mt-8 btn btn-primary">
        Go Home
      </Link>
    </div>
  );
};
```

## Route Constants

Define route paths as constants:

```typescript
// src/config/routes.ts
export const ROUTES = {
  HOME: '/',
  LOGIN: '/login',
  REGISTER: '/register',
  VERIFY_EMAIL: '/verify-email/:token',
  FORGOT_PASSWORD: '/forgot-password',
  RESET_PASSWORD: '/reset-password/:token',
  
  DASHBOARD: '/dashboard',
  URL_ANALYSIS: '/url-analysis',
  URL_CHECK_DETAIL: '/url-analysis/:checkId',
  AI_ANALYSIS: '/ai-analysis',
  REPORTS: '/reports',
  REPORT_DETAIL: '/reports/:reportId',
  API_KEYS: '/api-keys',
  PROFILE: '/profile',
  SESSIONS: '/sessions',
  SUBSCRIPTIONS: '/subscriptions',
  
  PRIVACY: '/privacy',
  TERMS: '/terms',
} as const;

// Helper to build paths with parameters
export const buildPath = (path: string, params: Record<string, string>) => {
  return Object.entries(params).reduce(
    (acc, [key, value]) => acc.replace(`:${key}`, value),
    path
  );
};

// Usage
navigate(buildPath(ROUTES.URL_CHECK_DETAIL, { checkId: '123' }));
// Result: '/url-analysis/123'
```

## Best Practices

### Do's ✅

1. **Use lazy loading**: Split code by routes for better performance
2. **Protect routes**: Wrap authenticated routes with RequireAuth
3. **Use constants**: Define route paths as constants
4. **Handle loading**: Show loading states during navigation
5. **Handle errors**: Implement error boundaries and 404 pages
6. **Use NavLink**: For navigation with active state styling
7. **Preserve state**: Use location state for temporary data
8. **Use query params**: For filters, pagination, and shareable URLs
9. **Implement breadcrumbs**: Help users understand their location
10. **Test routes**: Ensure all routes work correctly

### Don'ts ❌

1. **Don't rely on route protection for security**: Backend enforces access control
2. **Don't use window.location**: Use navigate() instead
3. **Don't forget Suspense**: Always wrap lazy components
4. **Don't hardcode paths**: Use route constants
5. **Don't forget replace**: Use replace for redirects
6. **Don't overuse state**: Use query params for shareable data
7. **Don't nest too deeply**: Keep route hierarchy reasonable
8. **Don't forget accessibility**: Ensure keyboard navigation works

## Summary

React Router v6+ provides:

- **Declarative routing**: Define routes as configuration
- **Nested routes**: Build complex layouts with Outlet
- **Code splitting**: Lazy load routes for performance
- **Type safety**: Full TypeScript support
- **Flexible navigation**: Programmatic and declarative
- **Route protection**: Easy authentication guards
- **Error handling**: Built-in error boundaries

**Key Patterns**:
- Use RequireAuth for protected routes
- Lazy load pages with Suspense
- Use query params for filters and pagination
- Define route constants for maintainability
- Implement proper loading and error states

---

**Last Updated**: January 2025
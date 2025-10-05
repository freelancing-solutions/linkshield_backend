# Security Best Practices

## Overview

This document outlines security best practices for client-side development in the LinkShield application. **Important**: The client is a presentation layer only. All security enforcement happens on the backend. Client-side security measures are for user experience, not actual security.

## Core Security Principle

### Backend Enforces Security, Client Provides UX

```
┌─────────────────────────────────────────┐
│           CLIENT (Browser)              │
│  ┌───────────────────────────────────┐  │
│  │  Client-Side "Security"           │  │
│  │  • Input validation (UX only)     │  │
│  │  • Route protection (UX only)     │  │
│  │  • Token storage (convenience)    │  │
│  │  • Form validation (UX only)      │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
                    ↓
         HTTPS (Encrypted Transport)
                    ↓
┌─────────────────────────────────────────┐
│         BACKEND (Server)                │
│  ┌───────────────────────────────────┐  │
│  │  Real Security Enforcement        │  │
│  │  • Authentication                 │  │
│  │  • Authorization                  │  │
│  │  • Data validation                │  │
│  │  • Rate limiting                  │  │
│  │  • Input sanitization             │  │
│  │  • SQL injection prevention       │  │
│  │  • XSS prevention                 │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**Key Points**:
- Users can bypass any client-side check
- Never trust client-side validation for security
- Route protection is UX, not security
- Backend must validate and authorize every request

## Token Storage

### JWT Token Storage Strategy

**Current Approach**: Store tokens in memory (Zustand store)

```typescript
// src/stores/authStore.ts
export const useAuthStore = create<AuthStore>((set) => ({
  token: null, // Stored in memory only
  user: null,
  isAuthenticated: false,
  
  setToken: (token) => set({ token }),
  clearAuth: () => set({ token: null, user: null, isAuthenticated: false }),
}));
```

**Pros**:
- ✅ Not accessible to JavaScript from other domains
- ✅ Cleared when tab/window closes
- ✅ No XSS risk from localStorage

**Cons**:
- ❌ Lost on page refresh (user must log in again)
- ❌ Not shared across tabs

### Alternative: localStorage

```typescript
// Store token in localStorage (less secure but more convenient)
const setToken = (token: string) => {
  localStorage.setItem('auth_token', token);
  set({ token });
};

const getToken = () => {
  return localStorage.getItem('auth_token');
};

const clearToken = () => {
  localStorage.removeItem('auth_token');
  set({ token: null });
};
```

**Pros**:
- ✅ Persists across page refreshes
- ✅ Shared across tabs

**Cons**:
- ❌ Vulnerable to XSS attacks
- ❌ Accessible to any JavaScript on the page

### Best Practice: httpOnly Cookies (Backend Implementation)

The most secure approach requires backend support:

```typescript
// Backend sets httpOnly cookie
res.cookie('auth_token', token, {
  httpOnly: true,  // Not accessible to JavaScript
  secure: true,    // Only sent over HTTPS
  sameSite: 'strict', // CSRF protection
  maxAge: 3600000, // 1 hour
});

// Client doesn't need to handle token
// Browser automatically sends cookie with requests
```

**Pros**:
- ✅ Not accessible to JavaScript (XSS protection)
- ✅ Automatic CSRF protection with sameSite
- ✅ Persists across page refreshes

**Cons**:
- ❌ Requires backend implementation
- ❌ More complex CORS setup

### Recommendation

For LinkShield:
1. **Development**: Memory storage (current approach)
2. **Production**: Request backend team to implement httpOnly cookies
3. **Interim**: localStorage with XSS prevention measures

## XSS Prevention

### React's Built-in Protection

React automatically escapes values in JSX:

```typescript
// ✅ Safe - React escapes the content
const UserProfile = ({ user }: { user: User }) => {
  return (
    <div>
      <h1>{user.name}</h1>
      <p>{user.bio}</p>
    </div>
  );
};

// Even if user.name contains <script>alert('xss')</script>
// React will render it as text, not execute it
```

### Dangerous HTML Rendering

Only use `dangerouslySetInnerHTML` when absolutely necessary:

```typescript
// ❌ Dangerous - Never do this with user input
const DangerousComponent = ({ html }: { html: string }) => {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
};

// ✅ Safe - Sanitize first with DOMPurify
import DOMPurify from 'dompurify';

const SafeHtmlComponent = ({ html }: { html: string }) => {
  const sanitizedHtml = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
    ALLOWED_ATTR: ['href'],
  });
  
  return <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />;
};
```

### URL Sanitization

Validate URLs before using them:

```typescript
// src/utils/validators.ts
export const isValidUrl = (url: string): boolean => {
  try {
    const parsed = new URL(url);
    // Only allow http and https protocols
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
};

// Usage
const ExternalLink = ({ url, children }: { url: string; children: React.ReactNode }) => {
  if (!isValidUrl(url)) {
    return <span>{children}</span>;
  }
  
  return (
    <a 
      href={url} 
      target="_blank" 
      rel="noopener noreferrer" // Prevent window.opener access
    >
      {children}
    </a>
  );
};
```

## CSRF Protection

### JWT-Based Authentication

JWT tokens in Authorization header don't require CSRF protection:

```typescript
// CSRF not needed because:
// 1. Token is in Authorization header, not cookie
// 2. Browser doesn't automatically send Authorization header
// 3. Attacker can't access token from different origin

apiClient.interceptors.request.use((config) => {
  const token = authStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});
```

### Cookie-Based Authentication

If using cookies, implement CSRF protection:

```typescript
// Backend sends CSRF token in response
// Client includes it in subsequent requests

apiClient.interceptors.request.use((config) => {
  const csrfToken = getCsrfToken(); // From meta tag or cookie
  if (csrfToken) {
    config.headers['X-CSRF-Token'] = csrfToken;
  }
  return config;
});
```

## Input Validation

### Client-Side Validation (UX Only)

```typescript
// ✅ Good for UX - Immediate feedback
const validateEmail = (email: string): string | undefined => {
  if (!email) return 'Email is required';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return 'Invalid email format';
  }
  return undefined;
};

// ❌ Don't rely on this for security
// Backend MUST validate again
```

### Zod Schema Validation

```typescript
import { z } from 'zod';

// Client-side schema
const userSchema = z.object({
  email: z.string().email('Invalid email'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  full_name: z.string().min(2, 'Name must be at least 2 characters'),
});

// Backend MUST have identical or stricter validation
```

**Remember**: Client-side validation is for UX. Backend validation is for security.

## Sensitive Data Handling

### Never Log Sensitive Information

```typescript
// ❌ Bad - Logs password
console.log('Login attempt:', { email, password });

// ✅ Good - Omits password
console.log('Login attempt:', { email });

// ❌ Bad - Logs full user object (may contain sensitive data)
console.log('User data:', user);

// ✅ Good - Logs only necessary fields
console.log('User logged in:', { id: user.id, email: user.email });
```

### Redact Sensitive Data in Error Tracking

```typescript
// Configure error tracking to redact sensitive fields
Sentry.init({
  beforeSend(event) {
    // Remove sensitive data
    if (event.request) {
      delete event.request.cookies;
      delete event.request.headers?.Authorization;
    }
    return event;
  },
});
```

### API Keys Display

```typescript
// ✅ Show API key only once on creation
const ApiKeyCreated = ({ apiKey }: { apiKey: string }) => {
  const [copied, setCopied] = useState(false);
  
  return (
    <div className="api-key-display">
      <Alert variant="warning">
        Save this API key now. You won't be able to see it again.
      </Alert>
      <div className="api-key-value">
        <code>{apiKey}</code>
        <button onClick={() => {
          navigator.clipboard.writeText(apiKey);
          setCopied(true);
        }}>
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
    </div>
  );
};

// ✅ Mask API keys in lists
const ApiKeysList = ({ keys }: { keys: ApiKey[] }) => {
  return (
    <table>
      <tbody>
        {keys.map((key) => (
          <tr key={key.id}>
            <td>{key.name}</td>
            <td>
              <code>sk_...{key.last_4_chars}</code>
            </td>
            <td>{formatDate(key.created_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};
```

## Environment Variables

### Never Expose Secrets

```bash
# ❌ Bad - Secret keys in client
VITE_API_SECRET_KEY=super_secret_key_123
VITE_DATABASE_PASSWORD=password123

# ✅ Good - Only public configuration
VITE_API_BASE_URL=https://www.linkshield.site/api/v1
VITE_ENABLE_ANALYTICS=true
VITE_ENV=production
```

**Rule**: If it starts with `VITE_`, it's exposed to the client. Never put secrets there.

### Environment Variable Validation

```typescript
// src/config/env.ts
import { z } from 'zod';

const envSchema = z.object({
  VITE_API_BASE_URL: z.string().url(),
  VITE_ENV: z.enum(['development', 'staging', 'production']),
  VITE_ENABLE_ANALYTICS: z.string().transform((val) => val === 'true'),
});

export const env = envSchema.parse({
  VITE_API_BASE_URL: import.meta.env.VITE_API_BASE_URL,
  VITE_ENV: import.meta.env.VITE_ENV,
  VITE_ENABLE_ANALYTICS: import.meta.env.VITE_ENABLE_ANALYTICS,
});

// Usage
const apiClient = axios.create({
  baseURL: env.VITE_API_BASE_URL,
});
```

## Authentication State

### Token Expiration Handling

```typescript
// src/services/api.ts
apiClient.interceptors.response.use(
  (response) => response.data,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      authStore.getState().clearAuth();
      
      // Redirect to login
      window.location.href = '/login';
      
      toast.error('Session expired. Please log in again.');
    }
    return Promise.reject(error);
  }
);
```

### Automatic Logout on Inactivity

```typescript
// src/hooks/useInactivityLogout.ts
import { useEffect, useRef } from 'react';
import { useAuthStore } from '@/stores/authStore';

export const useInactivityLogout = (timeoutMinutes = 30) => {
  const { isAuthenticated, clearAuth } = useAuthStore();
  const timeoutRef = useRef<NodeJS.Timeout>();
  
  useEffect(() => {
    if (!isAuthenticated) return;
    
    const resetTimeout = () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      
      timeoutRef.current = setTimeout(() => {
        clearAuth();
        window.location.href = '/login?reason=inactivity';
      }, timeoutMinutes * 60 * 1000);
    };
    
    // Reset timeout on user activity
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    events.forEach((event) => {
      document.addEventListener(event, resetTimeout);
    });
    
    resetTimeout();
    
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
      events.forEach((event) => {
        document.removeEventListener(event, resetTimeout);
      });
    };
  }, [isAuthenticated, clearAuth, timeoutMinutes]);
};

// Usage in App.tsx
const App = () => {
  useInactivityLogout(30); // 30 minutes
  return <RouterProvider router={router} />;
};
```

## Route Protection

### Client-Side Route Guards (UX Only)

```typescript
// src/components/auth/RequireAuth.tsx
export const RequireAuth = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated } = useAuthStore();
  const location = useLocation();
  
  if (!isAuthenticated) {
    // Redirect to login - UX only, not security
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  
  return <>{children}</>;
};
```

**Important**: This is UX, not security. Users can:
- Modify JavaScript to bypass this check
- Call API endpoints directly
- Use browser dev tools to access protected routes

**Backend must enforce authorization on every API request.**

## Dependency Security

### Regular Security Audits

```bash
# Check for known vulnerabilities
npm audit

# Fix vulnerabilities automatically
npm audit fix

# Check for outdated packages
npm outdated

# Update packages
npm update
```

### Automated Security Scanning

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm ci
      - run: npm audit
      - run: npm run lint
```

### Dependency Review

Before adding new dependencies:
1. Check npm package reputation
2. Review package size
3. Check last update date
4. Review open issues
5. Check number of maintainers
6. Scan for known vulnerabilities

## Content Security Policy

### CSP Headers (Backend Configuration)

```typescript
// Backend should set CSP headers
// Client can't set these, but should be aware

// Example CSP header
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' 'unsafe-inline' 'unsafe-eval';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self' data:;
  connect-src 'self' https://www.linkshield.site;
  frame-ancestors 'none';
```

## HTTPS Only

### Enforce HTTPS

```typescript
// Redirect HTTP to HTTPS (in production)
if (import.meta.env.PROD && window.location.protocol === 'http:') {
  window.location.href = window.location.href.replace('http:', 'https:');
}
```

### Secure External Links

```typescript
// Always use rel="noopener noreferrer" for external links
<a 
  href="https://external-site.com" 
  target="_blank"
  rel="noopener noreferrer" // Prevents window.opener access
>
  External Link
</a>
```

## Security Checklist

### Development

- [ ] Never commit secrets to git
- [ ] Use environment variables for configuration
- [ ] Validate environment variables on startup
- [ ] Never log sensitive information
- [ ] Use HTTPS in development (if possible)
- [ ] Keep dependencies updated
- [ ] Run security audits regularly

### Code Review

- [ ] No hardcoded secrets or API keys
- [ ] Input validation is for UX only
- [ ] No sensitive data in console.log
- [ ] External links have rel="noopener noreferrer"
- [ ] dangerouslySetInnerHTML is sanitized
- [ ] URLs are validated before use
- [ ] Error messages don't expose sensitive info

### Deployment

- [ ] Environment variables configured correctly
- [ ] HTTPS enforced
- [ ] CSP headers configured (backend)
- [ ] Error tracking configured with data redaction
- [ ] Security headers configured (backend)
- [ ] Rate limiting configured (backend)
- [ ] CORS configured correctly (backend)

## Common Security Mistakes

### ❌ Don't Do This

```typescript
// ❌ Storing secrets in code
const API_KEY = 'sk_live_abc123';

// ❌ Trusting client-side validation
if (isValidEmail(email)) {
  // Assuming email is safe to use
}

// ❌ Exposing sensitive data in URLs
navigate(`/reset-password?token=${resetToken}&email=${email}`);

// ❌ Not sanitizing HTML
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// ❌ Logging sensitive data
console.log('User object:', user); // May contain sensitive fields

// ❌ Assuming route protection is security
// Just because user can't see the page doesn't mean they can't call the API
```

### ✅ Do This Instead

```typescript
// ✅ Use environment variables
const API_KEY = import.meta.env.VITE_API_KEY;

// ✅ Validate on client for UX, trust backend validation
if (isValidEmail(email)) {
  // Show success UI, but backend will validate again
}

// ✅ Use route parameters, not query strings for sensitive data
navigate(`/reset-password/${resetToken}`);

// ✅ Sanitize HTML before rendering
const sanitized = DOMPurify.sanitize(userInput);
<div dangerouslySetInnerHTML={{ __html: sanitized }} />

// ✅ Log only necessary information
console.log('User logged in:', { id: user.id });

// ✅ Understand that backend enforces security
// Client-side checks are for UX only
```

## Summary

**Key Security Principles**:

1. **Backend Enforces Security**: Client-side security is UX, not enforcement
2. **Never Trust Client Input**: Backend must validate everything
3. **Protect Tokens**: Use memory storage or httpOnly cookies
4. **Prevent XSS**: React helps, but be careful with dangerouslySetInnerHTML
5. **No Secrets in Client**: Never expose API keys or secrets
6. **HTTPS Only**: Always use encrypted connections
7. **Keep Dependencies Updated**: Regular security audits
8. **Log Carefully**: Never log sensitive information

**Remember**: The client is in the user's control. They can:
- View all JavaScript code
- Modify any client-side validation
- Bypass route protection
- Access localStorage and cookies
- Call API endpoints directly

**Always enforce security on the backend.**

---

**Last Updated**: January 2025
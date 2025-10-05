# API Integration

## Overview

This document explains how the LinkShield client integrates with the backend API at `https://www.linkshield.site/api/v1`. All API communication follows consistent patterns using Axios for HTTP requests and React Query for state management.

## Base Configuration

### API Base URL

All API requests are made to:
```
https://www.linkshield.site/api/v1
```

This base URL is configured via environment variable:
```bash
VITE_API_BASE_URL=https://www.linkshield.site/api/v1
```

### Axios Instance

Create a configured Axios instance for all API calls:

```typescript
// src/services/api.ts
import axios from 'axios';
import { authStore } from '@/stores/authStore';

export const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'https://www.linkshield.site/api/v1',
  timeout: 30000, // 30 seconds
  headers: {
    'Content-Type': 'application/json',
  },
});
```

## Request Interceptors

### Authentication Token Injection

Automatically add JWT token to all requests:

```typescript
// src/services/api.ts
apiClient.interceptors.request.use(
  (config) => {
    const token = authStore.getState().token;
    
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);
```

**Header Format**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Request Logging (Development Only)

Log requests in development for debugging:

```typescript
apiClient.interceptors.request.use(
  (config) => {
    if (import.meta.env.DEV) {
      console.log(`[API Request] ${config.method?.toUpperCase()} ${config.url}`, {
        params: config.params,
        data: config.data,
      });
    }
    return config;
  }
);
```

## Response Interceptors

### Automatic Data Extraction

Extract data from response automatically:

```typescript
apiClient.interceptors.response.use(
  (response) => {
    // Return only the data, not the full Axios response
    return response.data;
  },
  (error) => {
    return Promise.reject(error);
  }
);
```

### Error Handling

Handle common error scenarios:

```typescript
// src/services/api.ts
import { toast } from 'react-hot-toast';

apiClient.interceptors.response.use(
  (response) => response.data,
  (error) => {
    const status = error.response?.status;
    const errorCode = error.response?.data?.error_code;
    const message = error.response?.data?.message;
    
    // Handle 401 Unauthorized - Token expired or invalid
    if (status === 401) {
      authStore.getState().clearAuth();
      window.location.href = '/login';
      toast.error('Session expired. Please log in again.');
      return Promise.reject(error);
    }
    
    // Handle 403 Forbidden - Insufficient permissions
    if (status === 403) {
      toast.error('You do not have permission to perform this action.');
      return Promise.reject(error);
    }
    
    // Handle 404 Not Found
    if (status === 404) {
      toast.error('Resource not found.');
      return Promise.reject(error);
    }
    
    // Handle 429 Rate Limit Exceeded
    if (status === 429) {
      const retryAfter = error.response?.headers['retry-after'];
      const retryMessage = retryAfter 
        ? `Rate limit exceeded. Please try again in ${retryAfter} seconds.`
        : 'Rate limit exceeded. Please try again later.';
      toast.error(retryMessage);
      return Promise.reject(error);
    }
    
    // Handle 500 Internal Server Error
    if (status === 500) {
      toast.error('Server error. Please try again later.');
      return Promise.reject(error);
    }
    
    // Handle specific error codes from backend
    if (errorCode) {
      const userMessage = ERROR_MESSAGES[errorCode] || message || 'An error occurred';
      toast.error(userMessage);
    }
    
    // Log error in development
    if (import.meta.env.DEV) {
      console.error('[API Error]', {
        status,
        errorCode,
        message,
        url: error.config?.url,
      });
    }
    
    return Promise.reject(error);
  }
);
```

### Error Message Mapping

Map backend error codes to user-friendly messages:

```typescript
// src/utils/errorMessages.ts
export const ERROR_MESSAGES: Record<string, string> = {
  // Authentication Errors
  EMAIL_ALREADY_EXISTS: 'This email is already registered. Try logging in instead.',
  INVALID_CREDENTIALS: 'Invalid email or password. Please try again.',
  ACCOUNT_LOCKED: 'Your account has been locked due to too many failed login attempts. Please try again in 30 minutes.',
  EMAIL_NOT_VERIFIED: 'Please verify your email address before logging in.',
  TOKEN_EXPIRED: 'Your session has expired. Please log in again.',
  INVALID_TOKEN: 'This link is invalid or has expired. Please request a new one.',
  
  // Rate Limiting
  RATE_LIMIT_EXCEEDED: 'Too many requests. Please try again later.',
  DAILY_LIMIT_REACHED: 'You have reached your daily limit. Upgrade your plan for more.',
  
  // Validation Errors
  INVALID_URL: 'Please enter a valid URL.',
  URL_TOO_LONG: 'URL is too long. Maximum length is 2048 characters.',
  INVALID_EMAIL: 'Please enter a valid email address.',
  PASSWORD_TOO_WEAK: 'Password does not meet security requirements.',
  
  // Resource Errors
  RESOURCE_NOT_FOUND: 'The requested resource was not found.',
  DUPLICATE_RESOURCE: 'This resource already exists.',
  
  // Permission Errors
  INSUFFICIENT_PERMISSIONS: 'You do not have permission to perform this action.',
  SUBSCRIPTION_REQUIRED: 'This feature requires an active subscription.',
  PLAN_UPGRADE_REQUIRED: 'Please upgrade your plan to access this feature.',
  
  // Service Errors
  SERVICE_UNAVAILABLE: 'This service is temporarily unavailable. Please try again later.',
  EXTERNAL_SERVICE_ERROR: 'An external service is experiencing issues. Please try again later.',
};
```

## API Service Modules

Organize API calls by feature domain:

### Authentication Service

```typescript
// src/services/auth.service.ts
import { apiClient } from './api';
import type { 
  LoginRequest, 
  LoginResponse, 
  RegisterRequest, 
  User 
} from '@/types/user.types';

export const authService = {
  /**
   * Register a new user
   */
  register: async (data: RegisterRequest): Promise<void> => {
    return apiClient.post('/user/register', data);
  },
  
  /**
   * Login user and get JWT token
   */
  login: async (data: LoginRequest): Promise<LoginResponse> => {
    return apiClient.post('/user/login', {
      ...data,
      device_info: getDeviceInfo(), // Add device info for session tracking
    });
  },
  
  /**
   * Logout current user
   */
  logout: async (): Promise<void> => {
    return apiClient.post('/user/logout');
  },
  
  /**
   * Verify email with token
   */
  verifyEmail: async (token: string): Promise<void> => {
    return apiClient.post('/user/verify-email', { token });
  },
  
  /**
   * Resend verification email
   */
  resendVerification: async (email: string): Promise<void> => {
    return apiClient.post('/user/resend-verification', { email });
  },
  
  /**
   * Get current user profile
   */
  getProfile: async (): Promise<User> => {
    return apiClient.get('/user/profile');
  },
  
  /**
   * Update user profile
   */
  updateProfile: async (data: Partial<User>): Promise<User> => {
    return apiClient.put('/user/profile', data);
  },
  
  /**
   * Change password
   */
  changePassword: async (data: { 
    current_password: string; 
    new_password: string;
  }): Promise<void> => {
    return apiClient.post('/user/change-password', data);
  },
  
  /**
   * Request password reset
   */
  forgotPassword: async (email: string): Promise<void> => {
    return apiClient.post('/user/forgot-password', { email });
  },
  
  /**
   * Reset password with token
   */
  resetPassword: async (data: { 
    token: string; 
    new_password: string;
  }): Promise<void> => {
    return apiClient.post('/user/reset-password', data);
  },
  
  /**
   * Get user sessions
   */
  getSessions: async (): Promise<Session[]> => {
    return apiClient.get('/user/sessions');
  },
  
  /**
   * Revoke a specific session
   */
  revokeSession: async (sessionId: string): Promise<void> => {
    return apiClient.delete(`/user/sessions/${sessionId}`);
  },
  
  /**
   * Terminate all sessions except current
   */
  terminateAllSessions: async (): Promise<void> => {
    return apiClient.delete('/user/sessions');
  },
};

/**
 * Get device information for session tracking
 */
function getDeviceInfo() {
  return {
    browser: navigator.userAgent,
    os: navigator.platform,
    screen_resolution: `${window.screen.width}x${window.screen.height}`,
  };
}
```

### URL Check Service

```typescript
// src/services/url-check.service.ts
import { apiClient } from './api';
import type {
  UrlCheckRequest,
  UrlCheckResponse,
  UrlCheck,
  UrlCheckDetail,
  UrlHistoryFilters,
  BulkCheckRequest,
  BulkCheckResponse,
  DomainReputation,
  UrlCheckStats,
} from '@/types/url-check.types';

export const urlCheckService = {
  /**
   * Check a single URL
   */
  check: async (data: UrlCheckRequest): Promise<UrlCheckResponse> => {
    return apiClient.post('/url-check/check', data);
  },
  
  /**
   * Bulk check multiple URLs
   */
  bulkCheck: async (data: BulkCheckRequest): Promise<BulkCheckResponse> => {
    return apiClient.post('/url-check/bulk-check', data);
  },
  
  /**
   * Get check detail by ID
   */
  getDetail: async (checkId: string): Promise<UrlCheckDetail> => {
    return apiClient.get(`/url-check/check/${checkId}`);
  },
  
  /**
   * Get provider results for a check
   */
  getResults: async (checkId: string): Promise<ProviderResult[]> => {
    return apiClient.get(`/url-check/check/${checkId}/results`);
  },
  
  /**
   * Get broken links for a check
   */
  getBrokenLinks: async (checkId: string): Promise<BrokenLink[]> => {
    return apiClient.get(`/url-check/check/${checkId}/broken-links`);
  },
  
  /**
   * Get check history with filters
   */
  getHistory: async (filters: UrlHistoryFilters): Promise<UrlCheck[]> => {
    return apiClient.get('/url-check/history', { params: filters });
  },
  
  /**
   * Get domain reputation
   */
  getReputation: async (domain: string): Promise<DomainReputation> => {
    return apiClient.get(`/url-check/reputation/${domain}`);
  },
  
  /**
   * Get URL check statistics
   */
  getStats: async (): Promise<UrlCheckStats> => {
    return apiClient.get('/url-check/stats');
  },
};
```

## TypeScript Integration

### Request/Response Types

Define TypeScript interfaces for all API requests and responses:

```typescript
// src/types/user.types.ts
export interface LoginRequest {
  email: string;
  password: string;
  remember_me?: boolean;
}

export interface LoginResponse {
  access_token: string;
  token_type: 'bearer';
  expires_in: number;
  user: User;
  session_id: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  full_name: string;
  company?: string;
  accept_terms: boolean;
  marketing_consent?: boolean;
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  company?: string;
  role: 'USER' | 'ADMIN';
  subscription_plan: SubscriptionPlan;
  is_active: boolean;
  is_verified: boolean;
  profile_picture_url?: string;
  timezone?: string;
  language?: string;
  marketing_consent: boolean;
  created_at: string;
  updated_at?: string;
}
```

### Generic API Response Type

For consistent error handling:

```typescript
// src/types/api.types.ts
export interface ApiResponse<T = any> {
  data?: T;
  error_code?: string;
  message?: string;
  details?: Record<string, any>;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface ApiError {
  error_code: string;
  message: string;
  details?: Record<string, any>;
  status: number;
}
```

## React Query Integration

### Query Hooks

Create query hooks for GET requests:

```typescript
// src/hooks/url-check/useUrlHistory.ts
import { useQuery } from '@tanstack/react-query';
import { urlCheckService } from '@/services/url-check.service';
import type { UrlHistoryFilters } from '@/types/url-check.types';

export const useUrlHistory = (filters: UrlHistoryFilters) => {
  return useQuery({
    queryKey: ['url-history', filters],
    queryFn: () => urlCheckService.getHistory(filters),
    staleTime: 2 * 60 * 1000, // 2 minutes
    gcTime: 10 * 60 * 1000, // 10 minutes (formerly cacheTime)
    enabled: true, // Only run if user is authenticated
  });
};
```

### Mutation Hooks

Create mutation hooks for POST/PUT/DELETE requests:

```typescript
// src/hooks/url-check/useUrlCheck.ts
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { urlCheckService } from '@/services/url-check.service';
import { toast } from 'react-hot-toast';
import type { UrlCheckRequest } from '@/types/url-check.types';

export const useUrlCheck = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: (data: UrlCheckRequest) => urlCheckService.check(data),
    onSuccess: (data) => {
      // Invalidate and refetch history
      queryClient.invalidateQueries({ queryKey: ['url-history'] });
      toast.success('URL checked successfully');
    },
    onError: (error: any) => {
      // Error already handled by interceptor, but can add specific handling here
      console.error('URL check failed:', error);
    },
  });
};
```

### Query Keys Organization

Organize query keys consistently:

```typescript
// src/config/queryKeys.ts
export const queryKeys = {
  // Authentication
  auth: {
    profile: ['auth', 'profile'] as const,
    sessions: ['auth', 'sessions'] as const,
  },
  
  // URL Checks
  urlCheck: {
    all: ['url-check'] as const,
    history: (filters: UrlHistoryFilters) => ['url-check', 'history', filters] as const,
    detail: (id: string) => ['url-check', 'detail', id] as const,
    results: (id: string) => ['url-check', 'results', id] as const,
    reputation: (domain: string) => ['url-check', 'reputation', domain] as const,
    stats: ['url-check', 'stats'] as const,
  },
  
  // Reports
  reports: {
    all: ['reports'] as const,
    list: (filters: ReportFilters) => ['reports', 'list', filters] as const,
    detail: (id: string) => ['reports', 'detail', id] as const,
    templates: ['reports', 'templates'] as const,
    stats: ['reports', 'stats'] as const,
  },
  
  // Dashboard
  dashboard: {
    overview: ['dashboard', 'overview'] as const,
    projects: ['dashboard', 'projects'] as const,
    project: (id: string) => ['dashboard', 'project', id] as const,
    alerts: (projectId: string) => ['dashboard', 'alerts', projectId] as const,
  },
};

// Usage
useQuery({
  queryKey: queryKeys.urlCheck.history(filters),
  queryFn: () => urlCheckService.getHistory(filters),
});
```

## Request Cancellation

Cancel requests when component unmounts or query key changes:

```typescript
// React Query handles this automatically, but for manual cancellation:
import { useEffect } from 'react';
import axios from 'axios';

export const useManualRequest = () => {
  useEffect(() => {
    const source = axios.CancelToken.source();
    
    const fetchData = async () => {
      try {
        const data = await apiClient.get('/endpoint', {
          cancelToken: source.token,
        });
        // Handle data
      } catch (error) {
        if (axios.isCancel(error)) {
          console.log('Request canceled');
        }
      }
    };
    
    fetchData();
    
    return () => {
      source.cancel('Component unmounted');
    };
  }, []);
};
```

## File Upload

Handle file uploads with progress tracking:

```typescript
// src/services/upload.service.ts
export const uploadService = {
  uploadFile: async (
    file: File,
    onProgress?: (progress: number) => void
  ): Promise<{ url: string }> => {
    const formData = new FormData();
    formData.append('file', file);
    
    return apiClient.post('/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (progressEvent.total) {
          const progress = Math.round(
            (progressEvent.loaded * 100) / progressEvent.total
          );
          onProgress?.(progress);
        }
      },
    });
  },
};

// Usage in component
const [progress, setProgress] = useState(0);

const handleUpload = async (file: File) => {
  try {
    const result = await uploadService.uploadFile(file, setProgress);
    console.log('File uploaded:', result.url);
  } catch (error) {
    console.error('Upload failed:', error);
  }
};
```

## Summary

The API integration follows these principles:

1. **Centralized Configuration**: Single Axios instance with base URL and interceptors
2. **Automatic Token Injection**: JWT token added to all requests automatically
3. **Consistent Error Handling**: Interceptors handle common errors globally
4. **Type Safety**: TypeScript interfaces for all requests and responses
5. **Service Modules**: API calls organized by feature domain
6. **React Query Integration**: Queries and mutations for optimal caching and state management
7. **User-Friendly Errors**: Backend error codes mapped to clear messages

This approach ensures:
- Consistent API communication patterns
- Reduced boilerplate code
- Better error handling and user experience
- Type safety throughout the application
- Optimal caching and performance with React Query

---

**Last Updated**: January 2025
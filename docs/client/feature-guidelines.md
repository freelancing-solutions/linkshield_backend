# Feature Implementation Guidelines

## Overview

This document provides a step-by-step guide for implementing new features in the LinkShield client application. Follow these guidelines to ensure consistency, quality, and maintainability.

## Feature Implementation Checklist

Use this checklist for every new feature:

- [ ] 1. Review feature specification
- [ ] 2. Plan component structure
- [ ] 3. Create feature directory structure
- [ ] 4. Define TypeScript types
- [ ] 5. Create API service module
- [ ] 6. Create React Query hooks
- [ ] 7. Build UI components
- [ ] 8. Add routing
- [ ] 9. Implement forms (if needed)
- [ ] 10. Handle error states
- [ ] 11. Handle loading states
- [ ] 12. Implement accessibility
- [ ] 13. Write unit tests
- [ ] 14. Write integration tests
- [ ] 15. Write E2E tests
- [ ] 16. Update documentation
- [ ] 17. Code review
- [ ] 18. QA testing

## Step-by-Step Implementation

### Step 1: Review Feature Specification

Before writing code, thoroughly review the feature specification:

```markdown
# Example: URL Analysis Feature

## Requirements
- Display URL check history with filters
- Show check details with provider results
- Support bulk URL analysis
- Display domain reputation

## API Endpoints
- GET /url-check/history
- GET /url-check/check/{id}
- POST /url-check/bulk-check
- GET /url-check/reputation/{domain}

## User Stories
- As a user, I want to view my URL check history
- As a user, I want to filter checks by date and status
- As a user, I want to see detailed results for each check
```

**Questions to Answer**:
- What are the main user flows?
- What API endpoints are needed?
- What data needs to be displayed?
- What user interactions are required?
- What error cases need handling?

### Step 2: Plan Component Structure

Sketch out the component hierarchy:

```
UrlAnalysisPage
├── PageHeader
├── UrlHistoryFilters
│   ├── DateRangePicker
│   ├── StatusFilter
│   └── SearchInput
├── UrlHistoryTable
│   ├── TableHeader
│   ├── TableBody
│   │   └── UrlHistoryRow (multiple)
│   └── TablePagination
└── BulkAnalysisDialog
    └── BulkAnalysisForm
```

**Identify**:
- Page components (route-level)
- Feature components (specific to this feature)
- Shared components (reusable across features)
- Layout components (structure and positioning)

### Step 3: Create Feature Directory Structure

Create organized directory structure:

```bash
# Create feature directory
mkdir -p src/features/url-analysis

# Create subdirectories
mkdir -p src/features/url-analysis/components
mkdir -p src/features/url-analysis/hooks
mkdir -p src/features/url-analysis/types
mkdir -p src/features/url-analysis/services
mkdir -p src/features/url-analysis/pages
```

Final structure:

```
src/features/url-analysis/
├── components/
│   ├── UrlHistoryTable.tsx
│   ├── UrlHistoryFilters.tsx
│   ├── CheckDetailView.tsx
│   ├── BulkAnalysisForm.tsx
│   └── index.ts
├── hooks/
│   ├── useUrlHistory.ts
│   ├── useUrlCheck.ts
│   ├── useBulkCheck.ts
│   └── index.ts
├── types/
│   └── url-check.types.ts
├── services/
│   └── url-check.service.ts
├── pages/
│   ├── UrlAnalysisPage.tsx
│   └── CheckDetailPage.tsx
└── index.ts
```

### Step 4: Define TypeScript Types

Create type definitions first:

```typescript
// src/features/url-analysis/types/url-check.types.ts

export interface UrlCheck {
  id: string;
  url: string;
  status: 'pending' | 'completed' | 'failed';
  threat_level: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  created_at: string;
  completed_at?: string;
}

export interface UrlCheckDetail extends UrlCheck {
  provider_results: ProviderResult[];
  broken_links: BrokenLink[];
  metadata: UrlMetadata;
}

export interface ProviderResult {
  provider: string;
  status: 'clean' | 'malicious' | 'suspicious' | 'error';
  details: string;
  checked_at: string;
}

export interface BrokenLink {
  url: string;
  status_code: number;
  error: string;
}

export interface UrlMetadata {
  title?: string;
  description?: string;
  favicon?: string;
}

export interface UrlHistoryFilters {
  page?: number;
  per_page?: number;
  status?: UrlCheck['status'];
  threat_level?: UrlCheck['threat_level'];
  date_from?: string;
  date_to?: string;
  search?: string;
}

export interface BulkCheckRequest {
  urls: string[];
  scan_type?: 'quick' | 'comprehensive' | 'deep';
}

export interface BulkCheckResponse {
  job_id: string;
  total_urls: number;
  status: 'processing' | 'completed' | 'failed';
}
```

### Step 5: Create API Service Module

Implement API calls:

```typescript
// src/features/url-analysis/services/url-check.service.ts
import { apiClient } from '@/services/api';
import type {
  UrlCheck,
  UrlCheckDetail,
  UrlHistoryFilters,
  BulkCheckRequest,
  BulkCheckResponse,
} from '../types/url-check.types';

export const urlCheckService = {
  /**
   * Get URL check history with filters
   */
  getHistory: async (filters: UrlHistoryFilters): Promise<UrlCheck[]> => {
    return apiClient.get('/url-check/history', { params: filters });
  },
  
  /**
   * Get detailed check results
   */
  getDetail: async (checkId: string): Promise<UrlCheckDetail> => {
    return apiClient.get(`/url-check/check/${checkId}`);
  },
  
  /**
   * Submit bulk URL check
   */
  bulkCheck: async (data: BulkCheckRequest): Promise<BulkCheckResponse> => {
    return apiClient.post('/url-check/bulk-check', data);
  },
  
  /**
   * Get domain reputation
   */
  getReputation: async (domain: string) => {
    return apiClient.get(`/url-check/reputation/${domain}`);
  },
};
```

### Step 6: Create React Query Hooks

Create hooks for data fetching:

```typescript
// src/features/url-analysis/hooks/useUrlHistory.ts
import { useQuery } from '@tanstack/react-query';
import { urlCheckService } from '../services/url-check.service';
import type { UrlHistoryFilters } from '../types/url-check.types';

export const useUrlHistory = (filters: UrlHistoryFilters) => {
  return useQuery({
    queryKey: ['url-history', filters],
    queryFn: () => urlCheckService.getHistory(filters),
    staleTime: 2 * 60 * 1000, // 2 minutes
  });
};

// src/features/url-analysis/hooks/useUrlCheckDetail.ts
import { useQuery } from '@tanstack/react-query';
import { urlCheckService } from '../services/url-check.service';

export const useUrlCheckDetail = (checkId: string) => {
  return useQuery({
    queryKey: ['url-check', 'detail', checkId],
    queryFn: () => urlCheckService.getDetail(checkId),
    enabled: !!checkId,
  });
};

// src/features/url-analysis/hooks/useBulkCheck.ts
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { urlCheckService } from '../services/url-check.service';
import { toast } from 'react-hot-toast';

export const useBulkCheck = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: urlCheckService.bulkCheck,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['url-history'] });
      toast.success('Bulk check started successfully');
    },
    onError: () => {
      toast.error('Failed to start bulk check');
    },
  });
};
```

### Step 7: Build UI Components

Create components from smallest to largest:

```typescript
// 1. Small, reusable components
// src/features/url-analysis/components/ThreatBadge.tsx
interface ThreatBadgeProps {
  level: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}

export const ThreatBadge: React.FC<ThreatBadgeProps> = ({ level }) => {
  const colors = {
    safe: 'bg-green-100 text-green-800',
    low: 'bg-blue-100 text-blue-800',
    medium: 'bg-yellow-100 text-yellow-800',
    high: 'bg-orange-100 text-orange-800',
    critical: 'bg-red-100 text-red-800',
  };
  
  return (
    <span className={`px-2 py-1 rounded text-sm ${colors[level]}`}>
      {level.toUpperCase()}
    </span>
  );
};

// 2. Feature-specific components
// src/features/url-analysis/components/UrlHistoryTable.tsx
interface UrlHistoryTableProps {
  data: UrlCheck[];
  isLoading: boolean;
  onRowClick: (check: UrlCheck) => void;
}

export const UrlHistoryTable: React.FC<UrlHistoryTableProps> = ({
  data,
  isLoading,
  onRowClick,
}) => {
  if (isLoading) {
    return <TableSkeleton />;
  }
  
  if (data.length === 0) {
    return <EmptyState message="No URL checks found" />;
  }
  
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>URL</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Threat Level</TableHead>
          <TableHead>Date</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((check) => (
          <TableRow
            key={check.id}
            onClick={() => onRowClick(check)}
            className="cursor-pointer hover:bg-gray-50"
          >
            <TableCell className="font-medium">{check.url}</TableCell>
            <TableCell>
              <StatusBadge status={check.status} />
            </TableCell>
            <TableCell>
              <ThreatBadge level={check.threat_level} />
            </TableCell>
            <TableCell>{formatDate(check.created_at)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
};

// 3. Page component
// src/features/url-analysis/pages/UrlAnalysisPage.tsx
export const UrlAnalysisPage = () => {
  const [filters, setFilters] = useState<UrlHistoryFilters>({});
  const { data, isLoading } = useUrlHistory(filters);
  const navigate = useNavigate();
  
  const handleRowClick = (check: UrlCheck) => {
    navigate(`/url-analysis/${check.id}`);
  };
  
  return (
    <PageLayout>
      <PageHeader title="URL Analysis" />
      
      <div className="space-y-6">
        <UrlHistoryFilters 
          filters={filters} 
          onChange={setFilters} 
        />
        
        <UrlHistoryTable
          data={data || []}
          isLoading={isLoading}
          onRowClick={handleRowClick}
        />
      </div>
    </PageLayout>
  );
};
```

### Step 8: Add Routing

Add routes to router configuration:

```typescript
// src/config/routes.tsx
import { UrlAnalysisPage } from '@/features/url-analysis/pages/UrlAnalysisPage';
import { CheckDetailPage } from '@/features/url-analysis/pages/CheckDetailPage';

export const routes = [
  // ... other routes
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
];
```

Add navigation links:

```typescript
// src/components/layout/Sidebar.tsx
<NavLink to="/url-analysis">
  <CheckIcon className="h-5 w-5" />
  URL Analysis
</NavLink>
```

### Step 9: Implement Forms

Use React Hook Form with Zod validation:

```typescript
// src/features/url-analysis/components/BulkAnalysisForm.tsx
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

const bulkCheckSchema = z.object({
  urls: z.string()
    .min(1, 'Please enter at least one URL')
    .transform((val) => val.split('\n').filter(Boolean)),
  scan_type: z.enum(['quick', 'comprehensive', 'deep']),
});

type BulkCheckFormData = z.infer<typeof bulkCheckSchema>;

export const BulkAnalysisForm = () => {
  const bulkCheck = useBulkCheck();
  
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<BulkCheckFormData>({
    resolver: zodResolver(bulkCheckSchema),
    defaultValues: {
      scan_type: 'quick',
    },
  });
  
  const onSubmit = async (data: BulkCheckFormData) => {
    await bulkCheck.mutateAsync({
      urls: data.urls,
      scan_type: data.scan_type,
    });
  };
  
  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      <div>
        <Label htmlFor="urls">URLs (one per line)</Label>
        <textarea
          id="urls"
          {...register('urls')}
          rows={10}
          className="w-full border rounded p-2"
          placeholder="https://example.com&#10;https://another-site.com"
        />
        {errors.urls && (
          <p className="text-red-600 text-sm mt-1">{errors.urls.message}</p>
        )}
      </div>
      
      <div>
        <Label htmlFor="scan_type">Scan Type</Label>
        <select id="scan_type" {...register('scan_type')} className="w-full border rounded p-2">
          <option value="quick">Quick</option>
          <option value="comprehensive">Comprehensive</option>
          <option value="deep">Deep</option>
        </select>
      </div>
      
      <Button type="submit" disabled={bulkCheck.isPending}>
        {bulkCheck.isPending ? 'Starting...' : 'Start Bulk Check'}
      </Button>
    </form>
  );
};
```

### Step 10: Handle Error States

Implement comprehensive error handling:

```typescript
// Component-level error handling
export const UrlAnalysisPage = () => {
  const { data, isLoading, error, isError } = useUrlHistory(filters);
  
  if (isError) {
    return (
      <ErrorMessage
        title="Failed to load URL history"
        message={error.message}
        onRetry={() => refetch()}
      />
    );
  }
  
  // ... rest of component
};

// Reusable error component
interface ErrorMessageProps {
  title: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorMessage: React.FC<ErrorMessageProps> = ({
  title,
  message,
  onRetry,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-8">
      <AlertCircle className="h-12 w-12 text-red-500 mb-4" />
      <h3 className="text-lg font-semibold mb-2">{title}</h3>
      <p className="text-gray-600 mb-4">{message}</p>
      {onRetry && (
        <Button onClick={onRetry} variant="outline">
          Try Again
        </Button>
      )}
    </div>
  );
};
```

### Step 11: Handle Loading States

Implement loading indicators:

```typescript
// Skeleton screens
export const TableSkeleton = () => {
  return (
    <div className="space-y-2">
      {[...Array(5)].map((_, i) => (
        <Skeleton key={i} className="h-16 w-full" />
      ))}
    </div>
  );
};

// Loading spinner
export const LoadingSpinner = () => {
  return (
    <div className="flex items-center justify-center p-8">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary" />
    </div>
  );
};

// Usage in component
if (isLoading) {
  return <TableSkeleton />;
}
```

### Step 12: Implement Accessibility

Ensure components are accessible:

```typescript
// Accessible table
<Table>
  <caption className="sr-only">URL Check History</caption>
  <TableHeader>
    <TableRow>
      <TableHead scope="col">URL</TableHead>
      <TableHead scope="col">Status</TableHead>
    </TableRow>
  </TableHeader>
  <TableBody>
    {data.map((check) => (
      <TableRow
        key={check.id}
        onClick={() => onRowClick(check)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            onRowClick(check);
          }
        }}
        tabIndex={0}
        role="button"
        aria-label={`View details for ${check.url}`}
      >
        <TableCell>{check.url}</TableCell>
        <TableCell>
          <StatusBadge status={check.status} />
        </TableCell>
      </TableRow>
    ))}
  </TableBody>
</Table>

// Accessible form
<form onSubmit={handleSubmit(onSubmit)}>
  <div>
    <Label htmlFor="urls">
      URLs
      <span className="text-red-500" aria-label="required">*</span>
    </Label>
    <textarea
      id="urls"
      {...register('urls')}
      aria-required="true"
      aria-invalid={!!errors.urls}
      aria-describedby={errors.urls ? 'urls-error' : undefined}
    />
    {errors.urls && (
      <p id="urls-error" className="text-red-600" role="alert">
        {errors.urls.message}
      </p>
    )}
  </div>
</form>
```

### Step 13: Write Unit Tests

Test individual components and hooks:

```typescript
// src/features/url-analysis/components/UrlHistoryTable.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { UrlHistoryTable } from './UrlHistoryTable';

describe('UrlHistoryTable', () => {
  const mockData = [
    {
      id: '1',
      url: 'https://example.com',
      status: 'completed',
      threat_level: 'safe',
      created_at: '2025-01-01T00:00:00Z',
    },
  ];
  
  it('renders table with data', () => {
    render(
      <UrlHistoryTable
        data={mockData}
        isLoading={false}
        onRowClick={vi.fn()}
      />
    );
    
    expect(screen.getByText('https://example.com')).toBeInTheDocument();
    expect(screen.getByText('SAFE')).toBeInTheDocument();
  });
  
  it('calls onRowClick when row is clicked', () => {
    const handleRowClick = vi.fn();
    render(
      <UrlHistoryTable
        data={mockData}
        isLoading={false}
        onRowClick={handleRowClick}
      />
    );
    
    fireEvent.click(screen.getByText('https://example.com'));
    expect(handleRowClick).toHaveBeenCalledWith(mockData[0]);
  });
  
  it('shows loading skeleton when loading', () => {
    render(
      <UrlHistoryTable
        data={[]}
        isLoading={true}
        onRowClick={vi.fn()}
      />
    );
    
    expect(screen.getByTestId('table-skeleton')).toBeInTheDocument();
  });
  
  it('shows empty state when no data', () => {
    render(
      <UrlHistoryTable
        data={[]}
        isLoading={false}
        onRowClick={vi.fn()}
      />
    );
    
    expect(screen.getByText('No URL checks found')).toBeInTheDocument();
  });
});
```

### Step 14: Write Integration Tests

Test component interactions:

```typescript
// src/features/url-analysis/pages/UrlAnalysisPage.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { UrlAnalysisPage } from './UrlAnalysisPage';

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });
  
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
};

describe('UrlAnalysisPage', () => {
  it('loads and displays URL history', async () => {
    render(<UrlAnalysisPage />, { wrapper: createWrapper() });
    
    await waitFor(() => {
      expect(screen.getByText('https://example.com')).toBeInTheDocument();
    });
  });
  
  it('navigates to detail page when row is clicked', async () => {
    const { user } = render(<UrlAnalysisPage />, { wrapper: createWrapper() });
    
    await waitFor(() => {
      expect(screen.getByText('https://example.com')).toBeInTheDocument();
    });
    
    await user.click(screen.getByText('https://example.com'));
    
    expect(window.location.pathname).toBe('/url-analysis/1');
  });
});
```

### Step 15: Write E2E Tests

Test complete user flows:

```typescript
// tests/url-analysis.spec.ts
import { test, expect } from '@playwright/test';

test.describe('URL Analysis', () => {
  test.beforeEach(async ({ page }) => {
    // Login
    await page.goto('/login');
    await page.fill('[name="email"]', 'test@example.com');
    await page.fill('[name="password"]', 'password123');
    await page.click('button[type="submit"]');
    await page.waitForURL('/dashboard');
  });
  
  test('should display URL history', async ({ page }) => {
    await page.goto('/url-analysis');
    
    await expect(page.locator('h1')).toContainText('URL Analysis');
    await expect(page.locator('table')).toBeVisible();
  });
  
  test('should filter URL history', async ({ page }) => {
    await page.goto('/url-analysis');
    
    await page.selectOption('[name="status"]', 'completed');
    await page.click('button:has-text("Apply Filters")');
    
    await expect(page.locator('table tbody tr')).toHaveCount(5);
  });
  
  test('should navigate to check detail', async ({ page }) => {
    await page.goto('/url-analysis');
    
    await page.click('table tbody tr:first-child');
    
    await expect(page).toHaveURL(/\/url-analysis\/\d+/);
    await expect(page.locator('h1')).toContainText('Check Details');
  });
});
```

### Step 16: Update Documentation

Document the new feature:

```markdown
# URL Analysis Feature

## Overview
The URL Analysis feature allows users to view their URL check history, filter results, and view detailed check information.

## Components
- `UrlAnalysisPage`: Main page component
- `UrlHistoryTable`: Displays check history
- `UrlHistoryFilters`: Filter controls
- `CheckDetailPage`: Detailed check results

## API Endpoints
- `GET /url-check/history`: Get check history
- `GET /url-check/check/{id}`: Get check details

## Usage
```typescript
import { UrlAnalysisPage } from '@/features/url-analysis';

<Route path="/url-analysis" element={<UrlAnalysisPage />} />
```
```

### Step 17: Code Review

Submit for code review:

1. Create pull request
2. Add description and screenshots
3. Link to feature specification
4. Request reviewers
5. Address feedback
6. Update based on comments

### Step 18: QA Testing

Test the feature thoroughly:

- [ ] Test all user flows
- [ ] Test error cases
- [ ] Test loading states
- [ ] Test on different browsers
- [ ] Test on different screen sizes
- [ ] Test keyboard navigation
- [ ] Test with screen reader
- [ ] Test performance

## Best Practices

### Do's ✅

1. **Start with types**: Define TypeScript interfaces first
2. **Build incrementally**: Start with small components
3. **Test as you go**: Write tests alongside code
4. **Handle all states**: Loading, error, empty, success
5. **Make it accessible**: ARIA labels, keyboard navigation
6. **Document your code**: Add JSDoc comments
7. **Follow conventions**: Use established patterns
8. **Review specifications**: Ensure requirements are met

### Don'ts ❌

1. **Don't skip planning**: Plan before coding
2. **Don't skip tests**: Tests are not optional
3. **Don't ignore errors**: Handle all error cases
4. **Don't forget accessibility**: Make it usable for everyone
5. **Don't duplicate code**: Extract reusable logic
6. **Don't skip documentation**: Document as you build
7. **Don't ignore performance**: Optimize as needed
8. **Don't skip code review**: Get feedback early

## Summary

**Feature Implementation Process**:
1. Review specification
2. Plan structure
3. Define types
4. Create API service
5. Create hooks
6. Build components
7. Add routing
8. Implement forms
9. Handle errors and loading
10. Ensure accessibility
11. Write tests
12. Document
13. Review and QA

**Key Principles**:
- Type safety with TypeScript
- Component composition
- Separation of concerns
- Comprehensive testing
- Accessibility first
- Documentation always

---

**Last Updated**: January 2025
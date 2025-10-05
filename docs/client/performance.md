# Performance Optimization

## Overview

This document outlines performance optimization techniques for the LinkShield client application. Performance is critical for user experience, and these guidelines help ensure the application remains fast and responsive.

## Performance Targets

### Core Web Vitals

Target metrics for production:

| Metric | Target | Description |
|--------|--------|-------------|
| **LCP** (Largest Contentful Paint) | < 2.5s | Time until largest content element is visible |
| **FID** (First Input Delay) | < 100ms | Time until page responds to first user interaction |
| **CLS** (Cumulative Layout Shift) | < 0.1 | Visual stability (no unexpected layout shifts) |
| **FCP** (First Contentful Paint) | < 1.5s | Time until first content is visible |
| **TTI** (Time to Interactive) | < 3.5s | Time until page is fully interactive |

### Bundle Size Targets

| Bundle | Target | Description |
|--------|--------|-------------|
| Initial Bundle | < 200KB gzipped | First JavaScript bundle loaded |
| Route Chunks | < 50KB gzipped | Lazy-loaded route bundles |
| Vendor Chunk | < 150KB gzipped | Third-party dependencies |
| Total Bundle | < 500KB gzipped | All JavaScript combined |

## Code Splitting

### Route-Based Code Splitting

Split code by routes for smaller initial bundle:

```typescript
// src/config/routes.tsx
import { lazy, Suspense } from 'react';

// Lazy load page components
const DashboardPage = lazy(() => import('@/pages/DashboardPage'));
const UrlAnalysisPage = lazy(() => import('@/pages/UrlAnalysisPage'));
const ReportsPage = lazy(() => import('@/pages/ReportsPage'));

// Wrapper with loading fallback
const LazyPage = ({ children }: { children: React.ReactNode }) => (
  <Suspense fallback={<LoadingSpinner />}>
    {children}
  </Suspense>
);

export const routes = [
  {
    path: '/dashboard',
    element: <LazyPage><DashboardPage /></LazyPage>,
  },
  {
    path: '/url-analysis',
    element: <LazyPage><UrlAnalysisPage /></LazyPage>,
  },
];
```

### Component-Level Code Splitting

Split large components:

```typescript
// Lazy load heavy components
const ChartComponent = lazy(() => import('./ChartComponent'));
const DataTable = lazy(() => import('./DataTable'));

export const Dashboard = () => {
  return (
    <div>
      <h1>Dashboard</h1>
      
      <Suspense fallback={<ChartSkeleton />}>
        <ChartComponent data={data} />
      </Suspense>
      
      <Suspense fallback={<TableSkeleton />}>
        <DataTable data={data} />
      </Suspense>
    </div>
  );
};
```

### Dynamic Imports

Import modules dynamically when needed:

```typescript
// Import heavy library only when needed
const handleExport = async () => {
  const { exportToPDF } = await import('./pdfExporter');
  await exportToPDF(data);
};

// Import chart library only when showing charts
const showChart = async () => {
  const { Chart } = await import('chart.js');
  const chart = new Chart(ctx, config);
};
```

## Bundle Optimization

### Analyze Bundle Size

```bash
# Install bundle analyzer
npm install --save-dev rollup-plugin-visualizer

# Build with analysis
npm run build

# Open analysis
open stats.html
```

### Manual Chunks Configuration

```typescript
// vite.config.ts
export default defineConfig({
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          // React and core libraries
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          
          // UI libraries
          'ui-vendor': [
            '@radix-ui/react-dialog',
            '@radix-ui/react-dropdown-menu',
            '@radix-ui/react-select',
          ],
          
          // Data fetching
          'query-vendor': ['@tanstack/react-query', 'axios'],
          
          // Form libraries
          'form-vendor': ['react-hook-form', 'zod'],
          
          // Charts (if used)
          'chart-vendor': ['recharts'],
        },
      },
    },
  },
});
```

### Tree Shaking

Ensure tree shaking works:

```typescript
// ✅ Good - Named imports enable tree shaking
import { Button, Input } from '@/components/ui';

// ❌ Bad - Default import includes everything
import * as UI from '@/components/ui';

// ✅ Good - Import only what you need
import { format } from 'date-fns';

// ❌ Bad - Imports entire library
import dateFns from 'date-fns';
```

## Image Optimization

### Use Modern Formats

```typescript
// Use WebP with fallback
<picture>
  <source srcSet="/image.webp" type="image/webp" />
  <source srcSet="/image.jpg" type="image/jpeg" />
  <img src="/image.jpg" alt="Description" />
</picture>

// Or use next-gen formats
<img 
  src="/image.avif" 
  alt="Description"
  loading="lazy"
/>
```

### Lazy Load Images

```typescript
// Native lazy loading
<img 
  src="/large-image.jpg" 
  alt="Description"
  loading="lazy"
  decoding="async"
/>

// Intersection Observer for more control
import { useEffect, useRef, useState } from 'react';

export const LazyImage = ({ src, alt }: { src: string; alt: string }) => {
  const [isLoaded, setIsLoaded] = useState(false);
  const imgRef = useRef<HTMLImageElement>(null);
  
  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsLoaded(true);
          observer.disconnect();
        }
      },
      { rootMargin: '50px' }
    );
    
    if (imgRef.current) {
      observer.observe(imgRef.current);
    }
    
    return () => observer.disconnect();
  }, []);
  
  return (
    <img
      ref={imgRef}
      src={isLoaded ? src : '/placeholder.jpg'}
      alt={alt}
      loading="lazy"
    />
  );
};
```

### Responsive Images

```typescript
// Serve different sizes based on viewport
<img
  srcSet="
    /image-320w.jpg 320w,
    /image-640w.jpg 640w,
    /image-1280w.jpg 1280w
  "
  sizes="
    (max-width: 320px) 280px,
    (max-width: 640px) 600px,
    1200px
  "
  src="/image-640w.jpg"
  alt="Description"
/>
```

## React Query Caching

### Configure Stale Times

```typescript
// src/config/queryClient.ts
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60 * 1000, // 1 minute default
      gcTime: 5 * 60 * 1000, // 5 minutes (formerly cacheTime)
    },
  },
});

// Per-query configuration
useQuery({
  queryKey: ['url-history'],
  queryFn: getUrlHistory,
  staleTime: 2 * 60 * 1000, // 2 minutes for frequently changing data
});

useQuery({
  queryKey: ['subscription-plans'],
  queryFn: getPlans,
  staleTime: 60 * 60 * 1000, // 1 hour for rarely changing data
});
```

### Prefetch Data

```typescript
// Prefetch on hover
const handleMouseEnter = () => {
  queryClient.prefetchQuery({
    queryKey: ['url-check', checkId],
    queryFn: () => urlCheckService.getDetail(checkId),
  });
};

<Link 
  to={`/url-analysis/${checkId}`}
  onMouseEnter={handleMouseEnter}
>
  View Details
</Link>

// Prefetch on route change
useEffect(() => {
  // Prefetch likely next pages
  queryClient.prefetchQuery({
    queryKey: ['dashboard'],
    queryFn: getDashboard,
  });
}, []);
```

### Request Deduplication

React Query automatically deduplicates requests:

```typescript
// Multiple components requesting same data
// Only one request is made
const Component1 = () => {
  const { data } = useQuery({ queryKey: ['user'], queryFn: getUser });
  // ...
};

const Component2 = () => {
  const { data } = useQuery({ queryKey: ['user'], queryFn: getUser });
  // ...
};
```

## React Rendering Optimization

### React.memo

Prevent unnecessary re-renders:

```typescript
// ✅ Good - Memoize expensive components
export const ExpensiveComponent = React.memo(({ data }: Props) => {
  // Expensive rendering logic
  return <div>{/* ... */}</div>;
});

// With custom comparison
export const UserCard = React.memo(
  ({ user }: { user: User }) => {
    return <div>{user.name}</div>;
  },
  (prevProps, nextProps) => {
    // Only re-render if user.id changes
    return prevProps.user.id === nextProps.user.id;
  }
);
```

### useMemo

Memoize expensive calculations:

```typescript
// ✅ Good - Memoize expensive calculations
const ExpensiveComponent = ({ data }: { data: Item[] }) => {
  const sortedData = useMemo(() => {
    return data.sort((a, b) => a.value - b.value);
  }, [data]);
  
  const filteredData = useMemo(() => {
    return sortedData.filter((item) => item.active);
  }, [sortedData]);
  
  return <List items={filteredData} />;
};

// ❌ Bad - Recalculates on every render
const ExpensiveComponent = ({ data }: { data: Item[] }) => {
  const sortedData = data.sort((a, b) => a.value - b.value);
  const filteredData = sortedData.filter((item) => item.active);
  
  return <List items={filteredData} />;
};
```

### useCallback

Memoize callback functions:

```typescript
// ✅ Good - Stable callback reference
const ParentComponent = () => {
  const [count, setCount] = useState(0);
  
  const handleClick = useCallback(() => {
    setCount((c) => c + 1);
  }, []); // Stable reference
  
  return <ChildComponent onClick={handleClick} />;
};

// ❌ Bad - New function on every render
const ParentComponent = () => {
  const [count, setCount] = useState(0);
  
  const handleClick = () => {
    setCount(count + 1);
  }; // New function every render
  
  return <ChildComponent onClick={handleClick} />;
};
```

### When NOT to Optimize

```typescript
// ❌ Don't optimize simple components
const SimpleComponent = React.memo(({ text }: { text: string }) => {
  return <p>{text}</p>; // Too simple to benefit from memo
});

// ❌ Don't memoize cheap calculations
const Component = ({ a, b }: { a: number; b: number }) => {
  const sum = useMemo(() => a + b, [a, b]); // Overkill
  return <div>{sum}</div>;
};

// ✅ Do optimize expensive operations
const Component = ({ data }: { data: Item[] }) => {
  const processed = useMemo(() => {
    return data
      .filter(complexFilter)
      .map(expensiveTransform)
      .sort(complexSort);
  }, [data]); // Worth memoizing
  
  return <List items={processed} />;
};
```

## List Virtualization

### React Window

Virtualize long lists:

```bash
npm install react-window
```

```typescript
import { FixedSizeList } from 'react-window';

interface RowProps {
  index: number;
  style: React.CSSProperties;
}

const Row = ({ index, style }: RowProps) => (
  <div style={style}>
    Row {index}
  </div>
);

export const VirtualizedList = ({ items }: { items: any[] }) => {
  return (
    <FixedSizeList
      height={600}
      itemCount={items.length}
      itemSize={50}
      width="100%"
    >
      {Row}
    </FixedSizeList>
  );
};
```

### Variable Size Lists

```typescript
import { VariableSizeList } from 'react-window';

const getItemSize = (index: number) => {
  // Return different heights based on content
  return items[index].isExpanded ? 200 : 50;
};

<VariableSizeList
  height={600}
  itemCount={items.length}
  itemSize={getItemSize}
  width="100%"
>
  {Row}
</VariableSizeList>
```

## Debouncing and Throttling

### Debounce Search Input

```typescript
import { useState, useEffect } from 'react';

const useDebounce = <T,>(value: T, delay: number): T => {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);
  
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);
    
    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);
  
  return debouncedValue;
};

// Usage
const SearchComponent = () => {
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebounce(search, 500);
  
  const { data } = useQuery({
    queryKey: ['search', debouncedSearch],
    queryFn: () => searchAPI(debouncedSearch),
    enabled: debouncedSearch.length > 0,
  });
  
  return (
    <input
      value={search}
      onChange={(e) => setSearch(e.target.value)}
      placeholder="Search..."
    />
  );
};
```

### Throttle Scroll Events

```typescript
import { useEffect, useRef } from 'react';

const useThrottle = (callback: () => void, delay: number) => {
  const lastRun = useRef(Date.now());
  
  useEffect(() => {
    const handler = () => {
      const now = Date.now();
      if (now - lastRun.current >= delay) {
        callback();
        lastRun.current = now;
      }
    };
    
    window.addEventListener('scroll', handler);
    return () => window.removeEventListener('scroll', handler);
  }, [callback, delay]);
};

// Usage
const Component = () => {
  useThrottle(() => {
    console.log('Scroll event');
  }, 200);
  
  return <div>{/* ... */}</div>;
};
```

## Request Cancellation

### Cancel Stale Requests

```typescript
// React Query handles this automatically
useQuery({
  queryKey: ['search', searchTerm],
  queryFn: ({ signal }) => {
    return axios.get('/search', {
      params: { q: searchTerm },
      signal, // Axios will cancel if query key changes
    });
  },
});

// Manual cancellation with AbortController
useEffect(() => {
  const controller = new AbortController();
  
  const fetchData = async () => {
    try {
      const response = await fetch('/api/data', {
        signal: controller.signal,
      });
      const data = await response.json();
      setData(data);
    } catch (error) {
      if (error.name === 'AbortError') {
        console.log('Request cancelled');
      }
    }
  };
  
  fetchData();
  
  return () => {
    controller.abort();
  };
}, []);
```

## Loading States

### Skeleton Screens

Prefer skeletons over spinners:

```typescript
// ✅ Good - Skeleton shows content structure
export const UserCardSkeleton = () => {
  return (
    <div className="border rounded p-4 space-y-3">
      <Skeleton className="h-6 w-3/4" />
      <Skeleton className="h-4 w-full" />
      <Skeleton className="h-4 w-5/6" />
    </div>
  );
};

// ❌ Less ideal - Spinner doesn't show structure
export const LoadingSpinner = () => {
  return <div className="spinner" />;
};
```

### Progressive Loading

```typescript
// Load critical content first
export const Dashboard = () => {
  const { data: stats } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
  });
  
  const { data: charts } = useQuery({
    queryKey: ['charts'],
    queryFn: getCharts,
    enabled: !!stats, // Load after stats
  });
  
  return (
    <div>
      {stats ? <StatsGrid stats={stats} /> : <StatsSkeleton />}
      {charts ? <Charts data={charts} /> : <ChartsSkeleton />}
    </div>
  );
};
```

## Performance Monitoring

### Measure Performance

```typescript
// Use Performance API
const measurePerformance = (name: string, fn: () => void) => {
  performance.mark(`${name}-start`);
  fn();
  performance.mark(`${name}-end`);
  performance.measure(name, `${name}-start`, `${name}-end`);
  
  const measure = performance.getEntriesByName(name)[0];
  console.log(`${name} took ${measure.duration}ms`);
};

// Use React Profiler
import { Profiler } from 'react';

const onRenderCallback = (
  id: string,
  phase: 'mount' | 'update',
  actualDuration: number,
) => {
  console.log(`${id} ${phase} took ${actualDuration}ms`);
};

<Profiler id="Dashboard" onRender={onRenderCallback}>
  <Dashboard />
</Profiler>
```

### Core Web Vitals

```typescript
// Measure Core Web Vitals
import { getCLS, getFID, getLCP } from 'web-vitals';

getCLS(console.log);
getFID(console.log);
getLCP(console.log);
```

## Production Optimizations

### Vite Configuration

```typescript
// vite.config.ts
export default defineConfig({
  build: {
    target: 'es2020',
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true, // Remove console.log
        drop_debugger: true,
      },
    },
    rollupOptions: {
      output: {
        manualChunks: {
          // Split vendors
        },
      },
    },
  },
  
  // Enable compression
  plugins: [
    compression({
      algorithm: 'gzip',
      ext: '.gz',
    }),
    compression({
      algorithm: 'brotliCompress',
      ext: '.br',
    }),
  ],
});
```

### CDN for Static Assets

```typescript
// Serve static assets from CDN
const CDN_URL = 'https://cdn.linkshield.site';

<img src={`${CDN_URL}/images/logo.png`} alt="Logo" />
<link rel="stylesheet" href={`${CDN_URL}/styles/main.css`} />
```

## Performance Checklist

### Development

- [ ] Use code splitting for routes
- [ ] Lazy load heavy components
- [ ] Optimize images (WebP, lazy loading)
- [ ] Configure React Query caching
- [ ] Use React.memo for expensive components
- [ ] Debounce search inputs
- [ ] Virtualize long lists
- [ ] Cancel stale requests

### Build

- [ ] Analyze bundle size
- [ ] Configure manual chunks
- [ ] Enable tree shaking
- [ ] Minify code
- [ ] Remove console.log
- [ ] Compress assets (gzip, brotli)

### Deployment

- [ ] Use CDN for static assets
- [ ] Enable HTTP/2
- [ ] Configure caching headers
- [ ] Monitor Core Web Vitals
- [ ] Set up performance budgets

## Summary

**Key Performance Strategies**:

1. **Code Splitting**: Split by routes and components
2. **Bundle Optimization**: Analyze and optimize bundle size
3. **Image Optimization**: Use modern formats and lazy loading
4. **Caching**: Configure React Query appropriately
5. **React Optimization**: Use memo, useMemo, useCallback wisely
6. **Virtualization**: Virtualize long lists
7. **Debouncing**: Debounce expensive operations
8. **Monitoring**: Measure and track performance

**Remember**: Premature optimization is the root of all evil. Profile first, optimize second.

---

**Last Updated**: January 2025
# Component Patterns

## Overview

This document outlines component design patterns and best practices for building consistent, reusable, and maintainable React components in the LinkShield client application.

## Functional Components with TypeScript

### Basic Component Structure

All components use functional components with TypeScript:

```typescript
// src/components/UserCard.tsx
import React from 'react';

interface UserCardProps {
  user: User;
  onEdit?: (user: User) => void;
  className?: string;
}

export const UserCard: React.FC<UserCardProps> = ({ 
  user, 
  onEdit,
  className = '' 
}) => {
  return (
    <div className={`user-card ${className}`}>
      <h3>{user.full_name}</h3>
      <p>{user.email}</p>
      {onEdit && (
        <button onClick={() => onEdit(user)}>Edit</button>
      )}
    </div>
  );
};
```

### Component with State

```typescript
import { useState } from 'react';

interface ExpandableCardProps {
  title: string;
  children: React.ReactNode;
  defaultExpanded?: boolean;
}

export const ExpandableCard: React.FC<ExpandableCardProps> = ({
  title,
  children,
  defaultExpanded = false,
}) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);
  
  return (
    <div className="expandable-card">
      <button 
        onClick={() => setIsExpanded(!isExpanded)}
        className="card-header"
      >
        {title}
        <span>{isExpanded ? '−' : '+'}</span>
      </button>
      {isExpanded && (
        <div className="card-content">
          {children}
        </div>
      )}
    </div>
  );
};
```

## Component Composition

### Building Complex UIs from Small Components

```typescript
// Small, focused components
const StatCard = ({ label, value, icon }: StatCardProps) => (
  <div className="stat-card">
    <div className="stat-icon">{icon}</div>
    <div className="stat-content">
      <p className="stat-label">{label}</p>
      <p className="stat-value">{value}</p>
    </div>
  </div>
);

const StatsGrid = ({ children }: { children: React.ReactNode }) => (
  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
    {children}
  </div>
);

// Composed into larger component
export const DashboardOverview = () => {
  const { data: stats } = useDashboardStats();
  
  return (
    <div>
      <h1>Dashboard</h1>
      <StatsGrid>
        <StatCard 
          label="Total Checks" 
          value={stats.totalChecks} 
          icon={<CheckIcon />} 
        />
        <StatCard 
          label="Threats Detected" 
          value={stats.threats} 
          icon={<AlertIcon />} 
        />
        <StatCard 
          label="API Calls" 
          value={stats.apiCalls} 
          icon={<ApiIcon />} 
        />
      </StatsGrid>
    </div>
  );
};
```

### Container/Presentational Pattern

Separate logic from presentation:

```typescript
// Presentational Component (UI only)
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
  if (isLoading) return <LoadingSkeleton />;
  
  return (
    <table>
      {/* Table implementation */}
    </table>
  );
};

// Container Component (logic)
export const UrlHistoryContainer = () => {
  const [filters, setFilters] = useState<UrlHistoryFilters>({});
  const { data, isLoading } = useUrlHistory(filters);
  const navigate = useNavigate();
  
  const handleRowClick = (check: UrlCheck) => {
    navigate(`/url-analysis/${check.id}`);
  };
  
  return (
    <div>
      <UrlHistoryFilters filters={filters} onChange={setFilters} />
      <UrlHistoryTable 
        data={data || []}
        isLoading={isLoading}
        onRowClick={handleRowClick}
      />
    </div>
  );
};
```

## Props Patterns

### Required vs Optional Props

```typescript
interface ButtonProps {
  // Required props
  children: React.ReactNode;
  onClick: () => void;
  
  // Optional props with defaults
  variant?: 'primary' | 'secondary' | 'danger';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
  className?: string;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  onClick,
  variant = 'primary',
  size = 'md',
  disabled = false,
  className = '',
}) => {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`btn btn-${variant} btn-${size} ${className}`}
    >
      {children}
    </button>
  );
};
```

### Discriminated Union Props

Use discriminated unions for variant props:

```typescript
// Base props
interface BaseAlertProps {
  title: string;
  onClose?: () => void;
}

// Variant-specific props
type AlertProps = BaseAlertProps & (
  | { variant: 'success'; message: string }
  | { variant: 'error'; error: Error }
  | { variant: 'warning'; message: string }
  | { variant: 'info'; message: string }
);

export const Alert: React.FC<AlertProps> = (props) => {
  const { title, variant, onClose } = props;
  
  // TypeScript knows which props are available based on variant
  const message = variant === 'error' 
    ? props.error.message 
    : props.message;
  
  return (
    <div className={`alert alert-${variant}`}>
      <h4>{title}</h4>
      <p>{message}</p>
      {onClose && <button onClick={onClose}>×</button>}
    </div>
  );
};

// Usage
<Alert variant="success" title="Success" message="Operation completed" />
<Alert variant="error" title="Error" error={new Error('Failed')} />
```

### Children Patterns

```typescript
// Simple children
interface CardProps {
  children: React.ReactNode;
}

// Render prop pattern
interface DataTableProps<T> {
  data: T[];
  renderRow: (item: T, index: number) => React.ReactNode;
}

export const DataTable = <T,>({ data, renderRow }: DataTableProps<T>) => {
  return (
    <table>
      <tbody>
        {data.map((item, index) => (
          <tr key={index}>{renderRow(item, index)}</tr>
        ))}
      </tbody>
    </table>
  );
};

// Usage
<DataTable
  data={users}
  renderRow={(user) => (
    <>
      <td>{user.name}</td>
      <td>{user.email}</td>
    </>
  )}
/>

// Compound component pattern
interface TabsProps {
  children: React.ReactNode;
  defaultValue: string;
}

interface TabsListProps {
  children: React.ReactNode;
}

interface TabsTriggerProps {
  value: string;
  children: React.ReactNode;
}

interface TabsContentProps {
  value: string;
  children: React.ReactNode;
}

export const Tabs = ({ children, defaultValue }: TabsProps) => {
  const [activeTab, setActiveTab] = useState(defaultValue);
  
  return (
    <TabsContext.Provider value={{ activeTab, setActiveTab }}>
      <div className="tabs">{children}</div>
    </TabsContext.Provider>
  );
};

Tabs.List = ({ children }: TabsListProps) => (
  <div className="tabs-list">{children}</div>
);

Tabs.Trigger = ({ value, children }: TabsTriggerProps) => {
  const { activeTab, setActiveTab } = useTabsContext();
  return (
    <button
      onClick={() => setActiveTab(value)}
      className={activeTab === value ? 'active' : ''}
    >
      {children}
    </button>
  );
};

Tabs.Content = ({ value, children }: TabsContentProps) => {
  const { activeTab } = useTabsContext();
  if (activeTab !== value) return null;
  return <div className="tabs-content">{children}</div>;
};

// Usage
<Tabs defaultValue="overview">
  <Tabs.List>
    <Tabs.Trigger value="overview">Overview</Tabs.Trigger>
    <Tabs.Trigger value="team">Team</Tabs.Trigger>
  </Tabs.List>
  <Tabs.Content value="overview">
    <ProjectOverview />
  </Tabs.Content>
  <Tabs.Content value="team">
    <ProjectTeam />
  </Tabs.Content>
</Tabs>
```

## Custom Hooks

### Extracting Component Logic

```typescript
// src/hooks/useToggle.ts
import { useState, useCallback } from 'react';

export const useToggle = (initialValue = false) => {
  const [value, setValue] = useState(initialValue);
  
  const toggle = useCallback(() => {
    setValue((v) => !v);
  }, []);
  
  const setTrue = useCallback(() => {
    setValue(true);
  }, []);
  
  const setFalse = useCallback(() => {
    setValue(false);
  }, []);
  
  return { value, toggle, setTrue, setFalse };
};

// Usage in component
const Modal = () => {
  const { value: isOpen, toggle, setFalse } = useToggle();
  
  return (
    <>
      <button onClick={toggle}>Open Modal</button>
      <Dialog open={isOpen} onClose={setFalse}>
        {/* Modal content */}
      </Dialog>
    </>
  );
};
```

### Form Hook Pattern

```typescript
// src/hooks/useForm.ts
import { useState, useCallback } from 'react';

export const useForm = <T extends Record<string, any>>(initialValues: T) => {
  const [values, setValues] = useState<T>(initialValues);
  const [errors, setErrors] = useState<Partial<Record<keyof T, string>>>({});
  
  const handleChange = useCallback((name: keyof T, value: any) => {
    setValues((prev) => ({ ...prev, [name]: value }));
    // Clear error when user types
    setErrors((prev) => ({ ...prev, [name]: undefined }));
  }, []);
  
  const handleSubmit = useCallback(
    (onSubmit: (values: T) => void | Promise<void>) => 
      async (e: React.FormEvent) => {
        e.preventDefault();
        try {
          await onSubmit(values);
        } catch (error) {
          console.error('Form submission error:', error);
        }
      },
    [values]
  );
  
  const reset = useCallback(() => {
    setValues(initialValues);
    setErrors({});
  }, [initialValues]);
  
  return {
    values,
    errors,
    handleChange,
    handleSubmit,
    setErrors,
    reset,
  };
};
```

## Form Components

### React Hook Form Integration

```typescript
// src/components/auth/LoginForm.tsx
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  remember_me: z.boolean().optional(),
});

type LoginFormData = z.infer<typeof loginSchema>;

interface LoginFormProps {
  onSubmit: (data: LoginFormData) => void | Promise<void>;
  isLoading?: boolean;
}

export const LoginForm: React.FC<LoginFormProps> = ({ 
  onSubmit, 
  isLoading = false 
}) => {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      email: '',
      password: '',
      remember_me: false,
    },
  });
  
  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      <div>
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          type="email"
          {...register('email')}
          error={errors.email?.message}
        />
      </div>
      
      <div>
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          type="password"
          {...register('password')}
          error={errors.password?.message}
        />
      </div>
      
      <div className="flex items-center">
        <input
          id="remember_me"
          type="checkbox"
          {...register('remember_me')}
          className="mr-2"
        />
        <Label htmlFor="remember_me">Remember me</Label>
      </div>
      
      <Button type="submit" disabled={isLoading} className="w-full">
        {isLoading ? 'Logging in...' : 'Log In'}
      </Button>
    </form>
  );
};
```

## Error Boundaries

### Class-Based Error Boundary

```typescript
// src/components/ErrorBoundary.tsx
import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  
  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }
  
  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Error caught by boundary:', error, errorInfo);
    // Log to error tracking service (e.g., Sentry)
  }
  
  render() {
    if (this.state.hasError) {
      return this.props.fallback || (
        <div className="error-boundary">
          <h2>Something went wrong</h2>
          <p>{this.state.error?.message}</p>
          <button onClick={() => this.setState({ hasError: false, error: null })}>
            Try again
          </button>
        </div>
      );
    }
    
    return this.props.children;
  }
}

// Usage
<ErrorBoundary fallback={<ErrorFallback />}>
  <App />
</ErrorBoundary>
```

## Loading States

### Loading Spinner

```typescript
// src/components/shared/LoadingSpinner.tsx
export const LoadingSpinner = ({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) => {
  const sizeClasses = {
    sm: 'h-4 w-4',
    md: 'h-8 w-8',
    lg: 'h-12 w-12',
  };
  
  return (
    <div className="flex items-center justify-center">
      <div className={`animate-spin rounded-full border-b-2 border-primary ${sizeClasses[size]}`} />
    </div>
  );
};
```

### Skeleton Screens

```typescript
// src/components/shared/Skeleton.tsx
export const Skeleton = ({ className = '' }: { className?: string }) => {
  return (
    <div className={`animate-pulse bg-gray-200 rounded ${className}`} />
  );
};

// Usage - Table skeleton
export const TableSkeleton = () => {
  return (
    <div className="space-y-2">
      {[...Array(5)].map((_, i) => (
        <div key={i} className="flex space-x-4">
          <Skeleton className="h-12 w-full" />
        </div>
      ))}
    </div>
  );
};

// Usage - Card skeleton
export const CardSkeleton = () => {
  return (
    <div className="border rounded-lg p-4 space-y-3">
      <Skeleton className="h-6 w-3/4" />
      <Skeleton className="h-4 w-full" />
      <Skeleton className="h-4 w-5/6" />
    </div>
  );
};
```

## Accessibility Patterns

### Accessible Button

```typescript
interface AccessibleButtonProps {
  children: React.ReactNode;
  onClick: () => void;
  ariaLabel?: string;
  disabled?: boolean;
}

export const AccessibleButton: React.FC<AccessibleButtonProps> = ({
  children,
  onClick,
  ariaLabel,
  disabled = false,
}) => {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      aria-disabled={disabled}
      className="btn"
    >
      {children}
    </button>
  );
};
```

### Accessible Form Input

```typescript
interface AccessibleInputProps {
  id: string;
  label: string;
  type?: string;
  value: string;
  onChange: (value: string) => void;
  error?: string;
  required?: boolean;
  helpText?: string;
}

export const AccessibleInput: React.FC<AccessibleInputProps> = ({
  id,
  label,
  type = 'text',
  value,
  onChange,
  error,
  required = false,
  helpText,
}) => {
  const errorId = `${id}-error`;
  const helpId = `${id}-help`;
  
  return (
    <div className="form-field">
      <label htmlFor={id} className="form-label">
        {label}
        {required && <span aria-label="required">*</span>}
      </label>
      
      <input
        id={id}
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-invalid={!!error}
        aria-describedby={error ? errorId : helpText ? helpId : undefined}
        aria-required={required}
        className={`form-input ${error ? 'error' : ''}`}
      />
      
      {helpText && !error && (
        <p id={helpId} className="form-help">
          {helpText}
        </p>
      )}
      
      {error && (
        <p id={errorId} className="form-error" role="alert">
          {error}
        </p>
      )}
    </div>
  );
};
```

### Accessible Modal

```typescript
import { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}

export const AccessibleModal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
}) => {
  const modalRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  
  useEffect(() => {
    if (isOpen) {
      // Save currently focused element
      previousFocusRef.current = document.activeElement as HTMLElement;
      
      // Focus modal
      modalRef.current?.focus();
      
      // Trap focus in modal
      const handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') {
          onClose();
        }
        
        if (e.key === 'Tab') {
          // Implement focus trap logic
        }
      };
      
      document.addEventListener('keydown', handleKeyDown);
      
      return () => {
        document.removeEventListener('keydown', handleKeyDown);
        // Restore focus
        previousFocusRef.current?.focus();
      };
    }
  }, [isOpen, onClose]);
  
  if (!isOpen) return null;
  
  return createPortal(
    <div
      className="modal-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
    >
      <div
        ref={modalRef}
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        tabIndex={-1}
      >
        <h2 id="modal-title">{title}</h2>
        <button
          onClick={onClose}
          aria-label="Close modal"
          className="modal-close"
        >
          ×
        </button>
        {children}
      </div>
    </div>,
    document.body
  );
};
```

## Component Testing

### Testing with React Testing Library

```typescript
// src/components/Button.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { Button } from './Button';

describe('Button', () => {
  it('renders children correctly', () => {
    render(<Button onClick={() => {}}>Click me</Button>);
    expect(screen.getByText('Click me')).toBeInTheDocument();
  });
  
  it('calls onClick when clicked', () => {
    const handleClick = vi.fn();
    render(<Button onClick={handleClick}>Click me</Button>);
    
    fireEvent.click(screen.getByText('Click me'));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });
  
  it('is disabled when disabled prop is true', () => {
    render(<Button onClick={() => {}} disabled>Click me</Button>);
    expect(screen.getByText('Click me')).toBeDisabled();
  });
  
  it('applies correct variant class', () => {
    render(<Button onClick={() => {}} variant="danger">Delete</Button>);
    expect(screen.getByText('Delete')).toHaveClass('btn-danger');
  });
});
```

## Best Practices

### Do's ✅

1. **Use functional components**: With hooks, not class components
2. **Type all props**: Use TypeScript interfaces
3. **Keep components small**: Single responsibility principle
4. **Extract logic to hooks**: Reuse logic across components
5. **Use composition**: Build complex UIs from small components
6. **Handle loading states**: Show skeletons or spinners
7. **Handle error states**: Display user-friendly errors
8. **Make components accessible**: ARIA labels, keyboard navigation
9. **Test components**: Unit tests with React Testing Library
10. **Document complex components**: Add JSDoc comments

### Don'ts ❌

1. **Don't use class components**: Use functional components
2. **Don't use any type**: Always type props properly
3. **Don't make components too large**: Split into smaller components
4. **Don't duplicate logic**: Extract to custom hooks
5. **Don't forget error boundaries**: Catch React errors
6. **Don't skip loading states**: Always show loading feedback
7. **Don't ignore accessibility**: Make components usable for everyone
8. **Don't forget to test**: Write tests for components
9. **Don't use inline styles**: Use Tailwind classes
10. **Don't mutate props**: Props are read-only

## Summary

Component patterns provide:

- **Consistency**: Standard patterns across the application
- **Reusability**: Components can be used in multiple places
- **Maintainability**: Easy to understand and modify
- **Type Safety**: TypeScript catches errors early
- **Accessibility**: Components work for all users
- **Testability**: Easy to test with React Testing Library

**Key Patterns**:
- Functional components with TypeScript
- Component composition over inheritance
- Custom hooks for logic extraction
- React Hook Form for forms
- Error boundaries for error handling
- Skeleton screens for loading states
- Accessible components with ARIA

---

**Last Updated**: January 2025
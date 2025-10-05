# Accessibility Standards

## Overview

This document outlines accessibility standards and implementation guidelines for the LinkShield client application. We target WCAG 2.1 Level AA compliance to ensure the application is usable by everyone, including people with disabilities.

## WCAG 2.1 Level AA Compliance

### What is WCAG?

Web Content Accessibility Guidelines (WCAG) 2.1 is an international standard for web accessibility. Level AA is the recommended conformance level for most websites.

### Four Principles (POUR)

1. **Perceivable**: Information must be presentable to users in ways they can perceive
2. **Operable**: User interface components must be operable
3. **Understandable**: Information and operation must be understandable
4. **Robust**: Content must be robust enough to work with assistive technologies

## Semantic HTML

### Use Proper HTML Elements

```typescript
// ✅ Good - Semantic HTML
<nav>
  <ul>
    <li><a href="/dashboard">Dashboard</a></li>
    <li><a href="/reports">Reports</a></li>
  </ul>
</nav>

<main>
  <article>
    <h1>Page Title</h1>
    <p>Content...</p>
  </article>
</main>

<footer>
  <p>&copy; 2025 LinkShield</p>
</footer>

// ❌ Bad - Generic divs
<div className="nav">
  <div className="nav-item">Dashboard</div>
  <div className="nav-item">Reports</div>
</div>

<div className="content">
  <div className="title">Page Title</div>
  <div>Content...</div>
</div>
```

### Heading Hierarchy

```typescript
// ✅ Good - Proper heading hierarchy
<h1>Main Page Title</h1>
<section>
  <h2>Section Title</h2>
  <h3>Subsection Title</h3>
  <h3>Another Subsection</h3>
</section>
<section>
  <h2>Another Section</h2>
</section>

// ❌ Bad - Skipping levels
<h1>Main Page Title</h1>
<h4>Section Title</h4> {/* Skipped h2 and h3 */}
```

### Landmark Regions

```typescript
// Use semantic landmarks
<header>
  <nav aria-label="Main navigation">
    {/* Navigation links */}
  </nav>
</header>

<main>
  {/* Main content */}
</main>

<aside aria-label="Sidebar">
  {/* Sidebar content */}
</aside>

<footer>
  {/* Footer content */}
</footer>
```

## ARIA Attributes

### When to Use ARIA

**First Rule of ARIA**: Don't use ARIA if you can use native HTML.

```typescript
// ✅ Good - Native HTML
<button onClick={handleClick}>Click me</button>

// ❌ Bad - Unnecessary ARIA
<div role="button" onClick={handleClick}>Click me</div>

// ✅ Good - ARIA when needed
<div role="alert" aria-live="polite">
  Form submitted successfully
</div>
```

### Common ARIA Attributes

#### aria-label

```typescript
// Provide accessible name when text isn't visible
<button aria-label="Close dialog">
  <X className="h-4 w-4" />
</button>

<input
  type="search"
  aria-label="Search URL history"
  placeholder="Search..."
/>
```

#### aria-labelledby

```typescript
// Reference another element for label
<div>
  <h2 id="dialog-title">Confirm Delete</h2>
  <div role="dialog" aria-labelledby="dialog-title">
    <p>Are you sure you want to delete this item?</p>
  </div>
</div>
```

#### aria-describedby

```typescript
// Provide additional description
<input
  type="password"
  aria-describedby="password-requirements"
/>
<p id="password-requirements">
  Password must be at least 8 characters
</p>
```

#### aria-invalid and aria-errormessage

```typescript
// Indicate validation errors
<input
  type="email"
  aria-invalid={!!error}
  aria-errormessage={error ? 'email-error' : undefined}
/>
{error && (
  <p id="email-error" role="alert">
    {error}
  </p>
)}
```

#### aria-expanded

```typescript
// Indicate expandable content state
const [isExpanded, setIsExpanded] = useState(false);

<button
  onClick={() => setIsExpanded(!isExpanded)}
  aria-expanded={isExpanded}
  aria-controls="content-panel"
>
  {isExpanded ? 'Collapse' : 'Expand'}
</button>

<div id="content-panel" hidden={!isExpanded}>
  {/* Content */}
</div>
```

#### aria-live

```typescript
// Announce dynamic content changes
<div aria-live="polite" aria-atomic="true">
  {message}
</div>

// For urgent announcements
<div aria-live="assertive" role="alert">
  {errorMessage}
</div>
```

## Keyboard Navigation

### Focus Management

```typescript
// Ensure all interactive elements are focusable
<button onClick={handleClick}>Click me</button>
<a href="/page">Link</a>
<input type="text" />

// Make custom interactive elements focusable
<div
  role="button"
  tabIndex={0}
  onClick={handleClick}
  onKeyDown={(e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      handleClick();
    }
  }}
>
  Custom Button
</div>
```

### Focus Indicators

```css
/* Ensure visible focus indicators */
button:focus-visible,
a:focus-visible,
input:focus-visible {
  outline: 2px solid #0ea5e9;
  outline-offset: 2px;
}

/* Don't remove focus outline */
/* ❌ Bad */
*:focus {
  outline: none;
}
```

### Focus Trapping in Modals

```typescript
import { useEffect, useRef } from 'react';

export const Modal = ({ isOpen, onClose, children }: ModalProps) => {
  const modalRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  
  useEffect(() => {
    if (isOpen) {
      // Save currently focused element
      previousFocusRef.current = document.activeElement as HTMLElement;
      
      // Focus modal
      modalRef.current?.focus();
      
      // Trap focus
      const handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') {
          onClose();
        }
        
        if (e.key === 'Tab') {
          const focusableElements = modalRef.current?.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
          );
          
          if (!focusableElements || focusableElements.length === 0) return;
          
          const firstElement = focusableElements[0] as HTMLElement;
          const lastElement = focusableElements[focusableElements.length - 1] as HTMLElement;
          
          if (e.shiftKey && document.activeElement === firstElement) {
            e.preventDefault();
            lastElement.focus();
          } else if (!e.shiftKey && document.activeElement === lastElement) {
            e.preventDefault();
            firstElement.focus();
          }
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
  
  return (
    <div
      ref={modalRef}
      role="dialog"
      aria-modal="true"
      tabIndex={-1}
    >
      {children}
    </div>
  );
};
```

### Skip Links

```typescript
// Allow keyboard users to skip navigation
export const SkipLink = () => {
  return (
    <a
      href="#main-content"
      className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-white"
    >
      Skip to main content
    </a>
  );
};

// In layout
<SkipLink />
<nav>{/* Navigation */}</nav>
<main id="main-content">
  {/* Main content */}
</main>
```

## Color Contrast

### Minimum Contrast Ratios

- **Normal text**: 4.5:1
- **Large text** (18pt+ or 14pt+ bold): 3:1
- **UI components and graphics**: 3:1

### Check Contrast

```typescript
// Use tools to check contrast:
// - Chrome DevTools
// - WebAIM Contrast Checker
// - axe DevTools

// ✅ Good contrast
<button className="bg-blue-600 text-white">
  Click me
</button>

// ❌ Bad contrast
<button className="bg-gray-300 text-gray-400">
  Click me
</button>
```

### Don't Rely on Color Alone

```typescript
// ✅ Good - Uses icon and color
<div className="flex items-center gap-2">
  <AlertCircle className="h-4 w-4 text-red-600" />
  <span className="text-red-600">Error: Invalid input</span>
</div>

// ❌ Bad - Color only
<span className="text-red-600">Error: Invalid input</span>
```

## Forms

### Label Association

```typescript
// ✅ Good - Explicit label association
<div>
  <label htmlFor="email">Email</label>
  <input id="email" type="email" />
</div>

// ✅ Good - Implicit label association
<label>
  Email
  <input type="email" />
</label>

// ❌ Bad - No label
<input type="email" placeholder="Email" />
```

### Required Fields

```typescript
// Indicate required fields
<label htmlFor="email">
  Email
  <span className="text-red-500" aria-label="required">*</span>
</label>
<input
  id="email"
  type="email"
  required
  aria-required="true"
/>
```

### Error Messages

```typescript
// Associate errors with inputs
<div>
  <label htmlFor="email">Email</label>
  <input
    id="email"
    type="email"
    aria-invalid={!!error}
    aria-describedby={error ? 'email-error' : undefined}
  />
  {error && (
    <p id="email-error" className="text-red-600" role="alert">
      {error}
    </p>
  )}
</div>
```

### Fieldset and Legend

```typescript
// Group related inputs
<fieldset>
  <legend>Contact Information</legend>
  
  <div>
    <label htmlFor="name">Name</label>
    <input id="name" type="text" />
  </div>
  
  <div>
    <label htmlFor="email">Email</label>
    <input id="email" type="email" />
  </div>
</fieldset>
```

## Tables

### Accessible Tables

```typescript
// Use proper table structure
<table>
  <caption>URL Check History</caption>
  <thead>
    <tr>
      <th scope="col">URL</th>
      <th scope="col">Status</th>
      <th scope="col">Date</th>
    </tr>
  </thead>
  <tbody>
    {data.map((item) => (
      <tr key={item.id}>
        <td>{item.url}</td>
        <td>{item.status}</td>
        <td>{item.date}</td>
      </tr>
    ))}
  </tbody>
</table>
```

### Complex Tables

```typescript
// Use headers attribute for complex tables
<table>
  <thead>
    <tr>
      <th id="url" scope="col">URL</th>
      <th id="provider1" scope="col">Provider 1</th>
      <th id="provider2" scope="col">Provider 2</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th id="check1" scope="row">example.com</th>
      <td headers="check1 provider1">Clean</td>
      <td headers="check1 provider2">Clean</td>
    </tr>
  </tbody>
</table>
```

## Images

### Alt Text

```typescript
// ✅ Good - Descriptive alt text
<img src="/chart.png" alt="Bar chart showing URL checks over time" />

// ✅ Good - Empty alt for decorative images
<img src="/decoration.png" alt="" />

// ❌ Bad - Missing alt
<img src="/chart.png" />

// ❌ Bad - Redundant alt
<img src="/chart.png" alt="Image of chart" />
```

### Complex Images

```typescript
// Provide detailed description
<figure>
  <img
    src="/complex-chart.png"
    alt="Threat detection trends"
    aria-describedby="chart-description"
  />
  <figcaption id="chart-description">
    Bar chart showing threat detection trends from January to December.
    Malware detections increased from 100 in January to 500 in December.
    Phishing attempts remained steady at around 200 per month.
  </figcaption>
</figure>
```

## Dynamic Content

### Live Regions

```typescript
// Announce status updates
export const StatusMessage = ({ message }: { message: string }) => {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-atomic="true"
      className="sr-only"
    >
      {message}
    </div>
  );
};

// Usage
const [status, setStatus] = useState('');

const handleSubmit = async () => {
  setStatus('Submitting form...');
  await submitForm();
  setStatus('Form submitted successfully');
};

return (
  <>
    <form onSubmit={handleSubmit}>
      {/* Form fields */}
    </form>
    <StatusMessage message={status} />
  </>
);
```

### Loading States

```typescript
// Announce loading states
<div role="status" aria-live="polite">
  {isLoading ? 'Loading data...' : 'Data loaded'}
</div>

// Or use aria-busy
<div aria-busy={isLoading}>
  {isLoading ? <LoadingSpinner /> : <DataTable data={data} />}
</div>
```

## Screen Reader Testing

### Screen Reader Shortcuts

**NVDA (Windows)**:
- Start/Stop: Ctrl + Alt + N
- Read next: Down Arrow
- Read previous: Up Arrow
- Navigate headings: H
- Navigate links: K
- Navigate forms: F

**JAWS (Windows)**:
- Start/Stop: Ctrl + Alt + J
- Read next: Down Arrow
- Navigate headings: H
- Navigate links: Tab
- Forms mode: Enter

**VoiceOver (macOS)**:
- Start/Stop: Cmd + F5
- Navigate: VO + Arrow keys
- Rotor: VO + U
- Read all: VO + A

### Testing Checklist

- [ ] Navigate entire page with keyboard only
- [ ] Test with screen reader (NVDA, JAWS, or VoiceOver)
- [ ] Check heading hierarchy
- [ ] Verify form labels and error messages
- [ ] Test focus management in modals
- [ ] Verify ARIA live regions announce updates
- [ ] Check color contrast
- [ ] Test with browser zoom (200%)
- [ ] Verify images have alt text
- [ ] Test with high contrast mode

## Automated Testing

### axe-core

```bash
npm install --save-dev @axe-core/react
```

```typescript
// src/main.tsx
if (import.meta.env.DEV) {
  import('@axe-core/react').then((axe) => {
    axe.default(React, ReactDOM, 1000);
  });
}
```

### Jest + jest-axe

```bash
npm install --save-dev jest-axe
```

```typescript
// Component.test.tsx
import { axe, toHaveNoViolations } from 'jest-axe';

expect.extend(toHaveNoViolations);

test('should have no accessibility violations', async () => {
  const { container } = render(<Component />);
  const results = await axe(container);
  expect(results).toHaveNoViolations();
});
```

### Playwright Accessibility Testing

```typescript
// tests/accessibility.spec.ts
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('should not have accessibility violations', async ({ page }) => {
  await page.goto('/dashboard');
  
  const accessibilityScanResults = await new AxeBuilder({ page }).analyze();
  
  expect(accessibilityScanResults.violations).toEqual([]);
});
```

## Accessibility Checklist

### Development

- [ ] Use semantic HTML elements
- [ ] Maintain proper heading hierarchy
- [ ] Provide text alternatives for images
- [ ] Ensure sufficient color contrast
- [ ] Make all functionality keyboard accessible
- [ ] Provide visible focus indicators
- [ ] Use ARIA attributes appropriately
- [ ] Associate labels with form inputs
- [ ] Announce dynamic content changes
- [ ] Trap focus in modals

### Testing

- [ ] Test with keyboard only
- [ ] Test with screen reader
- [ ] Run automated accessibility tests
- [ ] Check color contrast
- [ ] Test with browser zoom
- [ ] Verify focus management
- [ ] Test form validation
- [ ] Check error messages
- [ ] Verify ARIA attributes
- [ ] Test with high contrast mode

### Documentation

- [ ] Document accessibility features
- [ ] Provide keyboard shortcuts guide
- [ ] Document ARIA patterns used
- [ ] Include accessibility in component docs

## Common Patterns

### Accessible Button

```typescript
interface ButtonProps {
  children: React.ReactNode;
  onClick: () => void;
  disabled?: boolean;
  ariaLabel?: string;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  onClick,
  disabled = false,
  ariaLabel,
}) => {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      aria-disabled={disabled}
    >
      {children}
    </button>
  );
};
```

### Accessible Dialog

```typescript
export const Dialog = ({ isOpen, onClose, title, children }: DialogProps) => {
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="dialog-title"
      hidden={!isOpen}
    >
      <h2 id="dialog-title">{title}</h2>
      {children}
      <button onClick={onClose} aria-label="Close dialog">
        Close
      </button>
    </div>
  );
};
```

### Accessible Tabs

```typescript
export const Tabs = ({ tabs }: { tabs: Tab[] }) => {
  const [activeTab, setActiveTab] = useState(0);
  
  return (
    <div>
      <div role="tablist" aria-label="Content tabs">
        {tabs.map((tab, index) => (
          <button
            key={tab.id}
            role="tab"
            aria-selected={activeTab === index}
            aria-controls={`panel-${tab.id}`}
            id={`tab-${tab.id}`}
            onClick={() => setActiveTab(index)}
            tabIndex={activeTab === index ? 0 : -1}
          >
            {tab.label}
          </button>
        ))}
      </div>
      
      {tabs.map((tab, index) => (
        <div
          key={tab.id}
          role="tabpanel"
          id={`panel-${tab.id}`}
          aria-labelledby={`tab-${tab.id}`}
          hidden={activeTab !== index}
        >
          {tab.content}
        </div>
      ))}
    </div>
  );
};
```

## Resources

### Tools

- **axe DevTools**: Browser extension for accessibility testing
- **WAVE**: Web accessibility evaluation tool
- **Lighthouse**: Built into Chrome DevTools
- **Color Contrast Analyzer**: Check color contrast ratios
- **Screen Readers**: NVDA (Windows), JAWS (Windows), VoiceOver (macOS)

### Guidelines

- **WCAG 2.1**: https://www.w3.org/WAI/WCAG21/quickref/
- **ARIA Authoring Practices**: https://www.w3.org/WAI/ARIA/apg/
- **WebAIM**: https://webaim.org/
- **A11y Project**: https://www.a11yproject.com/

## Summary

**Key Accessibility Principles**:

1. **Semantic HTML**: Use proper HTML elements
2. **Keyboard Navigation**: All functionality accessible via keyboard
3. **Screen Readers**: Provide text alternatives and ARIA labels
4. **Color Contrast**: Ensure sufficient contrast ratios
5. **Focus Management**: Visible focus indicators and proper focus order
6. **Forms**: Associate labels and provide clear error messages
7. **Dynamic Content**: Announce changes with ARIA live regions
8. **Testing**: Test with keyboard, screen readers, and automated tools

**Remember**: Accessibility is not optional. It's a fundamental requirement for building inclusive web applications.

---

**Last Updated**: January 2025
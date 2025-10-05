# Development Workflow

## Overview

This document provides a comprehensive guide for setting up, developing, testing, and deploying the LinkShield client application.

## Prerequisites

### Required Software

- **Node.js**: 18.0.0 or higher (20.x LTS recommended)
- **npm**: 9.0.0 or higher (or yarn 1.22+)
- **Git**: Latest version
- **Code Editor**: VS Code recommended

### Recommended VS Code Extensions

```json
{
  "recommendations": [
    "dbaeumer.vscode-eslint",
    "esbenp.prettier-vscode",
    "bradlc.vscode-tailwindcss",
    "ms-vscode.vscode-typescript-next",
    "usernamehw.errorlens",
    "christian-kohler.path-intellisense",
    "dsznajder.es7-react-js-snippets"
  ]
}
```

## Initial Setup

### 1. Clone Repository

```bash
# Clone the repository
git clone https://github.com/your-org/linkshield-client.git
cd linkshield-client
```

### 2. Install Dependencies

```bash
# Using npm
npm install

# Or using yarn
yarn install
```

### 3. Environment Configuration

Create environment files:

```bash
# Copy example environment file
cp .env.example .env.local
```

Edit `.env.local` with your configuration:

```bash
# API Configuration
VITE_API_BASE_URL=https://www.linkshield.site/api/v1

# Environment
VITE_ENV=development

# Feature Flags
VITE_ENABLE_ANALYTICS=false
VITE_ENABLE_SOCIAL_PROTECTION=true

# Optional: Local backend for development
# VITE_API_BASE_URL=http://localhost:8000/api/v1
```

### 4. Verify Setup

```bash
# Check Node.js version
node --version  # Should be 18.0.0 or higher

# Check npm version
npm --version   # Should be 9.0.0 or higher

# Verify dependencies installed
npm list --depth=0
```

## Development Server

### Start Development Server

```bash
# Start dev server with hot reload
npm run dev

# Server will start at http://localhost:5173
```

The development server includes:
- ⚡ Hot Module Replacement (HMR)
- 🔄 Automatic page reload on file changes
- 📝 TypeScript type checking
- 🎨 Tailwind CSS compilation

### Development Server Options

```bash
# Start on different port
npm run dev -- --port 3000

# Start with host exposed (for testing on other devices)
npm run dev -- --host

# Start with HTTPS (requires certificate)
npm run dev -- --https
```

## Code Quality

### Linting

Check code for errors and style issues:

```bash
# Run ESLint
npm run lint

# Fix auto-fixable issues
npm run lint:fix

# Lint specific files
npm run lint -- src/components/**/*.tsx
```

### Code Formatting

Format code with Prettier:

```bash
# Check formatting
npm run format:check

# Fix formatting
npm run format

# Format specific files
npm run format -- src/components/**/*.tsx
```

### Type Checking

Run TypeScript type checker:

```bash
# Check types
npm run type-check

# Watch mode
npm run type-check:watch
```

### Pre-commit Checks

Set up Husky for automatic checks:

```bash
# Install Husky
npm install --save-dev husky lint-staged

# Initialize Husky
npx husky install

# Add pre-commit hook
npx husky add .husky/pre-commit "npx lint-staged"
```

Configure lint-staged in `package.json`:

```json
{
  "lint-staged": {
    "*.{ts,tsx}": [
      "eslint --fix",
      "prettier --write"
    ],
    "*.{json,md,css}": [
      "prettier --write"
    ]
  }
}
```

## Testing

### Unit Tests

Run unit tests with Vitest:

```bash
# Run all tests
npm run test

# Run tests in watch mode
npm run test:watch

# Run tests with coverage
npm run test:coverage

# Run specific test file
npm run test -- src/components/Button.test.tsx

# Run tests matching pattern
npm run test -- --grep "Button"
```

### Integration Tests

Run integration tests:

```bash
# Run integration tests
npm run test:integration

# Run with coverage
npm run test:integration -- --coverage
```

### End-to-End Tests

Run E2E tests with Playwright:

```bash
# Install Playwright browsers (first time only)
npx playwright install

# Run E2E tests
npm run test:e2e

# Run E2E tests in UI mode
npm run test:e2e:ui

# Run specific test file
npm run test:e2e -- tests/auth.spec.ts

# Run tests in specific browser
npm run test:e2e -- --project=chromium
npm run test:e2e -- --project=firefox
npm run test:e2e -- --project=webkit

# Debug tests
npm run test:e2e -- --debug
```

### Test Coverage

Generate and view coverage reports:

```bash
# Generate coverage report
npm run test:coverage

# Open coverage report in browser
open coverage/index.html  # macOS
start coverage/index.html # Windows
xdg-open coverage/index.html # Linux
```

### Testing Best Practices

```typescript
// ✅ Good test structure
describe('LoginForm', () => {
  it('should render email and password inputs', () => {
    render(<LoginForm onSubmit={vi.fn()} />);
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
  });
  
  it('should call onSubmit with form data when submitted', async () => {
    const handleSubmit = vi.fn();
    render(<LoginForm onSubmit={handleSubmit} />);
    
    await userEvent.type(screen.getByLabelText('Email'), 'test@example.com');
    await userEvent.type(screen.getByLabelText('Password'), 'password123');
    await userEvent.click(screen.getByRole('button', { name: /log in/i }));
    
    expect(handleSubmit).toHaveBeenCalledWith({
      email: 'test@example.com',
      password: 'password123',
    });
  });
  
  it('should display validation errors', async () => {
    render(<LoginForm onSubmit={vi.fn()} />);
    
    await userEvent.click(screen.getByRole('button', { name: /log in/i }));
    
    expect(screen.getByText('Email is required')).toBeInTheDocument();
  });
});
```

## Building for Production

### Production Build

Create optimized production build:

```bash
# Build for production
npm run build

# Output will be in dist/ directory
```

Build process includes:
- 📦 Code minification
- 🗜️ Asset compression
- 🌳 Tree shaking (removing unused code)
- 📊 Bundle analysis
- 🎯 Code splitting

### Preview Production Build

Test production build locally:

```bash
# Build and preview
npm run build
npm run preview

# Preview will start at http://localhost:4173
```

### Analyze Bundle Size

Analyze what's in your bundle:

```bash
# Install bundle analyzer
npm install --save-dev rollup-plugin-visualizer

# Build with analysis
npm run build

# Open bundle analysis
open stats.html
```

### Build Optimization

```typescript
// vite.config.ts
export default defineConfig({
  build: {
    // Target modern browsers
    target: 'es2020',
    
    // Minify with terser
    minify: 'terser',
    terserOptions: {
      compress: {
        drop_console: true, // Remove console.log in production
      },
    },
    
    // Chunk size warnings
    chunkSizeWarningLimit: 500,
    
    // Manual chunks for better caching
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'ui-vendor': ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu'],
          'query-vendor': ['@tanstack/react-query'],
        },
      },
    },
  },
});
```

## Deployment

### Vercel Deployment

```bash
# Install Vercel CLI
npm install -g vercel

# Login to Vercel
vercel login

# Deploy to preview
vercel

# Deploy to production
vercel --prod
```

Configure `vercel.json`:

```json
{
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "framework": "vite",
  "env": {
    "VITE_API_BASE_URL": "https://www.linkshield.site/api/v1",
    "VITE_ENV": "production"
  }
}
```

### Netlify Deployment

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Login to Netlify
netlify login

# Deploy to preview
netlify deploy

# Deploy to production
netlify deploy --prod
```

Configure `netlify.toml`:

```toml
[build]
  command = "npm run build"
  publish = "dist"

[[redirects]]
  from = "/*"
  to = "/index.html"
  status = 200

[build.environment]
  VITE_API_BASE_URL = "https://www.linkshield.site/api/v1"
  VITE_ENV = "production"
```

### AWS S3 + CloudFront

```bash
# Build for production
npm run build

# Install AWS CLI
# https://aws.amazon.com/cli/

# Sync to S3
aws s3 sync dist/ s3://your-bucket-name --delete

# Invalidate CloudFront cache
aws cloudfront create-invalidation \
  --distribution-id YOUR_DISTRIBUTION_ID \
  --paths "/*"
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

```bash
# Build Docker image
docker build -t linkshield-client .

# Run container
docker run -p 80:80 linkshield-client
```

## Git Workflow

### Branch Strategy

```
main (production)
  ↑
develop (staging)
  ↑
feature/feature-name (development)
```

### Creating Feature Branch

```bash
# Update develop branch
git checkout develop
git pull origin develop

# Create feature branch
git checkout -b feature/url-analysis-filters

# Work on feature
# ... make changes ...

# Commit changes
git add .
git commit -m "feat: add filters to URL analysis page"

# Push to remote
git push origin feature/url-analysis-filters
```

### Commit Conventions

Follow Conventional Commits:

```bash
# Feature
git commit -m "feat: add URL history filters"

# Bug fix
git commit -m "fix: resolve pagination issue in reports table"

# Documentation
git commit -m "docs: update API integration guide"

# Style changes
git commit -m "style: format code with prettier"

# Refactoring
git commit -m "refactor: extract form logic to custom hook"

# Performance
git commit -m "perf: optimize table rendering with virtualization"

# Tests
git commit -m "test: add tests for LoginForm component"

# Chore
git commit -m "chore: update dependencies"
```

### Pull Request Process

1. Create feature branch
2. Make changes and commit
3. Push to remote
4. Create pull request
5. Request code review
6. Address review comments
7. Merge to develop
8. Delete feature branch

## CI/CD Pipeline

### GitHub Actions

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Lint
        run: npm run lint
      
      - name: Type check
        run: npm run type-check
      
      - name: Run tests
        run: npm run test:coverage
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/coverage-final.json
  
  build:
    runs-on: ubuntu-latest
    needs: test
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Build
        run: npm run build
      
      - name: Upload build artifacts
        uses: actions/upload-artifact@v3
        with:
          name: dist
          path: dist/
```

## Troubleshooting

### Common Issues

#### Port Already in Use

```bash
# Find process using port 5173
lsof -i :5173  # macOS/Linux
netstat -ano | findstr :5173  # Windows

# Kill process
kill -9 <PID>  # macOS/Linux
taskkill /PID <PID> /F  # Windows

# Or use different port
npm run dev -- --port 3000
```

#### Module Not Found

```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Clear npm cache
npm cache clean --force
npm install
```

#### TypeScript Errors

```bash
# Restart TypeScript server in VS Code
# Cmd+Shift+P (macOS) or Ctrl+Shift+P (Windows)
# Type: "TypeScript: Restart TS Server"

# Or rebuild TypeScript
npm run type-check
```

#### Build Failures

```bash
# Clear Vite cache
rm -rf node_modules/.vite

# Clear dist directory
rm -rf dist

# Rebuild
npm run build
```

## Development Tips

### Hot Reload Not Working

```typescript
// Ensure you're using default exports for pages
export default function HomePage() {
  return <div>Home</div>;
}

// Or use named exports with React.memo
export const HomePage = React.memo(() => {
  return <div>Home</div>;
});
```

### Debugging

```typescript
// Use React DevTools
// Install: https://react.dev/learn/react-developer-tools

// Use React Query DevTools (already included)
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';

<QueryClientProvider client={queryClient}>
  <App />
  <ReactQueryDevtools initialIsOpen={false} />
</QueryClientProvider>

// Use browser debugger
debugger; // Execution will pause here

// Use console methods
console.log('Value:', value);
console.table(arrayOfObjects);
console.time('operation');
// ... code ...
console.timeEnd('operation');
```

### Performance Profiling

```typescript
// Use React Profiler
import { Profiler } from 'react';

<Profiler id="Dashboard" onRender={onRenderCallback}>
  <Dashboard />
</Profiler>

function onRenderCallback(
  id, // "Dashboard"
  phase, // "mount" or "update"
  actualDuration, // Time spent rendering
  baseDuration, // Estimated time without memoization
  startTime, // When React began rendering
  commitTime, // When React committed the update
) {
  console.log(`${id} ${phase} took ${actualDuration}ms`);
}
```

## Package Scripts Reference

```json
{
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "lint": "eslint . --ext ts,tsx --report-unused-disable-directives --max-warnings 0",
    "lint:fix": "eslint . --ext ts,tsx --fix",
    "format": "prettier --write \"src/**/*.{ts,tsx,json,css,md}\"",
    "format:check": "prettier --check \"src/**/*.{ts,tsx,json,css,md}\"",
    "type-check": "tsc --noEmit",
    "type-check:watch": "tsc --noEmit --watch",
    "test": "vitest",
    "test:watch": "vitest --watch",
    "test:coverage": "vitest --coverage",
    "test:ui": "vitest --ui",
    "test:e2e": "playwright test",
    "test:e2e:ui": "playwright test --ui",
    "test:e2e:debug": "playwright test --debug"
  }
}
```

## Summary

**Development Workflow**:
1. Clone repository and install dependencies
2. Configure environment variables
3. Start development server
4. Make changes with hot reload
5. Run linting and type checking
6. Write and run tests
7. Build for production
8. Deploy to hosting platform

**Key Commands**:
- `npm run dev` - Start development server
- `npm run lint` - Check code quality
- `npm run test` - Run tests
- `npm run build` - Build for production
- `npm run preview` - Preview production build

**Best Practices**:
- Use feature branches for development
- Follow commit conventions
- Write tests for new features
- Run linting before committing
- Review code before merging
- Keep dependencies updated

---

**Last Updated**: January 2025
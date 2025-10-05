# LinkShield Client Documentation

## Overview

The LinkShield client is a modern React-based web application that provides a comprehensive user interface for URL security analysis, AI-powered content analysis, subscription management, and social protection features. 

**Important Architectural Principle**: The LinkShield client is a **thin presentation layer** that consumes the backend API. All business logic, data validation, security enforcement, and data persistence reside in the backend at `https://www.linkshield.site/api/v1`. The client is responsible solely for:

- User interface rendering and user experience
- Client-side routing and navigation
- State management (UI state and server state caching)
- API communication and request/response handling
- User interaction and form handling

This architectural decision ensures:
- Security is enforced on the backend, not the client
- Client-side validation is for UX enhancement only
- Route protection is a UX feature, not a security measure
- The client can be rebuilt with different technologies without changing business logic
- Clear separation of concerns between presentation and business logic

## Documentation Index

### Getting Started
- **[Development Workflow](./development-workflow.md)** - Setup, development, testing, and deployment guide

### Architecture & Design
- **[Technology Stack](./tech-stack.md)** - Complete list of frameworks, libraries, and tools
- **[Architecture](./architecture.md)** - Architectural principles, patterns, and design decisions
- **[Project Structure](./project-structure.md)** - Directory organization and file naming conventions

### Implementation Guides
- **[API Integration](./api-integration.md)** - Backend API communication patterns
- **[State Management](./state-management.md)** - Zustand and React Query usage
- **[Routing](./routing.md)** - Navigation and route protection
- **[Component Patterns](./component-patterns.md)** - Component design patterns and best practices
- **[Feature Guidelines](./feature-guidelines.md)** - Step-by-step guide for implementing new features

### Best Practices
- **[Security](./security.md)** - Security best practices for client-side development
- **[Performance](./performance.md)** - Performance optimization techniques
- **[Accessibility](./accessibility.md)** - WCAG 2.1 Level AA compliance guide

## Quick Start

To get started with development:

1. Follow the [Development Workflow](./development-workflow.md) guide for initial setup
2. Review the [Technology Stack](./tech-stack.md) to understand the tools and frameworks
3. Study the [Architecture](./architecture.md) to understand the design principles
4. Use the [Feature Guidelines](./feature-guidelines.md) when implementing new features

## Feature Specifications

Detailed specifications for each feature are available in the `client_architecture/` directory:

- **Authentication** - User registration, login, email verification, sessions
- **Dashboard** - Overview, projects, monitoring, alerts
- **URL Analysis** - URL checking, history, bulk analysis, reputation
- **AI Analysis** - Content analysis, similar content discovery
- **Community Reports** - Submit and view security reports
- **Subscriptions** - Plan management and usage tracking
- **API Keys** - API key generation and management
- **Profile Settings** - User profile and preferences
- **Social Protection** - Extension integration and algorithm health monitoring

## Technology Stack Summary

- **Framework**: React 18.2+ with TypeScript 5.0+
- **State Management**: Zustand (UI state) + TanStack Query (server state)
- **Routing**: React Router 6.20+
- **UI Components**: shadcn/ui with Tailwind CSS 3.4+
- **Forms**: React Hook Form 7.48+ with Zod 3.22+
- **HTTP Client**: Axios 1.6+
- **Build Tool**: Vite 5.0+
- **Testing**: Vitest, React Testing Library, Playwright

## API Base URL

All API requests are made to: `https://www.linkshield.site/api/v1`

## Contributing

When contributing to the client application:

1. Follow the patterns and conventions documented in this guide
2. Ensure all code is TypeScript with strict mode enabled
3. Write tests for all new features (unit, integration, E2E)
4. Ensure WCAG 2.1 Level AA accessibility compliance
5. Follow the Git workflow and commit conventions
6. Update documentation when adding new features or patterns

## Support

For questions or issues:
- Review the relevant documentation section
- Check the feature specifications in `client_architecture/`
- Refer to the backend API documentation in `docs/api/`

---

**Last Updated**: January 2025

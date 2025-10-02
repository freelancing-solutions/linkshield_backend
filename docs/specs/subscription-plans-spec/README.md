# LinkShield Subscription Plans Specification

## Overview

This directory contains the comprehensive specification for LinkShield's subscription plan redesign. The new subscription system is designed to cater to 5 distinct user demographics while properly gating all services (URL analysis, social protection, bot services, dashboard features, and AI analysis) behind appropriate subscription tiers.

## Goals

1. Demographic-Focused Plans: Create subscription tiers that align with specific user needs
2. Comprehensive Service Gating: Ensure all services are properly gated with clear limits
3. Market-Aligned Pricing: Price plans based on market research and competitive analysis
4. Paddle Integration: Seamless integration with Paddle Billing for payment processing

## Documents

1. specification.md — Main specification with tiers, pricing, mapping, gating rules, usage tracking, migration and implementation considerations.
2. feature-matrix.md — Comprehensive feature comparison matrix showing all features across all tiers.
3. service-gating-rules.md — Technical specification for service gating with pseudo-code examples.
4. usage-types.md — Usage tracking specification with new model fields and reset logic.
5. paddle-integration.md — Paddle Billing integration specification with product definitions and webhook handling.

## Implementation Phases

Phase 1: Update Subscription Plans (LNKS-004)
- Update src/services/subscription_service.py with new plans
- Add new fields to src/models/subscription.py
- Update Paddle integration
- Create database migration

Phase 2: Implement Service Gating Middleware (LNKS-005)
- Create src/middleware/subscription_gate.py
- Implement usage tracking for all service types
- Add helper functions for limit checking
- Create decorators for FastAPI routes

Phase 3: Apply Gating to API Endpoints (LNKS-006)
- Update all API routes with subscription checks
- Update controllers with limit enforcement
- Add appropriate error responses
- Test all gating scenarios

Phase 4: Update Documentation (LNKS-007)
- Update API documentation with subscription requirements
- Create subscription plan comparison pages
- Update README and getting started guides
- Create migration guides for existing users
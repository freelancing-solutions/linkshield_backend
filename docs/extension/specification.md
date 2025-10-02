# Browser Extension Controller - Technical Specification

**Version:** 1.0.0  
**Date:** October 2025  
**Location:** `src/controllers/extension_controller.py`  
**Status:** Specification for Implementation

## Executive Summary

The Browser Extension Controller serves as the central API gateway for the LinkShield browser extension, providing unified access to all protection services including URL analysis, social media protection, content analysis, threat intelligence, and user management. This controller orchestrates communication between the browser extension and backend services while managing authentication, rate limiting, and service coordination.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Core Responsibilities](#core-responsibilities)
4. [API Endpoints](#api-endpoints)
5. [Data Models](#data-models)
6. [Service Integration](#service-integration)
7. [Authentication & Authorization](#authentication--authorization)
8. [Rate Limiting](#rate-limiting)
9. [Error Handling](#error-handling)
10. [Performance Requirements](#performance-requirements)
11. [Security Requirements](#security-requirements)
12. [Implementation Guidelines](#implementation-guidelines)

---

## 1. Overview

### 1.1 Purpose

The Extension Controller provides a comprehensive API interface specifically designed for browser extension clients, offering:

- **Unified Service Access**: Single entry point for all extension features
- **Optimized Responses**: Lightweight payloads optimized for browser environments
- **Batch Operations**: Efficient bulk processing for multiple URLs/requests
- **Real-time Processing**: Low-latency responses for interactive use cases
- **Subscription Management**: Tier-based feature access and quota enforcement

### 1.2 Scope

This controller handles:

- ✅ URL security analysis and threat detection
- ✅ Social media profile and content analysis
- ✅ Content risk and spam detection
- ✅ Broken link scanning
- ✅ Domain reputation checks
- ✅ User authentication and session management
- ✅ Usage statistics and reporting
- ✅ Webhook notifications
- ✅ Extension configuration management

### 1.3 Key Design Principles

1. **Extension-First Design**: All APIs optimized for browser extension use cases
2. **Performance Critical**: Sub-second response times for real-time protection
3. **Backward Compatible**: Versioned APIs to support multiple extension versions
4. **Graceful Degradation**: Continue working with partial service failures
5. **Privacy Focused**: Minimal data collection, local processing where possible

---

## 2. Architecture

### 2.1 Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                   Browser Extension                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │  Content   │  │ Background │  │   Popup    │           │
│  │  Script    │  │  Service   │  │     UI     │           │
│  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘           │
│         │               │               │                   │
│         └───────────────┴───────────────┘                   │
│                       │                                      │
│                       │ HTTPS/REST API                      │
└───────────────────────┼──────────────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────────────┐
│            Extension Controller (This Spec)                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Route Layer (FastAPI Endpoints)                       │ │
│  │  - Authentication validation                           │ │
│  │  - Request parsing and validation                      │ │
│  │  - Response formatting                                 │ │
│  └──────────────────────┬─────────────────────────────────┘ │
│  ┌──────────────────────▼─────────────────────────────────┐ │
│  │  Controller Business Logic                             │ │
│  │  - Service orchestration                               │ │
│  │  - Rate limiting enforcement                           │ │
│  │  - Error handling                                      │ │
│  │  - Caching strategy                                    │ │
│  └──────────────────────┬─────────────────────────────────┘ │
└─────────────────────────┼────────────────────────────────────┘
                          │
     ┌────────────────────┼────────────────────────┐
     │                    │                        │
┌────▼─────┐   ┌─────────▼────────┐   ┌──────────▼──────────┐
│   URL    │   │  Social Media    │   │   Content Analyzer  │
│ Analysis │   │   Protection     │   │      Service        │
│ Service  │   │    Controller    │   │                     │
└──────────┘   └──────────────────┘   └─────────────────────┘
     │                    │                        │
┌────▼─────────────────────▼────────────────────────▼─────────┐
│              Shared Services Layer                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   Auth   │  │   Email  │  │   AI     │  │  Cache   │   │
│  │ Service  │  │ Service  │  │ Service  │  │ (Redis)  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 Request Flow

```
Extension Request
      ↓
[API Gateway/Load Balancer]
      ↓
[Extension Controller Route]
      ↓
[JWT Authentication Middleware]
      ↓
[Rate Limit Check]
      ↓
[Request Validation]
      ↓
[Controller Business Logic]
      ↓
┌─────┴────────┬──────────┬──────────┐
│              │          │          │
[URL Analysis] [Social]  [Content]  [Other Services]
│              │          │          │
└─────┬────────┴──────────┴──────────┘
      ↓
[Response Aggregation]
      ↓
[Response Formatting]
      ↓
[Caching (if applicable)]
      ↓
[Return to Extension]
```

### 2.3 Technology Stack

- **Framework**: FastAPI 0.104.1
- **Language**: Python 3.9+
- **Database**: PostgreSQL (via URLCheckController, other controllers)
- **Cache**: Redis (for rate limiting, session storage)
- **Authentication**: JWT tokens
- **Background Tasks**: FastAPI BackgroundTasks
- **Validation**: Pydantic models

---

## 3. Core Responsibilities

### 3.1 Service Orchestration

The controller coordinates multiple backend services:

```python
class ExtensionController(BaseController):
    """Main controller for browser extension API endpoints."""
    
    def __init__(
        self,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService,
        url_check_controller: URLCheckController,
        social_protection_controller: SocialProtectionController,
        content_analyzer_service: ContentAnalyzerService,
        ai_service: AIService
    ):
        """Initialize with all required services."""
```

### 3.2 Request Processing Pipeline

1. **Authentication**: Validate JWT token, extract user context
2. **Authorization**: Check subscription tier and feature access
3. **Rate Limiting**: Enforce per-user/per-tier limits
4. **Input Validation**: Validate request payload with Pydantic
5. **Service Delegation**: Route to appropriate service(s)
6. **Response Aggregation**: Combine results from multiple services
7. **Response Formatting**: Optimize for extension consumption
8. **Error Handling**: Standardized error responses
9. **Logging**: Comprehensive request/response logging
10. **Caching**: Cache frequent requests (optional)

### 3.3 Subscription Tier Management

```python
class SubscriptionTier(str, Enum):
    FREE = "free"
    BASIC = "basic"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"

TIER_LIMITS = {
    SubscriptionTier.FREE: {
        "url_checks_per_hour": 100,
        "bulk_check_size": 10,
        "broken_link_scans_per_hour": 10,
        "social_checks_per_hour": 50,
        "ai_analysis": False,
        "priority_processing": False,
        "webhook_support": False
    },
    SubscriptionTier.PREMIUM: {
        "url_checks_per_hour": 1000,
        "bulk_check_size": 100,
        "broken_link_scans_per_hour": 50,
        "social_checks_per_hour": 500,
        "ai_analysis": True,
        "priority_processing": True,
        "webhook_support": True
    }
}
```

---

## 4. API Endpoints

### 4.1 URL Protection Endpoints

#### 4.1.1 Quick URL Check
```python
@router.post("/api/v1/ext/url/check", response_model=ExtensionURLCheckResponse)
async def quick_url_check(
    request: ExtensionURLCheckRequest,
    user: User = Depends(get_current_user)
) -> ExtensionURLCheckResponse:
    """
    Quick URL security check optimized for real-time extension use.
    
    Features:
    - Sub-second response time
    - Cached results for frequent URLs
    - Minimal payload for bandwidth efficiency
    - Automatic threat level classification
    
    Rate Limit: User tier dependent
    Cache TTL: 5 minutes for safe URLs, 1 hour for threats
    """
```

**Request Model:**
```python
class ExtensionURLCheckRequest(BaseModel):
    url: str = Field(..., description="URL to analyze")
    scan_types: List[ScanType] = Field(
        default=[ScanType.SECURITY, ScanType.REPUTATION],
        description="Types of scans to perform"
    )
    use_cache: bool = Field(default=True, description="Use cached results")
    priority: bool = Field(default=False, description="Priority processing (premium)")
```

**Response Model:**
```python
class ExtensionURLCheckResponse(BaseModel):
    check_id: uuid.UUID
    url: str
    threat_level: ThreatLevel
    confidence_score: float
    is_safe: bool
    threat_types: List[str]
    short_summary: str  # One-line description
    recommended_action: str  # "block", "warn", "allow"
    details_url: str  # Link to full report
    cached: bool
    scan_duration_ms: int
```

#### 4.1.2 Bulk URL Check
```python
@router.post("/api/v1/ext/url/bulk-check", response_model=ExtensionBulkCheckResponse)
async def bulk_url_check(
    request: ExtensionBulkCheckRequest,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user)
) -> ExtensionBulkCheckResponse:
    """
    Batch URL analysis for page scanning.
    
    Use Cases:
    - Scanning all links on a page
    - Batch verification of bookmarks
    - Scheduled security audits
    
    Processing:
    - Immediate response with check IDs
    - Async processing in background
    - Webhook notification on completion (premium)
    
    Rate Limit: Tier dependent (free: 10 URLs, premium: 100 URLs)
    """
```

#### 4.1.3 Get URL Check Status
```python
@router.get("/api/v1/ext/url/check/{check_id}", response_model=ExtensionURLCheckResponse)
async def get_url_check_status(
    check_id: uuid.UUID,
    user: User = Depends(get_current_user)
) -> ExtensionURLCheckResponse:
    """Retrieve status and results of a URL check."""
```

#### 4.1.4 Domain Reputation
```python
@router.get("/api/v1/ext/domain/reputation/{domain}", response_model=DomainReputationResponse)
async def get_domain_reputation(
    domain: str,
    user: Optional[User] = Depends(get_optional_user)
) -> DomainReputationResponse:
    """
    Get domain reputation information.
    
    Features:
    - Historical threat data
    - Community ratings
    - First-seen and last-seen timestamps
    - Malicious activity count
    
    Public endpoint (no auth required, but rate limited)
    """
```

### 4.2 Social Media Protection Endpoints

#### 4.2.1 Analyze Social Profile
```python
@router.post("/api/v1/ext/social/profile", response_model=SocialProfileAnalysisResponse)
async def analyze_social_profile(
    request: SocialProfileAnalysisRequest,
    user: User = Depends(get_current_user)
) -> SocialProfileAnalysisResponse:
    """
    Analyze social media profile for authenticity.
    
    Analysis Includes:
    - Fake profile detection
    - Bot account identification
    - Engagement manipulation detection
    - Account age and activity patterns
    - Profile completeness and consistency
    
    Supported Platforms: Twitter, Facebook, Instagram, LinkedIn
    Rate Limit: Tier dependent
    """
```

**Request Model:**
```python
class SocialProfileAnalysisRequest(BaseModel):
    platform: SocialPlatform
    profile_data: Dict[str, Any]  # Platform-specific profile data
    include_posts: bool = Field(default=False, description="Analyze recent posts")
    deep_analysis: bool = Field(default=False, description="AI-powered deep analysis (premium)")
```

**Response Model:**
```python
class SocialProfileAnalysisResponse(BaseModel):
    profile_id: str
    platform: SocialPlatform
    authenticity_score: float  # 0-100
    is_fake: bool
    is_bot: bool
    risk_factors: List[str]
    confidence: float
    recommendations: List[str]
    detailed_report: Optional[Dict[str, Any]]
```

#### 4.2.2 Analyze Social Post
```python
@router.post("/api/v1/ext/social/post", response_model=SocialPostAnalysisResponse)
async def analyze_social_post(
    request: SocialPostAnalysisRequest,
    user: User = Depends(get_current_user)
) -> SocialPostAnalysisResponse:
    """
    Analyze social media post for threats and content risk.
    
    Analysis Includes:
    - Malicious link detection
    - Scam pattern recognition
    - Spam detection
    - Engagement bait identification
    - Misinformation indicators
    
    Real-time processing for instant warnings
    """
```

#### 4.2.3 Check Engagement Authenticity
```python
@router.
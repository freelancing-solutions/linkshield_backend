# Specialized Controllers Specification

## Overview

The specialized controllers provide focused interfaces for different types of users and use cases within the social protection system. Each controller is optimized for specific workflows and user needs.

## Architecture

### Controller Structure
```
src/social_protection/controllers/
├── __init__.py
├── social_protection_controller.py  # Main controller
├── user_controller.py              # User-focused operations
├── bot_controller.py               # Bot integration and automation
└── extension_controller.py         # Browser extension integration
```

## Components

### 1. UserController

**Purpose**: User-focused social protection operations with personalized analytics and settings management

**Target Users**:
- Individual users managing their social media presence
- Content creators optimizing their reach
- Social media managers monitoring accounts

**Key Features**:
- Personalized dashboard and analytics
- Account protection settings management
- Content performance tracking
- Risk assessment and recommendations
- Historical data analysis

**Core Endpoints**:
```python
# Account Management
GET    /api/v1/social/user/accounts
POST   /api/v1/social/user/accounts
PUT    /api/v1/social/user/accounts/{account_id}
DELETE /api/v1/social/user/accounts/{account_id}

# Protection Settings
GET    /api/v1/social/user/protection/settings
PUT    /api/v1/social/user/protection/settings
POST   /api/v1/social/user/protection/settings/reset

# Analytics and Monitoring
GET    /api/v1/social/user/analytics/dashboard
GET    /api/v1/social/user/analytics/performance/{account_id}
GET    /api/v1/social/user/analytics/trends/{account_id}
GET    /api/v1/social/user/analytics/reports/{report_id}

# Content Analysis
POST   /api/v1/social/user/content/analyze
GET    /api/v1/social/user/content/history
POST   /api/v1/social/user/content/batch-analyze

# Risk Management
GET    /api/v1/social/user/risks/assessment
GET    /api/v1/social/user/risks/recommendations
POST   /api/v1/social/user/risks/acknowledge
```

**Data Models**:
```python
@dataclass
class UserProtectionSettings:
    user_id: str
    auto_scan_enabled: bool
    risk_threshold: RiskLevel
    notification_preferences: Dict[str, bool]
    protected_platforms: List[PlatformType]
    analysis_frequency: str
    privacy_settings: Dict[str, Any]

@dataclass
class UserAnalyticsSummary:
    user_id: str
    total_accounts: int
    total_scans: int
    risk_distribution: Dict[RiskLevel, int]
    performance_trends: Dict[str, Any]
    recent_alerts: List[Dict]
    recommendations: List[str]
```

### 2. BotController

**Purpose**: Bot integration and automated analysis services for rapid content assessment

**Target Users**:
- Discord/Telegram bots
- Automated monitoring systems
- Third-party integrations
- API consumers requiring fast responses

**Key Features**:
- Quick content analysis
- Batch processing capabilities
- Webhook integrations
- Rate-limited API access
- Minimal response formats

**Core Endpoints**:
```python
# Quick Analysis
POST   /api/v1/bot/analyze/quick
POST   /api/v1/bot/analyze/content
POST   /api/v1/bot/analyze/link
POST   /api/v1/bot/analyze/batch

# Bot Management
POST   /api/v1/bot/register
GET    /api/v1/bot/status
PUT    /api/v1/bot/settings
DELETE /api/v1/bot/unregister

# Webhook Integration
POST   /api/v1/bot/webhooks
GET    /api/v1/bot/webhooks
DELETE /api/v1/bot/webhooks/{webhook_id}

# Monitoring
GET    /api/v1/bot/usage/stats
GET    /api/v1/bot/usage/limits
GET    /api/v1/bot/health
```

**Data Models**:
```python
@dataclass
class BotAnalysisRequest:
    content: str
    analysis_type: BotAnalysisType
    response_format: BotResponseFormat
    priority: str
    metadata: Optional[Dict[str, Any]]

@dataclass
class BotAnalysisResponse:
    analysis_id: str
    risk_level: RiskLevel
    risk_score: float
    summary: str
    recommendations: List[str]
    processing_time: float
    confidence: float
```

### 3. ExtensionController

**Purpose**: Browser extension integration for real-time content analysis and seamless user experience

**Target Users**:
- Browser extension users
- Real-time content monitoring
- Interactive web applications
- Client-side integrations

**Key Features**:
- Real-time content analysis
- Page context processing
- Interactive risk warnings
- Seamless browser integration
- Low-latency responses

**Core Endpoints**:
```python
# Real-time Analysis
POST   /api/v1/extension/analyze/page
POST   /api/v1/extension/analyze/content
POST   /api/v1/extension/analyze/link
POST   /api/v1/extension/analyze/profile

# Extension Management
POST   /api/v1/extension/register
GET    /api/v1/extension/settings
PUT    /api/v1/extension/settings
POST   /api/v1/extension/sync

# Event Processing
POST   /api/v1/extension/events
GET    /api/v1/extension/events/history
POST   /api/v1/extension/events/batch

# User Interface
GET    /api/v1/extension/ui/warnings
POST   /api/v1/extension/ui/dismiss
GET    /api/v1/extension/ui/recommendations
```

**Data Models**:
```python
@dataclass
class ExtensionAnalysisRequest:
    url: str
    content: str
    page_context: Dict[str, Any]
    user_context: Dict[str, Any]
    analysis_mode: ExtensionAnalysisMode
    priority: str

@dataclass
class ExtensionAnalysisResponse:
    analysis_id: str
    risk_assessment: Dict[str, Any]
    warnings: List[Dict[str, Any]]
    recommendations: List[str]
    ui_elements: Dict[str, Any]
    processing_time: float
```

## Integration Architecture

### Service Dependencies
```python
# Common Dependencies (All Controllers)
- SecurityService: Authentication and authorization
- AuthService: User authentication
- EmailService: Notifications
- SocialScanService: Core scanning functionality

# Content Analysis Services
- ContentRiskAnalyzer: Content risk assessment
- LinkPenaltyDetector: Link safety analysis
- SpamPatternDetector: Spam detection
- CommunityNotesAnalyzer: Fact-check risk analysis

# Algorithm Health Services
- VisibilityScorer: Visibility analysis
- EngagementAnalyzer: Engagement patterns
- PenaltyDetector: Penalty detection
- ShadowBanDetector: Shadow ban analysis
```

### Controller Relationships
```
UserController
├── Provides comprehensive user experience
├── Uses all analysis services
└── Integrates with dashboard and reporting

BotController
├── Optimized for automation
├── Focuses on quick analysis
└── Minimal response formats

ExtensionController
├── Real-time browser integration
├── Context-aware analysis
└── Interactive user interface
```

## Performance Requirements

### UserController
- **Dashboard Load**: < 2 seconds
- **Analysis Request**: < 3 seconds
- **Batch Processing**: 100 items in < 30 seconds
- **Concurrent Users**: Support 1000+ simultaneous users

### BotController
- **Quick Analysis**: < 1 second
- **Batch Processing**: 500 items in < 10 seconds
- **Rate Limiting**: 1000 requests/minute per bot
- **Concurrent Bots**: Support 100+ simultaneous bots

### ExtensionController
- **Real-time Analysis**: < 500ms
- **Page Analysis**: < 2 seconds
- **Event Processing**: < 100ms
- **Concurrent Extensions**: Support 10,000+ simultaneous users

## Security Considerations

### Authentication and Authorization
- JWT-based authentication for all controllers
- Role-based access control (RBAC)
- API key management for bot integrations
- Extension-specific security tokens

### Rate Limiting
```python
RATE_LIMITS = {
    "user_controller": {
        "analysis_requests": "100/hour",
        "dashboard_loads": "1000/hour",
        "settings_updates": "10/hour"
    },
    "bot_controller": {
        "quick_analysis": "1000/minute",
        "batch_requests": "10/minute",
        "webhook_calls": "100/minute"
    },
    "extension_controller": {
        "real_time_analysis": "500/minute",
        "page_analysis": "100/minute",
        "event_processing": "1000/minute"
    }
}
```

### Data Protection
- Input sanitization and validation
- Secure data transmission (HTTPS)
- Privacy-compliant data handling
- Audit logging for all operations

## Testing Strategy

### Unit Tests
- Controller method functionality
- Request/response validation
- Error handling scenarios
- Security controls

### Integration Tests
- Service integration
- Database operations
- External API calls
- Cross-controller compatibility

### Performance Tests
- Load testing for each controller
- Concurrent user simulation
- Response time validation
- Resource utilization monitoring

### Security Tests
- Authentication bypass attempts
- Authorization validation
- Input injection testing
- Rate limiting verification

## Monitoring and Metrics

### Key Performance Indicators
- Request/response times
- Success/error rates
- User engagement metrics
- Resource utilization
- Security incident counts

### Alerting Thresholds
- Response time > 5 seconds
- Error rate > 5%
- Rate limit violations
- Security anomalies
- Resource exhaustion

## Future Enhancements

1. **GraphQL Integration**: Flexible query capabilities
2. **WebSocket Support**: Real-time bidirectional communication
3. **Mobile SDK**: Native mobile app integration
4. **Advanced Analytics**: Machine learning-powered insights
5. **Multi-tenant Support**: Enterprise-grade multi-tenancy
6. **API Versioning**: Backward compatibility management
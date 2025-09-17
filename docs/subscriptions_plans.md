# Subscription Plans

This document describes LinkShield's subscription tiers, features, usage limits, and billing structure based on the current implementation.

## Overview

LinkShield offers three subscription tiers designed to meet different user needs:
- **Free**: Basic URL analysis for individual users
- **Pro**: Enhanced features for power users and small teams  
- **Enterprise**: Full-featured solution for organizations

## Plan Comparison

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| **Monthly URL Checks** | 5 | 500 | 2,500 |
| **AI Content Analysis** | 2/month | 50/month | 500/month |
| **Projects** | 1 | Unlimited | Unlimited |
| **Team Members** | 1 | Unlimited | Unlimited |
| **Report Sharing** | ✅ | ✅ | ✅ |
| **Custom Branding** | ❌ | ❌ | ✅ |
| **API Access** | Limited | Standard | Premium |
| **Priority Support** | ❌ | ✅ | ✅ |
| **Advanced Analytics** | ❌ | ✅ | ✅ |
| **Bulk URL Import** | ❌ | ✅ | ✅ |
| **Export Reports** | Basic | Advanced | Enterprise |
| **SLA** | None | 99.5% | 99.9% |
| **Price** | Free | $19/month | $99/month |

## Free Plan

### Features
- **5 URL checks per month**
- **2 AI content analyses per month**
- Basic security analysis
- Domain reputation checking
- SSL certificate validation
- Phishing and malware detection
- Report sharing capabilities
- 1 project for organization
- Web dashboard access

### Limitations
- Limited AI-powered content analysis (2 per month)
- Limited to 5 checks per calendar month
- Basic support via documentation
- Single user account
- Standard report formats only

### Ideal For
- Individual users
- Personal URL verification
- Basic security checking
- Testing LinkShield features

## Pro Plan - $19/month

### Enhanced Features
- **500 URL checks per month**
- **50 AI content analyses per month**
- All Free plan features
- Advanced content quality scoring
- Topic categorization
- Content length analysis
- Historical trend analysis
- Unlimited projects
- Team collaboration (unlimited members)
- Priority email support
- Advanced analytics dashboard
- Bulk URL import (CSV/Excel)
- Enhanced report exports (PDF, CSV, JSON)
- API access with higher rate limits

### Advanced Analytics
- Security trend analysis
- Content quality metrics
- Team usage statistics
- Project-level reporting
- Custom date range filtering
- Export capabilities

### Payment Processing
- **PayPal**: $19.00 USD
- Immediate activation upon payment

### Ideal For
- Small to medium businesses
- Marketing teams
- Content creators
- Security professionals
- Development teams

## Enterprise Plan - $99/month

### Premium Features
- **2,500 URL checks per month**
- **500 AI content analyses per month**
- All Pro plan features
- Unlimited projects and team members
- Custom branding and white-labeling
- Advanced API access with premium limits
- Dedicated account manager
- Custom integrations
- SSO (Single Sign-On) support
- Advanced compliance features
- Custom SLA (99.9% uptime)
- On-premise deployment options
- Custom reporting and analytics

### Enterprise-Only Features
- **Custom Branding**: Add your logo and colors
- **White-label Reports**: Remove LinkShield branding
- **SSO Integration**: SAML, OIDC, Active Directory
- **Advanced Permissions**: Granular role-based access
- **Audit Logging**: Comprehensive activity tracking
- **Custom Integrations**: API webhooks and custom endpoints
- **Dedicated Infrastructure**: Isolated resources
- **Compliance**: SOC 2, GDPR, HIPAA support

### Payment Processing
- **PayPal**: $99.00 USD
- **Stripe**: Managed through Stripe pricing tiers
- Monthly billing cycle
- Custom billing terms available

### Ideal For
- Large enterprises
- Government agencies
- Financial institutions
- Healthcare organizations
- Companies with strict compliance requirements

## Usage Limits and Quotas

### Current Implementation
```typescript
// Plan limits as implemented in the system
const PLAN_LIMITS = {
  free: { 
    checksPerMonth: 5, 
    aiAnalysesPerMonth: 2 
  },
  pro: { 
    checksPerMonth: 500, 
    aiAnalysesPerMonth: 50 
  },
  enterprise: { 
    checksPerMonth: 2500, 
    aiAnalysesPerMonth: 500 
  }
}
```

### Monthly Reset Cycle
All usage limits reset on the first day of each calendar month at 00:00 UTC.

### Quota Tracking
- Real-time usage monitoring
- Dashboard displays current usage vs. limits
- Automatic enforcement of plan limits
- Usage statistics available in dashboard

### Overage Handling

**Free Plan**
- Hard limits enforced
- No overage allowed
- Upgrade prompt displayed when limits reached

**Pro Plan**
- Hard limits enforced at current implementation
- Upgrade to Enterprise for higher limits
- Usage monitoring and alerts

**Enterprise Plan**
- Highest tier limits
- Custom arrangements for additional usage
- Dedicated support for capacity planning

## Plan Features in Detail

### URL Analysis Features

**Security Analysis (All Plans)**
- Domain reputation checking
- SSL certificate validation
- Phishing detection
- Malware scanning
- Blacklist checking
- Redirect chain analysis
- Content safety assessment

**AI Content Analysis (All Plans with Limits)**
- Content quality scoring
- Topic categorization
- Readability analysis
- Content length metrics
- Language detection
- Sentiment analysis
- Quality assessment algorithms

### Reporting and Analytics

**Basic Reports (Free)**
- Individual URL analysis results
- Basic security scores
- Simple sharing links
- Standard report retention

**Advanced Reports (Pro)**
- Batch analysis summaries
- Trend analysis over time
- Custom report templates
- Multiple export formats
- Extended report retention

**Enterprise Reports (Enterprise)**
- Custom branded reports
- White-label options
- Advanced analytics dashboards
- Real-time monitoring
- Comprehensive report retention

### Team Collaboration

**Pro Team Features**
- Unlimited team members
- Shared projects and reports
- Collaborative workspace
- Team activity tracking
- Project-based organization

**Enterprise Team Features**
- Advanced role-based permissions
- Department-level organization
- Audit trails and compliance
- Custom approval workflows
- Enterprise-grade security

## API Access Tiers

### Free API Access
- Limited requests per hour
- Basic endpoints only
- Standard rate limiting
- Community support

### Pro API Access
- Increased request limits
- All analysis endpoints
- Enhanced rate limits
- Priority support

### Enterprise API Access
- Premium request limits
- Custom endpoints
- Dedicated infrastructure
- SLA guarantees
- Custom integrations

## Billing and Payment

### Payment Methods
- **Credit/Debit Cards** (via Stripe)
- **PayPal** (direct integration)
- **Bank Transfer** (Enterprise)
- **Purchase Orders** (Enterprise)

### Pricing Structure
- **Free**: $0/month
- **Pro**: $19/month (PayPal), Stripe pricing varies
- **Enterprise**: $99/month (PayPal), Stripe pricing varies

### Billing Cycles
- **Monthly**: Billed on the same date each month
- **Annual**: Discounts available for annual commitments
- **Enterprise**: Custom billing terms

### Currency Support
- USD (Primary)
- Additional currencies through payment processors
- Enterprise custom currency arrangements

### Tax Handling
- Automatic tax calculation through payment processors
- VAT support for international customers
- Tax-exempt status for qualifying organizations

## Plan Management

### Upgrading Plans

**Free to Pro**
1. Access billing settings in dashboard
2. Select Pro plan
3. Choose payment method (Stripe or PayPal)
4. Complete payment process
5. Immediate plan activation

**Pro to Enterprise**
1. Select Enterprise plan in dashboard
2. Complete payment process
3. Enhanced features activated immediately
4. Access to enterprise-specific features

### Downgrading Plans

**Pro/Enterprise to Free**
- Allowed at end of billing cycle
- Usage limits immediately reduced to Free tier
- Data retention according to Free plan limits
- Advanced features disabled

### Plan Changes
- Upgrades take effect immediately
- Downgrades take effect at next billing cycle
- Usage limits adjusted immediately
- Prorated billing where applicable

## Usage Monitoring

### Dashboard Metrics
- Current month usage vs. limits
- Historical usage trends
- Real-time usage tracking
- Plan limit notifications
- Usage analytics and insights

### Notifications
- Approaching limit warnings
- Limit exceeded notifications
- Monthly usage summaries
- Billing reminders
- Plan upgrade suggestions

### Usage Analytics Interface
```typescript
// Usage tracking as implemented
interface UsageMetrics {
  checksThisMonth: number
  aiAnalysesThisMonth: number
  checksLimit: number
  aiAnalysesLimit: number
  planType: 'free' | 'pro' | 'enterprise'
  resetDate: Date
}
```

## Fair Use Policy

### Acceptable Use
- Legitimate URL analysis for security purposes
- Content quality assessment
- Business intelligence gathering
- Academic research (with proper attribution)
- Security research and analysis

### Prohibited Use
- Automated scraping or crawling beyond plan limits
- Malicious or illegal activities
- Circumventing usage limits
- Reselling analysis results without permission
- Competitive intelligence on LinkShield

### Enforcement
- Automated monitoring for abuse
- Account suspension for violations
- Appeal process available
- Permanent ban for severe violations

## Support Levels

### Free Plan Support
- Documentation and knowledge base
- Community forums
- Email support (standard response time)
- Basic troubleshooting

### Pro Plan Support
- Priority email support
- Enhanced documentation access
- Faster response times
- Advanced troubleshooting

### Enterprise Support
- Dedicated account management
- Priority support channels
- Custom SLA agreements
- Advanced technical support
- Custom training and onboarding

## Migration and Data Export

### Data Portability
- Export all analysis results
- Project and team data export
- Custom report generation
- API access for data migration
- Bulk export capabilities

### Account Management
- Plan change history
- Usage history export
- Billing history access
- Data retention policies
- Account closure procedures

## Compliance and Security

### Data Protection
- GDPR compliance (all plans)
- Data encryption at rest and in transit
- Regular security audits
- Privacy-focused design

### Security Features
- Secure payment processing
- API authentication and authorization
- Rate limiting and abuse prevention
- Audit logging for enterprise

## Implementation Notes

### Technical Architecture
- Plan limits enforced at API level
- Real-time usage tracking
- Automatic plan validation
- Secure payment webhook handling
- Database-driven plan management

### Payment Integration
- Dual payment processor support (Stripe + PayPal)
- Webhook-based plan activation
- Automatic subscription management
- Secure payment data handling

This subscription structure provides clear tiers with appropriate limits while ensuring sustainable growth and feature development for LinkShield.

# Dashboard API Specification

## Overview

The Dashboard API provides comprehensive project management, monitoring configuration, and team collaboration features for LinkShield. It integrates with the existing subscription system to enforce limits and provides a unified interface for managing multiple projects.

## Architecture

### Controller Architecture
- **DashboardController**: Central business logic controller
- **Pydantic Models**: Type-safe request/response models
- **Dependency Injection**: Clean separation of concerns
- **Access Control**: Role-based permissions with subscription limits

### Database Integration
- **Project Model**: Core project information with settings
- **ProjectMember Model**: Team member relationships and roles
- **MonitoringConfig Model**: Scanning configuration per project
- **ProjectAlert Model**: Alert management and tracking
- **Subscription Integration**: Enforces plan limits and features

## API Endpoints

### Dashboard Overview
```
GET /dashboard/overview
```
Returns comprehensive dashboard overview including:
- Total and active projects count
- Recent alerts summary
- Subscription status
- Usage statistics
- Recent activity feed
- Monitoring summary

### Project Management

#### List Projects
```
GET /dashboard/projects?page=1&limit=20&search=term&status_filter=active
```
- Pagination support (page-based)
- Search by project name/domain
- Filter by status (active/inactive)
- Returns project list with member counts

#### Create Project
```
POST /dashboard/projects
```
Request body:
```json
{
  "name": "My Website",
  "description": "Main website monitoring",
  "website_url": "https://example.com",
  "settings": {
    "custom_field": "value"
  }
}
```
- Automatic domain extraction from URL
- Default monitoring configuration created
- Subscription limit validation

#### Get Project
```
GET /dashboard/projects/{project_id}
```
- Full project details with member count
- Access control validation
- Monitoring configuration included

#### Update Project
```
PATCH /dashboard/projects/{project_id}
```
Request body (all fields optional):
```json
{
  "name": "Updated Name",
  "description": "Updated description",
  "website_url": "https://new-domain.com",
  "settings": {"key": "value"},
  "is_active": true
}
```
- Permission-based access (owner/admin only)
- Partial updates supported
- Activity logging enabled

#### Delete Project
```
DELETE /dashboard/projects/{project_id}
```
- Soft delete (sets is_active = false)
- Owner-only permission
- Monitoring disabled on delete

### Monitoring Control

#### Toggle Monitoring
```
POST /dashboard/projects/{project_id}/monitoring/{enabled}
```
- Enable/disable project monitoring
- Automatic configuration creation if missing
- Activity logging

### Team Management

#### List Project Members
```
GET /dashboard/projects/{project_id}/members
```
- All active team members
- Includes invitation status
- User details (email, name, role)

#### Invite Team Member
```
POST /dashboard/projects/{project_id}/members/invite
```
Request body:
```json
{
  "email": "teammate@example.com",
  "role": "editor"
}
```
- Subscription limit validation
- Email invitation system
- Pending invitation tracking
- Role-based permissions

### Analytics (Placeholder)
```
GET /dashboard/analytics?date_from=2024-01-01&date_to=2024-01-31
```
Returns:
- Scan statistics
- Alert trends
- Usage patterns
- Subscription usage

### Alert Management (Placeholder)
```
GET /dashboard/alerts?limit=20&resolved=false
PATCH /dashboard/alerts/{alert_id}/resolve
```
- Alert listing and filtering
- Alert resolution
- Notification system

## Data Models

### ProjectResponse
```json
{
  "id": "uuid",
  "name": "string",
  "description": "string",
  "website_url": "string",
  "domain": "string",
  "is_active": "boolean",
  "monitoring_enabled": "boolean",
  "settings": "object",
  "member_count": "integer",
  "created_at": "datetime",
  "updated_at": "datetime",
  "last_scan_at": "datetime"
}
```

### DashboardOverviewResponse
```json
{
  "total_projects": "integer",
  "active_projects": "integer",
  "recent_alerts": "integer",
  "subscription_status": "string",
  "usage_stats": "object",
  "recent_activity": "array",
  "monitoring_summary": "object"
}
```

### MemberResponse
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "email": "string",
  "full_name": "string",
  "role": "string",
  "is_active": "boolean",
  "joined_at": "datetime",
  "invited_at": "datetime"
}
```

## Subscription Integration

### Plan Limits Enforced
- **Project Creation**: Limited by subscription plan
- **Team Members**: Limited by subscription plan
- **Monitoring Features**: Based on plan capabilities
- **Daily/Monthly Checks**: Enforced through subscription

### Usage Tracking
- Daily check usage
- Monthly check usage
- Project count tracking
- Team member count

## Access Control

### Role-Based Permissions
- **Owner**: Full project control, member management
- **Admin**: Project updates, member management
- **Editor**: Project updates, view members
- **Viewer**: Read-only access

### Subscription-Based Access
- Plan feature validation
- Usage limit enforcement
- Upgrade prompts for limits

## Error Handling

### Standard Error Responses
```json
{
  "detail": "Error message",
  "error_code": "ERROR_CODE"
}
```

### Common Error Codes
- `PROJECT_NOT_FOUND`: Project doesn't exist
- `ACCESS_DENIED`: Insufficient permissions
- `SUBSCRIPTION_LIMIT_REACHED`: Plan limit exceeded
- `VALIDATION_ERROR`: Invalid input data
- `CONFLICT`: Resource conflict (duplicate)

## Security Features

### Input Validation
- Pydantic model validation
- Email format validation
- URL format validation
- Role enumeration validation

### Rate Limiting
- Per-user rate limits
- Per-endpoint rate limits
- Invitation rate limiting
- Project creation rate limiting

### Access Control
- JWT-based authentication
- Role-based authorization
- Subscription-based access
- Resource ownership validation

## Performance Optimizations

### Database Queries
- Efficient joins for member counts
- Pagination for large datasets
- Index-based filtering
- Connection pooling

### Caching Strategy
- Subscription validation caching
- Project metadata caching
- Activity feed optimization
- Rate limit tracking

## Integration Points

### Existing Services
- **AuthService**: User authentication and authorization
- **SecurityService**: Token generation and validation
- **EmailService**: Invitation and notification emails
- **SubscriptionService**: Plan validation and usage tracking

### Future Integrations
- **AnalyticsService**: Comprehensive reporting
- **MonitoringService**: Real-time status tracking
- **NotificationService**: Multi-channel alerts
- **BillingService**: Subscription management

## Testing Strategy

### Unit Tests
- Controller method testing
- Model validation testing
- Access control testing
- Subscription limit testing

### Integration Tests
- API endpoint testing
- Database integration testing
- Service integration testing
- Error handling testing

### Load Testing
- Concurrent user testing
- Rate limit testing
- Database performance testing
- Subscription limit testing

## Monitoring and Logging

### Activity Logging
- Project creation/deletion
- Member invitation/acceptance
- Monitoring enable/disable
- Configuration changes

### Error Logging
- Database errors
- Validation errors
- Access control failures
- Subscription limit violations

### Performance Metrics
- API response times
- Database query performance
- Rate limit effectiveness
- Subscription usage patterns

## Future Enhancements

### Planned Features
- Advanced analytics dashboard
- Real-time monitoring status
- Team collaboration features
- Advanced notification system
- Multi-project management
- API key management
- Webhook support
- Custom integrations

### Scalability Improvements
- Database sharding
- Caching layer
- Message queue integration
- Microservices architecture
- CDN integration
- Load balancing

This specification provides a comprehensive foundation for the Dashboard API implementation while maintaining compatibility with the existing LinkShield architecture and subscription system.
# Admin Database Schema Documentation

## Overview

The LinkShield admin database schema is designed to support comprehensive administrative functionality with a focus on security, performance, and scalability. The schema includes four core admin tables with supporting enums, relationships, and a strategic indexing approach optimized for common admin operations.

**Database Engine**: PostgreSQL 14+  
**ORM**: SQLAlchemy with Alembic migrations  
**Schema Version**: 2.1.0  
**Last Updated**: January 2024

## Schema Architecture

### Entity Relationship Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Admin Database Schema                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐            │
│  │   admin_users   │    │  admin_roles    │    │ admin_sessions  │            │
│  │                 │    │                 │    │                 │            │
│  │ • id (PK)       │    │ • id (PK)       │    │ • id (PK)       │            │
│  │ • email         │◄───┤ • name          │    │ • admin_id (FK) │            │
│  │ • password_hash │    │ • permissions   │    │ • session_token │            │
│  │ • role_id (FK)  ├────┤ • description   │    │ • expires_at    │            │
│  │ • created_at    │    │ • is_active     │    │ • created_at    │            │
│  │ • updated_at    │    │ • created_at    │    │ • last_activity │            │
│  │ • is_active     │    │ • updated_at    │    │ • ip_address    │            │
│  │ • last_login    │    └─────────────────┘    │ • user_agent    │            │
│  │ • login_attempts│                           │ • is_active     │            │
│  │ • locked_until  │                           └─────────────────┘            │
│  │ • profile_data  │                                    │                      │
│  └─────────────────┘                                    │                      │
│           │                                             │                      │
│           │                                             ▼                      │
│           │                           ┌─────────────────────────────────────┐  │
│           │                           │         admin_audit_logs            │  │
│           │                           │                                     │  │
│           │                           │ • id (PK)                           │  │
│           │                           │ • audit_id (UNIQUE)                 │  │
│           │                           │ • admin_id (FK)                     │  │
│           └───────────────────────────┤ • session_id (FK)                   │  │
│                                       │ • timestamp                         │  │
│                                       │ • action_type                       │  │
│                                       │ • resource_type                     │  │
│                                       │ • resource_id                       │  │
│                                       │ • request_data                      │  │
│                                       │ • response_data                     │  │
│                                       │ • ip_address                        │  │
│                                       │ • user_agent                        │  │
│                                       │ • success                           │  │
│                                       │ • error_message                     │  │
│                                       │ • processing_time_ms                │  │
│                                       │ • risk_level                        │  │
│                                       └─────────────────────────────────────┘  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Table Definitions

### 1. admin_users

The core table storing admin user accounts and authentication information.

```sql
CREATE TABLE admin_users (
    -- Primary identification
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Authentication credentials
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    
    -- Role and permissions
    role_id UUID NOT NULL REFERENCES admin_roles(id) ON DELETE RESTRICT,
    
    -- Personal information
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    display_name VARCHAR(200),
    
    -- Account status and security
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE NOT NULL,
    is_locked BOOLEAN DEFAULT FALSE NOT NULL,
    
    -- Login tracking
    last_login TIMESTAMP WITH TIME ZONE,
    login_attempts INTEGER DEFAULT 0 NOT NULL,
    locked_until TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Two-factor authentication
    two_factor_enabled BOOLEAN DEFAULT FALSE NOT NULL,
    two_factor_secret VARCHAR(32),
    backup_codes TEXT[], -- Array of backup codes
    
    -- Profile and preferences
    profile_data JSONB DEFAULT '{}',
    preferences JSONB DEFAULT '{}',
    timezone VARCHAR(50) DEFAULT 'UTC',
    language VARCHAR(10) DEFAULT 'en',
    
    -- Audit timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    created_by UUID REFERENCES admin_users(id),
    updated_by UUID REFERENCES admin_users(id),
    
    -- Soft delete
    deleted_at TIMESTAMP WITH TIME ZONE,
    deleted_by UUID REFERENCES admin_users(id),
    
    -- Constraints
    CONSTRAINT admin_users_email_check CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT admin_users_login_attempts_check CHECK (login_attempts >= 0),
    CONSTRAINT admin_users_names_check CHECK (
        (first_name IS NULL AND last_name IS NULL) OR 
        (first_name IS NOT NULL AND last_name IS NOT NULL)
    )
);

-- Indexes for admin_users
CREATE INDEX idx_admin_users_email ON admin_users (email) WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_users_role_id ON admin_users (role_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_users_is_active ON admin_users (is_active) WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_users_last_login ON admin_users (last_login) WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_users_created_at ON admin_users (created_at) WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_users_locked_until ON admin_users (locked_until) WHERE locked_until IS NOT NULL;

-- Partial index for active users only
CREATE INDEX idx_admin_users_active ON admin_users (id, email, role_id) 
    WHERE is_active = TRUE AND deleted_at IS NULL;
```

#### Field Descriptions

| Field | Type | Description | Constraints |
|-------|------|-------------|-------------|
| `id` | UUID | Primary key, auto-generated | NOT NULL, PRIMARY KEY |
| `email` | VARCHAR(255) | Unique email address for login | NOT NULL, UNIQUE, Valid email format |
| `password_hash` | VARCHAR(255) | Bcrypt hashed password | NOT NULL |
| `role_id` | UUID | Foreign key to admin_roles | NOT NULL, REFERENCES admin_roles(id) |
| `first_name` | VARCHAR(100) | Admin's first name | Optional |
| `last_name` | VARCHAR(100) | Admin's last name | Optional |
| `display_name` | VARCHAR(200) | Display name for UI | Optional |
| `is_active` | BOOLEAN | Account active status | NOT NULL, DEFAULT TRUE |
| `is_verified` | BOOLEAN | Email verification status | NOT NULL, DEFAULT FALSE |
| `is_locked` | BOOLEAN | Account lock status | NOT NULL, DEFAULT FALSE |
| `last_login` | TIMESTAMP | Last successful login time | Optional |
| `login_attempts` | INTEGER | Failed login attempt counter | NOT NULL, DEFAULT 0, >= 0 |
| `locked_until` | TIMESTAMP | Account unlock time | Optional |
| `password_changed_at` | TIMESTAMP | Last password change time | NOT NULL, DEFAULT NOW() |
| `two_factor_enabled` | BOOLEAN | 2FA enablement status | NOT NULL, DEFAULT FALSE |
| `two_factor_secret` | VARCHAR(32) | TOTP secret key | Optional |
| `backup_codes` | TEXT[] | 2FA backup codes array | Optional |
| `profile_data` | JSONB | Additional profile information | DEFAULT '{}' |
| `preferences` | JSONB | User preferences and settings | DEFAULT '{}' |
| `timezone` | VARCHAR(50) | User's timezone | DEFAULT 'UTC' |
| `language` | VARCHAR(10) | Preferred language code | DEFAULT 'en' |

### 2. admin_roles

Defines admin roles and their associated permissions using RBAC (Role-Based Access Control).

```sql
CREATE TABLE admin_roles (
    -- Primary identification
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Role definition
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    
    -- Permissions (stored as JSON array)
    permissions JSONB NOT NULL DEFAULT '[]',
    
    -- Role hierarchy and inheritance
    parent_role_id UUID REFERENCES admin_roles(id) ON DELETE SET NULL,
    role_level INTEGER NOT NULL DEFAULT 1,
    
    -- Role status and configuration
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_system_role BOOLEAN DEFAULT FALSE NOT NULL, -- Cannot be deleted
    is_default BOOLEAN DEFAULT FALSE NOT NULL,
    
    -- Access restrictions
    max_sessions INTEGER DEFAULT 5,
    session_timeout_minutes INTEGER DEFAULT 480, -- 8 hours
    allowed_ip_ranges TEXT[], -- CIDR notation
    
    -- Audit timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    created_by UUID REFERENCES admin_users(id),
    updated_by UUID REFERENCES admin_users(id),
    
    -- Constraints
    CONSTRAINT admin_roles_name_check CHECK (name ~* '^[a-z_]+$'),
    CONSTRAINT admin_roles_level_check CHECK (role_level > 0 AND role_level <= 10),
    CONSTRAINT admin_roles_max_sessions_check CHECK (max_sessions > 0 AND max_sessions <= 100),
    CONSTRAINT admin_roles_timeout_check CHECK (session_timeout_minutes > 0)
);

-- Indexes for admin_roles
CREATE INDEX idx_admin_roles_name ON admin_roles (name) WHERE is_active = TRUE;
CREATE INDEX idx_admin_roles_parent_role_id ON admin_roles (parent_role_id);
CREATE INDEX idx_admin_roles_role_level ON admin_roles (role_level);
CREATE INDEX idx_admin_roles_is_active ON admin_roles (is_active);
CREATE INDEX idx_admin_roles_is_system ON admin_roles (is_system_role);

-- GIN index for permissions JSON queries
CREATE INDEX idx_admin_roles_permissions ON admin_roles USING GIN (permissions);
```

#### Standard Admin Roles

```sql
-- Insert default admin roles
INSERT INTO admin_roles (name, display_name, description, permissions, role_level, is_system_role, is_default) VALUES
('super_admin', 'Super Administrator', 'Full system access with all permissions', 
 '["*"]', 10, TRUE, FALSE),

('admin', 'Administrator', 'Standard admin with most permissions except system management', 
 '["users:*", "content:*", "reports:*", "monitoring:read"]', 8, TRUE, TRUE),

('moderator', 'Moderator', 'Content moderation and user management', 
 '["users:read", "users:update", "content:*", "reports:read"]', 5, TRUE, FALSE),

('analyst', 'Security Analyst', 'Read-only access to security and monitoring data', 
 '["monitoring:*", "reports:*", "audit:read", "users:read"]', 3, TRUE, FALSE),

('support', 'Support Agent', 'Limited access for customer support', 
 '["users:read", "users:update", "reports:read"]', 2, TRUE, FALSE);
```

### 3. admin_sessions

Tracks active admin sessions for security and session management.

```sql
CREATE TABLE admin_sessions (
    -- Primary identification
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Session identification
    session_token VARCHAR(128) UNIQUE NOT NULL,
    refresh_token VARCHAR(128) UNIQUE,
    
    -- User association
    admin_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    
    -- Session timing
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    
    -- Client information
    ip_address INET NOT NULL,
    user_agent TEXT,
    client_fingerprint VARCHAR(64),
    
    -- Geolocation (optional)
    country_code VARCHAR(2),
    city VARCHAR(100),
    
    -- Session metadata
    login_method VARCHAR(20) DEFAULT 'password', -- password, 2fa, sso
    device_type VARCHAR(20), -- desktop, mobile, tablet
    browser_name VARCHAR(50),
    os_name VARCHAR(50),
    
    -- Session status
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID REFERENCES admin_users(id),
    revoke_reason VARCHAR(100),
    
    -- Security flags
    is_suspicious BOOLEAN DEFAULT FALSE NOT NULL,
    risk_score INTEGER DEFAULT 0, -- 0-100 risk score
    
    -- Additional data
    session_data JSONB DEFAULT '{}',
    
    -- Constraints
    CONSTRAINT admin_sessions_expires_check CHECK (expires_at > created_at),
    CONSTRAINT admin_sessions_risk_score_check CHECK (risk_score >= 0 AND risk_score <= 100),
    CONSTRAINT admin_sessions_revoked_check CHECK (
        (is_revoked = FALSE AND revoked_at IS NULL) OR 
        (is_revoked = TRUE AND revoked_at IS NOT NULL)
    )
);

-- Indexes for admin_sessions
CREATE INDEX idx_admin_sessions_admin_id ON admin_sessions (admin_id);
CREATE INDEX idx_admin_sessions_token ON admin_sessions (session_token) WHERE is_active = TRUE;
CREATE INDEX idx_admin_sessions_expires_at ON admin_sessions (expires_at) WHERE is_active = TRUE;
CREATE INDEX idx_admin_sessions_last_activity ON admin_sessions (last_activity) WHERE is_active = TRUE;
CREATE INDEX idx_admin_sessions_ip_address ON admin_sessions (ip_address);
CREATE INDEX idx_admin_sessions_is_active ON admin_sessions (is_active);
CREATE INDEX idx_admin_sessions_is_suspicious ON admin_sessions (is_suspicious) WHERE is_suspicious = TRUE;

-- Composite index for session cleanup
CREATE INDEX idx_admin_sessions_cleanup ON admin_sessions (expires_at, is_active) 
    WHERE is_active = TRUE;

-- Partial index for active sessions by user
CREATE INDEX idx_admin_sessions_active_user ON admin_sessions (admin_id, created_at) 
    WHERE is_active = TRUE AND is_revoked = FALSE;
```

### 4. admin_audit_logs

Comprehensive audit logging for all admin actions and system events.

```sql
CREATE TABLE admin_audit_logs (
    -- Primary identification
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id VARCHAR(36) UNIQUE NOT NULL,
    
    -- Timestamp and partitioning
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    date_partition VARCHAR(10) NOT NULL, -- YYYY-MM-DD for partitioning
    
    -- User context
    admin_id UUID REFERENCES admin_users(id) ON DELETE SET NULL,
    session_id UUID REFERENCES admin_sessions(id) ON DELETE SET NULL,
    admin_email VARCHAR(255) NOT NULL,
    admin_role VARCHAR(50) NOT NULL,
    
    -- Request information
    http_method VARCHAR(10) NOT NULL,
    endpoint_path VARCHAR(500) NOT NULL,
    full_url TEXT NOT NULL,
    query_params JSONB,
    
    -- Client information
    ip_address INET NOT NULL,
    user_agent TEXT,
    client_fingerprint VARCHAR(64),
    forwarded_for VARCHAR(255), -- X-Forwarded-For header
    
    -- Geolocation
    country_code VARCHAR(2),
    region VARCHAR(100),
    city VARCHAR(100),
    
    -- Request/Response data
    request_headers JSONB,
    request_body_hash VARCHAR(64), -- SHA-256 hash
    request_size_bytes INTEGER DEFAULT 0,
    
    response_status INTEGER NOT NULL,
    response_headers JSONB,
    response_body_hash VARCHAR(64), -- SHA-256 hash
    response_size_bytes INTEGER DEFAULT 0,
    
    -- Performance metrics
    processing_time_ms INTEGER NOT NULL,
    database_queries_count INTEGER DEFAULT 0,
    database_time_ms INTEGER DEFAULT 0,
    cache_hits INTEGER DEFAULT 0,
    cache_misses INTEGER DEFAULT 0,
    
    -- Action classification
    action_category VARCHAR(50) NOT NULL, -- user_management, system_config, etc.
    action_type VARCHAR(50) NOT NULL,     -- create, read, update, delete, login, logout
    resource_type VARCHAR(50),            -- user, role, configuration, etc.
    resource_id VARCHAR(100),             -- ID of affected resource
    
    -- Security and risk assessment
    risk_level VARCHAR(20) DEFAULT 'low' NOT NULL, -- low, medium, high, critical
    threat_indicators JSONB DEFAULT '[]',
    security_flags JSONB DEFAULT '{}',
    
    -- Compliance and data protection
    compliance_flags JSONB DEFAULT '{}', -- GDPR, SOX, HIPAA, etc.
    data_classification VARCHAR(20) DEFAULT 'internal', -- public, internal, confidential, restricted
    sensitive_data_accessed BOOLEAN DEFAULT FALSE,
    pii_accessed BOOLEAN DEFAULT FALSE,
    
    -- Status and error handling
    is_successful BOOLEAN NOT NULL,
    is_suspicious BOOLEAN DEFAULT FALSE,
    is_automated BOOLEAN DEFAULT FALSE, -- System-generated action
    
    error_code VARCHAR(50),
    error_message TEXT,
    error_details JSONB,
    
    -- Business context
    business_context JSONB DEFAULT '{}',
    technical_context JSONB DEFAULT '{}',
    correlation_id VARCHAR(36), -- For tracing related actions
    
    -- Searchable tags and metadata
    tags TEXT[], -- Array of searchable tags
    metadata JSONB DEFAULT '{}',
    
    -- Data retention and archival
    retention_policy VARCHAR(50) DEFAULT 'standard', -- standard, extended, permanent
    archived_at TIMESTAMP WITH TIME ZONE,
    archive_location VARCHAR(255),
    
    -- Constraints
    CONSTRAINT admin_audit_logs_risk_level_check CHECK (
        risk_level IN ('low', 'medium', 'high', 'critical')
    ),
    CONSTRAINT admin_audit_logs_data_classification_check CHECK (
        data_classification IN ('public', 'internal', 'confidential', 'restricted')
    ),
    CONSTRAINT admin_audit_logs_retention_policy_check CHECK (
        retention_policy IN ('standard', 'extended', 'permanent')
    ),
    CONSTRAINT admin_audit_logs_processing_time_check CHECK (processing_time_ms >= 0),
    CONSTRAINT admin_audit_logs_response_status_check CHECK (
        response_status >= 100 AND response_status < 600
    )
) PARTITION BY RANGE (timestamp);

-- Create monthly partitions for audit logs (example for 2024)
CREATE TABLE admin_audit_logs_2024_01 PARTITION OF admin_audit_logs
    FOR VALUES FROM ('2024-01-01 00:00:00+00') TO ('2024-02-01 00:00:00+00');

CREATE TABLE admin_audit_logs_2024_02 PARTITION OF admin_audit_logs
    FOR VALUES FROM ('2024-02-01 00:00:00+00') TO ('2024-03-01 00:00:00+00');

CREATE TABLE admin_audit_logs_2024_03 PARTITION OF admin_audit_logs
    FOR VALUES FROM ('2024-03-01 00:00:00+00') TO ('2024-04-01 00:00:00+00');

-- Indexes for admin_audit_logs (applied to each partition)
CREATE INDEX idx_admin_audit_logs_timestamp ON admin_audit_logs (timestamp);
CREATE INDEX idx_admin_audit_logs_admin_id ON admin_audit_logs (admin_id) WHERE admin_id IS NOT NULL;
CREATE INDEX idx_admin_audit_logs_session_id ON admin_audit_logs (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_admin_audit_logs_endpoint_path ON admin_audit_logs (endpoint_path);
CREATE INDEX idx_admin_audit_logs_action_category ON admin_audit_logs (action_category);
CREATE INDEX idx_admin_audit_logs_action_type ON admin_audit_logs (action_type);
CREATE INDEX idx_admin_audit_logs_risk_level ON admin_audit_logs (risk_level);
CREATE INDEX idx_admin_audit_logs_ip_address ON admin_audit_logs (ip_address);
CREATE INDEX idx_admin_audit_logs_is_successful ON admin_audit_logs (is_successful);
CREATE INDEX idx_admin_audit_logs_is_suspicious ON admin_audit_logs (is_suspicious) WHERE is_suspicious = TRUE;
CREATE INDEX idx_admin_audit_logs_date_partition ON admin_audit_logs (date_partition);
CREATE INDEX idx_admin_audit_logs_correlation_id ON admin_audit_logs (correlation_id) WHERE correlation_id IS NOT NULL;

-- GIN indexes for JSON columns
CREATE INDEX idx_admin_audit_logs_tags ON admin_audit_logs USING GIN (tags);
CREATE INDEX idx_admin_audit_logs_metadata ON admin_audit_logs USING GIN (metadata);
CREATE INDEX idx_admin_audit_logs_compliance_flags ON admin_audit_logs USING GIN (compliance_flags);

-- Composite indexes for common queries
CREATE INDEX idx_admin_audit_logs_admin_timestamp ON admin_audit_logs (admin_id, timestamp DESC) 
    WHERE admin_id IS NOT NULL;

CREATE INDEX idx_admin_audit_logs_suspicious_recent ON admin_audit_logs (timestamp DESC, risk_level) 
    WHERE is_suspicious = TRUE AND timestamp > NOW() - INTERVAL '7 days';
```

## Enums and Types

### 1. Admin Role Permissions

```sql
-- Create enum for standardized permissions
CREATE TYPE admin_permission AS ENUM (
    -- User management
    'users:create',
    'users:read',
    'users:update',
    'users:delete',
    'users:impersonate',
    
    -- Role management
    'roles:create',
    'roles:read',
    'roles:update',
    'roles:delete',
    
    -- System configuration
    'system:config:read',
    'system:config:update',
    'system:maintenance',
    'system:backup',
    
    -- Content management
    'content:create',
    'content:read',
    'content:update',
    'content:delete',
    'content:moderate',
    
    -- Monitoring and analytics
    'monitoring:read',
    'monitoring:alerts',
    'analytics:read',
    'analytics:export',
    
    -- Audit and compliance
    'audit:read',
    'audit:export',
    'compliance:read',
    'compliance:report',
    
    -- Security
    'security:read',
    'security:update',
    'security:incidents',
    
    -- API management
    'api:read',
    'api:keys:manage',
    'api:rate_limits',
    
    -- Wildcard permissions
    '*' -- Full access (super admin only)
);
```

### 2. Action Categories and Types

```sql
-- Action categories for audit logging
CREATE TYPE audit_action_category AS ENUM (
    'authentication',
    'user_management',
    'role_management',
    'system_configuration',
    'content_management',
    'security_management',
    'monitoring',
    'api_management',
    'data_export',
    'system_maintenance'
);

-- Action types for audit logging
CREATE TYPE audit_action_type AS ENUM (
    'create',
    'read',
    'update',
    'delete',
    'login',
    'logout',
    'password_change',
    'password_reset',
    'enable_2fa',
    'disable_2fa',
    'lock_account',
    'unlock_account',
    'export_data',
    'import_data',
    'backup',
    'restore',
    'maintenance_start',
    'maintenance_end'
);

-- Risk levels for security assessment
CREATE TYPE risk_level AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);
```

## Relationships and Foreign Keys

### Primary Relationships

1. **admin_users → admin_roles**: Many-to-One
   - Each admin user has exactly one role
   - Roles can be assigned to multiple users
   - Constraint: `ON DELETE RESTRICT` (cannot delete role with active users)

2. **admin_sessions → admin_users**: Many-to-One
   - Each session belongs to one admin user
   - Users can have multiple active sessions
   - Constraint: `ON DELETE CASCADE` (delete sessions when user is deleted)

3. **admin_audit_logs → admin_users**: Many-to-One (Optional)
   - Each audit log entry can reference an admin user
   - Users can have many audit log entries
   - Constraint: `ON DELETE SET NULL` (preserve audit logs even if user is deleted)

4. **admin_audit_logs → admin_sessions**: Many-to-One (Optional)
   - Each audit log entry can reference a session
   - Sessions can have many audit log entries
   - Constraint: `ON DELETE SET NULL` (preserve audit logs even if session is deleted)

5. **admin_roles → admin_roles**: Self-referencing (Role Hierarchy)
   - Roles can inherit from parent roles
   - Supports role hierarchy and permission inheritance
   - Constraint: `ON DELETE SET NULL` (remove parent reference if parent role is deleted)

### Referential Integrity

```sql
-- Add foreign key constraints with proper cascading
ALTER TABLE admin_users 
    ADD CONSTRAINT fk_admin_users_role_id 
    FOREIGN KEY (role_id) REFERENCES admin_roles(id) ON DELETE RESTRICT;

ALTER TABLE admin_users 
    ADD CONSTRAINT fk_admin_users_created_by 
    FOREIGN KEY (created_by) REFERENCES admin_users(id) ON DELETE SET NULL;

ALTER TABLE admin_users 
    ADD CONSTRAINT fk_admin_users_updated_by 
    FOREIGN KEY (updated_by) REFERENCES admin_users(id) ON DELETE SET NULL;

ALTER TABLE admin_sessions 
    ADD CONSTRAINT fk_admin_sessions_admin_id 
    FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE CASCADE;

ALTER TABLE admin_sessions 
    ADD CONSTRAINT fk_admin_sessions_revoked_by 
    FOREIGN KEY (revoked_by) REFERENCES admin_users(id) ON DELETE SET NULL;

ALTER TABLE admin_audit_logs 
    ADD CONSTRAINT fk_admin_audit_logs_admin_id 
    FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE SET NULL;

ALTER TABLE admin_audit_logs 
    ADD CONSTRAINT fk_admin_audit_logs_session_id 
    FOREIGN KEY (session_id) REFERENCES admin_sessions(id) ON DELETE SET NULL;

ALTER TABLE admin_roles 
    ADD CONSTRAINT fk_admin_roles_parent_role_id 
    FOREIGN KEY (parent_role_id) REFERENCES admin_roles(id) ON DELETE SET NULL;
```

## Indexing Strategy

### Performance Optimization

The indexing strategy is designed to optimize common admin operations while maintaining reasonable storage overhead.

#### Primary Indexes

1. **Primary Keys**: Automatic B-tree indexes on all primary keys
2. **Unique Constraints**: Automatic indexes on unique columns (email, session_token, etc.)
3. **Foreign Keys**: Indexes on all foreign key columns for join performance

#### Query-Specific Indexes

```sql
-- User authentication and lookup
CREATE INDEX idx_admin_users_email_active ON admin_users (email) 
    WHERE is_active = TRUE AND deleted_at IS NULL;

CREATE INDEX idx_admin_users_login_lookup ON admin_users (email, password_hash, is_active) 
    WHERE deleted_at IS NULL;

-- Session management
CREATE INDEX idx_admin_sessions_token_active ON admin_sessions (session_token) 
    WHERE is_active = TRUE AND is_revoked = FALSE;

CREATE INDEX idx_admin_sessions_user_active ON admin_sessions (admin_id, last_activity DESC) 
    WHERE is_active = TRUE;

-- Audit log queries
CREATE INDEX idx_admin_audit_logs_recent ON admin_audit_logs (timestamp DESC, admin_id) 
    WHERE timestamp > NOW() - INTERVAL '30 days';

CREATE INDEX idx_admin_audit_logs_security ON admin_audit_logs (risk_level, is_suspicious, timestamp DESC) 
    WHERE risk_level IN ('high', 'critical') OR is_suspicious = TRUE;

-- Role and permission queries
CREATE INDEX idx_admin_roles_active_hierarchy ON admin_roles (parent_role_id, role_level) 
    WHERE is_active = TRUE;
```

#### Partial Indexes

Partial indexes are used to optimize queries on filtered datasets:

```sql
-- Active users only
CREATE INDEX idx_admin_users_active_only ON admin_users (id, email, role_id, last_login) 
    WHERE is_active = TRUE AND deleted_at IS NULL;

-- Locked accounts
CREATE INDEX idx_admin_users_locked ON admin_users (id, email, locked_until) 
    WHERE is_locked = TRUE;

-- Suspicious activities
CREATE INDEX idx_admin_audit_logs_suspicious ON admin_audit_logs (timestamp DESC, admin_id, action_type) 
    WHERE is_suspicious = TRUE;

-- Failed login attempts
CREATE INDEX idx_admin_audit_logs_failed_logins ON admin_audit_logs (timestamp DESC, admin_email, ip_address) 
    WHERE action_type = 'login' AND is_successful = FALSE;
```

#### JSON/JSONB Indexes

For efficient querying of JSON columns:

```sql
-- Role permissions (GIN index for containment queries)
CREATE INDEX idx_admin_roles_permissions_gin ON admin_roles USING GIN (permissions);

-- Audit log metadata
CREATE INDEX idx_admin_audit_logs_metadata_gin ON admin_audit_logs USING GIN (metadata);

-- User preferences
CREATE INDEX idx_admin_users_preferences_gin ON admin_users USING GIN (preferences);

-- Specific JSON path indexes for common queries
CREATE INDEX idx_admin_users_timezone ON admin_users ((preferences->>'timezone')) 
    WHERE preferences ? 'timezone';
```

## Performance Considerations

### Query Optimization

#### 1. User Authentication Queries

```sql
-- Optimized login query
EXPLAIN (ANALYZE, BUFFERS) 
SELECT u.id, u.email, u.password_hash, u.is_active, u.is_locked, 
       u.login_attempts, u.locked_until, r.name as role_name, r.permissions
FROM admin_users u
JOIN admin_roles r ON u.role_id = r.id
WHERE u.email = $1 
  AND u.is_active = TRUE 
  AND u.deleted_at IS NULL;

-- Uses: idx_admin_users_email_active
-- Expected cost: ~1-5ms for single user lookup
```

#### 2. Session Validation Queries

```sql
-- Optimized session validation
EXPLAIN (ANALYZE, BUFFERS)
SELECT s.id, s.admin_id, s.expires_at, s.last_activity,
       u.email, u.is_active, r.permissions
FROM admin_sessions s
JOIN admin_users u ON s.admin_id = u.id
JOIN admin_roles r ON u.role_id = r.id
WHERE s.session_token = $1 
  AND s.is_active = TRUE 
  AND s.is_revoked = FALSE 
  AND s.expires_at > NOW();

-- Uses: idx_admin_sessions_token_active
-- Expected cost: ~1-3ms for session lookup
```

#### 3. Audit Log Queries

```sql
-- Optimized audit log search
EXPLAIN (ANALYZE, BUFFERS)
SELECT id, timestamp, admin_email, action_type, resource_type, 
       endpoint_path, is_successful, risk_level
FROM admin_audit_logs
WHERE admin_id = $1 
  AND timestamp >= $2 
  AND timestamp <= $3
ORDER BY timestamp DESC
LIMIT 100;

-- Uses: idx_admin_audit_logs_admin_timestamp
-- Expected cost: ~5-15ms for user's recent activities
```

### Data Retention and Archival

#### Automated Cleanup Procedures

```sql
-- Procedure to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Delete expired sessions older than 7 days
    DELETE FROM admin_sessions 
    WHERE expires_at < NOW() - INTERVAL '7 days'
      AND is_active = FALSE;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Log cleanup activity
    INSERT INTO admin_audit_logs (
        audit_id, admin_email, admin_role, http_method, endpoint_path,
        full_url, ip_address, response_status, processing_time_ms,
        action_category, action_type, is_successful, is_automated,
        business_context
    ) VALUES (
        gen_random_uuid()::text, 'system@linkshield.com', 'system',
        'DELETE', '/system/cleanup/sessions', '/system/cleanup/sessions',
        '127.0.0.1', 200, 0, 'system_maintenance', 'delete', TRUE, TRUE,
        jsonb_build_object('deleted_sessions', deleted_count)
    );
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Schedule cleanup to run daily
SELECT cron.schedule('cleanup-expired-sessions', '0 2 * * *', 'SELECT cleanup_expired_sessions();');
```

#### Audit Log Partitioning Management

```sql
-- Function to create new monthly partitions
CREATE OR REPLACE FUNCTION create_audit_log_partition(partition_date DATE)
RETURNS VOID AS $$
DECLARE
    partition_name TEXT;
    start_date TEXT;
    end_date TEXT;
BEGIN
    partition_name := 'admin_audit_logs_' || to_char(partition_date, 'YYYY_MM');
    start_date := to_char(partition_date, 'YYYY-MM-01 00:00:00+00');
    end_date := to_char(partition_date + INTERVAL '1 month', 'YYYY-MM-01 00:00:00+00');
    
    EXECUTE format('CREATE TABLE %I PARTITION OF admin_audit_logs FOR VALUES FROM (%L) TO (%L)',
                   partition_name, start_date, end_date);
    
    -- Create indexes on the new partition
    EXECUTE format('CREATE INDEX %I ON %I (timestamp)', 
                   'idx_' || partition_name || '_timestamp', partition_name);
    EXECUTE format('CREATE INDEX %I ON %I (admin_id) WHERE admin_id IS NOT NULL', 
                   'idx_' || partition_name || '_admin_id', partition_name);
END;
$$ LANGUAGE plpgsql;

-- Automatically create partitions for the next 3 months
SELECT create_audit_log_partition(date_trunc('month', CURRENT_DATE + INTERVAL '1 month'));
SELECT create_audit_log_partition(date_trunc('month', CURRENT_DATE + INTERVAL '2 months'));
SELECT create_audit_log_partition(date_trunc('month', CURRENT_DATE + INTERVAL '3 months'));
```

### Database Maintenance

#### Statistics and Vacuum

```sql
-- Automated maintenance for admin tables
CREATE OR REPLACE FUNCTION maintain_admin_tables()
RETURNS VOID AS $$
BEGIN
    -- Update table statistics
    ANALYZE admin_users;
    ANALYZE admin_roles;
    ANALYZE admin_sessions;
    ANALYZE admin_audit_logs;
    
    -- Vacuum tables to reclaim space
    VACUUM (ANALYZE) admin_users;
    VACUUM (ANALYZE) admin_roles;
    VACUUM (ANALYZE) admin_sessions;
    
    -- Note: Partitioned tables are vacuumed automatically by autovacuum
END;
$$ LANGUAGE plpgsql;

-- Schedule maintenance to run weekly
SELECT cron.schedule('maintain-admin-tables', '0 3 * * 0', 'SELECT maintain_admin_tables();');
```

#### Index Maintenance

```sql
-- Monitor index usage and performance
CREATE VIEW admin_index_usage AS
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_tup_read,
    idx_tup_fetch,
    idx_scan,
    CASE 
        WHEN idx_scan = 0 THEN 'Never used'
        WHEN idx_scan < 100 THEN 'Rarely used'
        WHEN idx_scan < 1000 THEN 'Moderately used'
        ELSE 'Frequently used'
    END as usage_level
FROM pg_stat_user_indexes 
WHERE schemaname = 'public' 
  AND tablename LIKE 'admin_%'
ORDER BY idx_scan DESC;

-- Query to identify unused indexes
SELECT 
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size
FROM pg_stat_user_indexes 
WHERE schemaname = 'public' 
  AND tablename LIKE 'admin_%'
  AND idx_scan = 0
  AND indexname NOT LIKE '%_pkey';
```

## Migration Scripts

### Initial Schema Creation

```sql
-- File: migrations/001_create_admin_schema.sql

BEGIN;

-- Create admin roles table first (referenced by admin_users)
CREATE TABLE admin_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    parent_role_id UUID REFERENCES admin_roles(id) ON DELETE SET NULL,
    role_level INTEGER NOT NULL DEFAULT 1,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_system_role BOOLEAN DEFAULT FALSE NOT NULL,
    is_default BOOLEAN DEFAULT FALSE NOT NULL,
    max_sessions INTEGER DEFAULT 5,
    session_timeout_minutes INTEGER DEFAULT 480,
    allowed_ip_ranges TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    created_by UUID,
    updated_by UUID,
    
    CONSTRAINT admin_roles_name_check CHECK (name ~* '^[a-z_]+$'),
    CONSTRAINT admin_roles_level_check CHECK (role_level > 0 AND role_level <= 10),
    CONSTRAINT admin_roles_max_sessions_check CHECK (max_sessions > 0 AND max_sessions <= 100),
    CONSTRAINT admin_roles_timeout_check CHECK (session_timeout_minutes > 0)
);

-- Create admin users table
CREATE TABLE admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role_id UUID NOT NULL REFERENCES admin_roles(id) ON DELETE RESTRICT,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    display_name VARCHAR(200),
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE NOT NULL,
    is_locked BOOLEAN DEFAULT FALSE NOT NULL,
    last_login TIMESTAMP WITH TIME ZONE,
    login_attempts INTEGER DEFAULT 0 NOT NULL,
    locked_until TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    two_factor_enabled BOOLEAN DEFAULT FALSE NOT NULL,
    two_factor_secret VARCHAR(32),
    backup_codes TEXT[],
    profile_data JSONB DEFAULT '{}',
    preferences JSONB DEFAULT '{}',
    timezone VARCHAR(50) DEFAULT 'UTC',
    language VARCHAR(10) DEFAULT 'en',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    created_by UUID REFERENCES admin_users(id),
    updated_by UUID REFERENCES admin_users(id),
    deleted_at TIMESTAMP WITH TIME ZONE,
    deleted_by UUID REFERENCES admin_users(id),
    
    CONSTRAINT admin_users_email_check CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT admin_users_login_attempts_check CHECK (login_attempts >= 0),
    CONSTRAINT admin_users_names_check CHECK (
        (first_name IS NULL AND last_name IS NULL) OR 
        (first_name IS NOT NULL AND last_name IS NOT NULL)
    )
);

-- Create admin sessions table
CREATE TABLE admin_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_token VARCHAR(128) UNIQUE NOT NULL,
    refresh_token VARCHAR(128) UNIQUE,
    admin_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT,
    client_fingerprint VARCHAR(64),
    country_code VARCHAR(2),
    city VARCHAR(100),
    login_method VARCHAR(20) DEFAULT 'password',
    device_type VARCHAR(20),
    browser_name VARCHAR(50),
    os_name VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_revoked BOOLEAN DEFAULT FALSE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID REFERENCES admin_users(id),
    revoke_reason VARCHAR(100),
    is_suspicious BOOLEAN DEFAULT FALSE NOT NULL,
    risk_score INTEGER DEFAULT 0,
    session_data JSONB DEFAULT '{}',
    
    CONSTRAINT admin_sessions_expires_check CHECK (expires_at > created_at),
    CONSTRAINT admin_sessions_risk_score_check CHECK (risk_score >= 0 AND risk_score <= 100),
    CONSTRAINT admin_sessions_revoked_check CHECK (
        (is_revoked = FALSE AND revoked_at IS NULL) OR 
        (is_revoked = TRUE AND revoked_at IS NOT NULL)
    )
);

-- Create partitioned audit logs table
CREATE TABLE admin_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id VARCHAR(36) UNIQUE NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    date_partition VARCHAR(10) NOT NULL,
    admin_id UUID REFERENCES admin_users(id) ON DELETE SET NULL,
    session_id UUID REFERENCES admin_sessions(id) ON DELETE SET NULL,
    admin_email VARCHAR(255) NOT NULL,
    admin_role VARCHAR(50) NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    endpoint_path VARCHAR(500) NOT NULL,
    full_url TEXT NOT NULL,
    query_params JSONB,
    ip_address INET NOT NULL,
    user_agent TEXT,
    client_fingerprint VARCHAR(64),
    forwarded_for VARCHAR(255),
    country_code VARCHAR(2),
    region VARCHAR(100),
    city VARCHAR(100),
    request_headers JSONB,
    request_body_hash VARCHAR(64),
    request_size_bytes INTEGER DEFAULT 0,
    response_status INTEGER NOT NULL,
    response_headers JSONB,
    response_body_hash VARCHAR(64),
    response_size_bytes INTEGER DEFAULT 0,
    processing_time_ms INTEGER NOT NULL,
    database_queries_count INTEGER DEFAULT 0,
    database_time_ms INTEGER DEFAULT 0,
    cache_hits INTEGER DEFAULT 0,
    cache_misses INTEGER DEFAULT 0,
    action_category VARCHAR(50) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    risk_level VARCHAR(20) DEFAULT 'low' NOT NULL,
    threat_indicators JSONB DEFAULT '[]',
    security_flags JSONB DEFAULT '{}',
    compliance_flags JSONB DEFAULT '{}',
    data_classification VARCHAR(20) DEFAULT 'internal',
    sensitive_data_accessed BOOLEAN DEFAULT FALSE,
    pii_accessed BOOLEAN DEFAULT FALSE,
    is_successful BOOLEAN NOT NULL,
    is_suspicious BOOLEAN DEFAULT FALSE,
    is_automated BOOLEAN DEFAULT FALSE,
    error_code VARCHAR(50),
    error_message TEXT,
    error_details JSONB,
    business_context JSONB DEFAULT '{}',
    technical_context JSONB DEFAULT '{}',
    correlation_id VARCHAR(36),
    tags TEXT[],
    metadata JSONB DEFAULT '{}',
    retention_policy VARCHAR(50) DEFAULT 'standard',
    archived_at TIMESTAMP WITH TIME ZONE,
    archive_location VARCHAR(255),
    
    CONSTRAINT admin_audit_logs_risk_level_check CHECK (
        risk_level IN ('low', 'medium', 'high', 'critical')
    ),
    CONSTRAINT admin_audit_logs_data_classification_check CHECK (
        data_classification IN ('public', 'internal', 'confidential', 'restricted')
    ),
    CONSTRAINT admin_audit_logs_retention_policy_check CHECK (
        retention_policy IN ('standard', 'extended', 'permanent')
    ),
    CONSTRAINT admin_audit_logs_processing_time_check CHECK (processing_time_ms >= 0),
    CONSTRAINT admin_audit_logs_response_status_check CHECK (
        response_status >= 100 AND response_status < 600
    )
) PARTITION BY RANGE (timestamp);

-- Insert default roles
INSERT INTO admin_roles (name, display_name, description, permissions, role_level, is_system_role, is_default) VALUES
('super_admin', 'Super Administrator', 'Full system access with all permissions', 
 '["*"]', 10, TRUE, FALSE),
('admin', 'Administrator', 'Standard admin with most permissions except system management', 
 '["users:*", "content:*", "reports:*", "monitoring:read"]', 8, TRUE, TRUE),
('moderator', 'Moderator', 'Content moderation and user management', 
 '["users:read", "users:update", "content:*", "reports:read"]', 5, TRUE, FALSE),
('analyst', 'Security Analyst', 'Read-only access to security and monitoring data', 
 '["monitoring:*", "reports:*", "audit:read", "users:read"]', 3, TRUE, FALSE),
('support', 'Support Agent', 'Limited access for customer support', 
 '["users:read", "users:update", "reports:read"]', 2, TRUE, FALSE);

COMMIT;
```

### Index Creation Migration

```sql
-- File: migrations/002_create_admin_indexes.sql

BEGIN;

-- Admin users indexes
CREATE INDEX idx_admin_users_email ON admin_users (email) WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_users_role_id ON admin_users (role_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_users_is_active ON admin_users (is_active) WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_users_last_login ON admin_users (last_login) WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_users_created_at ON admin_users (created_at) WHERE deleted_at IS NULL;
CREATE INDEX idx_admin_users_locked_until ON admin_users (locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX idx_admin_users_active ON admin_users (id, email, role_id) 
    WHERE is_active = TRUE AND deleted_at IS NULL;

-- Admin roles indexes
CREATE INDEX idx_admin_roles_name ON admin_roles (name) WHERE is_active = TRUE;
CREATE INDEX idx_admin_roles_parent_role_id ON admin_roles (parent_role_id);
CREATE INDEX idx_admin_roles_role_level ON admin_roles (role_level);
CREATE INDEX idx_admin_roles_is_active ON admin_roles (is_active);
CREATE INDEX idx_admin_roles_is_system ON admin_roles (is_system_role);
CREATE INDEX idx_admin_roles_permissions ON admin_roles USING GIN (permissions);

-- Admin sessions indexes
CREATE INDEX idx_admin_sessions_admin_id ON admin_sessions (admin_id);
CREATE INDEX idx_admin_sessions_token ON admin_sessions (session_token) WHERE is_active = TRUE;
CREATE INDEX idx_admin_sessions_expires_at ON admin_sessions (expires_at) WHERE is_active = TRUE;
CREATE INDEX idx_admin_sessions_last_activity ON admin_sessions (last_activity) WHERE is_active = TRUE;
CREATE INDEX idx_admin_sessions_ip_address ON admin_sessions (ip_address);
CREATE INDEX idx_admin_sessions_is_active ON admin_sessions (is_active);
CREATE INDEX idx_admin_sessions_is_suspicious ON admin_sessions (is_suspicious) WHERE is_suspicious = TRUE;
CREATE INDEX idx_admin_sessions_cleanup ON admin_sessions (expires_at, is_active) 
    WHERE is_active = TRUE;
CREATE INDEX idx_admin_sessions_active_user ON admin_sessions (admin_id, created_at) 
    WHERE is_active = TRUE AND is_revoked = FALSE;

COMMIT;
```

---

*This comprehensive database schema documentation provides the foundation for the LinkShield admin system with enterprise-grade security, performance, and scalability features.*
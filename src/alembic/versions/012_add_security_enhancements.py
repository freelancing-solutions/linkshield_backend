"""
Add security enhancements for API key rotation, versioning, and security event logging.

Revision ID: 012_add_security_enhancements
Revises: 011_enhance_session_tracking
Create Date: 2025-01-21 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# revision identifiers, used by Alembic.
revision = '012_add_security_enhancements'
down_revision = '011_enhance_session_tracking'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Add security enhancement tables for API key rotation, versioning, and security event logging.
    Addresses REQ-029 (version-specific security policy support) and REQ-032 (backward-compatible schema updates).
    """
    
    # Create enum types for security enhancements
    op.execute("CREATE TYPE api_key_status AS ENUM ('active', 'rotating', 'deprecated', 'revoked', 'expired')")
    op.execute("CREATE TYPE api_key_version_type AS ENUM ('v1', 'v2', 'v3')")
    op.execute("CREATE TYPE compatibility_level AS ENUM ('full', 'partial', 'deprecated', 'incompatible')")
    op.execute("CREATE TYPE threat_level AS ENUM ('low', 'medium', 'high', 'critical')")
    op.execute("CREATE TYPE revocation_reason AS ENUM ('security_breach', 'suspicious_activity', 'policy_violation', 'manual_request', 'automated_detection', 'compliance_requirement')")
    op.execute("CREATE TYPE security_event_type AS ENUM ('authentication', 'authorization', 'api_key_usage', 'session_management', 'data_access', 'configuration_change', 'security_incident', 'compliance_check', 'threat_detection', 'audit_event')")
    op.execute("CREATE TYPE security_event_severity AS ENUM ('info', 'low', 'medium', 'high', 'critical')")
    op.execute("CREATE TYPE security_event_status AS ENUM ('detected', 'investigating', 'confirmed', 'resolved', 'false_positive')")
    op.execute("CREATE TYPE alert_channel AS ENUM ('email', 'sms', 'slack', 'webhook', 'push_notification', 'dashboard')")
    op.execute("CREATE TYPE alert_priority AS ENUM ('low', 'medium', 'high', 'critical', 'emergency')")
    op.execute("CREATE TYPE alert_status AS ENUM ('pending', 'sent', 'delivered', 'failed', 'suppressed')")
    
    # 1. API Key Rotation Configuration Table
    op.create_table(
        'api_key_rotation_config',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('rotation_interval_days', sa.Integer, nullable=False, default=90),
        sa.Column('warning_days_before', sa.Integer, nullable=False, default=7),
        sa.Column('auto_rotation_enabled', sa.Boolean, nullable=False, default=True),
        sa.Column('notification_enabled', sa.Boolean, nullable=False, default=True),
        sa.Column('max_concurrent_keys', sa.Integer, nullable=False, default=2),
        sa.Column('grace_period_hours', sa.Integer, nullable=False, default=24),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # 2. API Key Versions Table
    op.create_table(
        'api_key_versions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('api_key_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('api_keys.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('version_number', sa.Integer, nullable=False),
        sa.Column('version_type', postgresql.ENUM('v1', 'v2', 'v3', name='api_key_version_type'), nullable=False),
        sa.Column('status', postgresql.ENUM('active', 'rotating', 'deprecated', 'revoked', 'expired', name='api_key_status'), nullable=False, default='active'),
        sa.Column('key_hash', sa.String(255), nullable=False, unique=True, index=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deprecated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rotation_scheduled_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('compatibility_level', postgresql.ENUM('full', 'partial', 'deprecated', 'incompatible', name='compatibility_level'), nullable=False, default='full'),
        sa.Column('migration_notes', sa.Text, nullable=True),
        sa.UniqueConstraint('api_key_id', 'version_number', name='uq_api_key_version'),
    )
    
    # 3. Emergency Revocation Log Table
    op.create_table(
        'emergency_revocation_log',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('api_key_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('api_keys.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('revoked_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('threat_level', postgresql.ENUM('low', 'medium', 'high', 'critical', name='threat_level'), nullable=False),
        sa.Column('reason', postgresql.ENUM('security_breach', 'suspicious_activity', 'policy_violation', 'manual_request', 'automated_detection', 'compliance_requirement', name='revocation_reason'), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('automated', sa.Boolean, nullable=False, default=False),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text, nullable=True),
        sa.Column('additional_context', postgresql.JSONB, nullable=True),
        sa.Column('notification_sent', sa.Boolean, nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    
    # 4. Security Events Table
    op.create_table(
        'security_events',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('event_type', postgresql.ENUM('authentication', 'authorization', 'api_key_usage', 'session_management', 'data_access', 'configuration_change', 'security_incident', 'compliance_check', 'threat_detection', 'audit_event', name='security_event_type'), nullable=False),
        sa.Column('severity', postgresql.ENUM('info', 'low', 'medium', 'high', 'critical', name='security_event_severity'), nullable=False),
        sa.Column('status', postgresql.ENUM('detected', 'investigating', 'confirmed', 'resolved', 'false_positive', name='security_event_status'), nullable=False, default='detected'),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('user_sessions.id', ondelete='SET NULL'), nullable=True),
        sa.Column('api_key_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('api_keys.id', ondelete='SET NULL'), nullable=True),
        sa.Column('source', sa.String(100), nullable=False),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource', sa.String(255), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text, nullable=True),
        sa.Column('request_id', sa.String(100), nullable=True, index=True),
        sa.Column('correlation_id', sa.String(100), nullable=True, index=True),
        sa.Column('details', postgresql.JSONB, nullable=True),
        sa.Column('risk_score', sa.Float, nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.String), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False, index=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
    )
    
    # 5. Security Alerts Table
    op.create_table(
        'security_alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('event_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('security_events.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('alert_type', sa.String(100), nullable=False),
        sa.Column('priority', postgresql.ENUM('low', 'medium', 'high', 'critical', 'emergency', name='alert_priority'), nullable=False),
        sa.Column('status', postgresql.ENUM('pending', 'sent', 'delivered', 'failed', 'suppressed', name='alert_status'), nullable=False, default='pending'),
        sa.Column('channel', postgresql.ENUM('email', 'sms', 'slack', 'webhook', 'push_notification', 'dashboard', name='alert_channel'), nullable=False),
        sa.Column('recipient', sa.String(255), nullable=False),
        sa.Column('subject', sa.String(255), nullable=False),
        sa.Column('message', sa.Text, nullable=False),
        sa.Column('metadata', postgresql.JSONB, nullable=True),
        sa.Column('sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('delivered_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('failure_reason', sa.Text, nullable=True),
        sa.Column('retry_count', sa.Integer, nullable=False, default=0),
        sa.Column('max_retries', sa.Integer, nullable=False, default=3),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    
    # Add new columns to existing api_keys table for enhanced security
    op.add_column('api_keys', sa.Column('version_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column('api_keys', sa.Column('rotation_status', postgresql.ENUM('active', 'rotating', 'deprecated', 'revoked', 'expired', name='api_key_status'), nullable=False, server_default='active'))
    op.add_column('api_keys', sa.Column('next_rotation_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('api_keys', sa.Column('rotation_count', sa.Integer, nullable=False, default=0))
    op.add_column('api_keys', sa.Column('security_level', sa.String(20), nullable=False, server_default='standard'))
    op.add_column('api_keys', sa.Column('allowed_ips', postgresql.ARRAY(sa.String), nullable=True))
    op.add_column('api_keys', sa.Column('scopes', postgresql.ARRAY(sa.String), nullable=True))
    
    # Add new columns to existing user_sessions table for enhanced tracking
    op.add_column('user_sessions', sa.Column('security_context', postgresql.JSONB, nullable=True))
    op.add_column('user_sessions', sa.Column('risk_score', sa.Float, nullable=True))
    op.add_column('user_sessions', sa.Column('is_suspicious', sa.Boolean, nullable=False, default=False))
    op.add_column('user_sessions', sa.Column('concurrent_session_count', sa.Integer, nullable=False, default=1))
    
    # Create indexes for performance optimization
    op.create_index('idx_api_key_versions_status', 'api_key_versions', ['status'])
    op.create_index('idx_api_key_versions_expires_at', 'api_key_versions', ['expires_at'])
    op.create_index('idx_emergency_revocation_threat_level', 'emergency_revocation_log', ['threat_level'])
    op.create_index('idx_emergency_revocation_created_at', 'emergency_revocation_log', ['created_at'])
    op.create_index('idx_security_events_severity_created', 'security_events', ['severity', 'created_at'])
    op.create_index('idx_security_events_type_status', 'security_events', ['event_type', 'status'])
    op.create_index('idx_security_events_correlation', 'security_events', ['correlation_id'])
    op.create_index('idx_security_alerts_priority_status', 'security_alerts', ['priority', 'status'])
    op.create_index('idx_security_alerts_channel_created', 'security_alerts', ['channel', 'created_at'])
    
    # Create foreign key constraints for new columns
    op.create_foreign_key('fk_api_keys_version_id', 'api_keys', 'api_key_versions', ['version_id'], ['id'], ondelete='SET NULL')


def downgrade() -> None:
    """
    Remove security enhancement tables and columns.
    Maintains backward compatibility by preserving core functionality.
    """
    
    # Drop foreign key constraints
    op.drop_constraint('fk_api_keys_version_id', 'api_keys', type_='foreignkey')
    
    # Drop indexes
    op.drop_index('idx_security_alerts_channel_created')
    op.drop_index('idx_security_alerts_priority_status')
    op.drop_index('idx_security_events_correlation')
    op.drop_index('idx_security_events_type_status')
    op.drop_index('idx_security_events_severity_created')
    op.drop_index('idx_emergency_revocation_created_at')
    op.drop_index('idx_emergency_revocation_threat_level')
    op.drop_index('idx_api_key_versions_expires_at')
    op.drop_index('idx_api_key_versions_status')
    
    # Drop new columns from existing tables
    op.drop_column('user_sessions', 'concurrent_session_count')
    op.drop_column('user_sessions', 'is_suspicious')
    op.drop_column('user_sessions', 'risk_score')
    op.drop_column('user_sessions', 'security_context')
    
    op.drop_column('api_keys', 'scopes')
    op.drop_column('api_keys', 'allowed_ips')
    op.drop_column('api_keys', 'security_level')
    op.drop_column('api_keys', 'rotation_count')
    op.drop_column('api_keys', 'next_rotation_at')
    op.drop_column('api_keys', 'rotation_status')
    op.drop_column('api_keys', 'version_id')
    
    # Drop new tables
    op.drop_table('security_alerts')
    op.drop_table('security_events')
    op.drop_table('emergency_revocation_log')
    op.drop_table('api_key_versions')
    op.drop_table('api_key_rotation_config')
    
    # Drop enum types
    op.execute("DROP TYPE IF EXISTS alert_status")
    op.execute("DROP TYPE IF EXISTS alert_priority")
    op.execute("DROP TYPE IF EXISTS alert_channel")
    op.execute("DROP TYPE IF EXISTS security_event_status")
    op.execute("DROP TYPE IF EXISTS security_event_severity")
    op.execute("DROP TYPE IF EXISTS security_event_type")
    op.execute("DROP TYPE IF EXISTS revocation_reason")
    op.execute("DROP TYPE IF EXISTS threat_level")
    op.execute("DROP TYPE IF EXISTS compatibility_level")
    op.execute("DROP TYPE IF EXISTS api_key_version_type")
    op.execute("DROP TYPE IF EXISTS api_key_status")
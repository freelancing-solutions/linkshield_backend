"""
Enhance session tracking for concurrent session limits and security features.

Revision ID: 011_enhance_session_tracking
Revises: 010_link_bot_users_to_users
Create Date: 2025-01-21 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '011_enhance_session_tracking'
down_revision = '010_link_bot_users_to_users'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Add enhanced session tracking fields for concurrent session limits
    and security features as per REQ-009 and REQ-010.
    """
    
    # Add new columns to user_sessions table for enhanced tracking
    op.add_column('user_sessions', sa.Column('device_fingerprint', sa.String(255), nullable=True))
    op.add_column('user_sessions', sa.Column('geolocation_data', postgresql.JSONB(), nullable=True))
    op.add_column('user_sessions', sa.Column('session_type', sa.String(50), nullable=False, server_default='web'))
    op.add_column('user_sessions', sa.Column('is_suspicious', sa.Boolean(), nullable=False, server_default='false'))
    op.add_column('user_sessions', sa.Column('risk_score', sa.Float(), nullable=True))
    op.add_column('user_sessions', sa.Column('terminated_by', sa.String(50), nullable=True))
    op.add_column('user_sessions', sa.Column('termination_reason', sa.String(255), nullable=True))
    op.add_column('user_sessions', sa.Column('concurrent_session_count', sa.Integer(), nullable=False, server_default='1'))
    
    # Create indexes for performance optimization
    op.create_index('idx_user_sessions_user_id_active', 'user_sessions', ['user_id', 'is_active'])
    op.create_index('idx_user_sessions_device_fingerprint', 'user_sessions', ['device_fingerprint'])
    op.create_index('idx_user_sessions_session_type', 'user_sessions', ['session_type'])
    op.create_index('idx_user_sessions_is_suspicious', 'user_sessions', ['is_suspicious'])
    op.create_index('idx_user_sessions_created_at', 'user_sessions', ['created_at'])
    op.create_index('idx_user_sessions_last_accessed', 'user_sessions', ['last_accessed_at'])
    
    # Create composite index for concurrent session queries
    op.create_index(
        'idx_user_sessions_concurrent_lookup', 
        'user_sessions', 
        ['user_id', 'is_active', 'created_at']
    )
    
    # Create session activity log table for audit trail
    op.create_table(
        'session_activity_log',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('user_sessions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('activity_type', sa.String(50), nullable=False),  # 'login', 'logout', 'terminated', 'extended', 'suspicious'
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('geolocation_data', postgresql.JSONB(), nullable=True),
        sa.Column('metadata', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Index('idx_session_activity_session_id', 'session_id'),
        sa.Index('idx_session_activity_user_id', 'user_id'),
        sa.Index('idx_session_activity_type', 'activity_type'),
        sa.Index('idx_session_activity_created_at', 'created_at'),
    )
    
    # Create session limits configuration table for role-based limits
    op.create_table(
        'session_limits_config',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('role', sa.String(50), nullable=False, unique=True),
        sa.Column('max_concurrent_sessions', sa.Integer(), nullable=False, default=5),
        sa.Column('session_timeout_minutes', sa.Integer(), nullable=False, default=1440),  # 24 hours
        sa.Column('idle_timeout_minutes', sa.Integer(), nullable=False, default=60),
        sa.Column('require_device_verification', sa.Boolean(), nullable=False, default=False),
        sa.Column('enable_geolocation_check', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Index('idx_session_limits_role', 'role'),
    )
    
    # Insert default session limits for existing roles
    op.execute("""
        INSERT INTO session_limits_config (role, max_concurrent_sessions, session_timeout_minutes, idle_timeout_minutes, require_device_verification, enable_geolocation_check)
        VALUES 
            ('user', 3, 1440, 60, false, false),
            ('admin', 5, 720, 30, true, true),
            ('super_admin', 10, 480, 15, true, true),
            ('moderator', 4, 960, 45, false, true)
    """)


def downgrade() -> None:
    """
    Remove enhanced session tracking fields and tables.
    """
    
    # Drop tables
    op.drop_table('session_limits_config')
    op.drop_table('session_activity_log')
    
    # Drop indexes
    op.drop_index('idx_user_sessions_concurrent_lookup', 'user_sessions')
    op.drop_index('idx_user_sessions_last_accessed', 'user_sessions')
    op.drop_index('idx_user_sessions_created_at', 'user_sessions')
    op.drop_index('idx_user_sessions_is_suspicious', 'user_sessions')
    op.drop_index('idx_user_sessions_session_type', 'user_sessions')
    op.drop_index('idx_user_sessions_device_fingerprint', 'user_sessions')
    op.drop_index('idx_user_sessions_user_id_active', 'user_sessions')
    
    # Drop columns
    op.drop_column('user_sessions', 'concurrent_session_count')
    op.drop_column('user_sessions', 'termination_reason')
    op.drop_column('user_sessions', 'terminated_by')
    op.drop_column('user_sessions', 'risk_score')
    op.drop_column('user_sessions', 'is_suspicious')
    op.drop_column('user_sessions', 'session_type')
    op.drop_column('user_sessions', 'geolocation_data')
    op.drop_column('user_sessions', 'device_fingerprint')
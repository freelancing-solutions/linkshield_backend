"""
Add bot models for social media bot integration and URL analysis tracking.

Revision ID: 008_add_bot_models
Revises: 007_add_social_protection_models
Create Date: 2024-01-18 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '008_add_bot_models'
down_revision = '007_add_social_protection_models'
branch_labels = None
depends_on = None


def upgrade():
    """Add bot models for social media integration."""
    
    # Create bot_users table
    op.create_table(
        'bot_users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('platform', sa.String(length=20), nullable=False),
        sa.Column('platform_user_id', sa.String(length=100), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=True),
        sa.Column('display_name', sa.String(length=200), nullable=True),
        
        # User preferences
        sa.Column('notifications_enabled', sa.Boolean(), nullable=True, default=True),
        sa.Column('deep_analysis_enabled', sa.Boolean(), nullable=True, default=False),
        sa.Column('language_preference', sa.String(length=10), nullable=True, default='en'),
        
        # Statistics
        sa.Column('total_analyses', sa.Integer(), nullable=True, default=0),
        sa.Column('safe_urls_count', sa.Integer(), nullable=True, default=0),
        sa.Column('risky_urls_count', sa.Integer(), nullable=True, default=0),
        sa.Column('last_analysis_at', sa.DateTime(), nullable=True),
        
        # Metadata
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for bot_users
    op.create_index(op.f('ix_bot_users_id'), 'bot_users', ['id'], unique=False)
    op.create_index(op.f('ix_bot_users_platform'), 'bot_users', ['platform'], unique=False)
    op.create_index(op.f('ix_bot_users_platform_user_id'), 'bot_users', ['platform_user_id'], unique=False)
    
    # Create unique constraint for platform + platform_user_id combination
    op.create_index('ix_bot_users_platform_user_unique', 'bot_users', ['platform', 'platform_user_id'], unique=True)
    
    # Create bot_analysis_requests table
    op.create_table(
        'bot_analysis_requests',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        
        # Request details
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('url_hash', sa.String(length=64), nullable=False),
        sa.Column('platform', sa.String(length=20), nullable=False),
        sa.Column('request_type', sa.String(length=20), nullable=True, default='quick'),
        
        # Analysis results
        sa.Column('risk_level', sa.String(length=20), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('analysis_message', sa.Text(), nullable=True),
        sa.Column('threats_detected', sa.Text(), nullable=True),
        
        # Performance metrics
        sa.Column('analysis_duration_ms', sa.Integer(), nullable=True),
        sa.Column('cache_hit', sa.Boolean(), nullable=True, default=False),
        sa.Column('error_occurred', sa.Boolean(), nullable=True, default=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        
        # Metadata
        sa.Column('requested_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        
        # Platform-specific data
        sa.Column('platform_message_id', sa.String(length=100), nullable=True),
        sa.Column('platform_response_id', sa.String(length=100), nullable=True),
        
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['bot_users.id'], )
    )
    
    # Create indexes for bot_analysis_requests
    op.create_index(op.f('ix_bot_analysis_requests_id'), 'bot_analysis_requests', ['id'], unique=False)
    op.create_index(op.f('ix_bot_analysis_requests_user_id'), 'bot_analysis_requests', ['user_id'], unique=False)
    op.create_index(op.f('ix_bot_analysis_requests_url_hash'), 'bot_analysis_requests', ['url_hash'], unique=False)
    op.create_index(op.f('ix_bot_analysis_requests_platform'), 'bot_analysis_requests', ['platform'], unique=False)
    op.create_index(op.f('ix_bot_analysis_requests_requested_at'), 'bot_analysis_requests', ['requested_at'], unique=False)
    
    # Create bot_rate_limits table
    op.create_table(
        'bot_rate_limits',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('platform', sa.String(length=20), nullable=False),
        
        # Rate limiting data
        sa.Column('requests_count', sa.Integer(), nullable=True, default=0),
        sa.Column('window_start', sa.DateTime(), nullable=True),
        sa.Column('window_duration_minutes', sa.Integer(), nullable=True, default=60),
        sa.Column('max_requests', sa.Integer(), nullable=True, default=50),
        
        # Blocking data
        sa.Column('is_blocked', sa.Boolean(), nullable=True, default=False),
        sa.Column('blocked_until', sa.DateTime(), nullable=True),
        sa.Column('block_reason', sa.String(length=200), nullable=True),
        
        # Metadata
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['bot_users.id'], )
    )
    
    # Create indexes for bot_rate_limits
    op.create_index(op.f('ix_bot_rate_limits_id'), 'bot_rate_limits', ['id'], unique=False)
    op.create_index(op.f('ix_bot_rate_limits_user_id'), 'bot_rate_limits', ['user_id'], unique=False)
    op.create_index(op.f('ix_bot_rate_limits_platform'), 'bot_rate_limits', ['platform'], unique=False)
    
    # Create unique constraint for user_id + platform combination
    op.create_index('ix_bot_rate_limits_user_platform_unique', 'bot_rate_limits', ['user_id', 'platform'], unique=True)
    
    # Create bot_sessions table
    op.create_table(
        'bot_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('platform', sa.String(length=20), nullable=False),
        
        # Session data
        sa.Column('session_id', sa.String(length=100), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('last_activity_at', sa.DateTime(), nullable=True),
        sa.Column('ended_at', sa.DateTime(), nullable=True),
        
        # Session statistics
        sa.Column('total_requests', sa.Integer(), nullable=True, default=0),
        sa.Column('successful_analyses', sa.Integer(), nullable=True, default=0),
        sa.Column('failed_analyses', sa.Integer(), nullable=True, default=0),
        sa.Column('commands_used', sa.Text(), nullable=True),
        
        # Platform-specific data
        sa.Column('platform_chat_id', sa.String(length=100), nullable=True),
        sa.Column('platform_channel_id', sa.String(length=100), nullable=True),
        
        # Status
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
        
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['bot_users.id'], )
    )
    
    # Create indexes for bot_sessions
    op.create_index(op.f('ix_bot_sessions_id'), 'bot_sessions', ['id'], unique=False)
    op.create_index(op.f('ix_bot_sessions_user_id'), 'bot_sessions', ['user_id'], unique=False)
    op.create_index(op.f('ix_bot_sessions_platform'), 'bot_sessions', ['platform'], unique=False)
    op.create_index(op.f('ix_bot_sessions_session_id'), 'bot_sessions', ['session_id'], unique=True)
    
    # Create bot_configurations table
    op.create_table(
        'bot_configurations',
        sa.Column('id', sa.Integer(), nullable=False),
        
        # Configuration data
        sa.Column('config_key', sa.String(length=100), nullable=False),
        sa.Column('config_value', sa.Text(), nullable=False),
        sa.Column('config_type', sa.String(length=20), nullable=True, default='string'),
        
        # Metadata
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=50), nullable=True, default='general'),
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
        
        # Audit trail
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('updated_by', sa.String(length=100), nullable=True),
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for bot_configurations
    op.create_index(op.f('ix_bot_configurations_id'), 'bot_configurations', ['id'], unique=False)
    op.create_index(op.f('ix_bot_configurations_config_key'), 'bot_configurations', ['config_key'], unique=True)
    
    # Create bot_analytics_events table
    op.create_table(
        'bot_analytics_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        
        # Event data
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('event_category', sa.String(length=30), nullable=False),
        sa.Column('platform', sa.String(length=20), nullable=False),
        
        # Event details
        sa.Column('event_data', sa.Text(), nullable=True),
        sa.Column('user_agent', sa.String(length=200), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        
        # Performance metrics
        sa.Column('response_time_ms', sa.Integer(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=True, default=True),
        sa.Column('error_code', sa.String(length=50), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        
        # Metadata
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('session_id', sa.String(length=100), nullable=True),
        
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['bot_users.id'], )
    )
    
    # Create indexes for bot_analytics_events
    op.create_index(op.f('ix_bot_analytics_events_id'), 'bot_analytics_events', ['id'], unique=False)
    op.create_index(op.f('ix_bot_analytics_events_user_id'), 'bot_analytics_events', ['user_id'], unique=False)
    op.create_index(op.f('ix_bot_analytics_events_event_type'), 'bot_analytics_events', ['event_type'], unique=False)
    op.create_index(op.f('ix_bot_analytics_events_event_category'), 'bot_analytics_events', ['event_category'], unique=False)
    op.create_index(op.f('ix_bot_analytics_events_platform'), 'bot_analytics_events', ['platform'], unique=False)
    op.create_index(op.f('ix_bot_analytics_events_timestamp'), 'bot_analytics_events', ['timestamp'], unique=False)
    op.create_index(op.f('ix_bot_analytics_events_session_id'), 'bot_analytics_events', ['session_id'], unique=False)


def downgrade():
    """Remove bot models."""
    
    # Drop tables in reverse order (respecting foreign key constraints)
    op.drop_table('bot_analytics_events')
    op.drop_table('bot_configurations')
    op.drop_table('bot_sessions')
    op.drop_table('bot_rate_limits')
    op.drop_table('bot_analysis_requests')
    op.drop_table('bot_users')
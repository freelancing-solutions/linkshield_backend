"""
Add crisis detection and extension session models for social protection.

Revision ID: 009_add_crisis_and_extension_models
Revises: 008_add_bot_models
Create Date: 2025-10-02 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# revision identifiers, used by Alembic.
revision = '009_add_crisis_and_extension_models'
down_revision = '008_add_bot_models'
branch_labels = None
depends_on = None


def upgrade():
    """Add crisis detection and extension session models."""
    
    # Create sp_crisis_alerts table
    op.create_table(
        'sp_crisis_alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('brand', sa.String(256), nullable=False, index=True),
        sa.Column('platform', sa.String(64), nullable=True),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('severity', sa.String(16), nullable=False),
        sa.Column('reason', sa.String(128), nullable=True),
        sa.Column('window_from', sa.DateTime(timezone=True), nullable=False),
        sa.Column('window_to', sa.DateTime(timezone=True), nullable=False),
        sa.Column('payload', postgresql.JSON(), nullable=False, server_default='{}'),
        sa.Column('resolved', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for sp_crisis_alerts
    op.create_index('idx_crisis_brand_severity', 'sp_crisis_alerts', ['brand', 'severity'])
    op.create_index('idx_crisis_created_at', 'sp_crisis_alerts', ['created_at'])
    op.create_index('idx_crisis_resolved', 'sp_crisis_alerts', ['resolved'])
    
    # Create sp_crisis_state table
    op.create_table(
        'sp_crisis_state',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('brand', sa.String(256), nullable=False, unique=True, index=True),
        sa.Column('consecutive_high_windows', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_alert_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_severity', sa.String(16), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create sp_extension_sessions table
    op.create_table(
        'sp_extension_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('session_id', sa.String(128), nullable=False, unique=True, index=True),
        sa.Column('extension_version', sa.String(32), nullable=True),
        sa.Column('browser_info', postgresql.JSON(), nullable=False, server_default='{}'),
        sa.Column('active_tabs', postgresql.JSON(), nullable=False, server_default='[]'),
        sa.Column('settings_hash', sa.String(64), nullable=True),
        sa.Column('last_activity', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE')
    )
    
    # Create index for sp_extension_sessions
    op.create_index('idx_extension_user_activity', 'sp_extension_sessions', ['user_id', 'last_activity'])
    
    # Create sp_algorithm_health_metrics table
    op.create_table(
        'sp_algorithm_health_metrics',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False, index=True),
        sa.Column('platform', sa.String(64), nullable=False, index=True),
        sa.Column('visibility_score', sa.Float(), nullable=False),
        sa.Column('engagement_score', sa.Float(), nullable=False),
        sa.Column('penalty_score', sa.Float(), nullable=False),
        sa.Column('shadow_ban_score', sa.Float(), nullable=False),
        sa.Column('overall_health_score', sa.Float(), nullable=False),
        sa.Column('metrics_data', postgresql.JSON(), nullable=False, server_default='{}'),
        sa.Column('measured_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE')
    )
    
    # Create indexes for sp_algorithm_health_metrics
    op.create_index('idx_health_user_platform', 'sp_algorithm_health_metrics', ['user_id', 'platform'])
    op.create_index('idx_health_measured_at', 'sp_algorithm_health_metrics', ['measured_at'])


def downgrade():
    """Remove crisis detection and extension session models."""
    
    # Drop tables in reverse order
    op.drop_table('sp_algorithm_health_metrics')
    op.drop_table('sp_extension_sessions')
    op.drop_table('sp_crisis_state')
    op.drop_table('sp_crisis_alerts')

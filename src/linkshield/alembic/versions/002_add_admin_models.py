"""Add admin models and update UserRole enum

Revision ID: 002
Revises: 001
Create Date: 2024-12-19 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Update UserRole enum to include SUPER_ADMIN
    op.execute("ALTER TYPE userrole ADD VALUE 'super_admin'")
    
    # Create config_category enum
    config_category_enum = postgresql.ENUM(
        'security', 'rate_limiting', 'ai_services', 'external_apis', 
        'system', 'notifications',
        name='configcategory'
    )
    config_category_enum.create(op.get_bind())
    
    # Create action_type enum
    action_type_enum = postgresql.ENUM(
        'create', 'read', 'update', 'delete', 'login', 'logout',
        'config_change', 'user_management', 'system_operation',
        name='actiontype'
    )
    action_type_enum.create(op.get_bind())
    
    # Create health_status enum
    health_status_enum = postgresql.ENUM(
        'healthy', 'warning', 'critical', 'unknown',
        name='healthstatus'
    )
    health_status_enum.create(op.get_bind())
    
    # Create global_config table
    op.create_table('global_config',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('key', sa.String(length=255), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('category', postgresql.ENUM(name='configcategory'), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_sensitive', sa.Boolean(), nullable=False),
        sa.Column('data_type', sa.String(length=50), nullable=False),
        sa.Column('validation_regex', sa.String(length=500), nullable=True),
        sa.Column('min_value', sa.Float(), nullable=True),
        sa.Column('max_value', sa.Float(), nullable=True),
        sa.Column('allowed_values', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key')
    )
    op.create_index(op.f('ix_global_config_id'), 'global_config', ['id'], unique=False)
    op.create_index(op.f('ix_global_config_key'), 'global_config', ['key'], unique=False)
    op.create_index(op.f('ix_global_config_category'), 'global_config', ['category'], unique=False)
    
    # Create admin_actions table
    op.create_table('admin_actions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('action_type', postgresql.ENUM(name='actiontype'), nullable=False),
        sa.Column('endpoint', sa.String(length=255), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('request_data', sa.JSON(), nullable=True),
        sa.Column('query_params', sa.JSON(), nullable=True),
        sa.Column('path_params', sa.JSON(), nullable=True),
        sa.Column('response_status', sa.Integer(), nullable=True),
        sa.Column('response_data', sa.JSON(), nullable=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', sa.String(length=255), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('additional_data', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_admin_actions_id'), 'admin_actions', ['id'], unique=False)
    op.create_index(op.f('ix_admin_actions_action_type'), 'admin_actions', ['action_type'], unique=False)
    op.create_index(op.f('ix_admin_actions_user_id'), 'admin_actions', ['user_id'], unique=False)
    op.create_index(op.f('ix_admin_actions_session_id'), 'admin_actions', ['session_id'], unique=False)
    op.create_index(op.f('ix_admin_actions_ip_address'), 'admin_actions', ['ip_address'], unique=False)
    op.create_index(op.f('ix_admin_actions_timestamp'), 'admin_actions', ['timestamp'], unique=False)
    op.create_index(op.f('ix_admin_actions_success'), 'admin_actions', ['success'], unique=False)
    
    # Create system_health table
    op.create_table('system_health',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('component', sa.String(length=100), nullable=False),
        sa.Column('status', postgresql.ENUM(name='healthstatus'), nullable=False),
        sa.Column('response_time_ms', sa.Float(), nullable=True),
        sa.Column('cpu_usage_percent', sa.Float(), nullable=True),
        sa.Column('memory_usage_percent', sa.Float(), nullable=True),
        sa.Column('disk_usage_percent', sa.Float(), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('checked_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('component', 'checked_at', name='uq_component_timestamp')
    )
    op.create_index(op.f('ix_system_health_id'), 'system_health', ['id'], unique=False)
    op.create_index(op.f('ix_system_health_component'), 'system_health', ['component'], unique=False)
    op.create_index(op.f('ix_system_health_status'), 'system_health', ['status'], unique=False)
    op.create_index(op.f('ix_system_health_checked_at'), 'system_health', ['checked_at'], unique=False)
    
    # Create admin_sessions table
    op.create_table('admin_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_token', sa.String(length=255), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('location', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('last_activity', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('terminated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('permissions', sa.JSON(), nullable=True),
        sa.Column('mfa_verified', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_token')
    )
    op.create_index(op.f('ix_admin_sessions_id'), 'admin_sessions', ['id'], unique=False)
    op.create_index(op.f('ix_admin_sessions_session_token'), 'admin_sessions', ['session_token'], unique=False)
    op.create_index(op.f('ix_admin_sessions_user_id'), 'admin_sessions', ['user_id'], unique=False)
    op.create_index(op.f('ix_admin_sessions_ip_address'), 'admin_sessions', ['ip_address'], unique=False)
    op.create_index(op.f('ix_admin_sessions_is_active'), 'admin_sessions', ['is_active'], unique=False)


def downgrade() -> None:
    # Drop admin tables
    op.drop_table('admin_sessions')
    op.drop_table('system_health')
    op.drop_table('admin_actions')
    op.drop_table('global_config')
    
    # Drop enums
    op.execute("DROP TYPE IF EXISTS healthstatus")
    op.execute("DROP TYPE IF EXISTS actiontype")
    op.execute("DROP TYPE IF EXISTS configcategory")
    
    # Note: Cannot easily remove enum value from UserRole in PostgreSQL
    # This would require recreating the enum and updating all references
    # For production, consider a separate migration or manual intervention
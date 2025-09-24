"""
Add Dashboard Project Models

Revision ID: 004
Revises: 003
Create Date: 2025-01-01 00:00:00.000000

This migration adds dashboard functionality by creating:
- Project management models (Project, ProjectMember)
- Monitoring configuration (MonitoringConfig)
- Alert system (ProjectAlert)
- Subscription plan monitoring limits

Models support team collaboration, project-specific monitoring settings,
and customizable alert preferences for dashboard functionality.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '004_add_dashboard_project_models'
down_revision = '003_add_background_task_models'
branch_labels = None
depends_on = None


def create_project_role_enum():
    """Create project_role enum type."""
    project_role = sa.Enum('owner', 'admin', 'editor', 'viewer', name='project_role')
    project_role.create(op.get_bind(), checkfirst=True)
    return project_role


def create_alert_type_enum():
    """Create alert_type enum type."""
    alert_type = sa.Enum('broken_links', 'harmful_content', 'scan_failed', 'security_threat', name='alert_type')
    alert_type.create(op.get_bind(), checkfirst=True)
    return alert_type


def create_alert_channel_enum():
    """Create alert_channel enum type."""
    alert_channel = sa.Enum('email', 'dashboard', 'webhook', name='alert_channel')
    alert_channel.create(op.get_bind(), checkfirst=True)
    return alert_channel


def upgrade():
    """
    Upgrade database schema to add dashboard project models.
    """
    # Create enum types
    project_role_enum = create_project_role_enum()
    alert_type_enum = create_alert_type_enum()
    alert_channel_enum = create_alert_channel_enum()
    
    # Add monitoring limit columns to subscription_plans
    op.add_column('subscription_plans', sa.Column('max_projects', sa.Integer(), nullable=False, server_default='1'))
    op.add_column('subscription_plans', sa.Column('max_team_members_per_project', sa.Integer(), nullable=False, server_default='5'))
    op.add_column('subscription_plans', sa.Column('max_alerts_per_project', sa.Integer(), nullable=False, server_default='10'))
    op.add_column('subscription_plans', sa.Column('monitoring_frequency_minutes', sa.Integer(), nullable=False, server_default='60'))
    op.add_column('subscription_plans', sa.Column('scan_depth_limit', sa.Integer(), nullable=False, server_default='3'))
    op.add_column('subscription_plans', sa.Column('max_links_per_scan', sa.Integer(), nullable=False, server_default='100'))
    
    # Create projects table
    op.create_table('projects',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('website_url', sa.String(length=500), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('monitoring_enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('settings', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create project_members table
    op.create_table('project_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('invited_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('role', project_role_enum, nullable=False),
        sa.Column('invited_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('joined_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('invitation_token', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['invited_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('invitation_token', name='uq_project_members_invitation_token')
    )
    
    # Create monitoring_configs table
    op.create_table('monitoring_configs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_frequency_minutes', sa.Integer(), nullable=False),
        sa.Column('scan_depth', sa.Integer(), nullable=False),
        sa.Column('max_links_per_scan', sa.Integer(), nullable=False),
        sa.Column('check_broken_links', sa.Boolean(), nullable=False),
        sa.Column('check_harmful_content', sa.Boolean(), nullable=False),
        sa.Column('check_security_threats', sa.Boolean(), nullable=False),
        sa.Column('check_performance', sa.Boolean(), nullable=False),
        sa.Column('check_seo_issues', sa.Boolean(), nullable=False),
        sa.Column('exclude_patterns', postgresql.JSONB(), nullable=True),
        sa.Column('include_subdomains', sa.Boolean(), nullable=False),
        sa.Column('follow_redirects', sa.Boolean(), nullable=False),
        sa.Column('timeout_seconds', sa.Integer(), nullable=False),
        sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_scan_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('scan_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_id', name='uq_monitoring_configs_project_id')
    )
    
    # Create project_alerts table
    op.create_table('project_alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('alert_type', alert_type_enum, nullable=False),
        sa.Column('channel', alert_channel_enum, nullable=False),
        sa.Column('is_enabled', sa.Boolean(), nullable=False),
        sa.Column('threshold_value', sa.Integer(), nullable=True),
        sa.Column('last_alert_sent', sa.DateTime(timezone=True), nullable=True),
        sa.Column('alert_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('delivery_config', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for better performance
    op.create_index(op.f('ix_projects_user_id'), 'projects', ['user_id'], unique=False)
    op.create_index(op.f('ix_projects_name'), 'projects', ['name'], unique=False)
    op.create_index(op.f('ix_projects_domain'), 'projects', ['domain'], unique=False)
    op.create_index(op.f('ix_projects_is_active'), 'projects', ['is_active'], unique=False)
    op.create_index(op.f('ix_projects_monitoring_enabled'), 'projects', ['monitoring_enabled'], unique=False)
    op.create_index(op.f('ix_projects_created_at'), 'projects', ['created_at'], unique=False)
    op.create_index(op.f('ix_projects_last_scan_at'), 'projects', ['last_scan_at'], unique=False)
    op.create_index(op.f('ix_projects_user_domain'), 'projects', ['user_id', 'domain'], unique=False)
    
    op.create_index(op.f('ix_project_members_project_id'), 'project_members', ['project_id'], unique=False)
    op.create_index(op.f('ix_project_members_user_id'), 'project_members', ['user_id'], unique=False)
    op.create_index(op.f('ix_project_members_role'), 'project_members', ['role'], unique=False)
    op.create_index(op.f('ix_project_members_is_active'), 'project_members', ['is_active'], unique=False)
    op.create_index(op.f('ix_project_members_project_user'), 'project_members', ['project_id', 'user_id'], unique=True)
    
    op.create_index(op.f('ix_monitoring_configs_project_id'), 'monitoring_configs', ['project_id'], unique=False)
    op.create_index(op.f('ix_monitoring_configs_is_enabled'), 'monitoring_configs', ['is_enabled'], unique=False)
    op.create_index(op.f('ix_monitoring_configs_last_scan_at'), 'monitoring_configs', ['last_scan_at'], unique=False)
    op.create_index(op.f('ix_monitoring_configs_next_scan_at'), 'monitoring_configs', ['next_scan_at'], unique=False)
    

    op.create_index(op.f('ix_project_alerts_project_id'), 'project_alerts', ['project_id'], unique=False)
    op.create_index(op.f('ix_project_alerts_user_id'), 'project_alerts', ['user_id'], unique=False)
    op.create_index(op.f('ix_project_alerts_alert_type'), 'project_alerts', ['alert_type'], unique=False)
    op.create_index(op.f('ix_project_alerts_channel'), 'project_alerts', ['channel'], unique=False)
    op.create_index(op.f('ix_project_alerts_is_enabled'), 'project_alerts', ['is_enabled'], unique=False)
    op.create_index(op.f('ix_project_alerts_last_alert_sent'), 'project_alerts', ['last_alert_sent'], unique=False)
    op.create_index(op.f('ix_project_alerts_project_user_type'), 'project_alerts', ['project_id', 'user_id', 'alert_type'], unique=True)


def downgrade():
    """
    Downgrade database schema to remove dashboard project models.
    """
    # Convert JSONB columns back to Text before dropping tables
    op.alter_column('project_alerts', 'delivery_config', type_=sa.Text(), postgresql_using='delivery_config::text')
    op.alter_column('monitoring_configs', 'exclude_patterns', type_=sa.Text(), postgresql_using='exclude_patterns::text')
    op.alter_column('projects', 'settings', type_=sa.Text(), postgresql_using='settings::text')
    # Drop indexes
    op.drop_index(op.f('ix_project_alerts_project_user_type'), table_name='project_alerts')
    op.drop_index(op.f('ix_project_alerts_last_alert_sent'), table_name='project_alerts')
    op.drop_index(op.f('ix_project_alerts_is_enabled'), table_name='project_alerts')
    op.drop_index(op.f('ix_project_alerts_channel'), table_name='project_alerts')
    op.drop_index(op.f('ix_project_alerts_alert_type'), table_name='project_alerts')
    op.drop_index(op.f('ix_project_alerts_user_id'), table_name='project_alerts')
    op.drop_index(op.f('ix_project_alerts_project_id'), table_name='project_alerts')
    
    op.drop_index(op.f('ix_monitoring_configs_next_scan_at'), table_name='monitoring_configs')
    op.drop_index(op.f('ix_monitoring_configs_last_scan_at'), table_name='monitoring_configs')
    op.drop_index(op.f('ix_monitoring_configs_is_enabled'), table_name='monitoring_configs')
    op.drop_index(op.f('ix_monitoring_configs_project_id'), table_name='monitoring_configs')
    op.drop_constraint('uq_monitoring_configs_project_id', table_name='monitoring_configs')
    
    op.drop_index(op.f('ix_project_members_project_user'), table_name='project_members')
    op.drop_index(op.f('ix_project_members_is_active'), table_name='project_members')
    op.drop_index(op.f('ix_project_members_role'), table_name='project_members')
    op.drop_index(op.f('ix_project_members_user_id'), table_name='project_members')
    op.drop_index(op.f('ix_project_members_project_id'), table_name='project_members')
    op.drop_constraint('uq_project_members_invitation_token', table_name='project_members')
    
    op.drop_index(op.f('ix_projects_user_domain'), table_name='projects')
    op.drop_index(op.f('ix_projects_last_scan_at'), table_name='projects')
    op.drop_index(op.f('ix_projects_created_at'), table_name='projects')
    op.drop_index(op.f('ix_projects_monitoring_enabled'), table_name='projects')
    op.drop_index(op.f('ix_projects_is_active'), table_name='projects')
    op.drop_index(op.f('ix_projects_domain'), table_name='projects')
    op.drop_index(op.f('ix_projects_name'), table_name='projects')
    op.drop_index(op.f('ix_projects_user_id'), table_name='projects')
    
    # Drop tables
    op.drop_table('project_alerts')
    op.drop_table('monitoring_configs')
    op.drop_table('project_members')
    op.drop_table('projects')
    
    # Drop monitoring limit columns from subscription_plans table
    op.drop_column('subscription_plans', 'max_links_per_scan')
    op.drop_column('subscription_plans', 'scan_depth_limit')
    op.drop_column('subscription_plans', 'monitoring_frequency_minutes')
    op.drop_column('subscription_plans', 'max_alerts')
    op.drop_column('subscription_plans', 'max_team_members')
    op.drop_column('subscription_plans', 'max_projects')
    
    # Drop enum types
    op.execute('DROP TYPE IF EXISTS alert_channel')
    op.execute('DROP TYPE IF EXISTS alert_type')
    op.execute('DROP TYPE IF EXISTS project_role')
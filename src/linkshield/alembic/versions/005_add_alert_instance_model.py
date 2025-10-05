"""
Add AlertInstance model for alert management.

Revision ID: 005_add_alert_instance_model
Revises: 004_add_dashboard_project_models
Create Date: 2024-01-15 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '005_add_alert_instance_model'
down_revision = '004_add_dashboard_project_models'
branch_labels = None
depends_on = None


def upgrade():
    """Upgrade database schema."""
    # Create alert_instances table
    op.create_table(
        'alert_instances',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False, primary_key=True),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_alert_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('alert_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='medium'),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('context_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True, server_default='{}'),
        sa.Column('affected_urls', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='active'),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('notification_sent', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('notification_sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('notification_channel', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['project_alert_id'], ['project_alerts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.CheckConstraint("status IN ('active', 'acknowledged', 'resolved', 'dismissed')", name='valid_alert_status'),
        sa.CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name='valid_alert_severity'),
    )
    
    # Create indexes for performance
    op.create_index('ix_alert_instances_project_id_status', 'alert_instances', ['project_id', 'status'])
    op.create_index('ix_alert_instances_alert_type_severity', 'alert_instances', ['alert_type', 'severity'])
    op.create_index('ix_alert_instances_created_at', 'alert_instances', ['created_at'])
    op.create_index('ix_alert_instances_status', 'alert_instances', ['status'])
    op.create_index('ix_alert_instances_severity', 'alert_instances', ['severity'])


def downgrade():
    """Downgrade database schema."""
    # Drop indexes
    op.drop_index('ix_alert_instances_severity')
    op.drop_index('ix_alert_instances_status')
    op.drop_index('ix_alert_instances_created_at')
    op.drop_index('ix_alert_instances_alert_type_severity')
    op.drop_index('ix_alert_instances_project_id_status')
    
    # Drop table
    op.drop_table('alert_instances')
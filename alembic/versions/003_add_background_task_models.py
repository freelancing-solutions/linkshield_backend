"""Add background task models

Revision ID: 003_add_background_task_models
Revises: 002_add_admin_models
Create Date: 2024-01-15 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '003_add_background_task_models'
down_revision = '002_add_admin_models'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create TaskStatus enum
    task_status_enum = postgresql.ENUM(
        'PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'RETRYING',
        name='taskstatus',
        create_type=False
    )
    task_status_enum.create(op.get_bind(), checkfirst=True)
    
    # Create TaskType enum
    task_type_enum = postgresql.ENUM(
        'URL_ANALYSIS', 'REPORT_GENERATION', 'BULK_SCAN', 'DATA_EXPORT',
        'SYSTEM_MAINTENANCE', 'EMAIL_NOTIFICATION', 'WEBHOOK_DELIVERY',
        'AI_ANALYSIS', 'CUSTOM',
        name='tasktype',
        create_type=False
    )
    task_type_enum.create(op.get_bind(), checkfirst=True)
    
    # Create TaskPriority enum
    task_priority_enum = postgresql.ENUM(
        'LOW', 'NORMAL', 'HIGH', 'URGENT',
        name='taskpriority',
        create_type=False
    )
    task_priority_enum.create(op.get_bind(), checkfirst=True)
    
    # Create background_tasks table
    op.create_table(
        'background_tasks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('task_id', sa.String(length=36), nullable=False),
        sa.Column('task_name', sa.String(length=255), nullable=False),
        sa.Column('task_type', task_type_enum, nullable=False),
        sa.Column('priority', task_priority_enum, nullable=False, server_default='NORMAL'),
        sa.Column('status', task_status_enum, nullable=False, server_default='PENDING'),
        sa.Column('progress', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('estimated_duration_seconds', sa.Integer(), nullable=True),
        sa.Column('actual_duration_seconds', sa.Integer(), nullable=True),
        sa.Column('input_data', sa.JSON(), nullable=True),
        sa.Column('result_data', sa.JSON(), nullable=True),
        sa.Column('error_details', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('retry_delay_seconds', sa.Integer(), nullable=False, server_default='60'),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('session_id', sa.String(length=255), nullable=True),
        sa.Column('correlation_id', sa.String(length=255), nullable=True),
        sa.Column('webhook_url', sa.String(length=2048), nullable=True),
        sa.Column('webhook_secret', sa.String(length=255), nullable=True),
        sa.Column('notification_sent', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('tags', sa.ARRAY(sa.String()), nullable=True),
        sa.Column('worker_id', sa.String(length=255), nullable=True),
        sa.Column('queue_name', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('task_id')
    )
    
    # Create indexes for background_tasks
    op.create_index('ix_background_tasks_task_id', 'background_tasks', ['task_id'])
    op.create_index('ix_background_tasks_status', 'background_tasks', ['status'])
    op.create_index('ix_background_tasks_task_type', 'background_tasks', ['task_type'])
    op.create_index('ix_background_tasks_priority', 'background_tasks', ['priority'])
    op.create_index('ix_background_tasks_created_at', 'background_tasks', ['created_at'])
    op.create_index('ix_background_tasks_user_id', 'background_tasks', ['user_id'])
    op.create_index('ix_background_tasks_session_id', 'background_tasks', ['session_id'])
    op.create_index('ix_background_tasks_correlation_id', 'background_tasks', ['correlation_id'])
    op.create_index('ix_background_tasks_queue_name', 'background_tasks', ['queue_name'])
    op.create_index('ix_background_tasks_worker_id', 'background_tasks', ['worker_id'])
    
    # Create task_logs table
    op.create_table(
        'task_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('task_id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('level', sa.String(length=20), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('component', sa.String(length=100), nullable=True),
        sa.Column('function_name', sa.String(length=100), nullable=True),
        sa.Column('line_number', sa.Integer(), nullable=True),
        sa.Column('extra_data', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['task_id'], ['background_tasks.id'], ondelete='CASCADE')
    )
    
    # Create indexes for task_logs
    op.create_index('ix_task_logs_task_id', 'task_logs', ['task_id'])
    op.create_index('ix_task_logs_timestamp', 'task_logs', ['timestamp'])
    op.create_index('ix_task_logs_level', 'task_logs', ['level'])
    
    # Create task_dependencies table
    op.create_table(
        'task_dependencies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('dependent_task_id', sa.Integer(), nullable=False),
        sa.Column('prerequisite_task_id', sa.Integer(), nullable=False),
        sa.Column('dependency_type', sa.String(length=50), nullable=False, server_default='blocking'),
        sa.Column('is_blocking', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['dependent_task_id'], ['background_tasks.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['prerequisite_task_id'], ['background_tasks.id'], ondelete='CASCADE'),
        sa.UniqueConstraint('dependent_task_id', 'prerequisite_task_id', name='uq_task_dependency')
    )
    
    # Create indexes for task_dependencies
    op.create_index('ix_task_dependencies_dependent_task_id', 'task_dependencies', ['dependent_task_id'])
    op.create_index('ix_task_dependencies_prerequisite_task_id', 'task_dependencies', ['prerequisite_task_id'])
    op.create_index('ix_task_dependencies_is_blocking', 'task_dependencies', ['is_blocking'])
    op.create_index('ix_task_dependencies_created_at', 'task_dependencies', ['created_at'])


def downgrade() -> None:
    # Drop indexes first
    op.drop_index('ix_task_dependencies_created_at', table_name='task_dependencies')
    op.drop_index('ix_task_dependencies_is_blocking', table_name='task_dependencies')
    op.drop_index('ix_task_dependencies_prerequisite_task_id', table_name='task_dependencies')
    op.drop_index('ix_task_dependencies_dependent_task_id', table_name='task_dependencies')
    
    op.drop_index('ix_task_logs_level', table_name='task_logs')
    op.drop_index('ix_task_logs_timestamp', table_name='task_logs')
    op.drop_index('ix_task_logs_task_id', table_name='task_logs')
    
    op.drop_index('ix_background_tasks_worker_id', table_name='background_tasks')
    op.drop_index('ix_background_tasks_queue_name', table_name='background_tasks')
    op.drop_index('ix_background_tasks_correlation_id', table_name='background_tasks')
    op.drop_index('ix_background_tasks_session_id', table_name='background_tasks')
    op.drop_index('ix_background_tasks_user_id', table_name='background_tasks')
    op.drop_index('ix_background_tasks_created_at', table_name='background_tasks')
    op.drop_index('ix_background_tasks_priority', table_name='background_tasks')
    op.drop_index('ix_background_tasks_task_type', table_name='background_tasks')
    op.drop_index('ix_background_tasks_status', table_name='background_tasks')
    op.drop_index('ix_background_tasks_task_id', table_name='background_tasks')
    
    # Drop tables
    op.drop_table('task_dependencies')
    op.drop_table('task_logs')
    op.drop_table('background_tasks')
    
    # Drop enums
    op.execute('DROP TYPE IF EXISTS taskpriority')
    op.execute('DROP TYPE IF EXISTS tasktype')
    op.execute('DROP TYPE IF EXISTS taskstatus')
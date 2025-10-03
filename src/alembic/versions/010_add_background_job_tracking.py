"""
Add background job tracking model for social protection tasks.

Revision ID: 010_add_background_job_tracking
Revises: 009_add_crisis_and_extension_models
Create Date: 2025-10-03 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# revision identifiers, used by Alembic.
revision = '010_add_background_job_tracking'
down_revision = '009_add_crisis_and_extension_models'
branch_labels = None
depends_on = None


def upgrade():
    """Add background job tracking model."""
    
    # Create job_status enum
    job_status_enum = postgresql.ENUM(
        'PENDING', 'STARTED', 'IN_PROGRESS', 'SUCCESS', 'FAILURE', 'RETRY', 'REVOKED',
        name='jobstatus',
        create_type=True
    )
    job_status_enum.create(op.get_bind(), checkfirst=True)
    
    # Create sp_background_jobs table
    op.create_table(
        'sp_background_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('task_id', sa.String(255), nullable=False, unique=True, index=True),
        sa.Column('task_name', sa.String(255), nullable=False, index=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True, index=True),
        sa.Column('status', job_status_enum, nullable=False, server_default='PENDING', index=True),
        sa.Column('progress', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('task_args', postgresql.JSON(), nullable=False, server_default='{}'),
        sa.Column('task_kwargs', postgresql.JSON(), nullable=False, server_default='{}'),
        sa.Column('result', postgresql.JSON(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('traceback', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('metadata', postgresql.JSON(), nullable=False, server_default='{}'),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL')
    )
    
    # Create indexes for sp_background_jobs
    op.create_index('idx_job_user_status', 'sp_background_jobs', ['user_id', 'status'])
    op.create_index('idx_job_task_name', 'sp_background_jobs', ['task_name'])
    op.create_index('idx_job_created_at', 'sp_background_jobs', ['created_at'])


def downgrade():
    """Remove background job tracking model."""
    
    # Drop table
    op.drop_table('sp_background_jobs')
    
    # Drop enum
    job_status_enum = postgresql.ENUM(
        'PENDING', 'STARTED', 'IN_PROGRESS', 'SUCCESS', 'FAILURE', 'RETRY', 'REVOKED',
        name='jobstatus'
    )
    job_status_enum.drop(op.get_bind(), checkfirst=True)

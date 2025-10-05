"""
Add social protection models for profile scanning and content risk assessment.

Revision ID: 007_add_social_protection_models
Revises: 006_add_broken_link_fields
Create Date: 2024-01-17 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '007_add_social_protection_models'
down_revision = '006_add_broken_link_fields'
branch_labels = None
depends_on = None


def upgrade():
    """Add social protection models."""
    
    # Create platform_type enum
    platform_type_enum = postgresql.ENUM(
        'FACEBOOK', 'INSTAGRAM', 'TWITTER', 'LINKEDIN', 'TIKTOK', 'YOUTUBE', 'SNAPCHAT', 'PINTEREST', 'REDDIT', 'DISCORD',
        name='platformtype'
    )
    platform_type_enum.create(op.get_bind())
    
    # Create scan_status enum
    scan_status_enum = postgresql.ENUM(
        'PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED',
        name='scanstatus'
    )
    scan_status_enum.create(op.get_bind())
    
    # Create risk_level enum
    risk_level_enum = postgresql.ENUM(
        'VERY_LOW', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL',
        name='risklevel'
    )
    risk_level_enum.create(op.get_bind())
    
    # Create content_type enum
    content_type_enum = postgresql.ENUM(
        'POST', 'COMMENT', 'STORY', 'REEL', 'VIDEO', 'IMAGE', 'LINK', 'PROFILE_BIO', 'HASHTAG',
        name='contenttype'
    )
    content_type_enum.create(op.get_bind())
    
    # Create assessment_type enum
    assessment_type_enum = postgresql.ENUM(
        'PROFILE_SCAN', 'CONTENT_ANALYSIS', 'ALGORITHM_HEALTH', 'CRISIS_DETECTION', 'REPUTATION_MONITORING',
        name='assessmenttype'
    )
    assessment_type_enum.create(op.get_bind())
    
    # Create social_profile_scans table
    op.create_table(
        'social_profile_scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=True),
        sa.Column('platform', platform_type_enum, nullable=False),
        sa.Column('profile_url', sa.String(2048), nullable=False),
        sa.Column('profile_username', sa.String(255), nullable=True),
        sa.Column('scan_status', scan_status_enum, nullable=False, default='PENDING'),
        sa.Column('risk_level', risk_level_enum, nullable=True),
        sa.Column('risk_score', sa.Float, nullable=True),
        sa.Column('scan_request_data', sa.JSON, nullable=True),
        sa.Column('scan_result_data', sa.JSON, nullable=True),
        sa.Column('risk_factors', sa.JSON, nullable=True),
        sa.Column('recommendations', sa.JSON, nullable=True),
        sa.Column('error_message', sa.Text, nullable=True),
        sa.Column('scan_duration_seconds', sa.Float, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )
    
    # Create content_risk_assessments table
    op.create_table(
        'content_risk_assessments',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=True),
        sa.Column('platform', platform_type_enum, nullable=False),
        sa.Column('content_type', content_type_enum, nullable=False),
        sa.Column('content_url', sa.String(2048), nullable=True),
        sa.Column('content_text', sa.Text, nullable=True),
        sa.Column('assessment_type', assessment_type_enum, nullable=False),
        sa.Column('scan_status', scan_status_enum, nullable=False, default='PENDING'),
        sa.Column('risk_level', risk_level_enum, nullable=True),
        sa.Column('risk_score', sa.Float, nullable=True),
        sa.Column('analysis_request_data', sa.JSON, nullable=True),
        sa.Column('analysis_result_data', sa.JSON, nullable=True),
        sa.Column('risk_factors', sa.JSON, nullable=True),
        sa.Column('recommendations', sa.JSON, nullable=True),
        sa.Column('error_message', sa.Text, nullable=True),
        sa.Column('analysis_duration_seconds', sa.Float, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    )
    
    # Create indexes for efficient querying
    
    # Social profile scans indexes
    op.create_index('ix_social_profile_scans_user_id', 'social_profile_scans', ['user_id'])
    op.create_index('ix_social_profile_scans_project_id', 'social_profile_scans', ['project_id'])
    op.create_index('ix_social_profile_scans_platform', 'social_profile_scans', ['platform'])
    op.create_index('ix_social_profile_scans_scan_status', 'social_profile_scans', ['scan_status'])
    op.create_index('ix_social_profile_scans_risk_level', 'social_profile_scans', ['risk_level'])
    op.create_index('ix_social_profile_scans_created_at', 'social_profile_scans', ['created_at'])
    op.create_index('ix_social_profile_scans_user_platform', 'social_profile_scans', ['user_id', 'platform'])
    op.create_index('ix_social_profile_scans_project_platform', 'social_profile_scans', ['project_id', 'platform'])
    
    # Content risk assessments indexes
    op.create_index('ix_content_risk_assessments_user_id', 'content_risk_assessments', ['user_id'])
    op.create_index('ix_content_risk_assessments_project_id', 'content_risk_assessments', ['project_id'])
    op.create_index('ix_content_risk_assessments_platform', 'content_risk_assessments', ['platform'])
    op.create_index('ix_content_risk_assessments_content_type', 'content_risk_assessments', ['content_type'])
    op.create_index('ix_content_risk_assessments_assessment_type', 'content_risk_assessments', ['assessment_type'])
    op.create_index('ix_content_risk_assessments_scan_status', 'content_risk_assessments', ['scan_status'])
    op.create_index('ix_content_risk_assessments_risk_level', 'content_risk_assessments', ['risk_level'])
    op.create_index('ix_content_risk_assessments_created_at', 'content_risk_assessments', ['created_at'])
    op.create_index('ix_content_risk_assessments_user_platform', 'content_risk_assessments', ['user_id', 'platform'])
    op.create_index('ix_content_risk_assessments_project_platform', 'content_risk_assessments', ['project_id', 'platform'])


def downgrade():
    """Remove social protection models."""
    
    # Drop indexes first
    
    # Content risk assessments indexes
    op.drop_index('ix_content_risk_assessments_project_platform', table_name='content_risk_assessments')
    op.drop_index('ix_content_risk_assessments_user_platform', table_name='content_risk_assessments')
    op.drop_index('ix_content_risk_assessments_created_at', table_name='content_risk_assessments')
    op.drop_index('ix_content_risk_assessments_risk_level', table_name='content_risk_assessments')
    op.drop_index('ix_content_risk_assessments_scan_status', table_name='content_risk_assessments')
    op.drop_index('ix_content_risk_assessments_assessment_type', table_name='content_risk_assessments')
    op.drop_index('ix_content_risk_assessments_content_type', table_name='content_risk_assessments')
    op.drop_index('ix_content_risk_assessments_platform', table_name='content_risk_assessments')
    op.drop_index('ix_content_risk_assessments_project_id', table_name='content_risk_assessments')
    op.drop_index('ix_content_risk_assessments_user_id', table_name='content_risk_assessments')
    
    # Social profile scans indexes
    op.drop_index('ix_social_profile_scans_project_platform', table_name='social_profile_scans')
    op.drop_index('ix_social_profile_scans_user_platform', table_name='social_profile_scans')
    op.drop_index('ix_social_profile_scans_created_at', table_name='social_profile_scans')
    op.drop_index('ix_social_profile_scans_risk_level', table_name='social_profile_scans')
    op.drop_index('ix_social_profile_scans_scan_status', table_name='social_profile_scans')
    op.drop_index('ix_social_profile_scans_platform', table_name='social_profile_scans')
    op.drop_index('ix_social_profile_scans_project_id', table_name='social_profile_scans')
    op.drop_index('ix_social_profile_scans_user_id', table_name='social_profile_scans')
    
    # Drop tables
    op.drop_table('content_risk_assessments')
    op.drop_table('social_profile_scans')
    
    # Drop enums
    op.execute('DROP TYPE assessmenttype')
    op.execute('DROP TYPE contenttype')
    op.execute('DROP TYPE risklevel')
    op.execute('DROP TYPE scanstatus')
    op.execute('DROP TYPE platformtype')
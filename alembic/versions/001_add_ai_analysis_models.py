"""Add AI analysis models

Revision ID: 001
Revises: 
Create Date: 2024-12-19 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create processing_status enum
    processing_status_enum = postgresql.ENUM(
        'pending', 'processing', 'completed', 'failed', 'cached',
        name='processingstatus'
    )
    processing_status_enum.create(op.get_bind())
    
    # Create analysis_type enum
    analysis_type_enum = postgresql.ENUM(
        'content_summary', 'quality_scoring', 'topic_classification',
        'content_similarity', 'language_detection', 'seo_analysis',
        'sentiment_analysis', 'threat_analysis',
        name='analysistype'
    )
    analysis_type_enum.create(op.get_bind())
    
    # Create ai_analyses table
    op.create_table('ai_analyses',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('check_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('url', sa.String(length=2048), nullable=False),
        sa.Column('content_hash', sa.String(length=64), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('content_summary', sa.Text(), nullable=True),
        sa.Column('content_embedding', sa.JSON(), nullable=True),
        sa.Column('quality_metrics', sa.JSON(), nullable=True),
        sa.Column('topic_categories', sa.JSON(), nullable=True),
        sa.Column('keyword_density', sa.JSON(), nullable=True),
        sa.Column('seo_metrics', sa.JSON(), nullable=True),
        sa.Column('sentiment_analysis', sa.JSON(), nullable=True),
        sa.Column('content_length', sa.Integer(), nullable=True),
        sa.Column('language', sa.String(length=10), nullable=True),
        sa.Column('reading_level', sa.String(length=20), nullable=True),
        sa.Column('overall_quality_score', sa.Integer(), nullable=True),
        sa.Column('readability_score', sa.Integer(), nullable=True),
        sa.Column('trustworthiness_score', sa.Integer(), nullable=True),
        sa.Column('professionalism_score', sa.Integer(), nullable=True),
        sa.Column('processing_status', processing_status_enum, nullable=False),
        sa.Column('analysis_types', sa.JSON(), nullable=True),
        sa.Column('processing_time_ms', sa.Integer(), nullable=True),
        sa.Column('model_versions', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('retry_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['check_id'], ['url_checks.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('content_hash')
    )
    
    # Create indexes for ai_analyses
    op.create_index('idx_ai_analysis_user_created', 'ai_analyses', ['user_id', 'created_at'])
    op.create_index('idx_ai_analysis_domain_quality', 'ai_analyses', ['domain', 'overall_quality_score'])
    op.create_index('idx_ai_analysis_status_created', 'ai_analyses', ['processing_status', 'created_at'])
    op.create_index('idx_ai_analysis_hash_status', 'ai_analyses', ['content_hash', 'processing_status'])
    op.create_index(op.f('ix_ai_analyses_id'), 'ai_analyses', ['id'])
    op.create_index(op.f('ix_ai_analyses_user_id'), 'ai_analyses', ['user_id'])
    op.create_index(op.f('ix_ai_analyses_check_id'), 'ai_analyses', ['check_id'])
    op.create_index(op.f('ix_ai_analyses_url'), 'ai_analyses', ['url'])
    op.create_index(op.f('ix_ai_analyses_content_hash'), 'ai_analyses', ['content_hash'])
    op.create_index(op.f('ix_ai_analyses_domain'), 'ai_analyses', ['domain'])
    
    # Create content_similarities table
    op.create_table('content_similarities',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('source_analysis_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_analysis_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('similarity_score', sa.Float(), nullable=False),
        sa.Column('similarity_type', sa.String(length=50), nullable=False),
        sa.Column('matching_elements', sa.JSON(), nullable=True),
        sa.Column('confidence_score', sa.Integer(), nullable=False),
        sa.Column('algorithm_version', sa.String(length=20), nullable=True),
        sa.Column('processing_time_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['source_analysis_id'], ['ai_analyses.id'], ),
        sa.ForeignKeyConstraint(['target_analysis_id'], ['ai_analyses.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for content_similarities
    op.create_index('idx_similarity_source_score', 'content_similarities', ['source_analysis_id', 'similarity_score'])
    op.create_index('idx_similarity_target_score', 'content_similarities', ['target_analysis_id', 'similarity_score'])
    op.create_index('idx_similarity_score_type', 'content_similarities', ['similarity_score', 'similarity_type'])
    op.create_index(op.f('ix_content_similarities_id'), 'content_similarities', ['id'])
    op.create_index(op.f('ix_content_similarities_source_analysis_id'), 'content_similarities', ['source_analysis_id'])
    op.create_index(op.f('ix_content_similarities_target_analysis_id'), 'content_similarities', ['target_analysis_id'])
    
    # Create ai_model_metrics table
    op.create_table('ai_model_metrics',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('model_name', sa.String(length=100), nullable=False),
        sa.Column('model_version', sa.String(length=50), nullable=False),
        sa.Column('analysis_type', analysis_type_enum, nullable=False),
        sa.Column('total_requests', sa.Integer(), nullable=False),
        sa.Column('successful_requests', sa.Integer(), nullable=False),
        sa.Column('failed_requests', sa.Integer(), nullable=False),
        sa.Column('avg_processing_time_ms', sa.Float(), nullable=True),
        sa.Column('avg_confidence_score', sa.Float(), nullable=True),
        sa.Column('total_tokens_used', sa.Integer(), nullable=False),
        sa.Column('total_cost_usd', sa.Float(), nullable=False),
        sa.Column('date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('period_type', sa.String(length=20), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for ai_model_metrics
    op.create_index('idx_model_metrics_name_date', 'ai_model_metrics', ['model_name', 'date'])
    op.create_index('idx_model_metrics_type_date', 'ai_model_metrics', ['analysis_type', 'date'])
    op.create_index('idx_model_metrics_period_date', 'ai_model_metrics', ['period_type', 'date'])
    op.create_index(op.f('ix_ai_model_metrics_id'), 'ai_model_metrics', ['id'])
    op.create_index(op.f('ix_ai_model_metrics_model_name'), 'ai_model_metrics', ['model_name'])
    op.create_index(op.f('ix_ai_model_metrics_analysis_type'), 'ai_model_metrics', ['analysis_type'])
    op.create_index(op.f('ix_ai_model_metrics_date'), 'ai_model_metrics', ['date'])


def downgrade() -> None:
    # Drop tables
    op.drop_table('ai_model_metrics')
    op.drop_table('content_similarities')
    op.drop_table('ai_analyses')
    
    # Drop enums
    op.execute('DROP TYPE IF EXISTS analysistype')
    op.execute('DROP TYPE IF EXISTS processingstatus')
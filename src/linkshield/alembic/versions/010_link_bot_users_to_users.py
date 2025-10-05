"""
Link bot users to authenticated users with subscription validation.

Revision ID: 010_link_bot_users_to_users
Revises: 009_add_crisis_and_extension_models
Create Date: 2025-01-20 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# revision identifiers, used by Alembic.
revision = '010_link_bot_users_to_users'
down_revision = '009_add_crisis_and_extension_models'
branch_labels = None
depends_on = None


def upgrade():
    """Add user_id foreign key to bot_users table and establish relationship."""
    
    # Add user_id column to bot_users table
    # Initially nullable to allow for data migration of existing records
    op.add_column('bot_users', sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True))
    
    # Create index on user_id for performance
    op.create_index('idx_bot_users_user_id', 'bot_users', ['user_id'])
    
    # Add foreign key constraint to users table
    op.create_foreign_key(
        'fk_bot_users_user_id',
        'bot_users',
        'users',
        ['user_id'],
        ['id'],
        ondelete='CASCADE'
    )
    
    # Add unique constraint to prevent duplicate platform users per authenticated user
    # This ensures one platform account can only be linked to one authenticated user
    op.create_unique_constraint(
        'uq_bot_users_platform_user_authenticated',
        'bot_users',
        ['platform', 'platform_user_id', 'user_id']
    )
    
    # Add subscription validation fields to bot_users
    op.add_column('bot_users', sa.Column('subscription_validated_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('bot_users', sa.Column('last_subscription_check', sa.DateTime(timezone=True), nullable=True))
    op.add_column('bot_users', sa.Column('subscription_plan_at_link', sa.String(20), nullable=True))
    
    # Add bot-specific usage tracking
    op.add_column('bot_users', sa.Column('monthly_bot_requests', sa.Integer, default=0, nullable=False))
    op.add_column('bot_users', sa.Column('monthly_reset_date', sa.DateTime(timezone=True), nullable=True))
    op.add_column('bot_users', sa.Column('feature_access_level', sa.String(20), default='basic', nullable=False))
    
    # Create indexes for subscription validation performance
    op.create_index('idx_bot_users_subscription_check', 'bot_users', ['last_subscription_check'])
    op.create_index('idx_bot_users_feature_access', 'bot_users', ['feature_access_level'])


def downgrade():
    """Remove user_id foreign key and related fields from bot_users table."""
    
    # Drop indexes
    op.drop_index('idx_bot_users_feature_access', 'bot_users')
    op.drop_index('idx_bot_users_subscription_check', 'bot_users')
    op.drop_index('idx_bot_users_user_id', 'bot_users')
    
    # Drop unique constraint
    op.drop_constraint('uq_bot_users_platform_user_authenticated', 'bot_users', type_='unique')
    
    # Drop foreign key constraint
    op.drop_constraint('fk_bot_users_user_id', 'bot_users', type_='foreignkey')
    
    # Drop added columns
    op.drop_column('bot_users', 'feature_access_level')
    op.drop_column('bot_users', 'monthly_reset_date')
    op.drop_column('bot_users', 'monthly_bot_requests')
    op.drop_column('bot_users', 'subscription_plan_at_link')
    op.drop_column('bot_users', 'last_subscription_check')
    op.drop_column('bot_users', 'subscription_validated_at')
    op.drop_column('bot_users', 'user_id')
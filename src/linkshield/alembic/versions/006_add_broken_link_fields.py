"""
Add broken link fields to url_checks table.

Revision ID: 006_add_broken_link_fields
Revises: 005_add_alert_instance_model
Create Date: 2024-01-16 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '006_add_broken_link_fields'
down_revision = '005_add_alert_instance_model'
branch_labels = None
depends_on = None


def upgrade():
    """Add broken link fields to url_checks table."""
    # Add broken link columns to url_checks table
    op.add_column('url_checks', sa.Column('broken_links_count', sa.Integer(), nullable=True, default=0))
    op.add_column('url_checks', sa.Column('total_links_checked', sa.Integer(), nullable=True, default=0))
    op.add_column('url_checks', sa.Column('scan_depth_used', sa.Integer(), nullable=True))
    op.add_column('url_checks', sa.Column('max_links_used', sa.Integer(), nullable=True))
    
    # Create indexes for efficient querying
    op.create_index('ix_url_checks_broken_links_count', 'url_checks', ['broken_links_count'])
    op.create_index('ix_url_checks_domain_broken_links', 'url_checks', ['domain', 'broken_links_count'])
    op.create_index('ix_url_checks_total_links_checked', 'url_checks', ['total_links_checked'])
    
    # Update existing records with default values
    op.execute("UPDATE url_checks SET broken_links_count = 0, total_links_checked = 0 WHERE broken_links_count IS NULL")


def downgrade():
    """Remove broken link fields from url_checks table."""
    # Drop indexes first
    op.drop_index('ix_url_checks_total_links_checked', table_name='url_checks')
    op.drop_index('ix_url_checks_domain_broken_links', table_name='url_checks')
    op.drop_index('ix_url_checks_broken_links_count', table_name='url_checks')
    
    # Drop columns
    op.drop_column('url_checks', 'max_links_used')
    op.drop_column('url_checks', 'scan_depth_used')
    op.drop_column('url_checks', 'total_links_checked')
    op.drop_column('url_checks', 'broken_links_count')
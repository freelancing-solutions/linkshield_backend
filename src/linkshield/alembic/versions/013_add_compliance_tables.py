"""
Add compliance tracking and security policy management tables.

Revision ID: 013_add_compliance_tables
Revises: 012_add_security_enhancements
Create Date: 2025-01-21 13:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# revision identifiers, used by Alembic.
revision = '013_add_compliance_tables'
down_revision = '012_add_security_enhancements'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    Add compliance tracking and security policy management tables.
    Supports version-specific security policies (REQ-029) and compliance monitoring.
    """
    
    # Create enum types for compliance management
    op.execute("CREATE TYPE compliance_level AS ENUM ('compliant', 'partial', 'non_compliant', 'unknown')")
    op.execute("CREATE TYPE authentication_standard AS ENUM ('owasp_auth_cheat_sheet', 'nist_800_63', 'iso_27001', 'pci_dss', 'custom')")
    op.execute("CREATE TYPE policy_status AS ENUM ('active', 'draft', 'deprecated', 'archived')")
    op.execute("CREATE TYPE policy_type AS ENUM ('password', 'authentication', 'session', 'api_key', 'mfa', 'access_control', 'data_protection')")
    op.execute("CREATE TYPE mfa_method AS ENUM ('totp', 'sms', 'email', 'hardware_token', 'biometric', 'backup_codes')")
    
    # 1. Security Policies Table
    op.create_table(
        'security_policies',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('policy_type', postgresql.ENUM('password', 'authentication', 'session', 'api_key', 'mfa', 'access_control', 'data_protection', name='policy_type'), nullable=False),
        sa.Column('version', sa.String(20), nullable=False),
        sa.Column('status', postgresql.ENUM('active', 'draft', 'deprecated', 'archived', name='policy_status'), nullable=False, default='draft'),
        sa.Column('effective_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expiry_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('policy_config', postgresql.JSONB, nullable=False),
        sa.Column('compliance_standards', postgresql.ARRAY(sa.String), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('approved_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('name', 'version', name='uq_security_policy_name_version'),
    )
    
    # 2. Compliance Checks Table
    op.create_table(
        'compliance_checks',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('security_policies.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('check_type', sa.String(50), nullable=False),
        sa.Column('compliance_level', postgresql.ENUM('compliant', 'partial', 'non_compliant', 'unknown', name='compliance_level'), nullable=False),
        sa.Column('score', sa.Float, nullable=True),  # 0.0 to 1.0
        sa.Column('details', postgresql.JSONB, nullable=True),
        sa.Column('violations', postgresql.JSONB, nullable=True),
        sa.Column('recommendations', postgresql.JSONB, nullable=True),
        sa.Column('automated', sa.Boolean, nullable=False, default=True),
        sa.Column('checked_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False, index=True),
        sa.Column('next_check_at', sa.DateTime(timezone=True), nullable=True),
    )
    
    # 3. Password Policy Compliance Table
    op.create_table(
        'password_policy_compliance',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('security_policies.id', ondelete='CASCADE'), nullable=False),
        sa.Column('password_strength_score', sa.Float, nullable=False),  # 0.0 to 1.0
        sa.Column('meets_length_requirement', sa.Boolean, nullable=False),
        sa.Column('meets_complexity_requirement', sa.Boolean, nullable=False),
        sa.Column('contains_personal_info', sa.Boolean, nullable=False, default=False),
        sa.Column('is_common_password', sa.Boolean, nullable=False, default=False),
        sa.Column('is_breached_password', sa.Boolean, nullable=False, default=False),
        sa.Column('password_age_days', sa.Integer, nullable=True),
        sa.Column('violations', postgresql.JSONB, nullable=True),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    
    # 4. MFA Compliance Table
    op.create_table(
        'mfa_compliance',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('security_policies.id', ondelete='CASCADE'), nullable=False),
        sa.Column('is_required', sa.Boolean, nullable=False),
        sa.Column('is_enabled', sa.Boolean, nullable=False),
        sa.Column('enabled_methods', postgresql.ARRAY(postgresql.ENUM('totp', 'sms', 'email', 'hardware_token', 'biometric', 'backup_codes', name='mfa_method')), nullable=True),
        sa.Column('backup_codes_count', sa.Integer, nullable=False, default=0),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('setup_completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('compliance_status', postgresql.ENUM('compliant', 'partial', 'non_compliant', 'unknown', name='compliance_level'), nullable=False),
        sa.Column('grace_period_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # 5. Authentication Compliance Table
    op.create_table(
        'authentication_compliance',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=True, index=True),
        sa.Column('policy_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('security_policies.id', ondelete='CASCADE'), nullable=False),
        sa.Column('standard', postgresql.ENUM('owasp_auth_cheat_sheet', 'nist_800_63', 'iso_27001', 'pci_dss', 'custom', name='authentication_standard'), nullable=False),
        sa.Column('overall_compliance', postgresql.ENUM('compliant', 'partial', 'non_compliant', 'unknown', name='compliance_level'), nullable=False),
        sa.Column('password_storage_compliant', sa.Boolean, nullable=False),
        sa.Column('session_management_compliant', sa.Boolean, nullable=False),
        sa.Column('authentication_flow_compliant', sa.Boolean, nullable=False),
        sa.Column('account_lockout_compliant', sa.Boolean, nullable=False),
        sa.Column('credential_recovery_compliant', sa.Boolean, nullable=False),
        sa.Column('compliance_details', postgresql.JSONB, nullable=True),
        sa.Column('violations', postgresql.JSONB, nullable=True),
        sa.Column('recommendations', postgresql.JSONB, nullable=True),
        sa.Column('last_assessed_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    
    # 6. Compliance Reports Table
    op.create_table(
        'compliance_reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('report_name', sa.String(100), nullable=False),
        sa.Column('report_type', sa.String(50), nullable=False),  # 'user', 'system', 'policy'
        sa.Column('scope', sa.String(50), nullable=False),  # 'individual', 'organization', 'global'
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=True),  # user_id, policy_id, etc.
        sa.Column('overall_score', sa.Float, nullable=False),  # 0.0 to 1.0
        sa.Column('compliance_summary', postgresql.JSONB, nullable=False),
        sa.Column('policy_compliance', postgresql.JSONB, nullable=True),
        sa.Column('violations_summary', postgresql.JSONB, nullable=True),
        sa.Column('recommendations', postgresql.JSONB, nullable=True),
        sa.Column('generated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('report_period_start', sa.DateTime(timezone=True), nullable=True),
        sa.Column('report_period_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    
    # Add compliance tracking columns to existing users table
    op.add_column('users', sa.Column('compliance_score', sa.Float, nullable=True))
    op.add_column('users', sa.Column('last_compliance_check', sa.DateTime(timezone=True), nullable=True))
    op.add_column('users', sa.Column('compliance_status', postgresql.ENUM('compliant', 'partial', 'non_compliant', 'unknown', name='compliance_level'), nullable=False, server_default='unknown'))
    op.add_column('users', sa.Column('policy_version', sa.String(20), nullable=True))
    op.add_column('users', sa.Column('mfa_required', sa.Boolean, nullable=False, default=False))
    op.add_column('users', sa.Column('mfa_grace_period_expires', sa.DateTime(timezone=True), nullable=True))
    
    # Create indexes for performance optimization
    op.create_index('idx_security_policies_type_status', 'security_policies', ['policy_type', 'status'])
    op.create_index('idx_security_policies_effective_date', 'security_policies', ['effective_date'])
    op.create_index('idx_compliance_checks_level_created', 'compliance_checks', ['compliance_level', 'created_at'])
    op.create_index('idx_compliance_checks_next_check', 'compliance_checks', ['next_check_at'])
    op.create_index('idx_password_policy_compliance_score', 'password_policy_compliance', ['password_strength_score'])
    op.create_index('idx_mfa_compliance_status', 'mfa_compliance', ['compliance_status'])
    op.create_index('idx_mfa_compliance_grace_period', 'mfa_compliance', ['grace_period_expires_at'])
    op.create_index('idx_auth_compliance_standard_level', 'authentication_compliance', ['standard', 'overall_compliance'])
    op.create_index('idx_compliance_reports_type_created', 'compliance_reports', ['report_type', 'created_at'])
    op.create_index('idx_users_compliance_status', 'users', ['compliance_status'])
    op.create_index('idx_users_mfa_grace_period', 'users', ['mfa_grace_period_expires'])


def downgrade() -> None:
    """
    Remove compliance tracking tables and columns.
    Maintains backward compatibility by preserving core user functionality.
    """
    
    # Drop indexes
    op.drop_index('idx_users_mfa_grace_period')
    op.drop_index('idx_users_compliance_status')
    op.drop_index('idx_compliance_reports_type_created')
    op.drop_index('idx_auth_compliance_standard_level')
    op.drop_index('idx_mfa_compliance_grace_period')
    op.drop_index('idx_mfa_compliance_status')
    op.drop_index('idx_password_policy_compliance_score')
    op.drop_index('idx_compliance_checks_next_check')
    op.drop_index('idx_compliance_checks_level_created')
    op.drop_index('idx_security_policies_effective_date')
    op.drop_index('idx_security_policies_type_status')
    
    # Drop new columns from existing tables
    op.drop_column('users', 'mfa_grace_period_expires')
    op.drop_column('users', 'mfa_required')
    op.drop_column('users', 'policy_version')
    op.drop_column('users', 'compliance_status')
    op.drop_column('users', 'last_compliance_check')
    op.drop_column('users', 'compliance_score')
    
    # Drop new tables
    op.drop_table('compliance_reports')
    op.drop_table('authentication_compliance')
    op.drop_table('mfa_compliance')
    op.drop_table('password_policy_compliance')
    op.drop_table('compliance_checks')
    op.drop_table('security_policies')
    
    # Drop enum types
    op.execute("DROP TYPE IF EXISTS mfa_method")
    op.execute("DROP TYPE IF EXISTS policy_type")
    op.execute("DROP TYPE IF EXISTS policy_status")
    op.execute("DROP TYPE IF EXISTS authentication_standard")
    op.execute("DROP TYPE IF EXISTS compliance_level")
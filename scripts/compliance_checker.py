#!/usr/bin/env python3
"""
LinkShield Compliance Checker

Validates security implementations against industry standards and compliance requirements:
- OWASP Top 10 2021
- NIST Cybersecurity Framework
- ISO 27001 Security Controls
- PCI DSS Requirements (where applicable)
- GDPR Privacy Requirements

This script performs automated compliance checking and generates compliance reports.
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import argparse
import re

from pydantic import BaseModel, Field

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from config.settings import get_settings


class ComplianceRule(BaseModel):
    """Compliance rule model"""
    rule_id: str
    standard: str  # OWASP, NIST, ISO27001, PCI_DSS, GDPR
    category: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    check_type: str  # CODE_SCAN, CONFIG_CHECK, MANUAL_REVIEW
    automated: bool = True


class ComplianceResult(BaseModel):
    """Compliance check result"""
    rule_id: str
    status: str  # COMPLIANT, NON_COMPLIANT, PARTIAL, NOT_APPLICABLE, MANUAL_REVIEW
    message: str
    evidence: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    details: Optional[Dict[str, Any]] = None


class ComplianceReport(BaseModel):
    """Compliance report model"""
    timestamp: datetime
    environment: str
    standards_checked: List[str]
    total_rules: int
    compliant: int
    non_compliant: int
    partial: int
    not_applicable: int
    manual_review: int
    compliance_score: float
    results: List[ComplianceResult]
    summary_by_standard: Dict[str, Dict[str, int]]
    critical_issues: List[ComplianceResult]
    recommendations: List[str]


class ComplianceChecker:
    """Comprehensive compliance checker"""
    
    def __init__(self):
        """Initialize compliance checker"""
        self.settings = get_settings()
        self.results: List[ComplianceResult] = []
        self.project_root = Path(__file__).parent.parent
        
        # Initialize logger
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Define compliance rules
        self.rules = self._load_compliance_rules()
    
    def _load_compliance_rules(self) -> List[ComplianceRule]:
        """Load compliance rules for different standards"""
        rules = []
        
        # OWASP Top 10 2021 Rules
        owasp_rules = [
            ComplianceRule(
                rule_id="OWASP-A01-001",
                standard="OWASP",
                category="A01:2021 – Broken Access Control",
                title="Authentication Required for Protected Resources",
                description="Verify that authentication is required for all protected resources",
                severity="CRITICAL",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="OWASP-A01-002",
                standard="OWASP",
                category="A01:2021 – Broken Access Control",
                title="Authorization Checks Implemented",
                description="Verify that proper authorization checks are implemented",
                severity="CRITICAL",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="OWASP-A02-001",
                standard="OWASP",
                category="A02:2021 – Cryptographic Failures",
                title="Strong Cryptographic Algorithms",
                description="Verify that strong cryptographic algorithms are used",
                severity="HIGH",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="OWASP-A02-002",
                standard="OWASP",
                category="A02:2021 – Cryptographic Failures",
                title="Secure Key Management",
                description="Verify that cryptographic keys are securely managed",
                severity="HIGH",
                check_type="CONFIG_CHECK"
            ),
            ComplianceRule(
                rule_id="OWASP-A03-001",
                standard="OWASP",
                category="A03:2021 – Injection",
                title="Input Validation Implemented",
                description="Verify that input validation is implemented to prevent injection attacks",
                severity="CRITICAL",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="OWASP-A04-001",
                standard="OWASP",
                category="A04:2021 – Insecure Design",
                title="Secure Design Patterns",
                description="Verify that secure design patterns are implemented",
                severity="HIGH",
                check_type="MANUAL_REVIEW"
            ),
            ComplianceRule(
                rule_id="OWASP-A05-001",
                standard="OWASP",
                category="A05:2021 – Security Misconfiguration",
                title="Secure Configuration Management",
                description="Verify that security configurations are properly managed",
                severity="HIGH",
                check_type="CONFIG_CHECK"
            ),
            ComplianceRule(
                rule_id="OWASP-A06-001",
                standard="OWASP",
                category="A06:2021 – Vulnerable and Outdated Components",
                title="Component Vulnerability Management",
                description="Verify that components are up-to-date and vulnerability-free",
                severity="HIGH",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="OWASP-A07-001",
                standard="OWASP",
                category="A07:2021 – Identification and Authentication Failures",
                title="Strong Authentication Implementation",
                description="Verify that strong authentication mechanisms are implemented",
                severity="CRITICAL",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="OWASP-A08-001",
                standard="OWASP",
                category="A08:2021 – Software and Data Integrity Failures",
                title="Data Integrity Protection",
                description="Verify that data integrity protection mechanisms are in place",
                severity="HIGH",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="OWASP-A09-001",
                standard="OWASP",
                category="A09:2021 – Security Logging and Monitoring Failures",
                title="Comprehensive Security Logging",
                description="Verify that comprehensive security logging is implemented",
                severity="MEDIUM",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="OWASP-A10-001",
                standard="OWASP",
                category="A10:2021 – Server-Side Request Forgery (SSRF)",
                title="SSRF Protection Implemented",
                description="Verify that SSRF protection mechanisms are in place",
                severity="HIGH",
                check_type="CODE_SCAN"
            )
        ]
        
        # NIST Cybersecurity Framework Rules
        nist_rules = [
            ComplianceRule(
                rule_id="NIST-ID-001",
                standard="NIST",
                category="Identify (ID)",
                title="Asset Management",
                description="Verify that assets are properly identified and managed",
                severity="MEDIUM",
                check_type="MANUAL_REVIEW"
            ),
            ComplianceRule(
                rule_id="NIST-PR-001",
                standard="NIST",
                category="Protect (PR)",
                title="Access Control Implementation",
                description="Verify that access control mechanisms are implemented",
                severity="HIGH",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="NIST-PR-002",
                standard="NIST",
                category="Protect (PR)",
                title="Data Security Implementation",
                description="Verify that data security controls are implemented",
                severity="HIGH",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="NIST-DE-001",
                standard="NIST",
                category="Detect (DE)",
                title="Security Monitoring Implementation",
                description="Verify that security monitoring capabilities are implemented",
                severity="MEDIUM",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="NIST-RS-001",
                standard="NIST",
                category="Respond (RS)",
                title="Incident Response Procedures",
                description="Verify that incident response procedures are documented",
                severity="MEDIUM",
                check_type="MANUAL_REVIEW"
            )
        ]
        
        # ISO 27001 Rules
        iso_rules = [
            ComplianceRule(
                rule_id="ISO-A5-001",
                standard="ISO27001",
                category="A.5 Information Security Policies",
                title="Information Security Policy",
                description="Verify that information security policies are documented",
                severity="MEDIUM",
                check_type="MANUAL_REVIEW"
            ),
            ComplianceRule(
                rule_id="ISO-A9-001",
                standard="ISO27001",
                category="A.9 Access Control",
                title="Access Control Policy",
                description="Verify that access control policies are implemented",
                severity="HIGH",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="ISO-A10-001",
                standard="ISO27001",
                category="A.10 Cryptography",
                title="Cryptographic Controls",
                description="Verify that cryptographic controls are properly implemented",
                severity="HIGH",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="ISO-A12-001",
                standard="ISO27001",
                category="A.12 Operations Security",
                title="Operational Procedures",
                description="Verify that operational security procedures are documented",
                severity="MEDIUM",
                check_type="MANUAL_REVIEW"
            )
        ]
        
        # PCI DSS Rules (applicable sections)
        pci_rules = [
            ComplianceRule(
                rule_id="PCI-REQ2-001",
                standard="PCI_DSS",
                category="Requirement 2",
                title="Default Passwords Changed",
                description="Verify that default passwords are changed",
                severity="HIGH",
                check_type="CONFIG_CHECK"
            ),
            ComplianceRule(
                rule_id="PCI-REQ4-001",
                standard="PCI_DSS",
                category="Requirement 4",
                title="Data Encryption in Transit",
                description="Verify that sensitive data is encrypted during transmission",
                severity="HIGH",
                check_type="CODE_SCAN"
            ),
            ComplianceRule(
                rule_id="PCI-REQ8-001",
                standard="PCI_DSS",
                category="Requirement 8",
                title="Strong Authentication",
                description="Verify that strong authentication mechanisms are implemented",
                severity="HIGH",
                check_type="CODE_SCAN"
            )
        ]
        
        # GDPR Rules (privacy-related)
        gdpr_rules = [
            ComplianceRule(
                rule_id="GDPR-ART25-001",
                standard="GDPR",
                category="Article 25 - Data Protection by Design",
                title="Privacy by Design Implementation",
                description="Verify that privacy by design principles are implemented",
                severity="HIGH",
                check_type="MANUAL_REVIEW"
            ),
            ComplianceRule(
                rule_id="GDPR-ART32-001",
                standard="GDPR",
                category="Article 32 - Security of Processing",
                title="Technical Security Measures",
                description="Verify that appropriate technical security measures are implemented",
                severity="HIGH",
                check_type="CODE_SCAN"
            )
        ]
        
        rules.extend(owasp_rules)
        rules.extend(nist_rules)
        rules.extend(iso_rules)
        rules.extend(pci_rules)
        rules.extend(gdpr_rules)
        
        return rules
    
    def add_result(self, rule_id: str, status: str, message: str, 
                   evidence: Optional[List[str]] = None,
                   recommendations: Optional[List[str]] = None,
                   risk_level: str = "MEDIUM",
                   details: Optional[Dict] = None):
        """Add compliance check result"""
        result = ComplianceResult(
            rule_id=rule_id,
            status=status,
            message=message,
            evidence=evidence or [],
            recommendations=recommendations or [],
            risk_level=risk_level,
            details=details
        )
        self.results.append(result)
        
        # Log result
        log_level = {
            "COMPLIANT": logging.INFO,
            "NON_COMPLIANT": logging.ERROR,
            "PARTIAL": logging.WARNING,
            "NOT_APPLICABLE": logging.INFO,
            "MANUAL_REVIEW": logging.INFO
        }.get(status, logging.INFO)
        
        self.logger.log(log_level, f"{rule_id}: {status} - {message}")
    
    def scan_code_for_patterns(self, patterns: List[str], 
                              exclude_dirs: Optional[List[str]] = None) -> List[str]:
        """Scan code for specific patterns"""
        exclude_dirs = exclude_dirs or ['.git', '__pycache__', 'node_modules', '.pytest_cache']
        matches = []
        
        for root, dirs, files in os.walk(self.project_root):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.jsx', '.tsx')):
                    file_path = Path(root) / file
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            for pattern in patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    matches.append(str(file_path.relative_to(self.project_root)))
                    except (UnicodeDecodeError, PermissionError):
                        continue
        
        return matches
    
    def check_file_exists(self, file_paths: List[str]) -> List[str]:
        """Check if files exist"""
        existing_files = []
        for file_path in file_paths:
            full_path = self.project_root / file_path
            if full_path.exists():
                existing_files.append(file_path)
        return existing_files
    
    def check_owasp_a01_broken_access_control(self):
        """Check OWASP A01: Broken Access Control"""
        
        # Check for authentication decorators/middleware
        auth_patterns = [
            r'@require_auth',
            r'@login_required',
            r'authenticate',
            r'check_permissions',
            r'authorize'
        ]
        
        auth_files = self.scan_code_for_patterns(auth_patterns)
        
        if auth_files:
            self.add_result(
                "OWASP-A01-001",
                "COMPLIANT",
                f"Authentication mechanisms found in {len(auth_files)} files",
                evidence=auth_files[:5],  # Show first 5 files
                risk_level="LOW"
            )
        else:
            self.add_result(
                "OWASP-A01-001",
                "NON_COMPLIANT",
                "No authentication mechanisms found in codebase",
                recommendations=[
                    "Implement authentication decorators/middleware",
                    "Add access control checks to protected endpoints"
                ],
                risk_level="CRITICAL"
            )
        
        # Check for authorization patterns
        authz_patterns = [
            r'check_permission',
            r'has_permission',
            r'role_required',
            r'permission_required'
        ]
        
        authz_files = self.scan_code_for_patterns(authz_patterns)
        
        if authz_files:
            self.add_result(
                "OWASP-A01-002",
                "COMPLIANT",
                f"Authorization checks found in {len(authz_files)} files",
                evidence=authz_files[:5],
                risk_level="LOW"
            )
        else:
            self.add_result(
                "OWASP-A01-002",
                "PARTIAL",
                "Limited authorization mechanisms found",
                recommendations=[
                    "Implement comprehensive authorization checks",
                    "Add role-based access control (RBAC)"
                ],
                risk_level="HIGH"
            )
    
    def check_owasp_a02_cryptographic_failures(self):
        """Check OWASP A02: Cryptographic Failures"""
        
        # Check for strong cryptographic algorithms
        crypto_patterns = [
            r'AES',
            r'SHA-256',
            r'SHA-512',
            r'bcrypt',
            r'scrypt',
            r'PBKDF2'
        ]
        
        crypto_files = self.scan_code_for_patterns(crypto_patterns)
        
        if crypto_files:
            self.add_result(
                "OWASP-A02-001",
                "COMPLIANT",
                f"Strong cryptographic algorithms found in {len(crypto_files)} files",
                evidence=crypto_files[:5],
                risk_level="LOW"
            )
        else:
            self.add_result(
                "OWASP-A02-001",
                "NON_COMPLIANT",
                "No strong cryptographic algorithms found",
                recommendations=[
                    "Implement AES encryption for sensitive data",
                    "Use SHA-256 or stronger for hashing",
                    "Use bcrypt/scrypt for password hashing"
                ],
                risk_level="HIGH"
            )
        
        # Check for weak cryptographic patterns
        weak_patterns = [
            r'MD5',
            r'SHA1',
            r'DES',
            r'RC4'
        ]
        
        weak_files = self.scan_code_for_patterns(weak_patterns)
        
        if weak_files:
            self.add_result(
                "OWASP-A02-002",
                "NON_COMPLIANT",
                f"Weak cryptographic algorithms found in {len(weak_files)} files",
                evidence=weak_files,
                recommendations=[
                    "Replace MD5/SHA1 with SHA-256 or stronger",
                    "Replace DES/RC4 with AES",
                    "Update cryptographic libraries"
                ],
                risk_level="HIGH"
            )
        else:
            # Check for proper key management
            key_management_files = self.check_file_exists([
                "src/security/key_manager.py",
                "src/config/security.py",
                ".env.example"
            ])
            
            if key_management_files:
                self.add_result(
                    "OWASP-A02-002",
                    "COMPLIANT",
                    "Key management mechanisms found",
                    evidence=key_management_files,
                    risk_level="LOW"
                )
            else:
                self.add_result(
                    "OWASP-A02-002",
                    "PARTIAL",
                    "Limited key management mechanisms",
                    recommendations=[
                        "Implement secure key management",
                        "Use environment variables for secrets",
                        "Implement key rotation"
                    ],
                    risk_level="MEDIUM"
                )
    
    def check_owasp_a03_injection(self):
        """Check OWASP A03: Injection"""
        
        # Check for input validation
        validation_patterns = [
            r'validate_input',
            r'sanitize',
            r'escape',
            r'pydantic',
            r'marshmallow',
            r'@validator'
        ]
        
        validation_files = self.scan_code_for_patterns(validation_patterns)
        
        if validation_files:
            self.add_result(
                "OWASP-A03-001",
                "COMPLIANT",
                f"Input validation mechanisms found in {len(validation_files)} files",
                evidence=validation_files[:5],
                risk_level="LOW"
            )
        else:
            self.add_result(
                "OWASP-A03-001",
                "NON_COMPLIANT",
                "No input validation mechanisms found",
                recommendations=[
                    "Implement input validation using Pydantic or similar",
                    "Add SQL injection protection",
                    "Sanitize user inputs"
                ],
                risk_level="CRITICAL"
            )
        
        # Check for dangerous patterns
        dangerous_patterns = [
            r'eval\(',
            r'exec\(',
            r'os\.system',
            r'subprocess\.call.*shell=True'
        ]
        
        dangerous_files = self.scan_code_for_patterns(dangerous_patterns)
        
        if dangerous_files:
            self.add_result(
                "OWASP-A03-001",
                "NON_COMPLIANT",
                f"Dangerous code execution patterns found in {len(dangerous_files)} files",
                evidence=dangerous_files,
                recommendations=[
                    "Remove eval() and exec() calls",
                    "Use parameterized queries",
                    "Avoid shell=True in subprocess calls"
                ],
                risk_level="CRITICAL"
            )
    
    def check_owasp_a07_authentication_failures(self):
        """Check OWASP A07: Identification and Authentication Failures"""
        
        # Check for JWT implementation
        jwt_patterns = [
            r'jwt\.encode',
            r'jwt\.decode',
            r'JWTBlacklist',
            r'token_blacklist'
        ]
        
        jwt_files = self.scan_code_for_patterns(jwt_patterns)
        
        if jwt_files:
            self.add_result(
                "OWASP-A07-001",
                "COMPLIANT",
                f"JWT authentication implementation found in {len(jwt_files)} files",
                evidence=jwt_files[:5],
                risk_level="LOW"
            )
        else:
            self.add_result(
                "OWASP-A07-001",
                "NON_COMPLIANT",
                "No JWT authentication implementation found",
                recommendations=[
                    "Implement JWT-based authentication",
                    "Add token blacklisting mechanism",
                    "Implement secure session management"
                ],
                risk_level="CRITICAL"
            )
        
        # Check for session security
        session_patterns = [
            r'SessionManager',
            r'session_security',
            r'secure_session'
        ]
        
        session_files = self.scan_code_for_patterns(session_patterns)
        
        if session_files:
            self.add_result(
                "OWASP-A07-001",
                "COMPLIANT",
                f"Session security implementation found in {len(session_files)} files",
                evidence=session_files[:3],
                risk_level="LOW"
            )
    
    def check_owasp_a09_logging_monitoring(self):
        """Check OWASP A09: Security Logging and Monitoring Failures"""
        
        # Check for security logging
        logging_patterns = [
            r'SecurityEventLogger',
            r'security_log',
            r'audit_log',
            r'log_security_event'
        ]
        
        logging_files = self.scan_code_for_patterns(logging_patterns)
        
        if logging_files:
            self.add_result(
                "OWASP-A09-001",
                "COMPLIANT",
                f"Security logging implementation found in {len(logging_files)} files",
                evidence=logging_files[:5],
                risk_level="LOW"
            )
        else:
            self.add_result(
                "OWASP-A09-001",
                "NON_COMPLIANT",
                "No security logging implementation found",
                recommendations=[
                    "Implement comprehensive security logging",
                    "Add audit trail for security events",
                    "Implement real-time monitoring"
                ],
                risk_level="MEDIUM"
            )
        
        # Check for monitoring systems
        monitoring_patterns = [
            r'SecurityPerformanceMonitor',
            r'NotificationSystem',
            r'alert',
            r'monitor'
        ]
        
        monitoring_files = self.scan_code_for_patterns(monitoring_patterns)
        
        if monitoring_files:
            self.add_result(
                "OWASP-A09-001",
                "COMPLIANT",
                f"Security monitoring implementation found in {len(monitoring_files)} files",
                evidence=monitoring_files[:3],
                risk_level="LOW"
            )
    
    def check_nist_framework(self):
        """Check NIST Cybersecurity Framework compliance"""
        
        # NIST PR (Protect) - Access Control
        access_control_files = self.check_file_exists([
            "src/security/access_control.py",
            "src/authentication/dependencies.py",
            "src/security/permissions.py"
        ])
        
        if access_control_files:
            self.add_result(
                "NIST-PR-001",
                "COMPLIANT",
                "Access control implementation found",
                evidence=access_control_files,
                risk_level="LOW"
            )
        else:
            self.add_result(
                "NIST-PR-001",
                "PARTIAL",
                "Limited access control implementation",
                recommendations=[
                    "Implement comprehensive access control",
                    "Add role-based permissions"
                ],
                risk_level="MEDIUM"
            )
        
        # NIST PR (Protect) - Data Security
        data_security_files = self.check_file_exists([
            "src/security/encryption.py",
            "src/security/data_protection.py"
        ])
        
        crypto_files = self.scan_code_for_patterns([r'encrypt', r'decrypt', r'hash'])
        
        if data_security_files or crypto_files:
            self.add_result(
                "NIST-PR-002",
                "COMPLIANT",
                "Data security controls implemented",
                evidence=data_security_files + crypto_files[:3],
                risk_level="LOW"
            )
        else:
            self.add_result(
                "NIST-PR-002",
                "NON_COMPLIANT",
                "No data security controls found",
                recommendations=[
                    "Implement data encryption",
                    "Add data classification",
                    "Implement data loss prevention"
                ],
                risk_level="HIGH"
            )
        
        # NIST DE (Detect) - Security Monitoring
        monitoring_files = self.check_file_exists([
            "src/security/performance_monitor.py",
            "src/security/security_event_logger.py"
        ])
        
        if monitoring_files:
            self.add_result(
                "NIST-DE-001",
                "COMPLIANT",
                "Security monitoring capabilities implemented",
                evidence=monitoring_files,
                risk_level="LOW"
            )
        else:
            self.add_result(
                "NIST-DE-001",
                "NON_COMPLIANT",
                "No security monitoring found",
                recommendations=[
                    "Implement security monitoring",
                    "Add intrusion detection",
                    "Implement log analysis"
                ],
                risk_level="MEDIUM"
            )
    
    def check_iso27001_compliance(self):
        """Check ISO 27001 compliance"""
        
        # A.9 Access Control
        access_control_patterns = [
            r'access_control',
            r'permission',
            r'authorize',
            r'role'
        ]
        
        access_files = self.scan_code_for_patterns(access_control_patterns)
        
        if access_files:
            self.add_result(
                "ISO-A9-001",
                "COMPLIANT",
                f"Access control policies implemented in {len(access_files)} files",
                evidence=access_files[:5],
                risk_level="LOW"
            )
        else:
            self.add_result(
                "ISO-A9-001",
                "NON_COMPLIANT",
                "No access control policies found",
                recommendations=[
                    "Implement access control policies",
                    "Add user access management"
                ],
                risk_level="HIGH"
            )
        
        # A.10 Cryptography
        crypto_files = self.check_file_exists([
            "src/security/encryption.py",
            "src/security/crypto.py"
        ])
        
        if crypto_files:
            self.add_result(
                "ISO-A10-001",
                "COMPLIANT",
                "Cryptographic controls implemented",
                evidence=crypto_files,
                risk_level="LOW"
            )
        else:
            self.add_result(
                "ISO-A10-001",
                "PARTIAL",
                "Limited cryptographic controls",
                recommendations=[
                    "Implement comprehensive cryptographic controls",
                    "Add key management procedures"
                ],
                risk_level="MEDIUM"
            )
    
    def check_pci_dss_compliance(self):
        """Check PCI DSS compliance (applicable requirements)"""
        
        # Requirement 4: Encrypt transmission of cardholder data
        encryption_patterns = [
            r'https',
            r'ssl',
            r'tls',
            r'encrypt'
        ]
        
        encryption_files = self.scan_code_for_patterns(encryption_patterns)
        
        if encryption_files:
            self.add_result(
                "PCI-REQ4-001",
                "COMPLIANT",
                f"Data encryption in transit implemented in {len(encryption_files)} files",
                evidence=encryption_files[:3],
                risk_level="LOW"
            )
        else:
            self.add_result(
                "PCI-REQ4-001",
                "NON_COMPLIANT",
                "No data encryption in transit found",
                recommendations=[
                    "Implement HTTPS/TLS encryption",
                    "Encrypt sensitive data transmission"
                ],
                risk_level="HIGH"
            )
        
        # Requirement 8: Strong authentication
        auth_files = self.scan_code_for_patterns([
            r'strong_password',
            r'multi_factor',
            r'2fa',
            r'mfa'
        ])
        
        if auth_files:
            self.add_result(
                "PCI-REQ8-001",
                "COMPLIANT",
                "Strong authentication mechanisms found",
                evidence=auth_files[:3],
                risk_level="LOW"
            )
        else:
            self.add_result(
                "PCI-REQ8-001",
                "PARTIAL",
                "Limited strong authentication mechanisms",
                recommendations=[
                    "Implement multi-factor authentication",
                    "Add strong password policies"
                ],
                risk_level="MEDIUM"
            )
    
    def check_gdpr_compliance(self):
        """Check GDPR compliance"""
        
        # Article 32: Security of processing
        security_files = self.check_file_exists([
            "src/security/data_protection.py",
            "src/privacy/gdpr_compliance.py"
        ])
        
        security_patterns = [
            r'data_protection',
            r'privacy',
            r'anonymize',
            r'pseudonymize'
        ]
        
        security_code_files = self.scan_code_for_patterns(security_patterns)
        
        if security_files or security_code_files:
            self.add_result(
                "GDPR-ART32-001",
                "COMPLIANT",
                "Technical security measures implemented",
                evidence=security_files + security_code_files[:3],
                risk_level="LOW"
            )
        else:
            self.add_result(
                "GDPR-ART32-001",
                "PARTIAL",
                "Limited technical security measures",
                recommendations=[
                    "Implement data protection mechanisms",
                    "Add privacy controls",
                    "Implement data anonymization"
                ],
                risk_level="MEDIUM"
            )
    
    async def run_compliance_check(self, standards: Optional[List[str]] = None):
        """Run compliance check for specified standards"""
        standards = standards or ["OWASP", "NIST", "ISO27001", "PCI_DSS", "GDPR"]
        
        self.logger.info(f"Starting compliance check for standards: {standards}")
        
        if "OWASP" in standards:
            self.logger.info("Checking OWASP Top 10 compliance...")
            self.check_owasp_a01_broken_access_control()
            self.check_owasp_a02_cryptographic_failures()
            self.check_owasp_a03_injection()
            self.check_owasp_a07_authentication_failures()
            self.check_owasp_a09_logging_monitoring()
        
        if "NIST" in standards:
            self.logger.info("Checking NIST Framework compliance...")
            self.check_nist_framework()
        
        if "ISO27001" in standards:
            self.logger.info("Checking ISO 27001 compliance...")
            self.check_iso27001_compliance()
        
        if "PCI_DSS" in standards:
            self.logger.info("Checking PCI DSS compliance...")
            self.check_pci_dss_compliance()
        
        if "GDPR" in standards:
            self.logger.info("Checking GDPR compliance...")
            self.check_gdpr_compliance()
        
        self.logger.info("Compliance check completed")
    
    def generate_report(self) -> ComplianceReport:
        """Generate compliance report"""
        # Count results by status
        compliant = len([r for r in self.results if r.status == "COMPLIANT"])
        non_compliant = len([r for r in self.results if r.status == "NON_COMPLIANT"])
        partial = len([r for r in self.results if r.status == "PARTIAL"])
        not_applicable = len([r for r in self.results if r.status == "NOT_APPLICABLE"])
        manual_review = len([r for r in self.results if r.status == "MANUAL_REVIEW"])
        
        # Calculate compliance score
        total_applicable = compliant + non_compliant + partial
        compliance_score = (compliant + (partial * 0.5)) / total_applicable * 100 if total_applicable > 0 else 0
        
        # Group by standard
        standards_checked = list(set(
            next((rule.standard for rule in self.rules if rule.rule_id == result.rule_id), "UNKNOWN")
            for result in self.results
        ))
        
        summary_by_standard = {}
        for standard in standards_checked:
            standard_results = [
                r for r in self.results 
                if any(rule.rule_id == r.rule_id and rule.standard == standard for rule in self.rules)
            ]
            summary_by_standard[standard] = {
                "compliant": len([r for r in standard_results if r.status == "COMPLIANT"]),
                "non_compliant": len([r for r in standard_results if r.status == "NON_COMPLIANT"]),
                "partial": len([r for r in standard_results if r.status == "PARTIAL"]),
                "not_applicable": len([r for r in standard_results if r.status == "NOT_APPLICABLE"]),
                "manual_review": len([r for r in standard_results if r.status == "MANUAL_REVIEW"])
            }
        
        # Get critical issues
        critical_issues = [r for r in self.results if r.risk_level == "CRITICAL" and r.status == "NON_COMPLIANT"]
        
        # Generate recommendations
        recommendations = []
        for result in self.results:
            if result.status == "NON_COMPLIANT" and result.recommendations:
                recommendations.extend(result.recommendations)
        
        # Remove duplicates
        recommendations = list(set(recommendations))
        
        return ComplianceReport(
            timestamp=datetime.utcnow(),
            environment=os.getenv("ENVIRONMENT", "development"),
            standards_checked=standards_checked,
            total_rules=len(self.results),
            compliant=compliant,
            non_compliant=non_compliant,
            partial=partial,
            not_applicable=not_applicable,
            manual_review=manual_review,
            compliance_score=compliance_score,
            results=self.results,
            summary_by_standard=summary_by_standard,
            critical_issues=critical_issues,
            recommendations=recommendations[:10]  # Top 10 recommendations
        )
    
    def print_report(self, report: ComplianceReport):
        """Print compliance report to console"""
        print("\n" + "="*80)
        print("LINKSHIELD COMPLIANCE REPORT")
        print("="*80)
        print(f"Timestamp: {report.timestamp}")
        print(f"Environment: {report.environment}")
        print(f"Standards Checked: {', '.join(report.standards_checked)}")
        print()
        
        print("OVERALL COMPLIANCE:")
        print(f"  Compliance Score: {report.compliance_score:.1f}%")
        print(f"  Total Rules Checked: {report.total_rules}")
        print(f"  Compliant: {report.compliant}")
        print(f"  Non-Compliant: {report.non_compliant}")
        print(f"  Partial: {report.partial}")
        print(f"  Manual Review Required: {report.manual_review}")
        print()
        
        # Compliance by standard
        print("COMPLIANCE BY STANDARD:")
        for standard, summary in report.summary_by_standard.items():
            total = sum(summary.values())
            compliant_pct = (summary["compliant"] / total * 100) if total > 0 else 0
            print(f"  {standard}: {compliant_pct:.1f}% ({summary['compliant']}/{total} compliant)")
        print()
        
        # Critical issues
        if report.critical_issues:
            print("CRITICAL ISSUES:")
            for issue in report.critical_issues:
                print(f"  ✗ {issue.rule_id}: {issue.message}")
            print()
        
        # Top recommendations
        if report.recommendations:
            print("TOP RECOMMENDATIONS:")
            for i, rec in enumerate(report.recommendations, 1):
                print(f"  {i}. {rec}")
            print()
        
        # Detailed results by standard
        print("DETAILED RESULTS:")
        for standard in report.standards_checked:
            print(f"\n{standard}:")
            standard_results = [
                r for r in report.results 
                if any(rule.rule_id == r.rule_id and rule.standard == standard for rule in self.rules)
            ]
            
            for result in standard_results:
                status_symbol = {
                    "COMPLIANT": "✓",
                    "NON_COMPLIANT": "✗",
                    "PARTIAL": "◐",
                    "NOT_APPLICABLE": "○",
                    "MANUAL_REVIEW": "?"
                }.get(result.status, "?")
                
                print(f"  {status_symbol} {result.rule_id}: {result.message}")
        
        print("\n" + "="*80)
    
    def save_report(self, report: ComplianceReport, filename: str):
        """Save compliance report to file"""
        with open(filename, 'w') as f:
            json.dump(report.dict(), f, indent=2, default=str)
        
        self.logger.info(f"Compliance report saved to {filename}")


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="LinkShield Compliance Checker")
    parser.add_argument("--standards", nargs="+", 
                       choices=["OWASP", "NIST", "ISO27001", "PCI_DSS", "GDPR"],
                       help="Standards to check (default: all)")
    parser.add_argument("--output", help="Output file for report")
    parser.add_argument("--format", choices=["json", "console"], default="console",
                       help="Output format")
    
    args = parser.parse_args()
    
    checker = ComplianceChecker()
    
    try:
        await checker.run_compliance_check(args.standards)
        
        # Generate and display report
        report = checker.generate_report()
        
        if args.format == "console":
            checker.print_report(report)
        
        # Save report if requested
        if args.output:
            checker.save_report(report, args.output)
        
        # Exit with appropriate code based on compliance score
        if report.compliance_score < 80:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except Exception as e:
        logging.error(f"Compliance check failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
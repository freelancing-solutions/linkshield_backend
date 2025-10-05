#!/usr/bin/env python3
"""
Suspicious Pattern Analyzer

A comprehensive content analysis class for detecting suspicious patterns in web content
including phishing, social engineering, malware, and other malicious activities.
"""

import re
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass
from enum import Enum

class ThreatCategory(Enum):
    """Threat categories for pattern classification."""
    PHISHING = "phishing"
    SOCIAL_ENGINEERING = "social_engineering"
    MALWARE = "malware"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    BRAND_IMPERSONATION = "brand_impersonation"
    CONTENT_OBFUSCATION = "content_obfuscation"
    EXPLOIT_KIT = "exploit_kit"
    DECEPTIVE_UI = "deceptive_ui"
    SUSPICIOUS_JAVASCRIPT = "suspicious_javascript"

@dataclass
class PatternMatch:
    """Represents a detected suspicious pattern."""
    pattern_id: str
    category: ThreatCategory
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: str
    risk_level: str  # low, medium, high, critical

@dataclass
class SuspiciousPatternResult:
    """Complete analysis result from pattern detection."""
    total_patterns_found: int
    high_risk_patterns: int
    threat_categories: List[ThreatCategory]
    pattern_matches: List[PatternMatch]
    overall_risk_score: float  # 0.0 to 1.0
    risk_assessment: str  # safe, suspicious, malicious, critical
    summary: str

class SuspiciousPatternAnalyzer:
    """
    Comprehensive analyzer for detecting suspicious patterns in web content.
    """
    
    def __init__(self, current_url: Optional[str] = None):
        """
        Initialize the analyzer.
        
        Args:
            current_url: URL being analyzed for context-aware detection
        """
        self.current_url = current_url
        self.current_domain = self._extract_domain(current_url) if current_url else ""
        
        # Pattern weights for risk scoring
        self.category_weights = {
            ThreatCategory.PHISHING: 0.9,
            ThreatCategory.CREDENTIAL_HARVESTING: 0.95,
            ThreatCategory.MALWARE: 1.0,
            ThreatCategory.EXPLOIT_KIT: 0.95,
            ThreatCategory.BRAND_IMPERSONATION: 0.8,
            ThreatCategory.SOCIAL_ENGINEERING: 0.7,
            ThreatCategory.SUSPICIOUS_JAVASCRIPT: 0.6,
            ThreatCategory.CONTENT_OBFUSCATION: 0.5,
            ThreatCategory.DECEPTIVE_UI: 0.4
        }
        
        # Initialize pattern databases
        self._init_pattern_databases()
    
    def analyze_content(self, content: str, url: Optional[str] = None) -> SuspiciousPatternResult:
        """
        Main entry point for suspicious pattern analysis.
        
        Args:
            content: HTML/text content to analyze
            url: Optional URL for context (overrides instance URL)
            
        Returns:
            SuspiciousPatternResult with complete analysis
        """
        # Update context if URL provided
        if url:
            self.current_url = url
            self.current_domain = self._extract_domain(url)
        
        pattern_matches = []
        content_lower = content.lower()
        
        # Run all analysis modules
        pattern_matches.extend(self._detect_phishing_patterns(content, content_lower))
        pattern_matches.extend(self._detect_social_engineering(content, content_lower))
        pattern_matches.extend(self._detect_credential_harvesting(content))
        pattern_matches.extend(self._detect_brand_impersonation(content_lower))
        pattern_matches.extend(self._detect_malicious_javascript(content))
        pattern_matches.extend(self._detect_content_obfuscation(content))
        pattern_matches.extend(self._detect_exploit_patterns(content, content_lower))
        pattern_matches.extend(self._detect_deceptive_ui(content))
        
        # Calculate overall assessment
        return self._calculate_risk_assessment(pattern_matches)
    
    def _init_pattern_databases(self):
        """Initialize pattern databases and configurations."""
        
        # Phishing keyword patterns by category
        self.phishing_patterns = {
            'account_threats': [
                'account suspended', 'account locked', 'account disabled',
                'account will be closed', 'temporary suspension', 'suspended account',
                'account termination', 'access revoked', 'account deactivated'
            ],
            'immediate_action': [
                'click here immediately', 'urgent action required', 'act now',
                'immediate verification required', 'respond within 24 hours',
                'expires today', 'limited time', 'act fast', 'time sensitive'
            ],
            'verification_requests': [
                'verify your account', 'confirm your identity', 'update your information',
                'verify identity', 'confirm account', 'validate account', 're-verify'
            ],
            'security_alerts': [
                'security alert', 'unusual activity', 'suspicious login',
                'security breach', 'unauthorized access', 'login attempt',
                'security warning', 'account compromised', 'fraud alert'
            ],
            'payment_threats': [
                'update payment', 'payment failed', 'billing issue',
                'card expired', 'payment method', 'subscription cancelled',
                'payment declined', 'billing problem'
            ]
        }
        
        # Social engineering patterns
        self.social_engineering_patterns = {
            'authority_impersonation': [
                'from: support@', 'customer service', 'security team',
                'account team', 'billing department', 'technical support',
                'fraud department', 'verification team'
            ],
            'trust_indicators': [
                'trusted by millions', 'verified secure', 'bank-level security',
                'ssl protected', 'government approved', 'certified secure',
                'industry standard', 'military grade'
            ],
            'fear_tactics': [
                'legal action', 'account closure', 'service terminated',
                'unauthorized charges', 'fraud detected', 'breach detected',
                'criminal activity', 'investigation'
            ],
            'reward_baits': [
                'claim your prize', 'you have won', 'congratulations',
                'free gift', 'exclusive offer', 'limited offer',
                'special promotion', 'cash prize'
            ]
        }
        
        # Brand impersonation variants
        self.brand_variants = {
            'paypal': ['paypal', 'pay-pal', 'payp4l', 'paypaI', 'paypaĺ'],
            'amazon': ['amazon', 'amazom', 'amaz0n', 'amazone', 'аmazon'],
            'apple': ['apple', 'appIe', 'appl3', 'aple', 'аpple'],
            'microsoft': ['microsoft', 'microsft', 'micr0soft', 'microsooft'],
            'google': ['google', 'googIe', 'g00gle', 'gooogle', 'goog1e'],
            'facebook': ['facebook', 'facebok', 'faceb00k', 'facebooK'],
            'netflix': ['netflix', 'netfliix', 'netfl1x', 'netflex'],
            'instagram': ['instagram', 'instagran', 'inst4gram', 'instagramm'],
            'whatsapp': ['whatsapp', 'whatsap', 'whats4pp', 'whatsаpp'],
            'linkedin': ['linkedin', 'linkedln', 'link3din', 'linkedìn']
        }
        
        # Legitimate context indicators
        self.legitimate_contexts = {
            'security_page': [
                'privacy policy', 'terms of service', 'security center',
                'help center', 'support documentation', 'faq',
                'two-factor authentication', '2fa setup', 'security settings'
            ],
            'marketing': [
                'unsubscribe', 'newsletter', 'promotional email',
                'marketing preferences', 'email preferences'
            ],
            'login_page': [
                'remember me', 'forgot password', 'sign in', 'log in',
                'create account', 'register', 'login', 'authentication'
            ]
        }
    
    def _detect_phishing_patterns(self, content: str, content_lower: str) -> List[PatternMatch]:
        """Detect phishing-related patterns."""
        matches = []
        
        for category, keywords in self.phishing_patterns.items():
            found_keywords = [kw for kw in keywords if kw in content_lower]
            
            if found_keywords:
                # Check for legitimate context
                if not self._is_legitimate_security_context(content_lower):
                    confidence = min(0.9, len(found_keywords) * 0.3)
                    risk_level = "high" if len(found_keywords) >= 2 else "medium"
                    
                    matches.append(PatternMatch(
                        pattern_id=f"phishing_{category}",
                        category=ThreatCategory.PHISHING,
                        confidence=confidence,
                        description=f"Phishing pattern detected: {category}",
                        evidence=f"Keywords found: {', '.join(found_keywords[:3])}",
                        risk_level=risk_level
                    ))
        
        return matches
    
    def _detect_social_engineering(self, content: str, content_lower: str) -> List[PatternMatch]:
        """Detect social engineering patterns."""
        matches = []
        
        for category, indicators in self.social_engineering_patterns.items():
            found_indicators = [ind for ind in indicators if ind in content_lower]
            
            if found_indicators and not self._is_marketing_context(content_lower):
                confidence = min(0.8, len(found_indicators) * 0.4)
                risk_level = "medium" if len(found_indicators) == 1 else "high"
                
                matches.append(PatternMatch(
                    pattern_id=f"social_eng_{category}",
                    category=ThreatCategory.SOCIAL_ENGINEERING,
                    confidence=confidence,
                    description=f"Social engineering detected: {category}",
                    evidence=f"Indicators: {', '.join(found_indicators[:2])}",
                    risk_level=risk_level
                ))
        
        return matches
    
    def _detect_credential_harvesting(self, content: str) -> List[PatternMatch]:
        """Detect credential harvesting patterns."""
        matches = []
        
        # Password field analysis
        password_inputs = re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', content, re.IGNORECASE)
        
        if password_inputs:
            if not self._has_legitimate_login_context(content):
                matches.append(PatternMatch(
                    pattern_id="suspicious_password_input",
                    category=ThreatCategory.CREDENTIAL_HARVESTING,
                    confidence=0.7,
                    description="Password input without legitimate login context",
                    evidence=f"Found {len(password_inputs)} password fields",
                    risk_level="high"
                ))
            elif len(password_inputs) > 2:
                matches.append(PatternMatch(
                    pattern_id="multiple_password_fields",
                    category=ThreatCategory.CREDENTIAL_HARVESTING,
                    confidence=0.6,
                    description="Excessive password input fields",
                    evidence=f"Found {len(password_inputs)} password fields",
                    risk_level="medium"
                ))
        
        # Sensitive data input detection
        sensitive_patterns = {
            'ssn_input': (r'(?:ssn|social.security|social.security.number)', "Social Security Number"),
            'credit_card_input': (r'(?:credit.card|card.number|ccnum|cardnum)', "Credit Card"),
            'bank_account_input': (r'(?:account.number|routing.number|bank.account)', "Bank Account"),
            'pin_input': (r'(?:pin.number|pin.code|personal.identification)', "PIN Code"),
            'license_input': (r'(?:driver.license|license.number|dl.number)', "Driver License"),
            'passport_input': (r'(?:passport.number|passport.id)', "Passport")
        }
        
        for pattern_id, (regex, data_type) in sensitive_patterns.items():
            if re.search(r'<input[^>]*name=["\'][^"\']*' + regex + r'[^"\']*["\'][^>]*>', content, re.IGNORECASE):
                matches.append(PatternMatch(
                    pattern_id=pattern_id,
                    category=ThreatCategory.CREDENTIAL_HARVESTING,
                    confidence=0.9,
                    description=f"Form requesting {data_type} information",
                    evidence=f"Input field requesting {data_type.lower()}",
                    risk_level="critical"
                ))
        
        # Suspicious form actions
        form_actions = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', content, re.IGNORECASE)
        for action in form_actions:
            if self._is_suspicious_form_action(action):
                matches.append(PatternMatch(
                    pattern_id="suspicious_form_action",
                    category=ThreatCategory.CREDENTIAL_HARVESTING,
                    confidence=0.8,
                    description="Form submitting to suspicious endpoint",
                    evidence=f"Form action: {action}",
                    risk_level="high"
                ))
        
        return matches
    
    def _detect_brand_impersonation(self, content_lower: str) -> List[PatternMatch]:
        """Detect brand impersonation attempts."""
        matches = []
        
        for brand, variants in self.brand_variants.items():
            found_variants = [v for v in variants if v in content_lower]
            
            # Multiple variants suggest impersonation
            if len(found_variants) > 1:
                matches.append(PatternMatch(
                    pattern_id=f"brand_impersonation_{brand}",
                    category=ThreatCategory.BRAND_IMPERSONATION,
                    confidence=0.8,
                    description=f"Potential {brand.title()} brand impersonation",
                    evidence=f"Variants found: {', '.join(found_variants)}",
                    risk_level="high"
                ))
            
            # Check domain vs brand mismatch
            elif found_variants and self.current_domain:
                if brand not in self.current_domain and not any(v in self.current_domain for v in variants):
                    matches.append(PatternMatch(
                        pattern_id=f"brand_domain_mismatch_{brand}",
                        category=ThreatCategory.BRAND_IMPERSONATION,
                        confidence=0.6,
                        description=f"{brand.title()} branding on non-{brand} domain",
                        evidence=f"Brand mention: {found_variants[0]}, Domain: {self.current_domain}",
                        risk_level="medium"
                    ))
        
        return matches
    
    def _detect_malicious_javascript(self, content: str) -> List[PatternMatch]:
        """Detect malicious JavaScript patterns."""
        matches = []
        
        # Malicious JS patterns
        js_patterns = {
            'eval_usage': (r'eval\s*\(', "JavaScript eval() usage", 0.6),
            'document_write': (r'document\.write\s*\(', "Document.write usage", 0.4),
            'base64_decode': (r'atob\s*\(', "Base64 decoding", 0.7),
            'dynamic_script': (r'createElement\s*\(\s*["\']script["\']', "Dynamic script creation", 0.8),
            'iframe_injection': (r'createElement\s*\(\s*["\']iframe["\']', "Dynamic iframe creation", 0.8),
            'anti_debugging': (r'debugger;|console\.clear\(\)', "Anti-debugging techniques", 0.9)
        }
        
        for pattern_id, (regex, description, base_confidence) in js_patterns.items():
            matches_found = re.findall(regex, content, re.IGNORECASE)
            
            if matches_found and not self._is_legitimate_js_context(content):
                confidence = min(0.95, base_confidence + len(matches_found) * 0.1)
                risk_level = "high" if confidence > 0.7 else "medium"
                
                matches.append(PatternMatch(
                    pattern_id=f"malicious_js_{pattern_id}",
                    category=ThreatCategory.SUSPICIOUS_JAVASCRIPT,
                    confidence=confidence,
                    description=f"Suspicious JavaScript: {description}",
                    evidence=f"Found {len(matches_found)} instances",
                    risk_level=risk_level
                ))
        
        # Cryptocurrency mining detection
        crypto_patterns = ['coinhive', 'cryptonight', 'monero', 'miner.start', 'cryptoloot']
        found_crypto = [p for p in crypto_patterns if p in content.lower()]
        
        if found_crypto:
            matches.append(PatternMatch(
                pattern_id="cryptocurrency_mining",
                category=ThreatCategory.MALWARE,
                confidence=0.95,
                description="Cryptocurrency mining script detected",
                evidence=f"Mining indicators: {', '.join(found_crypto)}",
                risk_level="critical"
            ))
        
        return matches
    
    def _detect_content_obfuscation(self, content: str) -> List[PatternMatch]:
        """Detect content obfuscation techniques."""
        matches = []
        
        # Base64 content analysis
        base64_matches = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', content)
        if len(base64_matches) > 5:
            matches.append(PatternMatch(
                pattern_id="excessive_base64",
                category=ThreatCategory.CONTENT_OBFUSCATION,
                confidence=0.6,
                description="Excessive Base64 encoded content",
                evidence=f"Found {len(base64_matches)} Base64 strings",
                risk_level="medium"
            ))
        
        # Hex encoded strings
        hex_strings = re.findall(r'\\x[0-9a-fA-F]{2}', content)
        if len(hex_strings) > 20:
            matches.append(PatternMatch(
                pattern_id="hex_obfuscation",
                category=ThreatCategory.CONTENT_OBFUSCATION,
                confidence=0.7,
                description="Hex-encoded content obfuscation",
                evidence=f"Found {len(hex_strings)} hex sequences",
                risk_level="medium"
            ))
        
        # CSS hiding techniques
        css_hiding_patterns = [
            r'visibility:\s*hidden', r'display:\s*none', r'opacity:\s*0',
            r'position:\s*absolute.*left:\s*-\d+px'
        ]
        
        for pattern in css_hiding_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                matches.append(PatternMatch(
                    pattern_id="css_content_hiding",
                    category=ThreatCategory.DECEPTIVE_UI,
                    confidence=0.5,
                    description="CSS-based content hiding detected",
                    evidence="Hidden content elements found",
                    risk_level="low"
                ))
                break
        
        return matches
    
    def _detect_exploit_patterns(self, content: str, content_lower: str) -> List[PatternMatch]:
        """Detect exploit kit and malware patterns."""
        matches = []
        
        # Plugin exploitation
        plugin_exploits = ['flash', 'silverlight', 'java applet', 'activex', 'plugin download']
        found_exploits = [e for e in plugin_exploits if e in content_lower]
        
        if found_exploits:
            matches.append(PatternMatch(
                pattern_id="plugin_exploitation",
                category=ThreatCategory.EXPLOIT_KIT,
                confidence=0.7,
                description="Plugin exploitation attempt detected",
                evidence=f"Plugin references: {', '.join(found_exploits)}",
                risk_level="high"
            ))
        
        # Fake update prompts
        fake_updates = ['update required', 'plugin outdated', 'codec missing', 'player update']
        found_updates = [u for u in fake_updates if u in content_lower]
        
        if found_updates:
            matches.append(PatternMatch(
                pattern_id="fake_update_prompt",
                category=ThreatCategory.EXPLOIT_KIT,
                confidence=0.8,
                description="Fake update prompt detected",
                evidence=f"Update prompts: {', '.join(found_updates)}",
                risk_level="high"
            ))
        
        return matches
    
    def _detect_deceptive_ui(self, content: str) -> List[PatternMatch]:
        """Detect deceptive UI patterns."""
        matches = []
        
        # Fake close buttons
        if re.search(r'onclick=.*window\.open', content, re.IGNORECASE):
            matches.append(PatternMatch(
                pattern_id="fake_close_button",
                category=ThreatCategory.DECEPTIVE_UI,
                confidence=0.8,
                description="Fake close button detected",
                evidence="Button opens new window instead of closing",
                risk_level="medium"
            ))
        
        # Excessive popups
        popup_indicators = ['alert(', 'confirm(', 'prompt(', 'window.open']
        popup_count = sum(content.count(indicator) for indicator in popup_indicators)
        
        if popup_count > 3:
            matches.append(PatternMatch(
                pattern_id="excessive_popups",
                category=ThreatCategory.DECEPTIVE_UI,
                confidence=0.6,
                description="Excessive popup usage detected",
                evidence=f"Found {popup_count} popup triggers",
                risk_level="medium"
            ))
        
        return matches
    
    # Helper methods for context analysis
    
    def _is_legitimate_security_context(self, content: str) -> bool:
        """Check if security-related patterns appear in legitimate context."""
        return any(indicator in content for indicator in self.legitimate_contexts['security_page'])
    
    def _is_marketing_context(self, content: str) -> bool:
        """Check if patterns appear in marketing context."""
        return any(indicator in content for indicator in self.legitimate_contexts['marketing'])
    
    def _has_legitimate_login_context(self, content: str) -> bool:
        """Check if password inputs appear in legitimate login context."""
        login_indicators = self.legitimate_contexts['login_page']
        return any(indicator in content.lower() for indicator in login_indicators)
    
    def _is_legitimate_js_context(self, content: str) -> bool:
        """Check if JavaScript usage appears in legitimate context."""
        legitimate_js_libs = [
            'jquery', 'bootstrap', 'angular', 'react', 'vue',
            'google-analytics', 'gtag', 'facebook', 'twitter'
        ]
        return any(lib in content.lower() for lib in legitimate_js_libs)
    
    def _is_suspicious_form_action(self, action: str) -> bool:
        """Analyze form action URLs for suspicious patterns."""
        if not action or action.startswith('#'):
            return False
        
        # External form submissions
        if self.current_url:
            current_domain = urlparse(self.current_url).netloc
            action_domain = urlparse(action).netloc
            
            if action_domain and action_domain != current_domain:
                return True
        
        # Suspicious paths
        suspicious_paths = ['collect', 'harvest', 'capture', 'steal', 'phish']
        return any(path in action.lower() for path in suspicious_paths)
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            return urlparse(url).netloc.lower()
        except:
            return ""
    
    def _calculate_risk_assessment(self, pattern_matches: List[PatternMatch]) -> SuspiciousPatternResult:
        """Calculate overall risk assessment from pattern matches."""
        if not pattern_matches:
            return SuspiciousPatternResult(
                total_patterns_found=0,
                high_risk_patterns=0,
                threat_categories=[],
                pattern_matches=[],
                overall_risk_score=0.0,
                risk_assessment="safe",
                summary="No suspicious patterns detected"
            )
        
        # Calculate weighted risk score
        total_score = 0.0
        high_risk_count = 0
        threat_categories = set()
        
        for match in pattern_matches:
            category_weight = self.category_weights.get(match.category, 0.5)
            pattern_score = match.confidence * category_weight
            total_score += pattern_score
            
            threat_categories.add(match.category)
            
            if match.risk_level in ['high', 'critical']:
                high_risk_count += 1
        
        # Normalize score
        max_possible_score = len(pattern_matches) * 1.0
        normalized_score = min(1.0, total_score / max_possible_score) if max_possible_score > 0 else 0.0
        
        # Determine risk assessment
        if normalized_score >= 0.8 or high_risk_count >= 3:
            risk_assessment = "critical"
        elif normalized_score >= 0.6 or high_risk_count >= 2:
            risk_assessment = "malicious"
        elif normalized_score >= 0.3 or high_risk_count >= 1:
            risk_assessment = "suspicious"
        else:
            risk_assessment = "low_risk"
        
        # Generate summary
        category_names = [cat.value.replace('_', ' ').title() for cat in threat_categories]
        summary = f"Detected {len(pattern_matches)} suspicious patterns across {len(category_names)} categories: {', '.join(category_names)}"
        
        return SuspiciousPatternResult(
            total_patterns_found=len(pattern_matches),
            high_risk_patterns=high_risk_count,
            threat_categories=list(threat_categories),
            pattern_matches=pattern_matches,
            overall_risk_score=normalized_score,
            risk_assessment=risk_assessment,
            summary=summary
        )
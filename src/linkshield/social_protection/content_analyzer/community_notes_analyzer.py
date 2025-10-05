#!/usr/bin/env python3
"""
Community Notes Analyzer for Social Media Protection.

This module provides specialized analysis for content that might trigger
Community Notes or fact-checking mechanisms on social media platforms.
"""

import re
import asyncio
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timezone
from collections import Counter

from linkshield.services.ai_service import AIService
from linkshield.config.settings import get_settings


@dataclass
class CommunityNotesResult:
    """Result of Community Notes trigger analysis."""
    trigger_risk: bool
    risk_score: int  # 0-100
    trigger_factors: List[str]
    content_categories: List[str]
    recommendations: List[str]
    fact_check_likelihood: float  # 0.0-1.0
    misinformation_indicators: List[str]
    confidence_score: float  # 0.0-1.0
    analysis_timestamp: str


class CommunityNotesAnalyzer:
    """
    Analyzes content for potential Community Notes triggers.
    
    This analyzer identifies content patterns that commonly trigger
    fact-checking mechanisms, Community Notes, or similar crowdsourced
    verification systems on social media platforms.
    """
    
    def __init__(self, ai_service: AIService):
        self.ai_service = ai_service
        self.settings = get_settings()
        
        # Community Notes trigger patterns
        self.trigger_patterns = {
            "health_misinformation": [
                r"cure\s+for\s+\w+",
                r"doctors\s+don't\s+want\s+you\s+to\s+know",
                r"big\s+pharma\s+conspiracy",
                r"natural\s+remedy\s+that\s+works",
                r"miracle\s+cure",
                r"government\s+hiding\s+cure"
            ],
            "election_claims": [
                r"election\s+was\s+stolen",
                r"voter\s+fraud",
                r"rigged\s+election",
                r"fake\s+ballots",
                r"dead\s+people\s+voting"
            ],
            "conspiracy_theories": [
                r"deep\s+state",
                r"shadow\s+government",
                r"false\s+flag",
                r"crisis\s+actors",
                r"cover\s+up",
                r"they\s+don't\s+want\s+you\s+to\s+know"
            ],
            "financial_scams": [
                r"guaranteed\s+returns",
                r"get\s+rich\s+quick",
                r"investment\s+opportunity",
                r"limited\s+time\s+offer",
                r"insider\s+information",
                r"secret\s+method"
            ],
            "false_statistics": [
                r"\d+%\s+of\s+\w+\s+are",
                r"studies\s+show",
                r"research\s+proves",
                r"scientists\s+discovered",
                r"new\s+study\s+reveals"
            ]
        }
        
        # Misinformation indicators
        self.misinformation_indicators = [
            "mainstream media won't tell you",
            "they're trying to silence",
            "wake up people",
            "do your own research",
            "question everything",
            "the truth is out there",
            "open your eyes",
            "sheep mentality"
        ]
        
        # Fact-check trigger words
        self.fact_check_triggers = [
            "breaking news",
            "exclusive report",
            "leaked documents",
            "insider reveals",
            "shocking truth",
            "exposed",
            "bombshell",
            "whistleblower"
        ]

    async def analyze_community_notes_risk(
        self,
        content: str,
        platform: str = "twitter",
        metadata: Optional[Dict[str, Any]] = None
    ) -> CommunityNotesResult:
        """
        Analyze content for Community Notes trigger risk.
        
        Args:
            content: The content text to analyze
            platform: Social media platform name
            metadata: Additional content metadata
            
        Returns:
            CommunityNotesResult with trigger risk analysis
        """
        try:
            content_lower = content.lower()
            
            # Initialize analysis results
            trigger_factors = []
            content_categories = []
            misinformation_indicators = []
            recommendations = []
            
            # Check for trigger patterns by category
            for category, patterns in self.trigger_patterns.items():
                category_matches = 0
                for pattern in patterns:
                    if re.search(pattern, content_lower):
                        category_matches += 1
                        trigger_factors.append(f"{category}: {pattern}")
                
                if category_matches > 0:
                    content_categories.append(category)
                    if category_matches >= 2:
                        recommendations.append(f"High risk for {category} fact-checking")
            
            # Check for misinformation indicators
            for indicator in self.misinformation_indicators:
                if indicator in content_lower:
                    misinformation_indicators.append(indicator)
                    trigger_factors.append(f"misinformation_indicator: {indicator}")
            
            # Check for fact-check triggers
            fact_check_score = 0
            for trigger in self.fact_check_triggers:
                if trigger in content_lower:
                    fact_check_score += 1
                    trigger_factors.append(f"fact_check_trigger: {trigger}")
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(
                len(content_categories),
                len(misinformation_indicators),
                fact_check_score,
                len(trigger_factors)
            )
            
            # Determine if there's trigger risk
            trigger_risk = risk_score >= 40
            
            # Calculate fact-check likelihood
            fact_check_likelihood = min(1.0, (risk_score / 100) * 1.2)
            
            # Generate recommendations
            if not recommendations:
                if risk_score >= 60:
                    recommendations.append("High risk - consider revising content")
                elif risk_score >= 40:
                    recommendations.append("Medium risk - review for accuracy")
                else:
                    recommendations.append("Low risk - content appears safe")
            
            # Add specific recommendations based on categories
            if "health_misinformation" in content_categories:
                recommendations.append("Verify health claims with credible sources")
            if "election_claims" in content_categories:
                recommendations.append("Ensure election information is from official sources")
            if "conspiracy_theories" in content_categories:
                recommendations.append("Consider providing credible sources for claims")
            if "financial_scams" in content_categories:
                recommendations.append("Avoid investment advice without proper disclaimers")
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(
                len(trigger_factors),
                len(content_categories),
                len(misinformation_indicators)
            )
            
            return CommunityNotesResult(
                trigger_risk=trigger_risk,
                risk_score=risk_score,
                trigger_factors=trigger_factors,
                content_categories=content_categories,
                recommendations=recommendations,
                fact_check_likelihood=fact_check_likelihood,
                misinformation_indicators=misinformation_indicators,
                confidence_score=confidence_score,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )
            
        except Exception as e:
            # Return safe default result on error
            return CommunityNotesResult(
                trigger_risk=False,
                risk_score=0,
                trigger_factors=[],
                content_categories=[],
                recommendations=["Error in analysis - manual review recommended"],
                fact_check_likelihood=0.0,
                misinformation_indicators=[],
                confidence_score=0.0,
                analysis_timestamp=datetime.now(timezone.utc).isoformat()
            )

    def _calculate_risk_score(
        self,
        category_count: int,
        misinfo_count: int,
        fact_check_count: int,
        total_factors: int
    ) -> int:
        """Calculate overall risk score for Community Notes triggers."""
        score = 0
        
        # Base score from categories
        score += category_count * 25
        
        # Additional score from misinformation indicators
        score += misinfo_count * 15
        
        # Fact-check trigger bonus
        score += fact_check_count * 10
        
        # Total factors bonus
        score += min(20, total_factors * 2)
        
        return min(100, score)

    def _calculate_confidence_score(
        self,
        factor_count: int,
        category_count: int,
        misinfo_count: int
    ) -> float:
        """Calculate confidence score for the analysis."""
        # Base confidence
        confidence = 0.6
        
        # Increase confidence with more detected patterns
        if factor_count > 0:
            confidence += min(0.3, factor_count * 0.05)
        
        # High confidence for multiple categories
        if category_count > 1:
            confidence += 0.15
        
        # High confidence for misinformation indicators
        if misinfo_count > 0:
            confidence += min(0.2, misinfo_count * 0.1)
        
        return round(min(0.95, confidence), 2)

    async def analyze_batch_content(
        self,
        content_items: List[Dict[str, Any]]
    ) -> List[CommunityNotesResult]:
        """
        Analyze multiple content items for Community Notes risk.
        
        Args:
            content_items: List of content dictionaries
            
        Returns:
            List of CommunityNotesResult objects
        """
        tasks = []
        for item in content_items:
            task = self.analyze_community_notes_risk(
                content=item["content"],
                platform=item.get("platform", "twitter"),
                metadata=item.get("metadata")
            )
            tasks.append(task)
            
        return await asyncio.gather(*tasks)

    def get_risk_summary(self, results: List[CommunityNotesResult]) -> Dict[str, Any]:
        """
        Generate summary statistics for Community Notes risk analysis.
        
        Args:
            results: List of CommunityNotesResult objects
            
        Returns:
            Dictionary with summary statistics
        """
        if not results:
            return {}
            
        total_items = len(results)
        high_risk_items = sum(1 for r in results if r.risk_score >= 60)
        medium_risk_items = sum(1 for r in results if 40 <= r.risk_score < 60)
        low_risk_items = sum(1 for r in results if r.risk_score < 40)
        
        # Category distribution
        all_categories = []
        for result in results:
            all_categories.extend(result.content_categories)
        category_counts = Counter(all_categories)
        
        # Average scores
        avg_risk_score = sum(r.risk_score for r in results) / total_items
        avg_fact_check_likelihood = sum(r.fact_check_likelihood for r in results) / total_items
        
        return {
            "total_items": total_items,
            "risk_distribution": {
                "high_risk": high_risk_items,
                "medium_risk": medium_risk_items,
                "low_risk": low_risk_items
            },
            "average_risk_score": round(avg_risk_score, 2),
            "average_fact_check_likelihood": round(avg_fact_check_likelihood, 2),
            "category_distribution": dict(category_counts),
            "items_with_triggers": sum(1 for r in results if r.trigger_risk),
            "trigger_rate": sum(1 for r in results if r.trigger_risk) / total_items
        }

    async def get_content_recommendations(
        self,
        content: str,
        risk_result: CommunityNotesResult
    ) -> List[str]:
        """
        Get specific recommendations for improving content to reduce Community Notes risk.
        
        Args:
            content: Original content
            risk_result: Analysis result
            
        Returns:
            List of specific recommendations
        """
        recommendations = []
        
        if risk_result.risk_score >= 80:
            recommendations.append("Consider completely rewriting this content")
            recommendations.append("Verify all claims with multiple credible sources")
        elif risk_result.risk_score >= 60:
            recommendations.append("Significant revision needed to reduce fact-check risk")
            recommendations.append("Add credible sources to support claims")
        elif risk_result.risk_score >= 40:
            recommendations.append("Minor revisions recommended")
            recommendations.append("Consider adding context or disclaimers")
        
        # Category-specific recommendations
        for category in risk_result.content_categories:
            if category == "health_misinformation":
                recommendations.append("Consult medical professionals for health claims")
                recommendations.append("Include disclaimers about medical advice")
            elif category == "election_claims":
                recommendations.append("Use only official election sources")
                recommendations.append("Avoid unverified election information")
            elif category == "conspiracy_theories":
                recommendations.append("Focus on verifiable facts")
                recommendations.append("Avoid speculative language")
            elif category == "financial_scams":
                recommendations.append("Include proper financial disclaimers")
                recommendations.append("Avoid guarantees about returns")
        
        return recommendations

    async def extract_claims(
        self,
        content: str,
        use_ai: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Extract factual claims from content that can be fact-checked.
        
        Args:
            content: Text content to analyze
            use_ai: Whether to use AI service for advanced extraction
            
        Returns:
            List of extracted claims with metadata
        """
        claims = []
        
        # Pattern-based claim extraction
        claim_patterns = [
            # Statistical claims
            (r'(\d+(?:\.\d+)?%)\s+of\s+([^.!?]+)', 'statistical'),
            (r'(\d+(?:,\d{3})*(?:\.\d+)?)\s+([^.!?]+(?:died|infected|affected|reported))', 'statistical'),
            
            # Causal claims
            (r'([^.!?]+)\s+(?:causes?|leads? to|results? in)\s+([^.!?]+)', 'causal'),
            (r'([^.!?]+)\s+(?:is caused by|is due to|stems from)\s+([^.!?]+)', 'causal'),
            
            # Definitive statements
            (r'([^.!?]+)\s+(?:is|are|was|were)\s+(?:proven|confirmed|verified|established)\s+([^.!?]+)', 'definitive'),
            (r'(?:studies?|research|scientists?|experts?)\s+(?:show|prove|confirm|reveal)\s+(?:that\s+)?([^.!?]+)', 'definitive'),
            
            # Comparative claims
            (r'([^.!?]+)\s+(?:is|are)\s+(?:more|less|better|worse)\s+than\s+([^.!?]+)', 'comparative'),
            
            # Temporal claims
            (r'(?:in|on|during)\s+(\d{4}|\w+\s+\d{4}),?\s+([^.!?]+)', 'temporal'),
        ]
        
        content_lower = content.lower()
        
        for pattern, claim_type in claim_patterns:
            matches = re.finditer(pattern, content_lower, re.IGNORECASE)
            for match in matches:
                claim_text = match.group(0)
                
                # Extract claim components
                if len(match.groups()) >= 2:
                    subject = match.group(1).strip()
                    predicate = match.group(2).strip() if len(match.groups()) > 1 else ""
                else:
                    subject = claim_text
                    predicate = ""
                
                claims.append({
                    "claim_text": claim_text,
                    "claim_type": claim_type,
                    "subject": subject,
                    "predicate": predicate,
                    "position": match.start(),
                    "confidence": 0.7,
                    "requires_verification": True
                })
        
        # Use AI for advanced claim extraction if available
        if use_ai and self.ai_service and len(claims) < 10:
            try:
                ai_claims = await self._ai_extract_claims(content)
                
                # Merge AI claims with pattern-based claims, avoiding duplicates
                existing_texts = {c["claim_text"].lower() for c in claims}
                for ai_claim in ai_claims:
                    if ai_claim["claim_text"].lower() not in existing_texts:
                        claims.append(ai_claim)
            except Exception as e:
                # Continue with pattern-based claims if AI fails
                pass
        
        # Sort claims by position in text
        claims.sort(key=lambda x: x.get("position", 0))
        
        # Limit to most significant claims
        return claims[:20]

    async def _ai_extract_claims(self, content: str) -> List[Dict[str, Any]]:
        """
        Use AI service to extract claims from content.
        
        Args:
            content: Text content to analyze
            
        Returns:
            List of extracted claims
        """
        try:
            prompt = f"""Extract factual claims from the following content that can be fact-checked.
            
Content: {content[:2000]}

For each claim, identify:
1. The claim text
2. The type (statistical, causal, definitive, comparative, temporal)
3. Whether it requires verification

Return a JSON array of claims in this format:
[
  {{
    "claim_text": "the exact claim from the content",
    "claim_type": "statistical|causal|definitive|comparative|temporal",
    "subject": "what the claim is about",
    "predicate": "what is being claimed",
    "requires_verification": true|false,
    "confidence": 0.0-1.0
  }}
]

Only extract claims that are verifiable facts, not opinions or subjective statements."""

            # Use AI service to analyze
            response = await self.ai_service.analyze_with_prompt(prompt)
            
            # Parse response
            if isinstance(response, str):
                # Try to extract JSON from response
                json_match = re.search(r'\[.*\]', response, re.DOTALL)
                if json_match:
                    import json
                    claims = json.loads(json_match.group(0))
                    return claims
            elif isinstance(response, dict) and "claims" in response:
                return response["claims"]
            
            return []
            
        except Exception as e:
            return []

    async def assess_source_credibility(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Assess the credibility of sources cited in content.
        
        Args:
            content: Text content to analyze
            metadata: Additional metadata (author, platform, URLs, etc.)
            
        Returns:
            Dictionary with credibility assessment
        """
        credibility_score = 50  # Base score
        credibility_factors = []
        source_types = []
        cited_sources = []
        
        # Extract URLs from content
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, content)
        
        # Credible source domains
        credible_domains = {
            # News organizations
            'reuters.com': {'score': 90, 'type': 'news_agency'},
            'apnews.com': {'score': 90, 'type': 'news_agency'},
            'bbc.com': {'score': 85, 'type': 'news_outlet'},
            'nytimes.com': {'score': 85, 'type': 'news_outlet'},
            'washingtonpost.com': {'score': 85, 'type': 'news_outlet'},
            'theguardian.com': {'score': 85, 'type': 'news_outlet'},
            
            # Academic and research
            'nih.gov': {'score': 95, 'type': 'government_research'},
            'cdc.gov': {'score': 95, 'type': 'government_health'},
            'who.int': {'score': 95, 'type': 'international_health'},
            'nature.com': {'score': 90, 'type': 'academic_journal'},
            'science.org': {'score': 90, 'type': 'academic_journal'},
            'pubmed.ncbi.nlm.nih.gov': {'score': 90, 'type': 'academic_database'},
            'scholar.google.com': {'score': 85, 'type': 'academic_search'},
            
            # Government sources
            'gov': {'score': 85, 'type': 'government'},
            'edu': {'score': 80, 'type': 'educational'},
            
            # Fact-checking organizations
            'snopes.com': {'score': 85, 'type': 'fact_checker'},
            'factcheck.org': {'score': 85, 'type': 'fact_checker'},
            'politifact.com': {'score': 85, 'type': 'fact_checker'},
        }
        
        # Low credibility domains
        low_credibility_indicators = [
            'blogspot.com',
            'wordpress.com',
            'medium.com',
            'substack.com',
            'rumble.com',
            'bitchute.com',
        ]
        
        # Analyze cited URLs
        for url in urls:
            domain = self._extract_domain(url)
            cited_sources.append(url)
            
            # Check against credible sources
            source_found = False
            for credible_domain, info in credible_domains.items():
                if credible_domain in domain:
                    credibility_score += 15
                    credibility_factors.append(f"credible_source: {credible_domain}")
                    source_types.append(info['type'])
                    source_found = True
                    break
            
            # Check for low credibility indicators
            if not source_found:
                for low_cred in low_credibility_indicators:
                    if low_cred in domain:
                        credibility_score -= 10
                        credibility_factors.append(f"low_credibility_source: {low_cred}")
                        source_types.append('low_credibility')
                        break
        
        # Check for source citation patterns
        citation_patterns = [
            r'according to\s+([^,\.]+)',
            r'(?:study|research|report)\s+(?:by|from)\s+([^,\.]+)',
            r'([^,\.]+)\s+(?:reported|found|discovered|showed)',
            r'source:\s*([^,\.]+)',
            r'\[([^\]]+)\]',  # Bracketed citations
        ]
        
        content_lower = content.lower()
        for pattern in citation_patterns:
            matches = re.findall(pattern, content_lower)
            if matches:
                credibility_factors.append(f"citation_pattern_found: {len(matches)} citations")
                credibility_score += min(20, len(matches) * 5)
        
        # Check for lack of sources
        if not urls and not any(re.search(pattern, content_lower) for pattern in citation_patterns):
            credibility_score -= 20
            credibility_factors.append("no_sources_cited")
        
        # Check for anonymous sources
        anonymous_patterns = [
            r'anonymous\s+source',
            r'unnamed\s+source',
            r'sources\s+say',
            r'insider\s+(?:claims|says|reveals)',
        ]
        
        for pattern in anonymous_patterns:
            if re.search(pattern, content_lower):
                credibility_score -= 10
                credibility_factors.append(f"anonymous_source: {pattern}")
        
        # Check metadata for author credibility
        if metadata:
            author = metadata.get('author', '')
            if author:
                # Check for verified status
                if metadata.get('verified', False):
                    credibility_score += 10
                    credibility_factors.append("verified_author")
                
                # Check for professional credentials
                credential_patterns = [
                    r'(?:dr\.|doctor|phd|md)',
                    r'professor',
                    r'researcher',
                    r'journalist',
                ]
                
                author_lower = author.lower()
                for pattern in credential_patterns:
                    if re.search(pattern, author_lower):
                        credibility_score += 5
                        credibility_factors.append(f"author_credential: {pattern}")
        
        # Normalize score
        credibility_score = max(0, min(100, credibility_score))
        
        # Determine credibility level
        if credibility_score >= 80:
            credibility_level = "high"
        elif credibility_score >= 60:
            credibility_level = "medium"
        elif credibility_score >= 40:
            credibility_level = "low"
        else:
            credibility_level = "very_low"
        
        return {
            "credibility_score": credibility_score,
            "credibility_level": credibility_level,
            "credibility_factors": credibility_factors,
            "source_types": list(set(source_types)),
            "cited_sources": cited_sources,
            "source_count": len(cited_sources),
            "has_credible_sources": any(st in ['news_agency', 'government_research', 'academic_journal'] 
                                       for st in source_types),
            "recommendations": self._generate_credibility_recommendations(
                credibility_score, credibility_factors, cited_sources
            )
        }

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return url.lower()

    def _generate_credibility_recommendations(
        self,
        score: int,
        factors: List[str],
        sources: List[str]
    ) -> List[str]:
        """Generate recommendations for improving source credibility."""
        recommendations = []
        
        if score < 40:
            recommendations.append("Add credible sources to support claims")
            recommendations.append("Cite academic research or government sources")
        elif score < 60:
            recommendations.append("Consider adding more authoritative sources")
        
        if not sources:
            recommendations.append("Include source citations for factual claims")
        
        if any("anonymous_source" in f for f in factors):
            recommendations.append("Verify information from anonymous sources with named sources")
        
        if any("low_credibility_source" in f for f in factors):
            recommendations.append("Replace low-credibility sources with established outlets")
        
        return recommendations

    async def lookup_fact_checks(
        self,
        claims: List[Dict[str, Any]],
        use_ai: bool = True
    ) -> Dict[str, Any]:
        """
        Look up fact-checks for extracted claims.
        
        This method searches for existing fact-checks from credible fact-checking
        organizations and databases.
        
        Args:
            claims: List of extracted claims to fact-check
            use_ai: Whether to use AI for semantic matching
            
        Returns:
            Dictionary with fact-check results
        """
        fact_check_results = []
        
        # Known fact-checking databases and patterns
        fact_check_databases = {
            'snopes': {
                'url_pattern': 'snopes.com/fact-check/',
                'ratings': ['true', 'mostly true', 'mixture', 'mostly false', 'false', 'unproven']
            },
            'politifact': {
                'url_pattern': 'politifact.com/factchecks/',
                'ratings': ['true', 'mostly true', 'half true', 'mostly false', 'false', 'pants on fire']
            },
            'factcheck_org': {
                'url_pattern': 'factcheck.org/',
                'ratings': ['true', 'false', 'misleading', 'unproven']
            },
            'reuters_fact_check': {
                'url_pattern': 'reuters.com/fact-check/',
                'ratings': ['true', 'false', 'misleading', 'partly false']
            },
            'ap_fact_check': {
                'url_pattern': 'apnews.com/hub/ap-fact-check',
                'ratings': ['true', 'false', 'misleading', 'unproven']
            }
        }
        
        # Common debunked claims database (simplified - in production, use actual API)
        known_false_claims = [
            {
                'claim': '5g causes covid',
                'keywords': ['5g', 'covid', 'coronavirus', 'causes'],
                'verdict': 'false',
                'source': 'multiple fact-checkers',
                'confidence': 0.95
            },
            {
                'claim': 'vaccines contain microchips',
                'keywords': ['vaccine', 'microchip', 'tracking', 'bill gates'],
          
         'verdict': 'false',
                'source': 'multiple fact-checkers',
                'confidence': 0.95
            },
            {
                'claim': 'election was stolen',
                'keywords': ['election', 'stolen', 'fraud', 'rigged'],
                'verdict': 'false',
                'source': 'multiple fact-checkers',
                'confidence': 0.90
            },
            {
                'claim': 'climate change is a hoax',
                'keywords': ['climate change', 'hoax', 'fake', 'conspiracy'],
                'verdict': 'false',
                'source': 'scientific consensus',
                'confidence': 0.98
            },
            {
                'claim': 'drinking bleach cures diseases',
                'keywords': ['bleach', 'cure', 'drink', 'miracle'],
                'verdict': 'false',
                'source': 'medical authorities',
                'confidence': 0.99
            },
            {
                'claim': 'earth is flat',
                'keywords': ['flat earth', 'earth', 'flat', 'globe'],
                'verdict': 'false',
                'source': 'scientific consensus',
                'confidence': 0.99
            },
            {
                'claim': 'moon landing was faked',
                'keywords': ['moon landing', 'fake', 'hoax', 'staged'],
                'verdict': 'false',
                'source': 'multiple fact-checkers',
                'confidence': 0.95
            },
            {
                'claim': 'ivermectin cures covid',
                'keywords': ['ivermectin', 'covid', 'cure', 'treatment'],
                'verdict': 'misleading',
                'source': 'medical authorities',
                'confidence': 0.85
            },
            {
                'claim': 'masks dont work',
                'keywords': ['mask', 'dont work', 'ineffective', 'useless'],
                'verdict': 'false',
                'source': 'medical authorities',
                'confidence': 0.90
            }
        ]
        
        # Process each claim
        for claim in claims:
            claim_text = claim.get('claim_text', '').lower()
            claim_result = {
                'original_claim': claim,
                'fact_check_found': False,
                'verdict': None,
                'confidence': 0.0,
                'sources': [],
                'match_type': None,
                'details': None
            }
            
            # Check against known false claims database
            for known_claim in known_false_claims:
                # Calculate keyword match score
                keyword_matches = sum(
                    1 for keyword in known_claim['keywords']
                    if keyword.lower() in claim_text
                )
                
                match_ratio = keyword_matches / len(known_claim['keywords'])
                
                # If significant keyword overlap, consider it a match
                if match_ratio >= 0.6:
                    claim_result['fact_check_found'] = True
                    claim_result['verdict'] = known_claim['verdict']
                    claim_result['confidence'] = known_claim['confidence'] * match_ratio
                    claim_result['sources'].append(known_claim['source'])
                    claim_result['match_type'] = 'keyword_match'
                    claim_result['details'] = {
                        'matched_claim': known_claim['claim'],
                        'keyword_match_ratio': match_ratio,
                        'matched_keywords': [
                            kw for kw in known_claim['keywords']
                            if kw.lower() in claim_text
                        ]
                    }
                    break
            
            # Use AI for semantic matching if enabled and no match found
            if use_ai and not claim_result['fact_check_found'] and self.ai_service:
                try:
                    ai_fact_check = await self._ai_fact_check_lookup(
                        claim_text,
                        known_false_claims
                    )
                    
                    if ai_fact_check and ai_fact_check.get('match_found'):
                        claim_result['fact_check_found'] = True
                        claim_result['verdict'] = ai_fact_check.get('verdict')
                        claim_result['confidence'] = ai_fact_check.get('confidence', 0.7)
                        claim_result['sources'] = ai_fact_check.get('sources', [])
                        claim_result['match_type'] = 'ai_semantic_match'
                        claim_result['details'] = ai_fact_check.get('details')
                except Exception as e:
                    # Continue without AI if it fails
                    pass
            
            fact_check_results.append(claim_result)
        
        # Calculate summary statistics
        total_claims = len(claims)
        fact_checked_claims = sum(1 for r in fact_check_results if r['fact_check_found'])
        false_claims = sum(1 for r in fact_check_results if r['verdict'] == 'false')
        misleading_claims = sum(1 for r in fact_check_results if r['verdict'] == 'misleading')
        
        # Calculate overall misinformation risk
        if total_claims > 0:
            misinformation_risk = (false_claims + (misleading_claims * 0.5)) / total_claims
        else:
            misinformation_risk = 0.0
        
        return {
            'total_claims_analyzed': total_claims,
            'fact_checks_found': fact_checked_claims,
            'fact_check_coverage': fact_checked_claims / total_claims if total_claims > 0 else 0.0,
            'verdicts': {
                'false': false_claims,
                'misleading': misleading_claims,
                'true': sum(1 for r in fact_check_results if r['verdict'] == 'true'),
                'unproven': sum(1 for r in fact_check_results if r['verdict'] == 'unproven'),
            },
            'misinformation_risk_score': round(misinformation_risk * 100, 2),
            'fact_check_results': fact_check_results,
            'databases_consulted': list(fact_check_databases.keys()),
            'recommendations': self._generate_fact_check_recommendations(
                misinformation_risk,
                fact_checked_claims,
                total_claims
            )
        }

    async def _ai_fact_check_lookup(
        self,
        claim_text: str,
        known_claims: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Use AI to perform semantic matching against known fact-checked claims.
        
        Args:
            claim_text: The claim to fact-check
            known_claims: Database of known fact-checked claims
            
        Returns:
            Fact-check result if match found, None otherwise
        """
        try:
            # Create a prompt for AI to match the claim
            known_claims_text = "\n".join([
                f"- {c['claim']} (Verdict: {c['verdict']})"
                for c in known_claims[:20]  # Limit to avoid token limits
            ])
            
            prompt = f"""Analyze if the following claim matches any known fact-checked claims.

Claim to check: "{claim_text}"

Known fact-checked claims:
{known_claims_text}

Determine if the claim is semantically similar to any known fact-checked claim.
Consider paraphrasing, different wording, and implied meanings.

Respond in JSON format:
{{
    "match_found": true/false,
    "matched_claim": "the matching claim from the database",
    "verdict": "false|misleading|true|unproven",
    "confidence": 0.0-1.0,
    "reasoning": "brief explanation of the match",
    "sources": ["source1", "source2"]
}}

If no match is found, set match_found to false."""

            response = await self.ai_service.analyze_with_prompt(prompt)
            
            # Parse AI response
            if isinstance(response, str):
                # Try to extract JSON
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    import json
                    result = json.loads(json_match.group(0))
                    
                    if result.get('match_found'):
                        return {
                            'match_found': True,
                            'verdict': result.get('verdict'),
                            'confidence': result.get('confidence', 0.7),
                            'sources': result.get('sources', ['AI analysis']),
                            'details': {
                                'matched_claim': result.get('matched_claim'),
                                'reasoning': result.get('reasoning')
                            }
                        }
            
            return None
            
        except Exception as e:
            return None

    def _generate_fact_check_recommendations(
        self,
        misinformation_risk: float,
        fact_checked: int,
        total: int
    ) -> List[str]:
        """Generate recommendations based on fact-check results."""
        recommendations = []
        
        if misinformation_risk >= 0.5:
            recommendations.append("HIGH RISK: Multiple false or misleading claims detected")
            recommendations.append("Verify all claims with credible sources before sharing")
            recommendations.append("Consider not sharing this content")
        elif misinformation_risk >= 0.3:
            recommendations.append("MEDIUM RISK: Some questionable claims detected")
            recommendations.append("Review flagged claims carefully")
            recommendations.append("Add context or corrections if sharing")
        elif misinformation_risk > 0:
            recommendations.append("LOW RISK: Minor concerns detected")
            recommendations.append("Review flagged claims for accuracy")
        else:
            if fact_checked > 0:
                recommendations.append("No known false claims detected")
            else:
                recommendations.append("No matches in fact-check database")
                recommendations.append("Consider verifying claims independently")
        
        # Coverage recommendations
        if total > 0:
            coverage = fact_checked / total
            if coverage < 0.3:
                recommendations.append("Limited fact-check coverage - manual verification recommended")
        
        return recommendations

    async def analyze_with_fact_checks(
        self,
        content: str,
        platform: str = "twitter",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive analysis including Community Notes risk and fact-checking.
        
        This is a convenience method that combines multiple analysis steps.
        
        Args:
            content: Content to analyze
            platform: Platform name
            metadata: Additional metadata
            
        Returns:
            Comprehensive analysis results
        """
        # Perform Community Notes risk analysis
        notes_result = await self.analyze_community_notes_risk(content, platform, metadata)
        
        # Extract claims
        claims = await self.extract_claims(content, use_ai=True)
        
        # Look up fact-checks
        fact_check_results = await self.lookup_fact_checks(claims, use_ai=True)
        
        # Assess source credibility
        credibility_assessment = await self.assess_source_credibility(content, metadata)
        
        # Calculate combined risk score
        combined_risk_score = self._calculate_combined_risk(
            notes_result.risk_score,
            fact_check_results['misinformation_risk_score'],
            credibility_assessment['credibility_score']
        )
        
        return {
            'community_notes_analysis': {
                'trigger_risk': notes_result.trigger_risk,
                'risk_score': notes_result.risk_score,
                'trigger_factors': notes_result.trigger_factors,
                'content_categories': notes_result.content_categories,
                'fact_check_likelihood': notes_result.fact_check_likelihood,
                'confidence_score': notes_result.confidence_score
            },
            'fact_check_analysis': fact_check_results,
            'source_credibility': credibility_assessment,
            'claims_extracted': len(claims),
            'claims': claims[:10],  # Limit to first 10 for response size
            'combined_risk_score': combined_risk_score,
            'overall_verdict': self._determine_overall_verdict(combined_risk_score),
            'recommendations': self._generate_combined_recommendations(
                notes_result,
                fact_check_results,
                credibility_assessment,
                combined_risk_score
            ),
            'analysis_timestamp': datetime.now(timezone.utc).isoformat()
        }

    def _calculate_combined_risk(
        self,
        notes_risk: int,
        misinfo_risk: float,
        credibility_score: int
    ) -> int:
        """Calculate combined risk score from multiple analyses."""
        # Normalize all scores to 0-100
        notes_normalized = notes_risk
        misinfo_normalized = misinfo_risk
        credibility_normalized = 100 - credibility_score  # Invert so higher = more risk
        
        # Weighted average
        combined = (
            notes_normalized * 0.4 +
            misinfo_normalized * 0.4 +
            credibility_normalized * 0.2
        )
        
        return int(round(combined))

    def _determine_overall_verdict(self, risk_score: int) -> str:
        """Determine overall verdict based on combined risk score."""
        if risk_score >= 80:
            return "CRITICAL_RISK"
        elif risk_score >= 60:
            return "HIGH_RISK"
        elif risk_score >= 40:
            return "MEDIUM_RISK"
        elif risk_score >= 20:
            return "LOW_RISK"
        else:
            return "MINIMAL_RISK"

    def _generate_combined_recommendations(
        self,
        notes_result: CommunityNotesResult,
        fact_check_results: Dict[str, Any],
        credibility_assessment: Dict[str, Any],
        combined_risk: int
    ) -> List[str]:
        """Generate comprehensive recommendations from all analyses."""
        recommendations = []
        
        # Overall risk recommendations
        if combined_risk >= 80:
            recommendations.append("⚠️ CRITICAL: Do not share this content")
            recommendations.append("Content contains multiple high-risk factors")
        elif combined_risk >= 60:
            recommendations.append("⚠️ HIGH RISK: Significant concerns detected")
            recommendations.append("Thorough fact-checking required before sharing")
        elif combined_risk >= 40:
            recommendations.append("⚠️ MEDIUM RISK: Some concerns detected")
            recommendations.append("Review and verify before sharing")
        
        # Add specific recommendations from each analysis
        if notes_result.trigger_risk:
            recommendations.extend(notes_result.recommendations[:2])
        
        if fact_check_results['misinformation_risk_score'] > 30:
            recommendations.extend(fact_check_results['recommendations'][:2])
        
        if credibility_assessment['credibility_score'] < 50:
            recommendations.extend(credibility_assessment['recommendations'][:2])
        
        # Deduplicate recommendations
        return list(dict.fromkeys(recommendations))[:10]  # Keep unique, limit to 10

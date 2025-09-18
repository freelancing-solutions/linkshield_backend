#!/usr/bin/env python3
"""
LinkShield Backend AI Service

AI-powered content analysis service for threat detection, quality scoring,
and intelligent URL classification using machine learning models.
"""

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp
import openai
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification

from src.config.settings import get_settings


class AIServiceError(Exception):
    """
    Base AI service error.
    """
    pass


class ModelLoadError(AIServiceError):
    """
    Model loading error.
    """
    pass


class AnalysisError(AIServiceError):
    """
    Content analysis error.
    """
    pass


class AIService:
    """
    AI service for content analysis and threat detection.
    """
    
    def __init__(self):
        self.settings = get_settings()
        
        # Initialize OpenAI client if API key is available
        if self.settings.OPENAI_API_KEY:
            openai.api_key = self.settings.OPENAI_API_KEY
            self.openai_enabled = True
        else:
            self.openai_enabled = False
        
        # Initialize local models
        self.models = {}
        self.tokenizers = {}
        self.pipelines = {}
        
        # Model configurations
        self.model_configs = {
            "phishing_detector": {
                "model_name": "microsoft/DialoGPT-medium",  # Placeholder - would use specialized model
                "task": "text-classification",
                "enabled": True
            },
            "content_classifier": {
                "model_name": "distilbert-base-uncased-finetuned-sst-2-english",
                "task": "sentiment-analysis",
                "enabled": True
            },
            "spam_detector": {
                "model_name": "unitary/toxic-bert",  # Placeholder - would use specialized model
                "task": "text-classification",
                "enabled": True
            }
        }
        
        # Content analysis patterns
        self.threat_patterns = {
            "phishing": [
                r"verify\s+your\s+account",
                r"suspended\s+account",
                r"click\s+here\s+immediately",
                r"urgent\s+action\s+required",
                r"confirm\s+your\s+identity",
                r"update\s+payment\s+information",
                r"security\s+alert",
                r"unusual\s+activity\s+detected",
                r"temporary\s+suspension"
            ],
            "scam": [
                r"congratulations.*won",
                r"claim\s+your\s+prize",
                r"limited\s+time\s+offer",
                r"act\s+now",
                r"guaranteed\s+income",
                r"work\s+from\s+home",
                r"make\s+money\s+fast",
                r"no\s+experience\s+required"
            ],
            "malware": [
                r"download\s+now",
                r"install\s+required",
                r"update\s+your\s+software",
                r"codec\s+required",
                r"plugin\s+missing",
                r"flash\s+player\s+update"
            ]
        }
        
        # Quality indicators
        self.quality_indicators = {
            "positive": [
                "https", "ssl", "secure", "verified", "trusted",
                "official", "authentic", "legitimate", "certified"
            ],
            "negative": [
                "suspicious", "fake", "scam", "phishing", "malware",
                "virus", "trojan", "spam", "fraud", "deceptive"
            ]
        }
    
    async def initialize_models(self) -> None:
        """
        Initialize AI models for content analysis.
        """
        try:
            for model_name, config in self.model_configs.items():
                if not config["enabled"]:
                    continue
                
                try:
                    # Initialize pipeline for the model
                    self.pipelines[model_name] = pipeline(
                        config["task"],
                        model=config["model_name"],
                        return_all_scores=True
                    )
                    
                    print(f"Loaded model: {model_name}")
                    
                except Exception as e:
                    print(f"Failed to load model {model_name}: {str(e)}")
                    config["enabled"] = False
        
        except Exception as e:
            raise ModelLoadError(f"Failed to initialize models: {str(e)}")
    
    async def analyze_content(self, content: str, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive AI-powered content analysis.
        
        Args:
            content: HTML/text content to analyze
            url: Source URL of the content
        
        Returns:
            Analysis results with threat detection and quality scores
        """
        try:
            # Extract text content from HTML
            text_content = self._extract_text_content(content)
            
            # Perform multiple analysis types
            analysis_tasks = [
                self._analyze_phishing_indicators(text_content, url),
                self._analyze_content_quality(text_content),
                self._analyze_sentiment(text_content),
                self._detect_spam_patterns(text_content),
                self._analyze_structural_indicators(content)
            ]
            
            # Execute analysis tasks
            results = await asyncio.gather(*analysis_tasks, return_exceptions=True)
            
            # Combine results
            combined_analysis = {
                "phishing_analysis": results[0] if not isinstance(results[0], Exception) else {},
                "quality_analysis": results[1] if not isinstance(results[1], Exception) else {},
                "sentiment_analysis": results[2] if not isinstance(results[2], Exception) else {},
                "spam_analysis": results[3] if not isinstance(results[3], Exception) else {},
                "structural_analysis": results[4] if not isinstance(results[4], Exception) else {}
            }
            
            # Calculate overall threat score
            threat_detected, threat_types, confidence_score = self._calculate_threat_score(combined_analysis)
            
            return {
                "threat_detected": threat_detected,
                "threat_types": threat_types,
                "confidence_score": confidence_score,
                "detailed_analysis": combined_analysis,
                "analysis_timestamp": datetime.now(timezone.utc).isoformat()
            }
        
        except Exception as e:
            raise AnalysisError(f"Content analysis failed: {str(e)}")
    
    async def _analyze_phishing_indicators(self, text: str, url: str) -> Dict[str, Any]:
        """
        Analyze content for phishing indicators.
        """
        indicators = []
        confidence_scores = []
        
        # Pattern-based detection
        text_lower = text.lower()
        for pattern in self.threat_patterns["phishing"]:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                indicators.append(f"phishing_pattern_{pattern[:20]}")
                confidence_scores.append(80)
        
        # URL-based indicators
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Check for suspicious domain patterns
        if re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', domain):
            indicators.append("ip_address_domain")
            confidence_scores.append(70)
        
        if len(domain.split('.')) > 4:
            indicators.append("excessive_subdomains")
            confidence_scores.append(60)
        
        # Check for brand impersonation
        legitimate_brands = [
            'paypal', 'amazon', 'google', 'microsoft', 'apple',
            'facebook', 'twitter', 'instagram', 'linkedin', 'netflix'
        ]
        
        for brand in legitimate_brands:
            if brand in domain and not domain.endswith(f"{brand}.com"):
                indicators.append(f"brand_impersonation_{brand}")
                confidence_scores.append(90)
        
        # AI-based analysis if available
        ai_score = 0
        if self.openai_enabled:
            try:
                ai_analysis = await self._openai_phishing_analysis(text, url)
                ai_score = ai_analysis.get("confidence_score", 0)
                if ai_analysis.get("is_phishing"):
                    indicators.append("ai_detected_phishing")
                    confidence_scores.append(ai_score)
            except Exception:
                pass
        
        # Local model analysis
        if "phishing_detector" in self.pipelines:
            try:
                model_result = self.pipelines["phishing_detector"](text[:512])  # Limit text length
                if model_result and len(model_result) > 0:
                    phishing_score = next((score['score'] for score in model_result[0] 
                                         if score['label'] == 'PHISHING'), 0)
                    if phishing_score > 0.7:
                        indicators.append("model_detected_phishing")
                        confidence_scores.append(int(phishing_score * 100))
            except Exception:
                pass
        
        overall_confidence = max(confidence_scores) if confidence_scores else 0
        
        return {
            "indicators": indicators,
            "confidence_score": overall_confidence,
            "threat_detected": len(indicators) > 0,
            "ai_score": ai_score
        }
    
    async def _analyze_content_quality(self, text: str) -> Dict[str, Any]:
        """
        Analyze content quality and legitimacy.
        """
        quality_score = 50  # Base score
        quality_factors = []
        
        # Text length analysis
        text_length = len(text)
        if text_length < 100:
            quality_score -= 20
            quality_factors.append("very_short_content")
        elif text_length > 1000:
            quality_score += 10
            quality_factors.append("substantial_content")
        
        # Grammar and spelling analysis (simplified)
        sentences = text.split('.')
        if len(sentences) > 5:
            quality_score += 5
            quality_factors.append("multiple_sentences")
        
        # Check for excessive capitalization
        caps_ratio = sum(1 for c in text if c.isupper()) / len(text) if text else 0
        if caps_ratio > 0.3:
            quality_score -= 15
            quality_factors.append("excessive_caps")
        
        # Check for quality indicators
        text_lower = text.lower()
        positive_count = sum(1 for indicator in self.quality_indicators["positive"] 
                           if indicator in text_lower)
        negative_count = sum(1 for indicator in self.quality_indicators["negative"] 
                           if indicator in text_lower)
        
        quality_score += positive_count * 5
        quality_score -= negative_count * 10
        
        if positive_count > 0:
            quality_factors.append(f"positive_indicators_{positive_count}")
        if negative_count > 0:
            quality_factors.append(f"negative_indicators_{negative_count}")
        
        # Normalize score
        quality_score = max(0, min(100, quality_score))
        
        return {
            "quality_score": quality_score,
            "quality_factors": quality_factors,
            "text_length": text_length,
            "positive_indicators": positive_count,
            "negative_indicators": negative_count
        }
    
    async def _analyze_sentiment(self, text: str) -> Dict[str, Any]:
        """
        Analyze content sentiment.
        """
        try:
            if "content_classifier" in self.pipelines:
                # Use local model for sentiment analysis
                result = self.pipelines["content_classifier"](text[:512])
                
                if result and len(result) > 0:
                    sentiment_data = result[0]
                    sentiment = sentiment_data.get('label', 'NEUTRAL')
                    confidence = sentiment_data.get('score', 0)
                    
                    return {
                        "sentiment": sentiment.lower(),
                        "confidence": confidence,
                        "suspicious": sentiment == 'NEGATIVE' and confidence > 0.8
                    }
            
            # Fallback to simple pattern-based sentiment
            positive_words = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic']
            negative_words = ['bad', 'terrible', 'awful', 'horrible', 'disgusting', 'hate']
            
            text_lower = text.lower()
            positive_count = sum(1 for word in positive_words if word in text_lower)
            negative_count = sum(1 for word in negative_words if word in text_lower)
            
            if positive_count > negative_count:
                sentiment = 'positive'
                confidence = min(0.8, positive_count / 10)
            elif negative_count > positive_count:
                sentiment = 'negative'
                confidence = min(0.8, negative_count / 10)
            else:
                sentiment = 'neutral'
                confidence = 0.5
            
            return {
                "sentiment": sentiment,
                "confidence": confidence,
                "suspicious": sentiment == 'negative' and confidence > 0.6
            }
        
        except Exception:
            return {
                "sentiment": "neutral",
                "confidence": 0,
                "suspicious": False
            }
    
    async def _detect_spam_patterns(self, text: str) -> Dict[str, Any]:
        """
        Detect spam patterns in content.
        """
        spam_indicators = []
        confidence_scores = []
        
        text_lower = text.lower()
        
        # Pattern-based spam detection
        for pattern in self.threat_patterns["scam"]:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                spam_indicators.append(f"spam_pattern_{pattern[:20]}")
                confidence_scores.append(75)
        
        # Check for excessive punctuation
        exclamation_count = text.count('!')
        if exclamation_count > 5:
            spam_indicators.append("excessive_exclamations")
            confidence_scores.append(60)
        
        # Check for repeated words
        words = text_lower.split()
        word_counts = {}
        for word in words:
            if len(word) > 3:
                word_counts[word] = word_counts.get(word, 0) + 1
        
        repeated_words = [word for word, count in word_counts.items() if count > 3]
        if repeated_words:
            spam_indicators.append("repeated_words")
            confidence_scores.append(50)
        
        # Check for suspicious URLs in text
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls_in_text = re.findall(url_pattern, text)
        if len(urls_in_text) > 3:
            spam_indicators.append("multiple_urls")
            confidence_scores.append(70)
        
        overall_confidence = max(confidence_scores) if confidence_scores else 0
        
        return {
            "spam_indicators": spam_indicators,
            "confidence_score": overall_confidence,
            "is_spam": len(spam_indicators) >= 2,
            "urls_found": len(urls_in_text)
        }
    
    async def _analyze_structural_indicators(self, html_content: str) -> Dict[str, Any]:
        """
        Analyze HTML structure for suspicious patterns.
        """
        indicators = []
        
        # Check for hidden elements
        hidden_patterns = [
            r'style=["\'].*display:\s*none',
            r'style=["\'].*visibility:\s*hidden',
            r'style=["\'].*opacity:\s*0'
        ]
        
        for pattern in hidden_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                indicators.append("hidden_elements")
                break
        
        # Check for suspicious JavaScript
        js_patterns = [
            r'eval\s*\(',
            r'document\.write\s*\(',
            r'window\.location\s*=',
            r'setTimeout\s*\(',
            r'setInterval\s*\('
        ]
        
        for pattern in js_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                indicators.append("suspicious_javascript")
                break
        
        # Check for iframe usage
        iframe_count = len(re.findall(r'<iframe', html_content, re.IGNORECASE))
        if iframe_count > 2:
            indicators.append("multiple_iframes")
        
        # Check for form elements
        form_count = len(re.findall(r'<form', html_content, re.IGNORECASE))
        password_inputs = len(re.findall(r'type=["\']password["\']', html_content, re.IGNORECASE))
        
        if form_count > 0 and password_inputs > 0:
            indicators.append("password_form")
        
        # Check for suspicious meta redirects
        meta_refresh = re.search(r'<meta[^>]*http-equiv=["\']refresh["\']', html_content, re.IGNORECASE)
        if meta_refresh:
            indicators.append("meta_redirect")
        
        return {
            "structural_indicators": indicators,
            "iframe_count": iframe_count,
            "form_count": form_count,
            "password_inputs": password_inputs,
            "suspicious_structure": len(indicators) >= 2
        }
    
    async def _openai_phishing_analysis(self, text: str, url: str) -> Dict[str, Any]:
        """
        Use OpenAI API for advanced phishing detection.
        """
        try:
            prompt = f"""
            Analyze the following content for phishing indicators:
            
            URL: {url}
            Content: {text[:1000]}...
            
            Determine if this content is likely to be phishing. Consider:
            1. Urgency language
            2. Requests for personal information
            3. Suspicious links or domains
            4. Brand impersonation
            5. Grammar and spelling errors
            
            Respond with JSON format:
            {{
                "is_phishing": boolean,
                "confidence_score": number (0-100),
                "reasoning": "explanation",
                "threat_types": ["list of threat types"]
            }}
            """
            
            response = await openai.ChatCompletion.acreate(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in phishing detection."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.1
            )
            
            result_text = response.choices[0].message.content
            
            # Parse JSON response
            try:
                result = json.loads(result_text)
                return result
            except json.JSONDecodeError:
                # Fallback if JSON parsing fails
                return {
                    "is_phishing": "phishing" in result_text.lower(),
                    "confidence_score": 50,
                    "reasoning": "AI analysis completed",
                    "threat_types": []
                }
        
        except Exception as e:
            return {
                "is_phishing": False,
                "confidence_score": 0,
                "reasoning": f"Analysis failed: {str(e)}",
                "threat_types": []
            }
    
    def _extract_text_content(self, html_content: str) -> str:
        """
        Extract text content from HTML.
        """
        try:
            # Simple HTML tag removal (in production, use proper HTML parser)
            text = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r'<[^>]+>', '', text)
            
            # Clean up whitespace
            text = re.sub(r'\s+', ' ', text)
            text = text.strip()
            
            return text
        
        except Exception:
            return html_content
    
    def _calculate_threat_score(self, analysis_results: Dict[str, Any]) -> Tuple[bool, List[str], int]:
        """
        Calculate overall threat score from analysis results.
        """
        threat_types = []
        confidence_scores = []
        
        # Process phishing analysis
        phishing = analysis_results.get("phishing_analysis", {})
        if phishing.get("threat_detected"):
            threat_types.append("phishing")
            confidence_scores.append(phishing.get("confidence_score", 0))
        
        # Process spam analysis
        spam = analysis_results.get("spam_analysis", {})
        if spam.get("is_spam"):
            threat_types.append("spam")
            confidence_scores.append(spam.get("confidence_score", 0))
        
        # Process structural analysis
        structural = analysis_results.get("structural_analysis", {})
        if structural.get("suspicious_structure"):
            threat_types.append("suspicious_structure")
            confidence_scores.append(70)
        
        # Process quality analysis
        quality = analysis_results.get("quality_analysis", {})
        quality_score = quality.get("quality_score", 50)
        if quality_score < 30:
            threat_types.append("low_quality")
            confidence_scores.append(100 - quality_score)
        
        # Process sentiment analysis
        sentiment = analysis_results.get("sentiment_analysis", {})
        if sentiment.get("suspicious"):
            threat_types.append("negative_sentiment")
            confidence_scores.append(int(sentiment.get("confidence", 0) * 100))
        
        # Calculate overall confidence
        overall_confidence = max(confidence_scores) if confidence_scores else 0
        threat_detected = len(threat_types) > 0 and overall_confidence > 50
        
        return threat_detected, threat_types, overall_confidence
    
    async def analyze_url_reputation(self, url: str, historical_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze URL reputation using AI and historical data.
        """
        try:
            domain = urlparse(url).netloc.lower()
            
            # Analyze domain characteristics
            domain_analysis = {
                "domain_age": self._estimate_domain_age(domain),
                "domain_length": len(domain),
                "subdomain_count": len(domain.split('.')) - 2,
                "has_numbers": bool(re.search(r'\d', domain)),
                "has_hyphens": '-' in domain,
                "tld": domain.split('.')[-1] if '.' in domain else ''
            }
            
            # Calculate reputation score
            reputation_score = 50  # Base score
            
            # Adjust based on historical data
            if historical_data:
                total_checks = historical_data.get("total_checks", 0)
                malicious_checks = historical_data.get("malicious_count", 0)
                
                if total_checks > 0:
                    clean_ratio = (total_checks - malicious_checks) / total_checks
                    reputation_score = int(clean_ratio * 100)
            
            # Adjust based on domain characteristics
            if domain_analysis["domain_length"] > 50:
                reputation_score -= 10
            
            if domain_analysis["subdomain_count"] > 3:
                reputation_score -= 15
            
            if domain_analysis["tld"] in ['tk', 'ml', 'ga', 'cf']:  # Suspicious TLDs
                reputation_score -= 20
            
            # Normalize score
            reputation_score = max(0, min(100, reputation_score))
            
            return {
                "reputation_score": reputation_score,
                "domain_analysis": domain_analysis,
                "risk_level": "high" if reputation_score < 30 else "medium" if reputation_score < 70 else "low",
                "confidence": min(100, (historical_data.get("total_checks", 0) * 2))
            }
        
        except Exception as e:
            return {
                "reputation_score": 50,
                "error": str(e),
                "risk_level": "unknown",
                "confidence": 0
            }
    
    def _estimate_domain_age(self, domain: str) -> str:
        """
        Estimate domain age based on patterns (simplified).
        """
        # This is a simplified estimation
        # In production, you would use WHOIS data or domain age APIs
        
        if any(char.isdigit() for char in domain):
            return "recent"  # Domains with numbers often newer
        
        if len(domain.split('.')[0]) < 5:
            return "old"  # Short domains often older
        
        return "unknown"
    
    async def get_model_status(self) -> Dict[str, Any]:
        """
        Get status of loaded AI models.
        """
        return {
            "openai_enabled": self.openai_enabled,
            "local_models": {
                name: {
                    "enabled": config["enabled"],
                    "loaded": name in self.pipelines
                }
                for name, config in self.model_configs.items()
            },
            "total_models": len(self.pipelines)
        }
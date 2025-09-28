import asyncio
import aiohttp
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass
from datetime import datetime
import re

@dataclass
class RedirectChain:
    """Represents a single redirect in the chain."""
    url: str
    status_code: int
    response_time: float
    headers: Dict[str, str]
    is_shortener: bool = False
    risk_level: str = "low"  # low, medium, high
    
@dataclass 
class ShortenerAnalysisResult:
    """Complete analysis result for a URL shortener."""
    original_url: str
    final_destination: str
    is_shortener: bool
    redirect_chain: List[RedirectChain]
    total_redirects: int
    total_response_time: float
    risk_assessment: str  # safe, suspicious, malicious
    risk_factors: List[str]
    legitimate_shortener: bool
    analysis_summary: str

class URLShortenerAnalyzer:
    """
    Utility class for analyzing URL shorteners and following redirect chains.
    """
    
    def __init__(self):
        # Known legitimate shorteners with their characteristics
        self.legitimate_shorteners = {
            # Major platforms
            'bit.ly': {'trust_score': 95, 'category': 'commercial', 'provider': 'Bitly'},
            'tinyurl.com': {'trust_score': 90, 'category': 'free', 'provider': 'TinyURL'},
            't.co': {'trust_score': 95, 'category': 'social', 'provider': 'Twitter'},
            'goo.gl': {'trust_score': 85, 'category': 'deprecated', 'provider': 'Google'},
            'ow.ly': {'trust_score': 85, 'category': 'social', 'provider': 'Hootsuite'},
            'buff.ly': {'trust_score': 90, 'category': 'social', 'provider': 'Buffer'},
            'rebrand.ly': {'trust_score': 85, 'category': 'commercial', 'provider': 'Rebrandly'},
            
            # Business/Enterprise
            'short.link': {'trust_score': 80, 'category': 'commercial', 'provider': 'Short.link'},
            'tiny.cc': {'trust_score': 75, 'category': 'free', 'provider': 'Tiny.cc'},
            'is.gd': {'trust_score': 75, 'category': 'free', 'provider': 'is.gd'},
            'v.gd': {'trust_score': 75, 'category': 'free', 'provider': 'v.gd'},
            
            # Platform-specific
            'youtu.be': {'trust_score': 95, 'category': 'platform', 'provider': 'YouTube'},
            'aka.ms': {'trust_score': 90, 'category': 'corporate', 'provider': 'Microsoft'},
            'amzn.to': {'trust_score': 90, 'category': 'corporate', 'provider': 'Amazon'},
            'apple.co': {'trust_score': 90, 'category': 'corporate', 'provider': 'Apple'},
            
            # News/Media
            'nyti.ms': {'trust_score': 95, 'category': 'media', 'provider': 'New York Times'},
            'wapo.st': {'trust_score': 95, 'category': 'media', 'provider': 'Washington Post'},
            'politi.co': {'trust_score': 90, 'category': 'media', 'provider': 'Politico'},
        }
        
        # Suspicious or high-risk shorteners
        self.suspicious_shorteners = {
            # Free services with minimal moderation
            'cutt.ly': {'risk_level': 'medium', 'reason': 'minimal_moderation'},
            'short.ly': {'risk_level': 'medium', 'reason': 'abuse_reports'},
            'tinycc.com': {'risk_level': 'high', 'reason': 'frequent_abuse'},
            'u.to': {'risk_level': 'medium', 'reason': 'minimal_verification'},
            'clicky.me': {'risk_level': 'medium', 'reason': 'limited_oversight'},
            
            # Known problematic domains
            'bit.do': {'risk_level': 'high', 'reason': 'spam_reports'},
            'x.co': {'risk_level': 'high', 'reason': 'malware_history'},
        }
        
        # Patterns that indicate URL shorteners
        self.shortener_patterns = [
            r'^https?://[^/]{1,15}/[a-zA-Z0-9]{1,10}$',  # Short domain, short path
            r'^https?://[^/]+/[a-zA-Z0-9_-]{4,12}$',     # Typical shortener format
            r'^https?://[^/]+/r/[a-zA-Z0-9]+$',          # Reddit-style
            r'^https?://[^/]+/s/[a-zA-Z0-9]+$',          # S-style shortener
        ]
        
        self.max_redirects = 10
        self.timeout = 15
        self.user_agent = "LinkShield-Bot/1.0 URL-Shortener-Analyzer"
    
    async def analyze_shortener(self, url: str) -> ShortenerAnalysisResult:
        """
        Perform comprehensive analysis of a potential URL shortener.
        
        Args:
            url: URL to analyze
            
        Returns:
            ShortenerAnalysisResult with complete analysis
        """
        start_time = datetime.now()
        
        # Check if URL appears to be a shortener
        is_shortener = self._is_likely_shortener(url)
        
        if not is_shortener:
            return ShortenerAnalysisResult(
                original_url=url,
                final_destination=url,
                is_shortener=False,
                redirect_chain=[],
                total_redirects=0,
                total_response_time=0.0,
                risk_assessment="safe",
                risk_factors=[],
                legitimate_shortener=False,
                analysis_summary="Not a URL shortener"
            )
        
        # Follow redirect chain
        redirect_chain = await self._follow_redirect_chain(url)
        
        if not redirect_chain:
            return ShortenerAnalysisResult(
                original_url=url,
                final_destination=url,
                is_shortener=True,
                redirect_chain=[],
                total_redirects=0,
                total_response_time=0.0,
                risk_assessment="suspicious",
                risk_factors=["unreachable_shortener"],
                legitimate_shortener=False,
                analysis_summary="Shortener appears unreachable or broken"
            )
        
        # Analyze the redirect chain and final destination
        analysis = self._analyze_redirect_chain(url, redirect_chain)
        
        total_time = (datetime.now() - start_time).total_seconds()
        
        return ShortenerAnalysisResult(
            original_url=url,
            final_destination=redirect_chain[-1].url,
            is_shortener=True,
            redirect_chain=redirect_chain,
            total_redirects=len(redirect_chain) - 1,
            total_response_time=sum(r.response_time for r in redirect_chain),
            risk_assessment=analysis['risk_assessment'],
            risk_factors=analysis['risk_factors'],
            legitimate_shortener=analysis['legitimate_shortener'],
            analysis_summary=analysis['summary']
        )
    
    def _is_likely_shortener(self, url: str) -> bool:
        """
        Determine if URL is likely a shortener based on patterns and known domains.
        
        Args:
            url: URL to check
            
        Returns:
            True if likely a shortener
        """
        parsed = urlparse(url.lower())
        domain = parsed.netloc
        
        # Check known shortener domains
        if any(shortener in domain for shortener in self.legitimate_shorteners.keys()):
            return True
        
        if any(shortener in domain for shortener in self.suspicious_shorteners.keys()):
            return True
        
        # Check URL patterns
        for pattern in self.shortener_patterns:
            if re.match(pattern, url):
                return True
        
        # Heuristic checks
        path = parsed.path.strip('/')
        
        # Short domain with short path
        if len(domain) <= 15 and len(path) <= 10 and path.isalnum():
            return True
        
        # Single short path segment
        if '/' not in path and 3 <= len(path) <= 12 and re.match(r'^[a-zA-Z0-9_-]+$', path):
            return True
        
        return False
    
    async def _follow_redirect_chain(self, url: str) -> List[RedirectChain]:
        """
        Follow redirect chain and collect information about each hop.
        
        Args:
            url: Starting URL
            
        Returns:
            List of RedirectChain objects
        """
        chain = []
        current_url = url
        redirect_count = 0
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=aiohttp.TCPConnector(limit=10)
        ) as session:
            
            while redirect_count < self.max_redirects:
                start_time = datetime.now()
                
                try:
                    async with session.get(
                        current_url,
                        headers={'User-Agent': self.user_agent},
                        allow_redirects=False
                    ) as response:
                        
                        response_time = (datetime.now() - start_time).total_seconds()
                        
                        # Collect headers (limited for security)
                        safe_headers = {
                            'content-type': response.headers.get('content-type', ''),
                            'server': response.headers.get('server', ''),
                            'location': response.headers.get('location', ''),
                            'x-frame-options': response.headers.get('x-frame-options', ''),
                            'content-security-policy': response.headers.get('content-security-policy', '')
                        }
                        
                        # Determine if current URL is a shortener
                        is_shortener = self._is_likely_shortener(current_url)
                        
                        # Create redirect chain entry
                        chain_entry = RedirectChain(
                            url=current_url,
                            status_code=response.status,
                            response_time=response_time,
                            headers=safe_headers,
                            is_shortener=is_shortener
                        )
                        
                        chain.append(chain_entry)
                        
                        # Check if this is a redirect
                        if response.status in (301, 302, 303, 307, 308):
                            location = response.headers.get('location')
                            if location:
                                # Handle relative URLs
                                if location.startswith('/'):
                                    parsed_current = urlparse(current_url)
                                    location = f"{parsed_current.scheme}://{parsed_current.netloc}{location}"
                                elif not location.startswith(('http://', 'https://')):
                                    location = urljoin(current_url, location)
                                
                                current_url = location
                                redirect_count += 1
                                continue
                        
                        # Not a redirect, we've reached the final destination
                        break
                        
                except Exception as e:
                    # Add error entry to chain
                    chain.append(RedirectChain(
                        url=current_url,
                        status_code=0,
                        response_time=0.0,
                        headers={'error': str(e)},
                        is_shortener=self._is_likely_shortener(current_url)
                    ))
                    break
        
        return chain
    
    def _analyze_redirect_chain(self, original_url: str, chain: List[RedirectChain]) -> Dict[str, Any]:
        """
        Analyze redirect chain for security risks and legitimacy.
        
        Args:
            original_url: Original shortened URL
            chain: List of RedirectChain objects
            
        Returns:
            Dictionary with analysis results
        """
        if not chain:
            return {
                'risk_assessment': 'suspicious',
                'risk_factors': ['empty_chain'],
                'legitimate_shortener': False,
                'summary': 'Unable to follow redirect chain'
            }
        
        risk_factors = []
        risk_score = 0
        
        # Analyze original shortener legitimacy
        original_domain = urlparse(original_url).netloc.lower()
        legitimate_shortener = False
        
        for known_shortener, info in self.legitimate_shorteners.items():
            if known_shortener in original_domain:
                legitimate_shortener = True
                risk_score -= info['trust_score'] // 10  # Reduce risk for legitimate shorteners
                break
        
        for suspicious_shortener, info in self.suspicious_shorteners.items():
            if suspicious_shortener in original_domain:
                risk_factors.append(f"suspicious_shortener_{info['reason']}")
                risk_score += 30
                break
        
        # Analyze redirect chain length
        redirect_count = len(chain) - 1
        if redirect_count > 5:
            risk_factors.append("excessive_redirects")
            risk_score += 25
        elif redirect_count > 3:
            risk_factors.append("multiple_redirects")
            risk_score += 15
        
        # Analyze redirect patterns
        domains_in_chain = set()
        for entry in chain:
            domain = urlparse(entry.url).netloc.lower()
            domains_in_chain.add(domain)
            
            # Check for errors in chain
            if entry.status_code == 0 or 'error' in entry.headers:
                risk_factors.append("broken_redirect")
                risk_score += 20
            
            # Check for suspicious status codes
            if entry.status_code in (404, 403, 500, 502, 503):
                risk_factors.append("error_status_code")
                risk_score += 15
        
        # Domain hopping analysis
        if len(domains_in_chain) > 3:
            risk_factors.append("domain_hopping")
            risk_score += 20
        
        # Analyze final destination
        if chain:
            final_url = chain[-1].url
            final_domain = urlparse(final_url).netloc.lower()
            
            # Check for suspicious final destination patterns
            if self._is_likely_shortener(final_url):
                risk_factors.append("shortener_to_shortener")
                risk_score += 25
            
            # Check for suspicious TLDs
            high_risk_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc'}
            final_tld = final_domain.split('.')[-1] if '.' in final_domain else ''
            if final_tld in high_risk_tlds:
                risk_factors.append("high_risk_final_tld")
                risk_score += 15
            
            # Check for IP address destinations
            if re.match(r'^\d+\.\d+\.\d+\.\d+', final_domain):
                risk_factors.append("ip_address_destination")
                risk_score += 30
            
            # Check response time (potential honeypot detection)
            total_time = sum(entry.response_time for entry in chain)
            if total_time > 10:
                risk_factors.append("slow_response_time")
                risk_score += 10
        
        # Determine risk assessment
        if risk_score >= 50:
            risk_assessment = "malicious"
        elif risk_score >= 25 or len(risk_factors) >= 3:
            risk_assessment = "suspicious"
        else:
            risk_assessment = "safe"
        
        # Generate summary
        if legitimate_shortener and risk_assessment == "safe":
            summary = f"Legitimate shortener ({original_domain}) redirecting to safe destination"
        elif legitimate_shortener and risk_assessment != "safe":
            summary = f"Legitimate shortener with concerning redirect pattern (risk: {risk_assessment})"
        elif risk_assessment == "malicious":
            summary = "Potentially malicious shortener with high-risk indicators"
        elif risk_assessment == "suspicious":
            summary = "Suspicious shortener requiring caution"
        else:
            summary = "Appears to be a benign URL shortener"
        
        return {
            'risk_assessment': risk_assessment,
            'risk_factors': risk_factors,
            'legitimate_shortener': legitimate_shortener,
            'summary': summary,
            'risk_score': risk_score,
            'domains_in_chain': list(domains_in_chain)
        }
    
    async def get_shortener_info(self, url: str) -> Dict[str, Any]:
        """
        Get basic information about a shortener without following redirects.
        
        Args:
            url: Shortener URL
            
        Returns:
            Dictionary with shortener information
        """
        domain = urlparse(url.lower()).netloc
        
        # Check against known shorteners
        for shortener, info in self.legitimate_shorteners.items():
            if shortener in domain:
                return {
                    'is_known_shortener': True,
                    'legitimacy': 'legitimate',
                    'provider': info['provider'],
                    'trust_score': info['trust_score'],
                    'category': info['category']
                }
        
        for shortener, info in self.suspicious_shorteners.items():
            if shortener in domain:
                return {
                    'is_known_shortener': True,
                    'legitimacy': 'suspicious',
                    'risk_level': info['risk_level'],
                    'reason': info['reason']
                }
        
        # Check if it matches shortener patterns
        if self._is_likely_shortener(url):
            return {
                'is_known_shortener': False,
                'legitimacy': 'unknown',
                'pattern_match': True,
                'recommendation': 'verify_destination'
            }
        
        return {
            'is_known_shortener': False,
            'legitimacy': 'not_shortener',
            'pattern_match': False
        }


    """
    Enhanced shortener analysis method for integration with URLAnalysisService.
    
    Returns:
        Dictionary containing detailed shortener analysis results
    """
    analyzer = URLShortenerAnalyzer()
    
    # Quick check if URL is a shortener
    basic_info = await analyzer.get_shortener_info(url)
    
    if not basic_info.get('pattern_match', False) and not basic_info.get('is_known_shortener', False):
        return {
            'is_shortener': False,
            'analysis_performed': False
        }
    
    # Perform full analysis
    result = await analyzer.analyze_shortener(url)
    
    # Integrate with existing risk factor system
    risk_factors = []
    
    if result.risk_assessment == "malicious":
        risk_factors.extend(["malicious_shortener", "high_risk_destination"])
    elif result.risk_assessment == "suspicious":
        risk_factors.extend(["suspicious_shortener", "redirect_anomaly"])
    elif not result.legitimate_shortener:
        risk_factors.append("unknown_shortener")
    
    risk_factors.extend(result.risk_factors)
    
    return {
        'is_shortener': result.is_shortener,
        'legitimate_shortener': result.legitimate_shortener,
        'final_destination': result.final_destination,
        'redirect_count': result.total_redirects,
        'risk_assessment': result.risk_assessment,
        'risk_factors': risk_factors,
        'analysis_summary': result.analysis_summary,
        'analysis_performed': True,
        'shortener_analysis': result  # Full result object for detailed logging
    }
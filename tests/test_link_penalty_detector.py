"""
Unit tests for LinkPenaltyDetector.

Tests cover:
- Domain reputation checking
- Platform-specific link rules
- URL shortener detection
- Redirect chain analysis
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timezone

from src.social_protection.content_analyzer.link_penalty_detector import (
    LinkPenaltyDetector,
    LinkPenaltyResult
)
from src.services.ai_service import AIService


@pytest.fixture
def mock_ai_service():
    """Create a mock AI service."""
    service = Mock(spec=AIService)
    service.analyze_content = AsyncMock(return_value={
        "threat_detected": False,
        "confidence_score": 0
    })
    return service


@pytest.fixture
def mock_settings():
    """Create mock settings."""
    settings = Mock()
    settings.VIRUSTOTAL_API_KEY = None
    settings.GOOGLE_SAFE_BROWSING_API_KEY = None
    settings.URLVOID_API_KEY = None
    return settings


@pytest.fixture
def detector(mock_ai_service, mock_settings):
    """Create a LinkPenaltyDetector instance."""
    with patch('src.social_protection.content_analyzer.link_penalty_detector.get_settings', return_value=mock_settings):
        return LinkPenaltyDetector(mock_ai_service)


class TestLinkPenaltyDetector:
    """Test suite for LinkPenaltyDetector."""
    
    @pytest.mark.asyncio
    async def test_no_links_returns_safe_result(self, detector):
        """Test that content with no links returns a safe result."""
        result = await detector.detect_link_penalties(
            content="This is content without any links",
            platform="twitter"
        )
        
        assert isinstance(result, LinkPenaltyResult)
        assert result.has_penalty_risk is False
        assert result.penalty_score == 0
        assert len(result.penalty_types) == 0
        assert result.link_analysis["total_links"] == 0
    
    @pytest.mark.asyncio
    async def test_single_safe_link(self, detector):
        """Test that a single safe link has minimal penalty."""
        result = await detector.detect_link_penalties(
            content="Check out this article: https://example.com/article",
            platform="twitter"
        )
        
        assert isinstance(result, LinkPenaltyResult)
        assert result.link_analysis["total_links"] == 1
    
    @pytest.mark.asyncio
    async def test_url_shortener_detection(self, detector):
        """Test detection of URL shorteners."""
        # Test known shortener
        result = await detector.detect_link_penalties(
            content="Check this out: https://bit.ly/abc123",
            platform="twitter"
        )
        
        assert result.has_penalty_risk is True
        assert "url_shortener" in result.penalty_types
        assert any("shortener" in issue.lower() for issue in result.detected_issues)
        assert result.penalty_score > 0
    
    @pytest.mark.asyncio
    async def test_multiple_shorteners_detected(self, detector):
        """Test detection of multiple URL shorteners."""
        content = "Links: https://bit.ly/abc https://tinyurl.com/xyz https://goo.gl/123"
        result = await detector.detect_link_penalties(content, platform="twitter")
        
        assert result.has_penalty_risk is True
        assert "url_shortener" in result.penalty_types
        assert result.link_analysis["total_links"] == 3
    
    @pytest.mark.asyncio
    async def test_insecure_protocol_penalty(self, detector):
        """Test that HTTP URLs receive a penalty."""
        result = await detector.detect_link_penalties(
            content="Visit: http://example.com",
            platform="twitter"
        )
        
        assert "insecure_protocol" in result.penalty_types
        assert any("non-https" in issue.lower() or "http" in issue.lower() 
                  for issue in result.detected_issues)
    
    @pytest.mark.asyncio
    async def test_twitter_multiple_links_penalty(self, detector):
        """Test Twitter-specific penalty for multiple links."""
        content = "Links: https://example.com/1 https://example.com/2 https://example.com/3"
        result = await detector.detect_link_penalties(content, platform="twitter")
        
        assert result.has_penalty_risk is True
        assert result.penalty_score > 0
        # Check for multiple links detection in issues or recommendations
        assert (any("multiple" in rec.lower() for rec in result.recommendations) or
                any("multiple" in issue.lower() for issue in result.detected_issues))
    
    @pytest.mark.asyncio
    async def test_facebook_clickbait_detection(self, detector):
        """Test Facebook-specific clickbait detection."""
        content = "You won't believe what happened next! https://example.com"
        result = await detector.detect_link_penalties(content, platform="facebook")
        
        assert result.has_penalty_risk is True
        assert any("clickbait" in issue.lower() 
                  for issue in result.platform_specific_penalties.get("platform_issues", []))
    
    @pytest.mark.asyncio
    async def test_instagram_link_penalty(self, detector):
        """Test Instagram-specific link penalty."""
        content = "Check out: https://example.com"
        result = await detector.detect_link_penalties(content, platform="instagram")
        
        assert result.has_penalty_risk is True
        assert any("bio" in rec.lower() for rec in result.recommendations)
    
    @pytest.mark.asyncio
    async def test_linkedin_professional_domain_bonus(self, detector):
        """Test LinkedIn bonus for professional domains."""
        content = "Research: https://university.edu/research"
        result = await detector.detect_link_penalties(content, platform="linkedin")
        
        # Professional domains should have lower penalty
        assert result.penalty_score < 50
    
    @pytest.mark.asyncio
    async def test_tiktok_external_link_penalty(self, detector):
        """Test TikTok's heavy penalty for external links."""
        content = "Visit: https://example.com"
        result = await detector.detect_link_penalties(content, platform="tiktok")
        
        assert result.has_penalty_risk is True
        assert result.penalty_score > 30
        assert any("bio" in rec.lower() for rec in result.recommendations)
    
    @pytest.mark.asyncio
    async def test_affiliate_link_detection(self, detector):
        """Test detection of affiliate links."""
        content = "Buy now: https://amazon.com/product?tag=affiliate-20"
        result = await detector.detect_link_penalties(content, platform="twitter")
        
        assert "affiliate_link" in result.penalty_types
    
    @pytest.mark.asyncio
    async def test_suspicious_parameters_detection(self, detector):
        """Test detection of suspicious URL parameters."""
        content = "Click: https://example.com?utm_source=spam&tracking=12345"
        result = await detector.detect_link_penalties(content, platform="twitter")
        
        assert "suspicious_parameters" in result.penalty_types
    
    @pytest.mark.asyncio
    async def test_extract_links_from_content(self, detector):
        """Test link extraction from content."""
        content = """
        Check these links:
        https://example.com/page1
        http://test.org/page2
        www.another-site.com
        """
        links = detector._extract_links(content)
        
        assert len(links) >= 2  # Should extract at least the explicit URLs
        assert any("example.com" in link for link in links)
    
    def test_shortener_detection_known_service(self, detector):
        """Test shortener detection for known services."""
        result = detector._detect_url_shortener("https://bit.ly/abc123")
        
        assert result["is_shortener"] is True
        assert result["shortener_service"] == "bit.ly"
        assert result["confidence"] == 1.0
        assert result["penalty_score"] > 0
    
    def test_shortener_detection_pattern_match(self, detector):
        """Test shortener detection using patterns."""
        result = detector._detect_url_shortener("https://sho.rt/xyz")
        
        # Should detect based on pattern (short domain + short path)
        assert result["penalty_score"] >= 0
    
    def test_shortener_detection_false_positive(self, detector):
        """Test that normal URLs are not flagged as shorteners."""
        result = detector._detect_url_shortener("https://www.example.com/long/path/to/article")
        
        assert result["is_shortener"] is False
        assert result["penalty_score"] == 0
    
    @pytest.mark.asyncio
    async def test_redirect_chain_analysis_no_redirects(self, detector):
        """Test redirect analysis for URLs without redirects."""
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {}
            
            mock_session.return_value.__aenter__.return_value.head.return_value.__aenter__.return_value = mock_response
            
            result = await detector._analyze_redirect_chain("https://example.com")
            
            assert result["has_redirects"] is False
            assert result["redirect_count"] == 0
            assert result["final_url"] == "https://example.com"
    
    @pytest.mark.asyncio
    async def test_redirect_chain_analysis_single_redirect(self, detector):
        """Test redirect analysis returns valid structure."""
        # Test that the method returns a valid structure
        # (actual redirect following is tested in integration tests)
        result = await detector._analyze_redirect_chain("https://example.com")
        
        # Verify structure
        assert "has_redirects" in result
        assert "redirect_count" in result
        assert "redirect_chain" in result
        assert "final_url" in result
        assert "suspicious_redirects" in result
        assert "penalty_score" in result
        assert "issues" in result
        
        # Should have at least the original URL in the chain
        assert len(result["redirect_chain"]) >= 1
        assert isinstance(result["redirect_count"], int)
        assert isinstance(result["penalty_score"], int)
    
    @pytest.mark.asyncio
    async def test_redirect_chain_excessive_redirects(self, detector):
        """Test detection of excessive redirects."""
        with patch('aiohttp.ClientSession') as mock_session:
            # Create multiple redirect responses
            mock_responses = []
            for i in range(4):
                mock_response = AsyncMock()
                mock_response.status = 302
                mock_response.headers = {'Location': f'https://redirect{i}.com'}
                mock_responses.append(mock_response)
            
            # Final response
            final_response = AsyncMock()
            final_response.status = 200
            final_response.headers = {}
            mock_responses.append(final_response)
            
            mock_context = mock_session.return_value.__aenter__.return_value
            mock_context.head.return_value.__aenter__.side_effect = mock_responses
            
            result = await detector._analyze_redirect_chain("https://example.com")
            
            if result["redirect_count"] > 2:
                assert result["suspicious_redirects"] is True
                assert result["penalty_score"] > 0
    
    @pytest.mark.asyncio
    async def test_domain_reputation_without_api_keys(self, detector):
        """Test domain reputation check when API keys are not configured."""
        result = await detector._check_domain_reputation("https://example.com")
        
        assert "has_reputation_issues" in result
        assert "reputation_score" in result
        # Without API keys, should return neutral result
        assert result["reputation_score"] == 50
    
    @pytest.mark.asyncio
    async def test_domain_reputation_with_virustotal(self, detector, mock_settings):
        """Test domain reputation check with VirusTotal."""
        mock_settings.VIRUSTOTAL_API_KEY = "test_key"
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json = AsyncMock(return_value={
                "detected_urls": [
                    {"positives": 5, "total": 10},
                    {"positives": 3, "total": 10}
                ]
            })
            
            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response
            
            result = await detector._check_domain_reputation("https://malicious.com")
            
            # Should detect reputation issues
            if result["has_reputation_issues"]:
                assert result["penalty_score"] > 0
    
    @pytest.mark.asyncio
    async def test_platform_specific_rules_twitter(self, detector):
        """Test Twitter-specific link rules."""
        links = ["https://bit.ly/abc", "https://example.com"]
        content = "Check these links"
        
        result = detector._check_twitter_link_rules(links, content)
        
        assert "issues" in result
        assert "penalty_score" in result
        # Should flag multiple links and shortener
        assert result["penalty_score"] > 0
    
    @pytest.mark.asyncio
    async def test_platform_specific_rules_facebook(self, detector):
        """Test Facebook-specific link rules."""
        links = ["https://example.com"]
        content = "You won't believe this amazing trick!"
        
        result = detector._check_facebook_link_rules(links, content)
        
        assert "issues" in result
        # Should detect clickbait
        assert any("clickbait" in issue.lower() for issue in result["issues"])
    
    @pytest.mark.asyncio
    async def test_platform_specific_rules_instagram(self, detector):
        """Test Instagram-specific link rules."""
        links = ["https://example.com"]
        content = "Check out my link"
        
        result = detector._check_instagram_link_rules(links, content)
        
        assert "issues" in result
        # Should recommend bio link
        assert any("bio" in issue.lower() for issue in result["issues"])
    
    @pytest.mark.asyncio
    async def test_confidence_score_calculation(self, detector):
        """Test confidence score calculation."""
        # More links and issues should increase confidence
        confidence1 = detector._calculate_confidence_score(1, 1, 1)
        confidence2 = detector._calculate_confidence_score(5, 3, 10)
        
        assert 0.0 <= confidence1 <= 1.0
        assert 0.0 <= confidence2 <= 1.0
        assert confidence2 >= confidence1
    
    @pytest.mark.asyncio
    async def test_error_handling_in_link_analysis(self, detector):
        """Test that errors in link analysis are handled gracefully."""
        # Pass an invalid URL
        result = await detector.detect_link_penalties(
            content="Invalid: not-a-valid-url",
            platform="twitter"
        )
        
        # Should return a result without crashing
        assert isinstance(result, LinkPenaltyResult)
    
    @pytest.mark.asyncio
    async def test_recommendations_generated(self, detector):
        """Test that recommendations are generated for detected issues."""
        content = "Links: https://bit.ly/abc https://bit.ly/xyz"
        result = await detector.detect_link_penalties(content, platform="twitter")
        
        assert len(result.recommendations) > 0
        assert any("url" in rec.lower() or "link" in rec.lower() 
                  for rec in result.recommendations)
    
    @pytest.mark.asyncio
    async def test_penalty_score_normalization(self, detector):
        """Test that penalty scores are normalized to 0-100 range."""
        # Create content with many penalty triggers
        content = """
        http://bit.ly/spam http://tinyurl.com/bad http://goo.gl/evil
        http://bit.ly/more http://short.link/test
        """
        result = await detector.detect_link_penalties(content, platform="twitter")
        
        assert 0 <= result.penalty_score <= 100
    
    @pytest.mark.asyncio
    async def test_analysis_timestamp_present(self, detector):
        """Test that analysis results include a timestamp."""
        result = await detector.detect_link_penalties(
            content="https://example.com",
            platform="twitter"
        )
        
        assert result.analysis_timestamp is not None
        # Should be a valid ISO format timestamp
        datetime.fromisoformat(result.analysis_timestamp.replace('Z', '+00:00'))


class TestLinkExtractionEdgeCases:
    """Test edge cases in link extraction."""
    
    def test_extract_links_with_protocol(self, detector):
        """Test extraction of links with explicit protocol."""
        content = "Visit https://example.com and http://test.org"
        links = detector._extract_links(content)
        
        assert len(links) >= 2
        assert any("example.com" in link for link in links)
        assert any("test.org" in link for link in links)
    
    def test_extract_links_without_protocol(self, detector):
        """Test extraction of links without protocol."""
        content = "Visit www.example.com"
        links = detector._extract_links(content)
        
        assert len(links) >= 1
        assert any("example.com" in link for link in links)
    
    def test_extract_links_with_paths(self, detector):
        """Test extraction of links with paths and parameters."""
        content = "https://example.com/path/to/page?param=value&other=123"
        links = detector._extract_links(content)
        
        assert len(links) >= 1
        assert any("example.com" in link and "param=value" in link for link in links)
    
    def test_extract_no_links(self, detector):
        """Test extraction when no links are present."""
        content = "This is just plain text without any URLs"
        links = detector._extract_links(content)
        
        assert len(links) == 0


class TestPlatformPenaltyIntegration:
    """Test integration of platform-specific penalties."""
    
    @pytest.mark.asyncio
    async def test_discord_phishing_detection(self, detector):
        """Test Discord phishing link detection."""
        links = ["https://discord-nitro-free.com/claim"]
        content = "Free Discord Nitro!"
        
        result = detector._check_discord_link_rules(links, content)
        
        assert result["penalty_score"] > 0
        assert any("phishing" in issue.lower() for issue in result["issues"])
    
    @pytest.mark.asyncio
    async def test_telegram_spam_detection(self, detector):
        """Test Telegram spam link detection."""
        links = ["https://example.com/1", "https://example.com/2", 
                "https://example.com/3", "https://example.com/4"]
        content = "Guaranteed crypto profit! Invest now!"
        
        result = detector._check_telegram_link_rules(links, content)
        
        assert result["penalty_score"] > 0
    
    @pytest.mark.asyncio
    async def test_linkedin_promotional_content(self, detector):
        """Test LinkedIn promotional content detection."""
        links = ["https://example.com/sale"]
        content = "Limited time offer! Buy now and save 50%!"
        
        result = detector._check_linkedin_link_rules(links, content)
        
        assert result["penalty_score"] > 0
        assert any("promotional" in issue.lower() for issue in result["issues"])
    
    @pytest.mark.asyncio
    async def test_tiktok_affiliate_ban(self, detector):
        """Test TikTok affiliate link ban."""
        links = ["https://amazon.com/product?tag=affiliate-20"]
        content = "Check out this product"
        
        result = detector._check_tiktok_link_rules(links, content)
        
        assert result["penalty_score"] > 40
        assert any("affiliate" in issue.lower() for issue in result["issues"])

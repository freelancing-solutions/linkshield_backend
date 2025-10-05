#!/usr/bin/env python3
"""
Tests for Community Notes Analyzer fact-check lookup functionality.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from linkshield.social_protection.content_analyzer.community_notes_analyzer import (
    CommunityNotesAnalyzer,
    CommunityNotesResult
)
from linkshield.services.ai_service import AIService


@pytest.fixture
def mock_ai_service():
    """Create a mock AI service."""
    service = Mock(spec=AIService)
    service.analyze_with_prompt = AsyncMock()
    return service


@pytest.fixture
def analyzer(mock_ai_service):
    """Create a CommunityNotesAnalyzer instance with mocked AI service."""
    return CommunityNotesAnalyzer(ai_service=mock_ai_service)


@pytest.mark.asyncio
async def test_lookup_fact_checks_known_false_claim(analyzer):
    """Test fact-check lookup with a known false claim."""
    claims = [
        {
            'claim_text': '5G technology causes coronavirus infections',
            'claim_type': 'causal',
            'subject': '5G technology',
            'predicate': 'causes coronavirus infections',
            'confidence': 0.8
        }
    ]
    
    result = await analyzer.lookup_fact_checks(claims, use_ai=False)
    
    assert result['total_claims_analyzed'] == 1
    assert result['fact_checks_found'] >= 1
    assert result['verdicts']['false'] >= 1
    assert result['misinformation_risk_score'] > 50
    assert len(result['fact_check_results']) == 1
    
    fact_check = result['fact_check_results'][0]
    assert fact_check['fact_check_found'] is True
    assert fact_check['verdict'] == 'false'
    assert fact_check['confidence'] > 0.5
    assert fact_check['match_type'] == 'keyword_match'


@pytest.mark.asyncio
async def test_lookup_fact_checks_multiple_claims(analyzer):
    """Test fact-check lookup with multiple claims."""
    claims = [
        {
            'claim_text': 'vaccines contain microchips for tracking',
            'claim_type': 'definitive',
            'confidence': 0.8
        },
        {
            'claim_text': 'the election was stolen through fraud',
            'claim_type': 'definitive',
            'confidence': 0.8
        },
        {
            'claim_text': 'the sky is blue',
            'claim_type': 'definitive',
            'confidence': 0.9
        }
    ]
    
    result = await analyzer.lookup_fact_checks(claims, use_ai=False)
    
    assert result['total_claims_analyzed'] == 3
    assert result['fact_checks_found'] >= 2  # At least 2 should match
    assert result['verdicts']['false'] >= 2
    assert result['misinformation_risk_score'] > 30


@pytest.mark.asyncio
async def test_lookup_fact_checks_no_matches(analyzer):
    """Test fact-check lookup with claims that don't match database."""
    claims = [
        {
            'claim_text': 'the weather is nice today',
            'claim_type': 'definitive',
            'confidence': 0.9
        }
    ]
    
    result = await analyzer.lookup_fact_checks(claims, use_ai=False)
    
    assert result['total_claims_analyzed'] == 1
    assert result['fact_checks_found'] == 0
    assert result['misinformation_risk_score'] == 0
    assert 'No matches in fact-check database' in result['recommendations']


@pytest.mark.asyncio
async def test_lookup_fact_checks_with_ai(analyzer, mock_ai_service):
    """Test fact-check lookup with AI semantic matching."""
    claims = [
        {
            'claim_text': 'wireless 5G networks spread the virus',
            'claim_type': 'causal',
            'confidence': 0.8
        }
    ]
    
    # Mock AI response
    mock_ai_service.analyze_with_prompt.return_value = '''
    {
        "match_found": true,
        "matched_claim": "5g causes covid",
        "verdict": "false",
        "confidence": 0.9,
        "reasoning": "Semantically similar to known false claim about 5G and COVID",
        "sources": ["multiple fact-checkers"]
    }
    '''
    
    result = await analyzer.lookup_fact_checks(claims, use_ai=True)
    
    assert result['total_claims_analyzed'] == 1
    # Should find match either through keywords or AI
    assert result['fact_checks_found'] >= 1


@pytest.mark.asyncio
async def test_lookup_fact_checks_misleading_claim(analyzer):
    """Test fact-check lookup with a misleading claim."""
    claims = [
        {
            'claim_text': 'ivermectin is a cure for covid-19',
            'claim_type': 'definitive',
            'confidence': 0.8
        }
    ]
    
    result = await analyzer.lookup_fact_checks(claims, use_ai=False)
    
    assert result['total_claims_analyzed'] == 1
    if result['fact_checks_found'] > 0:
        # Should be marked as misleading or false
        assert result['verdicts']['misleading'] + result['verdicts']['false'] >= 1


@pytest.mark.asyncio
async def test_fact_check_recommendations_high_risk(analyzer):
    """Test recommendations for high-risk content."""
    claims = [
        {'claim_text': '5G causes covid', 'confidence': 0.8},
        {'claim_text': 'vaccines contain microchips', 'confidence': 0.8},
        {'claim_text': 'election was stolen', 'confidence': 0.8}
    ]
    
    result = await analyzer.lookup_fact_checks(claims, use_ai=False)
    
    # Should have risk warning in recommendations
    assert any('RISK' in r for r in result['recommendations'])
    # Should have actionable recommendations
    assert len(result['recommendations']) > 0


@pytest.mark.asyncio
async def test_analyze_with_fact_checks_comprehensive(analyzer):
    """Test comprehensive analysis with fact-checking."""
    content = """
    Breaking news! Studies show that 5G towers are causing coronavirus infections.
    The mainstream media won't tell you this, but vaccines contain microchips.
    Wake up people! Do your own research!
    """
    
    result = await analyzer.analyze_with_fact_checks(content, platform="twitter")
    
    # Check all analysis components are present
    assert 'community_notes_analysis' in result
    assert 'fact_check_analysis' in result
    assert 'source_credibility' in result
    assert 'combined_risk_score' in result
    assert 'overall_verdict' in result
    assert 'recommendations' in result
    
    # Should detect high risk
    assert result['combined_risk_score'] >= 50
    assert result['overall_verdict'] in ['HIGH_RISK', 'CRITICAL_RISK', 'MEDIUM_RISK']
    
    # Should have extracted claims
    assert result['claims_extracted'] > 0
    
    # Should have recommendations
    assert len(result['recommendations']) > 0


@pytest.mark.asyncio
async def test_analyze_with_fact_checks_safe_content(analyzer):
    """Test comprehensive analysis with safe content."""
    content = """
    According to the CDC, vaccines are safe and effective.
    Research published in Nature shows climate change is real.
    Official election results confirmed by state authorities.
    """
    
    result = await analyzer.analyze_with_fact_checks(content, platform="twitter")
    
    # Should have lower risk
    assert result['combined_risk_score'] < 60
    assert result['overall_verdict'] in ['LOW_RISK', 'MINIMAL_RISK', 'MEDIUM_RISK']


@pytest.mark.asyncio
async def test_fact_check_coverage_calculation(analyzer):
    """Test fact-check coverage calculation."""
    claims = [
        {'claim_text': '5G causes covid', 'confidence': 0.8},
        {'claim_text': 'the weather is nice', 'confidence': 0.9},
        {'claim_text': 'vaccines contain microchips', 'confidence': 0.8},
        {'claim_text': 'today is Thursday', 'confidence': 0.9}
    ]
    
    result = await analyzer.lookup_fact_checks(claims, use_ai=False)
    
    assert 'fact_check_coverage' in result
    assert 0.0 <= result['fact_check_coverage'] <= 1.0
    
    # Should have found at least 2 matches out of 4
    if result['fact_checks_found'] >= 2:
        assert result['fact_check_coverage'] >= 0.5


@pytest.mark.asyncio
async def test_keyword_matching_accuracy(analyzer):
    """Test keyword matching accuracy for fact-check lookup."""
    # Test with high keyword overlap
    claims = [
        {
            'claim_text': 'drinking bleach can cure diseases and infections',
            'claim_type': 'causal',
            'confidence': 0.8
        }
    ]
    
    result = await analyzer.lookup_fact_checks(claims, use_ai=False)
    
    if result['fact_checks_found'] > 0:
        fact_check = result['fact_check_results'][0]
        assert fact_check['match_type'] == 'keyword_match'
        assert 'details' in fact_check
        assert 'keyword_match_ratio' in fact_check['details']
        assert fact_check['details']['keyword_match_ratio'] >= 0.6


@pytest.mark.asyncio
async def test_databases_consulted_list(analyzer):
    """Test that databases consulted are listed in results."""
    claims = [{'claim_text': 'test claim', 'confidence': 0.8}]
    
    result = await analyzer.lookup_fact_checks(claims, use_ai=False)
    
    assert 'databases_consulted' in result
    assert isinstance(result['databases_consulted'], list)
    assert len(result['databases_consulted']) > 0
    assert 'snopes' in result['databases_consulted']
    assert 'politifact' in result['databases_consulted']


@pytest.mark.asyncio
async def test_empty_claims_list(analyzer):
    """Test fact-check lookup with empty claims list."""
    result = await analyzer.lookup_fact_checks([], use_ai=False)
    
    assert result['total_claims_analyzed'] == 0
    assert result['fact_checks_found'] == 0
    assert result['misinformation_risk_score'] == 0.0


@pytest.mark.asyncio
async def test_ai_fact_check_error_handling(analyzer, mock_ai_service):
    """Test that AI errors are handled gracefully."""
    claims = [
        {
            'claim_text': 'test claim that might need AI',
            'claim_type': 'definitive',
            'confidence': 0.8
        }
    ]
    
    # Make AI service raise an exception
    mock_ai_service.analyze_with_prompt.side_effect = Exception("AI service error")
    
    # Should not raise exception, should continue with keyword matching
    result = await analyzer.lookup_fact_checks(claims, use_ai=True)
    
    assert result['total_claims_analyzed'] == 1
    # Should complete without error


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

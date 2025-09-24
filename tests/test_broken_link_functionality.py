"""
Comprehensive tests for broken link functionality.

This module tests the broken link scanning feature including:
- BrokenLinkStatus, BrokenLinkDetail, and BrokenLinkScanResult models
- Integration with AnalysisResults
- URLAnalysisService broken link scanning
- URLCheckController broken link retrieval
"""

import pytest
import pytest_asyncio
import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import Mock, AsyncMock, patch
import json
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.models.analysis_results import (
    BrokenLinkStatus, BrokenLinkDetail, BrokenLinkScanResult, 
    AnalysisResults, ProviderScanResult
)
from src.models.url_check import ThreatLevel
from src.models.url_check import ScanType
from src.services.url_analysis_service import URLAnalysisService
from src.controllers.url_check_controller import URLCheckController


class TestBrokenLinkModels:
    """Test broken link data models."""
    
    def test_broken_link_status_enum(self):
        """Test BrokenLinkStatus enum values."""
        assert BrokenLinkStatus.WORKING == "working"
        assert BrokenLinkStatus.BROKEN == "broken"
        assert BrokenLinkStatus.TIMEOUT == "timeout"
        assert BrokenLinkStatus.REDIRECT == "redirect"
        assert BrokenLinkStatus.UNKNOWN == "unknown"
    
    def test_broken_link_detail_creation(self):
        """Test BrokenLinkDetail model creation."""
        detail = BrokenLinkDetail(
            url="https://example.com/broken",
            status_code=404,
            status=BrokenLinkStatus.BROKEN,
            error_message="Not Found",
            response_time=1.5,
            redirect_url=None,
            depth_level=1
        )
        
        assert detail.url == "https://example.com/broken"
        assert detail.status_code == 404
        assert detail.status == BrokenLinkStatus.BROKEN
        assert detail.error_message == "Not Found"
        assert detail.response_time == 1.5
        assert detail.redirect_url is None
        assert detail.depth_level == 1
    
    def test_broken_link_detail_to_dict(self):
        """Test BrokenLinkDetail to_dict method."""
        detail = BrokenLinkDetail(
            url="https://example.com/test",
            status_code=200,
            status=BrokenLinkStatus.WORKING,
            error_message=None,
            response_time=0.8,
            redirect_url="https://example.com/redirected",
            depth_level=2
        )
        
        result = detail.to_dict()
        expected = {
            "url": "https://example.com/test",
            "status_code": 200,
            "status": "working",
            "error_message": None,
            "response_time": 0.8,
            "redirect_url": "https://example.com/redirected",
            "depth_level": 2
        }
        
        assert result == expected
    
    def test_broken_link_detail_from_dict(self):
        """Test BrokenLinkDetail from_dict method."""
        data = {
            "url": "https://example.com/test",
            "status_code": 500,
            "status": "broken",
            "error_message": "Internal Server Error",
            "response_time": 2.1,
            "redirect_url": None,
            "depth_level": 1
        }
        
        detail = BrokenLinkDetail.from_dict(data)
        
        assert detail.url == "https://example.com/test"
        assert detail.status_code == 500
        assert detail.status == BrokenLinkStatus.BROKEN
        assert detail.error_message == "Internal Server Error"
        assert detail.response_time == 2.1
        assert detail.redirect_url is None
        assert detail.depth_level == 1
    
    def test_broken_link_scan_result_creation(self):
        """Test BrokenLinkScanResult model creation."""
        broken_links = [
            BrokenLinkDetail(
                url="https://example.com/broken1",
                status_code=404,
                status=BrokenLinkStatus.BROKEN,
                error_message="Not Found",
                response_time=1.0,
                redirect_url=None,
                depth_level=1
            ),
            BrokenLinkDetail(
                url="https://example.com/broken2",
                status_code=500,
                status=BrokenLinkStatus.BROKEN,
                error_message="Server Error",
                response_time=2.0,
                redirect_url=None,
                depth_level=2
            )
        ]
        
        scan_result = BrokenLinkScanResult(
            total_links_found=10,
            total_links_checked=10,
            broken_links_count=2,
            working_links_count=8,
            scan_depth_used=2,
            max_links_used=50,
            broken_links=broken_links,
            scan_duration=15.5
        )
        
        assert scan_result.total_links_found == 10
        assert scan_result.total_links_checked == 10
        assert scan_result.broken_links_count == 2
        assert scan_result.working_links_count == 8
        assert len(scan_result.broken_links) == 2
        assert scan_result.scan_depth_used == 2
        assert scan_result.max_links_used == 50
        assert scan_result.scan_duration == 15.5
    
    def test_broken_link_scan_result_to_dict(self):
        """Test BrokenLinkScanResult to_dict method."""
        broken_links = [
            BrokenLinkDetail(
                url="https://example.com/broken",
                status_code=404,
                status=BrokenLinkStatus.BROKEN,
                error_message="Not Found",
                response_time=1.0,
                redirect_url=None,
                depth_level=1
            )
        ]
        
        scan_result = BrokenLinkScanResult(
            total_links_found=5,
            total_links_checked=5,
            broken_links_count=1,
            working_links_count=4,
            scan_depth_used=1,
            max_links_used=25,
            broken_links=broken_links,
            scan_duration=8.2
        )
        
        result = scan_result.to_dict()
        
        assert result["total_links_found"] == 5
        assert result["total_links_checked"] == 5
        assert result["broken_links_count"] == 1
        assert result["working_links_count"] == 4
        assert result["scan_depth_used"] == 1
        assert result["max_links_used"] == 25
        assert len(result["broken_links"]) == 1
        assert result["broken_links"][0]["url"] == "https://example.com/broken"
        assert result["scan_duration"] == 8.2
    
    def test_broken_link_scan_result_from_dict(self):
        """Test BrokenLinkScanResult from_dict method."""
        data = {
            "total_links_found": 8,
            "broken_links": [
                {
                    "url": "https://example.com/test",
                    "status_code": 404,
                    "status": "broken",
                    "error_message": "Not Found",
                    "response_time": 1.5,
                    "redirect_url": None,
                    "depth_level": 1
                }
            ],
            "scan_depth": 2,
            "max_links_scanned": 30,
            "scan_duration": 12.0
        }
        
        scan_result = BrokenLinkScanResult.from_dict(data)
        
        assert scan_result.total_links_found == 8
        assert len(scan_result.broken_links) == 1
        assert scan_result.broken_links[0].url == "https://example.com/test"
        assert scan_result.scan_depth == 2
        assert scan_result.max_links_scanned == 30
        assert scan_result.scan_duration == 12.0


class TestAnalysisResultsIntegration:
    """Test integration of broken link data with AnalysisResults."""
    
    def test_analysis_results_with_broken_link_scan(self):
        """Test AnalysisResults with broken link scan data."""
        broken_links = [
            BrokenLinkDetail(
                url="https://example.com/broken",
                status_code=404,
                status=BrokenLinkStatus.BROKEN,
                error_message="Not Found",
                response_time=1.0,
                redirect_url=None,
                depth_level=1
            )
        ]
        
        broken_link_scan = BrokenLinkScanResult(
            total_links_found=10,
            broken_links=broken_links,
            scan_depth=2,
            max_links_scanned=50,
            scan_duration=15.5
        )
        
        analysis_results = AnalysisResults(
            threat_level=ThreatLevel.SAFE,
            confidence_score=85.0,
            scan_results=[],
            reputation_data=None,
            broken_link_scan=broken_link_scan
        )
        
        assert analysis_results.broken_link_scan is not None
        assert analysis_results.has_broken_links() is True
        assert analysis_results.get_broken_links_count() == 1
    
    def test_analysis_results_without_broken_link_scan(self):
        """Test AnalysisResults without broken link scan data."""
        analysis_results = AnalysisResults(
            threat_level=ThreatLevel.SAFE,
            confidence_score=85.0,
            scan_results=[],
            reputation_data=None
        )
        
        assert analysis_results.broken_link_scan is None
        assert analysis_results.has_broken_links() is False
        assert analysis_results.get_broken_links_count() == 0
    
    def test_analysis_results_to_dict_with_broken_links(self):
        """Test AnalysisResults to_dict with broken link data."""
        broken_links = [
            BrokenLinkDetail(
                url="https://example.com/broken",
                status_code=404,
                status=BrokenLinkStatus.BROKEN,
                error_message="Not Found",
                response_time=1.0,
                redirect_url=None,
                depth_level=1
            )
        ]
        
        broken_link_scan = BrokenLinkScanResult(
            total_links_found=5,
            broken_links=broken_links,
            scan_depth=1,
            max_links_scanned=25,
            scan_duration=8.2
        )
        
        analysis_results = AnalysisResults(
            threat_level=ThreatLevel.SAFE,
            confidence_score=90.0,
            scan_results=[],
            reputation_data=None,
            broken_link_scan=broken_link_scan
        )
        
        result_dict = analysis_results.to_dict()
        
        assert "broken_link_scan" in result_dict
        assert result_dict["broken_link_scan"]["total_links_found"] == 5
        assert len(result_dict["broken_link_scan"]["broken_links"]) == 1
    
    def test_analysis_results_from_dict_with_broken_links(self):
        """Test AnalysisResults from_dict with broken link data."""
        data = {
            "threat_level": "SAFE",
            "confidence_score": 88.0,
            "scan_results": [],
            "reputation_data": None,
            "broken_link_scan": {
                "total_links_found": 7,
                "broken_links": [
                    {
                        "url": "https://example.com/test",
                        "status_code": 500,
                        "status": "broken",
                        "error_message": "Server Error",
                        "response_time": 2.0,
                        "redirect_url": None,
                        "depth_level": 1
                    }
                ],
                "scan_depth": 2,
                "max_links_scanned": 40,
                "scan_duration": 10.5
            }
        }
        
        analysis_results = AnalysisResults.from_dict(data)
        
        assert analysis_results.broken_link_scan is not None
        assert analysis_results.broken_link_scan.total_links_found == 7
        assert len(analysis_results.broken_link_scan.broken_links) == 1
        assert analysis_results.has_broken_links() is True
        assert analysis_results.get_broken_links_count() == 1


class TestURLAnalysisServiceBrokenLinks:
    """Test broken link functionality in URLAnalysisService."""
    
    @pytest.fixture
    def mock_ai_service(self):
        """Mock AI service."""
        return Mock()
    
    @pytest.fixture
    def mock_security_service(self):
        """Mock security service."""
        return Mock()
    
    @pytest.fixture
    def url_analysis_service(self, mock_ai_service, mock_security_service):
        """Create URLAnalysisService instance with mocked dependencies."""
        return URLAnalysisService(mock_ai_service, mock_security_service)
    
    @patch('aiohttp.ClientSession.get')
    @pytest.mark.asyncio
    async def test_scan_broken_links_with_broken_links(self, mock_get, url_analysis_service):
        """Test broken link scanning with broken links found."""
        # Mock the main page response
        mock_main_response = Mock()
        mock_main_response.status = 200
        mock_main_response.text = AsyncMock(return_value='''
            <html>
                <body>
                    <a href="https://example.com/working">Working Link</a>
                    <a href="https://example.com/broken">Broken Link</a>
                    <a href="https://example.com/timeout">Timeout Link</a>
                </body>
            </html>
        ''')
        
        # Mock individual link responses
        mock_working_response = Mock()
        mock_working_response.status = 200
        
        mock_broken_response = Mock()
        mock_broken_response.status = 404
        
        # Configure mock to return different responses based on URL
        async def mock_get_side_effect(url, **kwargs):
            if "working" in str(url):
                return mock_working_response
            elif "broken" in str(url):
                return mock_broken_response
            elif "timeout" in str(url):
                raise asyncio.TimeoutError("Request timeout")
            else:
                return mock_main_response
        
        mock_get.side_effect = mock_get_side_effect
        
        # Test the broken link scanning
        result = await url_analysis_service._scan_broken_links(
            "https://example.com", 
            scan_depth=1, 
            max_links=10
        )
        
        assert isinstance(result, BrokenLinkScanResult)
        assert result.total_links_found == 3
        assert len(result.broken_links) >= 1  # At least the 404 link should be detected
        assert result.scan_depth == 1
        assert result.max_links_scanned == 10
        assert result.scan_duration > 0
    
    @pytest.mark.asyncio
    @patch('aiohttp.ClientSession.get')
    async def test_scan_broken_links_no_broken_links(self, mock_get, url_analysis_service):
        """Test broken link scanning with no broken links."""
        # Mock responses - all working
        mock_main_response = Mock()
        mock_main_response.status = 200
        mock_main_response.text = AsyncMock(return_value='''
            <html>
                <body>
                    <a href="https://example.com/link1">Link 1</a>
                    <a href="https://example.com/link2">Link 2</a>
                </body>
            </html>
        ''')
        
        mock_working_response = Mock()
        mock_working_response.status = 200
        
        mock_get.return_value = mock_working_response
        
        # First call returns main page, subsequent calls return working responses
        mock_get.side_effect = [mock_main_response, mock_working_response, mock_working_response]
        
        result = await url_analysis_service._scan_broken_links(
            "https://example.com", 
            scan_depth=1, 
            max_links=10
        )
        
        assert isinstance(result, BrokenLinkScanResult)
        assert result.total_links_found == 2
        assert result.total_links_checked == 2
        assert result.broken_links_count == 0
        assert result.working_links_count == 2
        assert len(result.broken_links) == 0
        assert result.scan_depth_used == 1
    
    @pytest.mark.asyncio
    @patch('src.services.url_analysis_service.URLAnalysisService._scan_broken_links')
    async def test_analyze_url_with_broken_links_scan_type(self, mock_scan_broken_links, url_analysis_service):
        """Test analyze_url method includes broken link scanning when BROKEN_LINKS scan type is specified."""
        with patch.object(url_analysis_service, '_perform_comprehensive_analysis') as mock_analysis:
            mock_analysis.return_value = AnalysisResults(
                threat_level=ThreatLevel.SAFE,
                confidence_score=85.0,
                scan_results=[],
                reputation_data=None
            )
            
            result = await url_analysis_service.analyze_url(
                url="https://example.com",
                scan_types=[ScanType.BROKEN_LINKS],
                scan_depth=2,
                max_links=50
            )
            
            # Verify that _perform_comprehensive_analysis was called with broken links parameters
            mock_analysis.assert_called_once()
            call_args = mock_analysis.call_args
            assert ScanType.BROKEN_LINKS in call_args[1]['scan_types']
            assert call_args[1]['scan_depth'] == 2
            assert call_args[1]['max_links'] == 50


class TestURLCheckControllerBrokenLinks:
    """Test broken link functionality in URLCheckController."""
    
    @pytest.fixture
    def mock_controller_dependencies(self):
        """Mock controller dependencies."""
        return {
            'url_analysis_service': Mock(),
            'user_service': Mock(),
            'auth_service': Mock(),
            'rate_limiter': Mock(),
            'logger': Mock()
        }
    
    @pytest.fixture
    def mock_url_check_controller(self, mock_controller_dependencies):
        """Create URLCheckController with mocked dependencies."""
        with patch('src.controllers.url_check_controller.URLCheckController.__init__', return_value=None):
            controller = URLCheckController.__new__(URLCheckController)
            for attr, mock_obj in mock_controller_dependencies.items():
                setattr(controller, attr, mock_obj)
            return controller
    
    @pytest.mark.asyncio
    async def test_get_broken_links_success(self, mock_url_check_controller):
        """Test successful retrieval of broken links."""
        # Mock URL check with broken link data
        mock_url_check = Mock()
        mock_url_check.analysis_results = json.dumps({
            "broken_link_scan": {
                "total_links_found": 5,
                "broken_links": [
                    {
                        "url": "https://example.com/broken",
                        "status_code": 404,
                        "status": "broken",
                        "error_message": "Not Found",
                        "response_time": 1.5,
                        "redirect_url": None,
                        "depth_level": 1
                    }
                ],
                "scan_depth": 2,
                "max_links_scanned": 25,
                "scan_duration": 10.0
            }
        })
        
        # Mock the get_url_check method
        with patch.object(mock_url_check_controller, 'get_url_check', return_value=mock_url_check):
            result = await mock_url_check_controller.get_broken_links(
                check_id=uuid.uuid4(),
                user=None
            )
            
            assert len(result) == 1
            assert result[0]["url"] == "https://example.com/broken"
            assert result[0]["status_code"] == 404
            assert result[0]["status"] == "broken"
    
    @pytest.mark.asyncio
    async def test_get_broken_links_no_broken_link_data(self, mock_url_check_controller):
        """Test retrieval when no broken link data exists."""
        # Mock URL check without broken link data
        mock_url_check = Mock()
        mock_url_check.analysis_results = json.dumps({
            "threat_level": "SAFE",
            "confidence_score": 85.0
        })
        
        with patch.object(mock_url_check_controller, 'get_url_check', return_value=mock_url_check):
            result = await mock_url_check_controller.get_broken_links(
                check_id=uuid.uuid4(),
                user=None
            )
            
            assert result == []
    
    @pytest.mark.asyncio
    async def test_get_broken_links_invalid_json(self, mock_url_check_controller):
        """Test handling of invalid JSON in analysis results."""
        # Mock URL check with invalid JSON
        mock_url_check = Mock()
        mock_url_check.analysis_results = "invalid json"
        
        with patch.object(mock_url_check_controller, 'get_url_check', return_value=mock_url_check):
            result = await mock_url_check_controller.get_broken_links(
                check_id=uuid.uuid4(),
                user=None
            )
            
            assert result == []


if __name__ == "__main__":
    pytest.main([__file__])
"""
Performance tests for social protection functionality.

This module tests the performance characteristics of social protection operations,
including scanning throughput, analysis response times, concurrent processing,
memory usage, and scalability under various load conditions.
"""

import pytest
import asyncio
import time
import uuid
import statistics
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from concurrent.futures import ThreadPoolExecutor, as_completed
from fastapi.testclient import TestClient

from linkshield.app import app
from linkshield.models.user import User
from linkshield.social_protection.data_models import (
    ProfileScanRequest,
    ContentRiskAssessment,
    ExtensionDataRequest,
    RealTimeAssessmentRequest,
    RiskLevel,
    PlatformType,
    ContentType,
    ScanStatus
)


class TestSocialProtectionPerformance:
    """Performance test suite for social protection operations."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(create_app())

    @pytest.fixture
    def mock_user_token(self):
        """Mock JWT token for authenticated requests."""
        return "Bearer mock_jwt_token_performance_test"

    @pytest.fixture
    def mock_user_id(self):
        """Mock user ID."""
        return uuid.uuid4()

    @pytest.fixture
    def mock_project_id(self):
        """Mock project ID."""
        return uuid.uuid4()

    @pytest.fixture
    def performance_scan_requests(self, mock_user_id, mock_project_id):
        """Generate multiple scan requests for performance testing."""
        platforms = [PlatformType.TWITTER, PlatformType.FACEBOOK, PlatformType.INSTAGRAM, PlatformType.LINKEDIN]
        scan_depths = ["basic", "detailed", "comprehensive"]
        
        requests = []
        for i in range(100):  # Generate 100 test requests
            platform = platforms[i % len(platforms)]
            depth = scan_depths[i % len(scan_depths)]
            
            request = ProfileScanRequest(
                user_id=mock_user_id,
                project_id=mock_project_id,
                platform=platform,
                profile_url=f"https://{platform.value}.com/user_{i}",
                scan_depth=depth,
                priority="normal"
            )
            requests.append(request)
        
        return requests

    @pytest.fixture
    def performance_assessment_requests(self, mock_user_id, mock_project_id):
        """Generate multiple assessment requests for performance testing."""
        content_types = [ContentType.TEXT, ContentType.IMAGE, ContentType.VIDEO, ContentType.LINK]
        
        requests = []
        for i in range(200):  # Generate 200 test requests
            content_type = content_types[i % len(content_types)]
            
            request = RealTimeAssessmentRequest(
                user_id=mock_user_id,
                project_id=mock_project_id,
                content_type=content_type,
                content_data=f"Sample content data for assessment {i}",
                source_url=f"https://example.com/content_{i}",
                context={"platform": "twitter", "user_followers": 1000 + i}
            )
            requests.append(request)
        
        return requests

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.social_protection.services.social_scan_service.SocialScanService')
    def test_profile_scan_throughput(
        self, mock_scan_service, mock_get_user, client, mock_user_token, 
        mock_user_id, performance_scan_requests
    ):
        """Test profile scanning throughput under load."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock scan service with realistic response times
        mock_service = AsyncMock()
        
        async def mock_initiate_scan(request):
            # Simulate processing time (50-200ms)
            await asyncio.sleep(0.05 + (hash(str(request.profile_url)) % 150) / 1000)
            return MagicMock(
                id=uuid.uuid4(),
                status=ScanStatus.QUEUED,
                estimated_completion=datetime.utcnow() + timedelta(minutes=5)
            )
        
        mock_service.initiate_profile_scan = mock_initiate_scan
        mock_scan_service.return_value = mock_service

        # Performance test parameters
        batch_size = 10
        num_batches = 10
        response_times = []
        
        # Test throughput in batches
        start_time = time.time()
        
        for batch_idx in range(num_batches):
            batch_start = time.time()
            batch_requests = performance_scan_requests[batch_idx * batch_size:(batch_idx + 1) * batch_size]
            
            # Process batch concurrently
            batch_responses = []
            for request in batch_requests:
                request_start = time.time()
                
                response = client.post(
                    "/social-protection/scan/initiate",
                    json={
                        "platform": request.platform.value,
                        "profile_url": request.profile_url,
                        "scan_depth": request.scan_depth,
                        "priority": request.priority
                    },
                    headers={"Authorization": mock_user_token}
                )
                
                request_end = time.time()
                response_times.append(request_end - request_start)
                batch_responses.append(response)
            
            batch_end = time.time()
            batch_time = batch_end - batch_start
            
            # Verify all requests in batch succeeded
            for response in batch_responses:
                assert response.status_code == 200
            
            # Log batch performance
            print(f"Batch {batch_idx + 1}: {batch_size} requests in {batch_time:.2f}s "
                  f"({batch_size / batch_time:.1f} req/s)")
        
        end_time = time.time()
        total_time = end_time - start_time
        total_requests = num_batches * batch_size
        
        # Performance assertions
        throughput = total_requests / total_time
        avg_response_time = statistics.mean(response_times)
        p95_response_time = statistics.quantiles(response_times, n=20)[18]  # 95th percentile
        
        print(f"\nProfile Scan Performance Results:")
        print(f"Total requests: {total_requests}")
        print(f"Total time: {total_time:.2f}s")
        print(f"Throughput: {throughput:.1f} req/s")
        print(f"Average response time: {avg_response_time:.3f}s")
        print(f"95th percentile response time: {p95_response_time:.3f}s")
        
        # Performance requirements
        assert throughput >= 10.0, f"Throughput {throughput:.1f} req/s below minimum 10 req/s"
        assert avg_response_time <= 1.0, f"Average response time {avg_response_time:.3f}s exceeds 1s limit"
        assert p95_response_time <= 2.0, f"95th percentile {p95_response_time:.3f}s exceeds 2s limit"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.social_protection.services.extension_data_processor.ExtensionDataProcessor')
    def test_content_assessment_latency(
        self, mock_processor, mock_get_user, client, mock_user_token, 
        mock_user_id, performance_assessment_requests
    ):
        """Test content assessment latency for real-time processing."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock processor with realistic response times
        mock_proc = AsyncMock()
        
        async def mock_process_request(request):
            # Simulate AI processing time (10-100ms)
            processing_time = 0.01 + (hash(str(request.content_data)) % 90) / 1000
            await asyncio.sleep(processing_time)
            
            return MagicMock(
                id=uuid.uuid4(),
                risk_level=RiskLevel.LOW,
                confidence_score=0.85,
                processing_time_ms=int(processing_time * 1000),
                risk_factors=[],
                recommendations=["Content appears safe"]
            )
        
        mock_proc.process_extension_request = mock_process_request
        mock_processor.return_value = mock_proc

        # Test real-time assessment latency
        latencies = []
        num_requests = 50
        
        for i in range(num_requests):
            request = performance_assessment_requests[i]
            
            start_time = time.time()
            
            response = client.post(
                "/social-protection/extension/process",
                json={
                    "content_type": request.content_type.value,
                    "content_data": request.content_data,
                    "source_url": request.source_url,
                    "context": request.context
                },
                headers={"Authorization": mock_user_token}
            )
            
            end_time = time.time()
            latency = (end_time - start_time) * 1000  # Convert to milliseconds
            latencies.append(latency)
            
            assert response.status_code == 200
        
        # Latency analysis
        avg_latency = statistics.mean(latencies)
        p50_latency = statistics.median(latencies)
        p95_latency = statistics.quantiles(latencies, n=20)[18]  # 95th percentile
        p99_latency = statistics.quantiles(latencies, n=100)[98]  # 99th percentile
        max_latency = max(latencies)
        
        print(f"\nContent Assessment Latency Results:")
        print(f"Requests processed: {num_requests}")
        print(f"Average latency: {avg_latency:.1f}ms")
        print(f"Median latency: {p50_latency:.1f}ms")
        print(f"95th percentile: {p95_latency:.1f}ms")
        print(f"99th percentile: {p99_latency:.1f}ms")
        print(f"Maximum latency: {max_latency:.1f}ms")
        
        # Real-time processing requirements
        assert avg_latency <= 200.0, f"Average latency {avg_latency:.1f}ms exceeds 200ms limit"
        assert p95_latency <= 500.0, f"95th percentile {p95_latency:.1f}ms exceeds 500ms limit"
        assert p99_latency <= 1000.0, f"99th percentile {p99_latency:.1f}ms exceeds 1s limit"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.social_protection.services.social_scan_service.SocialScanService')
    def test_concurrent_scan_processing(
        self, mock_scan_service, mock_get_user, client, mock_user_token, 
        mock_user_id, performance_scan_requests
    ):
        """Test concurrent scan processing capabilities."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock scan service
        mock_service = AsyncMock()
        
        async def mock_initiate_scan(request):
            # Simulate variable processing time
            await asyncio.sleep(0.1 + (hash(str(request.profile_url)) % 100) / 1000)
            return MagicMock(
                id=uuid.uuid4(),
                status=ScanStatus.QUEUED,
                estimated_completion=datetime.utcnow() + timedelta(minutes=5)
            )
        
        mock_service.initiate_profile_scan = mock_initiate_scan
        mock_scan_service.return_value = mock_service

        # Test different concurrency levels
        concurrency_levels = [1, 5, 10, 20]
        num_requests_per_level = 20
        
        results = {}
        
        for concurrency in concurrency_levels:
            print(f"\nTesting concurrency level: {concurrency}")
            
            requests = performance_scan_requests[:num_requests_per_level]
            start_time = time.time()
            
            # Process requests with specified concurrency
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                def make_request(request):
                    return client.post(
                        "/social-protection/scan/initiate",
                        json={
                            "platform": request.platform.value,
                            "profile_url": request.profile_url,
                            "scan_depth": request.scan_depth,
                            "priority": request.priority
                        },
                        headers={"Authorization": mock_user_token}
                    )
                
                # Submit all requests
                futures = [executor.submit(make_request, req) for req in requests]
                
                # Collect results
                responses = []
                for future in as_completed(futures):
                    response = future.result()
                    responses.append(response)
            
            end_time = time.time()
            total_time = end_time - start_time
            throughput = num_requests_per_level / total_time
            
            # Verify all requests succeeded
            success_count = sum(1 for r in responses if r.status_code == 200)
            success_rate = success_count / num_requests_per_level
            
            results[concurrency] = {
                "total_time": total_time,
                "throughput": throughput,
                "success_rate": success_rate
            }
            
            print(f"Time: {total_time:.2f}s, Throughput: {throughput:.1f} req/s, "
                  f"Success rate: {success_rate:.2%}")
            
            # Assertions for each concurrency level
            assert success_rate >= 0.95, f"Success rate {success_rate:.2%} below 95%"
            assert throughput >= concurrency * 2, f"Throughput {throughput:.1f} too low for concurrency {concurrency}"
        
        # Verify scaling efficiency
        baseline_throughput = results[1]["throughput"]
        for concurrency in [5, 10, 20]:
            scaling_factor = results[concurrency]["throughput"] / baseline_throughput
            expected_min_scaling = min(concurrency * 0.7, 10)  # Expect at least 70% scaling efficiency
            
            print(f"Concurrency {concurrency}: {scaling_factor:.1f}x scaling factor")
            assert scaling_factor >= expected_min_scaling, \
                f"Scaling factor {scaling_factor:.1f} below expected {expected_min_scaling:.1f}"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.controllers.depends.get_dashboard_controller')
    def test_dashboard_query_performance(
        self, mock_get_controller, mock_get_user, client, mock_user_token, 
        mock_user_id, mock_project_id
    ):
        """Test dashboard query performance with large datasets."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock controller with realistic query times
        mock_controller = AsyncMock()
        
        async def mock_get_overview(user_id, project_id=None, **kwargs):
            # Simulate database query time based on dataset size
            dataset_size = kwargs.get('dataset_size', 10000)
            query_time = 0.05 + (dataset_size / 100000) * 0.5  # 50ms base + scaling
            await asyncio.sleep(query_time)
            
            return MagicMock(
                total_scans=dataset_size,
                active_scans=int(dataset_size * 0.1),
                failed_scans=int(dataset_size * 0.05),
                total_assessments=dataset_size * 2,
                high_risk_items=int(dataset_size * 0.02),
                query_performance={
                    "execution_time_ms": int(query_time * 1000),
                    "records_processed": dataset_size,
                    "cache_hit_rate": 0.85
                }
            )
        
        mock_controller.get_social_protection_overview = mock_get_overview
        mock_get_controller.return_value = mock_controller

        # Test different dataset sizes
        dataset_sizes = [1000, 10000, 50000, 100000, 500000]
        query_times = []
        
        for size in dataset_sizes:
            print(f"\nTesting dataset size: {size:,} records")
            
            start_time = time.time()
            
            response = client.get(
                f"/dashboard/social-protection/overview?project_id={mock_project_id}&dataset_size={size}",
                headers={"Authorization": mock_user_token}
            )
            
            end_time = time.time()
            query_time = (end_time - start_time) * 1000  # Convert to milliseconds
            query_times.append(query_time)
            
            assert response.status_code == 200
            data = response.json()
            
            print(f"Query time: {query_time:.1f}ms")
            print(f"Records processed: {data.get('total_scans', 0):,}")
            
            # Performance requirements based on dataset size
            if size <= 10000:
                max_time = 200  # 200ms for small datasets
            elif size <= 100000:
                max_time = 500  # 500ms for medium datasets
            else:
                max_time = 1000  # 1s for large datasets
            
            assert query_time <= max_time, \
                f"Query time {query_time:.1f}ms exceeds {max_time}ms limit for {size:,} records"
        
        # Verify query time scaling is reasonable
        for i in range(1, len(dataset_sizes)):
            size_ratio = dataset_sizes[i] / dataset_sizes[i-1]
            time_ratio = query_times[i] / query_times[i-1]
            
            # Query time should not scale worse than O(n log n)
            max_time_ratio = size_ratio * 1.5  # Allow some overhead
            
            print(f"Size ratio: {size_ratio:.1f}x, Time ratio: {time_ratio:.1f}x")
            assert time_ratio <= max_time_ratio, \
                f"Query time scaling {time_ratio:.1f}x too high for size scaling {size_ratio:.1f}x"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.social_protection.services.extension_data_processor.ExtensionDataProcessor')
    def test_batch_processing_performance(
        self, mock_processor, mock_get_user, client, mock_user_token, 
        mock_user_id, performance_assessment_requests
    ):
        """Test batch processing performance for bulk operations."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock processor for batch operations
        mock_proc = AsyncMock()
        
        async def mock_process_batch(requests):
            # Simulate batch processing with efficiency gains
            batch_size = len(requests)
            base_time = 0.01 * batch_size  # Base processing time
            efficiency_factor = max(0.5, 1.0 - (batch_size - 1) * 0.01)  # Efficiency improves with batch size
            processing_time = base_time * efficiency_factor
            
            await asyncio.sleep(processing_time)
            
            results = []
            for i, request in enumerate(requests):
                results.append(MagicMock(
                    id=uuid.uuid4(),
                    risk_level=RiskLevel.LOW if i % 4 != 0 else RiskLevel.MEDIUM,
                    confidence_score=0.80 + (i % 20) / 100,
                    processing_time_ms=int(processing_time * 1000 / batch_size),
                    risk_factors=[],
                    recommendations=["Batch processed content"]
                ))
            
            return results
        
        mock_proc.process_batch_request = mock_process_batch
        mock_processor.return_value = mock_proc

        # Test different batch sizes
        batch_sizes = [1, 5, 10, 25, 50, 100]
        performance_results = {}
        
        for batch_size in batch_sizes:
            print(f"\nTesting batch size: {batch_size}")
            
            # Prepare batch request
            batch_requests = performance_assessment_requests[:batch_size]
            batch_data = [
                {
                    "content_type": req.content_type.value,
                    "content_data": req.content_data,
                    "source_url": req.source_url,
                    "context": req.context
                }
                for req in batch_requests
            ]
            
            start_time = time.time()
            
            response = client.post(
                "/social-protection/extension/batch-process",
                json={"requests": batch_data},
                headers={"Authorization": mock_user_token}
            )
            
            end_time = time.time()
            total_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            assert response.status_code == 200
            results = response.json()
            
            # Calculate performance metrics
            throughput = batch_size / (total_time / 1000)  # Items per second
            avg_time_per_item = total_time / batch_size
            
            performance_results[batch_size] = {
                "total_time": total_time,
                "throughput": throughput,
                "avg_time_per_item": avg_time_per_item
            }
            
            print(f"Total time: {total_time:.1f}ms")
            print(f"Throughput: {throughput:.1f} items/s")
            print(f"Avg time per item: {avg_time_per_item:.1f}ms")
            
            # Verify batch processing efficiency
            assert len(results["results"]) == batch_size
            
            # Performance requirements
            if batch_size == 1:
                assert avg_time_per_item <= 100, f"Single item processing {avg_time_per_item:.1f}ms too slow"
            else:
                # Batch processing should be more efficient
                single_item_time = performance_results[1]["avg_time_per_item"]
                efficiency_gain = single_item_time / avg_time_per_item
                expected_min_gain = min(1.5, 1.0 + (batch_size - 1) * 0.05)
                
                print(f"Efficiency gain: {efficiency_gain:.2f}x")
                assert efficiency_gain >= expected_min_gain, \
                    f"Batch efficiency {efficiency_gain:.2f}x below expected {expected_min_gain:.2f}x"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.social_protection.services.social_scan_service.SocialScanService')
    def test_memory_usage_under_load(
        self, mock_scan_service, mock_get_user, client, mock_user_token, 
        mock_user_id, performance_scan_requests
    ):
        """Test memory usage patterns under sustained load."""
        import psutil
        import os
        
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock scan service
        mock_service = AsyncMock()
        
        async def mock_initiate_scan(request):
            # Simulate memory allocation during processing
            await asyncio.sleep(0.05)
            return MagicMock(
                id=uuid.uuid4(),
                status=ScanStatus.QUEUED,
                estimated_completion=datetime.utcnow() + timedelta(minutes=5)
            )
        
        mock_service.initiate_profile_scan = mock_initiate_scan
        mock_scan_service.return_value = mock_service

        # Monitor memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_samples = [initial_memory]
        
        print(f"Initial memory usage: {initial_memory:.1f} MB")
        
        # Process requests in waves to test memory patterns
        num_waves = 5
        requests_per_wave = 20
        
        for wave in range(num_waves):
            print(f"\nProcessing wave {wave + 1}/{num_waves}")
            
            wave_start_memory = process.memory_info().rss / 1024 / 1024
            
            # Process wave of requests
            wave_requests = performance_scan_requests[wave * requests_per_wave:(wave + 1) * requests_per_wave]
            
            for request in wave_requests:
                response = client.post(
                    "/social-protection/scan/initiate",
                    json={
                        "platform": request.platform.value,
                        "profile_url": request.profile_url,
                        "scan_depth": request.scan_depth,
                        "priority": request.priority
                    },
                    headers={"Authorization": mock_user_token}
                )
                assert response.status_code == 200
            
            wave_end_memory = process.memory_info().rss / 1024 / 1024
            memory_samples.append(wave_end_memory)
            
            memory_increase = wave_end_memory - wave_start_memory
            print(f"Wave memory usage: {wave_start_memory:.1f} -> {wave_end_memory:.1f} MB "
                  f"(+{memory_increase:.1f} MB)")
            
            # Allow some time for garbage collection
            time.sleep(0.5)
        
        final_memory = process.memory_info().rss / 1024 / 1024
        total_memory_increase = final_memory - initial_memory
        
        print(f"\nMemory Usage Summary:")
        print(f"Initial: {initial_memory:.1f} MB")
        print(f"Final: {final_memory:.1f} MB")
        print(f"Total increase: {total_memory_increase:.1f} MB")
        print(f"Requests processed: {num_waves * requests_per_wave}")
        print(f"Memory per request: {total_memory_increase / (num_waves * requests_per_wave):.3f} MB")
        
        # Memory usage requirements
        max_memory_increase = 100  # Maximum 100MB increase
        max_memory_per_request = 0.5  # Maximum 0.5MB per request
        
        assert total_memory_increase <= max_memory_increase, \
            f"Memory increase {total_memory_increase:.1f} MB exceeds {max_memory_increase} MB limit"
        
        memory_per_request = total_memory_increase / (num_waves * requests_per_wave)
        assert memory_per_request <= max_memory_per_request, \
            f"Memory per request {memory_per_request:.3f} MB exceeds {max_memory_per_request} MB limit"
        
        # Check for memory leaks (memory should not continuously increase)
        if len(memory_samples) >= 3:
            # Calculate trend in memory usage
            recent_samples = memory_samples[-3:]
            memory_trend = (recent_samples[-1] - recent_samples[0]) / len(recent_samples)
            
            print(f"Recent memory trend: {memory_trend:.2f} MB per wave")
            
            # Memory trend should be minimal (< 5MB per wave)
            assert abs(memory_trend) <= 5.0, \
                f"Memory trend {memory_trend:.2f} MB/wave indicates potential leak"

    @patch('src.authentication.dependencies.get_current_user')
    @patch('src.social_protection.services.extension_data_processor.ExtensionDataProcessor')
    def test_error_handling_performance_impact(
        self, mock_processor, mock_get_user, client, mock_user_token, 
        mock_user_id, performance_assessment_requests
    ):
        """Test performance impact of error handling and recovery."""
        # Mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = mock_user_id
        mock_get_user.return_value = mock_user

        # Mock processor with intermittent failures
        mock_proc = AsyncMock()
        
        call_count = 0
        
        async def mock_process_with_errors(request):
            nonlocal call_count
            call_count += 1
            
            # Simulate 10% failure rate
            if call_count % 10 == 0:
                # Simulate error processing time
                await asyncio.sleep(0.2)  # Errors take longer
                raise Exception("Simulated processing error")
            else:
                # Normal processing
                await asyncio.sleep(0.05)
                return MagicMock(
                    id=uuid.uuid4(),
                    risk_level=RiskLevel.LOW,
                    confidence_score=0.85,
                    processing_time_ms=50,
                    risk_factors=[],
                    recommendations=["Content processed successfully"]
                )
        
        mock_proc.process_extension_request = mock_process_with_errors
        mock_processor.return_value = mock_proc

        # Test error handling performance
        num_requests = 50
        success_times = []
        error_times = []
        
        for i in range(num_requests):
            request = performance_assessment_requests[i]
            
            start_time = time.time()
            
            response = client.post(
                "/social-protection/extension/process",
                json={
                    "content_type": request.content_type.value,
                    "content_data": request.content_data,
                    "source_url": request.source_url,
                    "context": request.context
                },
                headers={"Authorization": mock_user_token}
            )
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            if response.status_code == 200:
                success_times.append(response_time)
            else:
                error_times.append(response_time)
                # Verify error response format
                assert response.status_code in [400, 500]
        
        # Analyze performance impact
        if success_times:
            avg_success_time = statistics.mean(success_times)
            print(f"Average success response time: {avg_success_time:.1f}ms")
        
        if error_times:
            avg_error_time = statistics.mean(error_times)
            print(f"Average error response time: {avg_error_time:.1f}ms")
            
            # Error handling should not be significantly slower
            if success_times:
                error_overhead = avg_error_time / avg_success_time
                print(f"Error handling overhead: {error_overhead:.2f}x")
                assert error_overhead <= 5.0, \
                    f"Error handling overhead {error_overhead:.2f}x too high"
        
        success_rate = len(success_times) / num_requests
        print(f"Success rate: {success_rate:.2%}")
        print(f"Successful requests: {len(success_times)}")
        print(f"Failed requests: {len(error_times)}")
        
        # Verify expected failure rate (around 10%)
        expected_failure_rate = 0.1
        actual_failure_rate = len(error_times) / num_requests
        assert abs(actual_failure_rate - expected_failure_rate) <= 0.05, \
            f"Failure rate {actual_failure_rate:.2%} differs from expected {expected_failure_rate:.2%}"

    def test_api_rate_limiting_performance(self, client, mock_user_token):
        """Test API rate limiting performance and behavior."""
        # Test rate limiting with rapid requests
        num_requests = 100
        request_interval = 0.01  # 10ms between requests (100 req/s)
        
        response_codes = []
        response_times = []
        
        print(f"Testing rate limiting with {num_requests} requests at {1/request_interval:.0f} req/s")
        
        for i in range(num_requests):
            start_time = time.time()
            
            response = client.get(
                "/social-protection/health",
                headers={"Authorization": mock_user_token}
            )
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            response_codes.append(response.status_code)
            response_times.append(response_time)
            
            # Small delay between requests
            time.sleep(request_interval)
        
        # Analyze rate limiting behavior
        success_responses = [code for code in response_codes if code == 200]
        rate_limited_responses = [code for code in response_codes if code == 429]
        
        success_rate = len(success_responses) / num_requests
        rate_limited_rate = len(rate_limited_responses) / num_requests
        
        print(f"Success responses: {len(success_responses)} ({success_rate:.2%})")
        print(f"Rate limited responses: {len(rate_limited_responses)} ({rate_limited_rate:.2%})")
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            print(f"Average response time: {avg_response_time:.1f}ms")
            
            # Rate limiting should not significantly impact response times
            assert avg_response_time <= 100, \
                f"Average response time {avg_response_time:.1f}ms too high under rate limiting"
        
        # Verify rate limiting is working (some requests should be limited at high rate)
        if request_interval < 0.02:  # If sending faster than 50 req/s
            assert rate_limited_rate > 0, "Rate limiting should activate at high request rates"
        
        # Verify successful requests still work properly
        assert success_rate >= 0.5, f"Success rate {success_rate:.2%} too low under rate limiting"
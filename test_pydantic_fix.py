#!/usr/bin/env python3
"""
Test script to verify Pydantic forward reference fix.

This script tests:
1. Import of dashboard models without errors
2. Model instantiation without TypeAdapter errors
3. Model validation and serialization
"""

import sys
import traceback
from typing import Dict, Any

def test_dashboard_models_import():
    """Test importing dashboard models."""
    print("Testing dashboard models import...")
    try:
        from src.controllers.dashboard_models import (
            DashboardOverviewResponse,
            ProjectResponse,
            ProjectCreateRequest,
            ProjectUpdateRequest,
            MemberResponse,
            MemberInviteRequest,
            MonitoringConfigResponse,
            AlertResponse,
            AlertInstanceResponse,
            AlertCreateRequest,
            AlertUpdateRequest,
            AnalyticsResponse,
            ActivityLogResponse,
        )
        print("✓ Dashboard models imported successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to import dashboard models: {e}")
        traceback.print_exc()
        return False

def test_model_instantiation():
    """Test creating instances of dashboard models."""
    print("\nTesting model instantiation...")
    try:
        from src.controllers.dashboard_models import (
            ProjectCreateRequest,
            ProjectUpdateRequest,
            MemberInviteRequest,
            AlertCreateRequest,
            AlertUpdateRequest,
        )
        
        # Test ProjectCreateRequest
        project_create = ProjectCreateRequest(
            name="Test Project",
            description="Test Description",
            monitoring_enabled=True
        )
        print("✓ ProjectCreateRequest created successfully")
        
        # Test ProjectUpdateRequest
        project_update = ProjectUpdateRequest(
            name="Updated Project",
            description="Updated Description"
        )
        print("✓ ProjectUpdateRequest created successfully")
        
        # Test MemberInviteRequest
        member_invite = MemberInviteRequest(
            email="test@example.com",
            role="viewer"
        )
        print("✓ MemberInviteRequest created successfully")
        
        # Test AlertCreateRequest
        alert_create = AlertCreateRequest(
            name="Test Alert",
            alert_type="url_status",
            conditions={"status_code": 404},
            enabled=True
        )
        print("✓ AlertCreateRequest created successfully")
        
        # Test AlertUpdateRequest
        alert_update = AlertUpdateRequest(
            name="Updated Alert",
            enabled=False
        )
        print("✓ AlertUpdateRequest created successfully")
        
        return True
    except Exception as e:
        print(f"✗ Failed to create model instances: {e}")
        traceback.print_exc()
        return False

def test_model_validation():
    """Test model validation and serialization."""
    print("\nTesting model validation...")
    try:
        from src.controllers.dashboard_models import ProjectCreateRequest
        
        # Test valid data
        valid_data = {
            "name": "Valid Project",
            "description": "Valid Description",
            "monitoring_enabled": True
        }
        project = ProjectCreateRequest(**valid_data)
        serialized = project.model_dump()
        print(f"✓ Model validation successful: {serialized}")
        
        # Test model_dump_json
        json_str = project.model_dump_json()
        print(f"✓ JSON serialization successful: {json_str}")
        
        return True
    except Exception as e:
        print(f"✗ Failed model validation: {e}")
        traceback.print_exc()
        return False

def test_dashboard_controller_import():
    """Test importing dashboard controller."""
    print("\nTesting dashboard controller import...")
    try:
        from src.controllers.dashboard_controller import DashboardController
        print("✓ DashboardController imported successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to import DashboardController: {e}")
        traceback.print_exc()
        return False

def test_dashboard_routes_import():
    """Test importing dashboard routes."""
    print("\nTesting dashboard routes import...")
    try:
        from src.routes.dashboard import router
        print("✓ Dashboard router imported successfully")
        return True
    except Exception as e:
        print(f"✗ Failed to import dashboard router: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("=== Pydantic Forward Reference Fix Test ===\n")
    
    tests = [
        test_dashboard_models_import,
        test_model_instantiation,
        test_model_validation,
        test_dashboard_controller_import,
        test_dashboard_routes_import,
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    print(f"\n=== Test Results ===")
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All tests passed! Pydantic forward reference fix is working.")
        return 0
    else:
        print("✗ Some tests failed. Check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
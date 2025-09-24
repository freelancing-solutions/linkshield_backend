#!/usr/bin/env python3
"""
Test script to verify the Pydantic forward reference issue is resolved.
"""

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_dashboard_models():
    """Test that dashboard models can be imported and used without forward reference errors."""
    print("Testing dashboard models import...")
    
    try:
        # Test importing all models
        from controllers.dashboard_models import (
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
        print("✅ All dashboard models imported successfully")
        
        # Test creating model instances
        try:
            # Test ProjectCreateRequest
            project_create = ProjectCreateRequest(
                name="Test Project",
                website_url="https://example.com"
            )
            print("✅ ProjectCreateRequest instance created successfully")
            
            # Test ProjectUpdateRequest
            project_update = ProjectUpdateRequest(
                name="Updated Project Name"
            )
            print("✅ ProjectUpdateRequest instance created successfully")
            
            # Test MemberInviteRequest
            member_invite = MemberInviteRequest(
                email="test@example.com",
                role="viewer"
            )
            print("✅ MemberInviteRequest instance created successfully")
            
            # Test AlertCreateRequest
            alert_create = AlertCreateRequest(
                alert_type="security_scan",
                title="Test Alert",
                severity="medium"
            )
            print("✅ AlertCreateRequest instance created successfully")
            
            # Test AlertUpdateRequest
            alert_update = AlertUpdateRequest(
                status="resolved",
                severity="low"
            )
            print("✅ AlertUpdateRequest instance created successfully")
            
        except Exception as e:
            print(f"❌ Error creating model instances: {e}")
            return False
        
        print("✅ All model instances created successfully")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_controller_import():
    """Test that the dashboard controller can be imported with the new models."""
    print("\nTesting dashboard controller import...")
    
    try:
        from controllers.dashboard_controller import DashboardController
        print("✅ DashboardController imported successfully")
        return True
    except ImportError as e:
        print(f"❌ DashboardController import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error importing controller: {e}")
        return False

def test_routes_import():
    """Test that the dashboard routes can be imported with the new models."""
    print("\nTesting dashboard routes import...")
    
    try:
        from routes.dashboard import router
        print("✅ Dashboard routes imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Dashboard routes import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error importing routes: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("Testing Pydantic Forward Reference Fix")
    print("=" * 60)
    
    success = True
    
    # Test models
    if not test_dashboard_models():
        success = False
    
    # Test controller
    if not test_controller_import():
        success = False
    
    # Test routes
    if not test_routes_import():
        success = False
    
    print("\n" + "=" * 60)
    if success:
        print("✅ All tests passed! The Pydantic forward reference issue appears to be resolved.")
    else:
        print("❌ Some tests failed. The issue may not be fully resolved.")
    print("=" * 60)
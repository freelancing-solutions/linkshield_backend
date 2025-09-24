#!/usr/bin/env python3
"""
Dashboard Models Validation Script
Tests model imports, structure, and relationships without database connectivity.
"""

import sys
import os
from datetime import datetime, timedelta
from enum import Enum

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

def test_model_imports():
    """Test that all models can be imported successfully."""
    print("Testing model imports...")
    
    try:
        from models.project import Project, ProjectMember, MonitoringConfig, ProjectAlert
        from models.project import ProjectRole, AlertType, AlertChannel
        from models.subscription import SubscriptionPlan
        from models.user import User
        print("✅ All model imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_enum_definitions():
    """Test that all enums are properly defined."""
    print("\nTesting enum definitions...")
    
    try:
        from models.project import ProjectRole, AlertType, AlertChannel
        
        # Test ProjectRole enum
        assert ProjectRole.OWNER == "owner"
        assert ProjectRole.ADMIN == "admin"
        assert ProjectRole.EDITOR == "editor"
        assert ProjectRole.VIEWER == "viewer"
        print("✅ ProjectRole enum definitions correct")
        
        # Test AlertType enum
        assert AlertType.BROKEN_LINKS == "broken_links"
        assert AlertType.HARMFUL_CONTENT == "harmful_content"
        assert AlertType.SCAN_FAILED == "scan_failed"
        assert AlertType.SECURITY_THREAT == "security_threat"
        print("✅ AlertType enum definitions correct")
        
        # Test AlertChannel enum
        assert AlertChannel.EMAIL == "email"
        assert AlertChannel.DASHBOARD == "dashboard"
        assert AlertChannel.WEBHOOK == "webhook"
        print("✅ AlertChannel enum definitions correct")
        
        return True
    except (ImportError, AssertionError) as e:
        print(f"❌ Enum definition error: {e}")
        return False

def test_model_instantiation():
    """Test that models can be instantiated with proper defaults."""
    print("\nTesting model instantiation...")
    
    try:
        from models.project import Project, ProjectMember, MonitoringConfig, ProjectAlert
        from models.project import ProjectRole, AlertType, AlertChannel
        
        # Test Project instantiation
        project = Project(
            user_id=1,
            name="Test Project",
            website_url="https://example.com",
            domain="example.com"
        )
        assert project.name == "Test Project"
        assert project.is_monitoring_enabled is True  # Default value
        assert project.total_scans == 0  # Default value
        print("✅ Project instantiation successful")
        
        # Test ProjectMember instantiation
        member = ProjectMember(
            project_id=1,
            user_id=2,
            role=ProjectRole.EDITOR
        )
        assert member.role == ProjectRole.EDITOR
        assert member.is_active is True  # Default value
        print("✅ ProjectMember instantiation successful")
        
        # Test MonitoringConfig instantiation
        config = MonitoringConfig(
            project_id=1
        )
        assert config.scan_frequency_minutes == 1440  # Default value
        assert config.check_broken_links is True  # Default value
        assert config.max_links_per_scan == 100  # Default value
        print("✅ MonitoringConfig instantiation successful")
        
        # Test ProjectAlert instantiation
        alert = ProjectAlert(
            project_id=1,
            user_id=1,
            alert_type=AlertType.BROKEN_LINKS,
            channel=AlertChannel.EMAIL
        )
        assert alert.alert_type == AlertType.BROKEN_LINKS
        assert alert.channel == AlertChannel.EMAIL
        assert alert.is_enabled is True  # Default value
        assert alert.alert_count == 0  # Default value
        print("✅ ProjectAlert instantiation successful")
        
        return True
    except (ImportError, AssertionError, Exception) as e:
        print(f"❌ Model instantiation error: {e}")
        return False

def test_subscription_enhancements():
    """Test subscription plan monitoring enhancements."""
    print("\nTesting subscription plan enhancements...")
    
    try:
        from models.subscription import SubscriptionPlan
        
        # Test that new monitoring columns exist
        plan = SubscriptionPlan(
            name="Test Plan",
            plan_type="basic",
            price=9.99,
            billing_interval="monthly"
        )
        
        # Check default values
        assert plan.max_projects == 1
        assert plan.max_team_members_per_project == 1
        assert plan.max_alerts_per_project == 5
        assert plan.monitoring_frequency_minutes == 1440
        print("✅ Subscription plan monitoring enhancements correct")
        
        return True
    except (ImportError, AssertionError) as e:
        print(f"❌ Subscription enhancement error: {e}")
        return False

def test_model_methods():
    """Test model utility methods."""
    print("\nTesting model utility methods...")
    
    try:
        from models.project import Project, ProjectMember, ProjectRole
        
        # Test Project methods
        project = Project(
            user_id=1,
            name="Test Project",
            website_url="https://example.com",
            domain="example.com"
        )
        
        # Test to_dict method exists
        project_dict = project.to_dict()
        assert isinstance(project_dict, dict)
        assert project_dict['name'] == "Test Project"
        print("✅ Project to_dict method works")
        
        # Test ProjectMember permission methods
        member = ProjectMember(
            project_id=1,
            user_id=2,
            role=ProjectRole.OWNER
        )
        
        assert member.has_permission('edit') is True
        assert member.has_permission('delete') is True
        print("✅ ProjectMember permission methods work")
        
        return True
    except (ImportError, AssertionError, Exception) as e:
        print(f"❌ Model methods error: {e}")
        return False

def main():
    """Run all validation tests."""
    print("🚀 Starting Dashboard Models Validation")
    print("=" * 50)
    
    tests = [
        test_model_imports,
        test_enum_definitions,
        test_model_instantiation,
        test_subscription_enhancements,
        test_model_methods
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ All tests passed! Dashboard models are ready for use.")
        return 0
    else:
        print("❌ Some tests failed. Please review the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
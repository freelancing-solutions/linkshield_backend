#!/usr/bin/env python3
"""
API Key Versioning Service

Manages API key versioning, lifecycle, compatibility checks,
and migration between different key versions.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import uuid
import json
import semver

import redis.asyncio as redis
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_
from sqlalchemy.orm import selectinload

from linkshield.config.settings import get_settings
from linkshield.config.database import get_db_session
from linkshield.models.user import User, APIKey


class APIKeyVersionType(Enum):
    """API Key version types"""
    MAJOR = "major"  # Breaking changes
    MINOR = "minor"  # New features, backward compatible
    PATCH = "patch"  # Bug fixes, backward compatible


class CompatibilityLevel(Enum):
    """API compatibility levels"""
    FULL = "full"  # Fully compatible
    PARTIAL = "partial"  # Partially compatible with warnings
    DEPRECATED = "deprecated"  # Deprecated but still works
    INCOMPATIBLE = "incompatible"  # Not compatible


@dataclass
class APIKeyVersionInfo:
    """API Key version information"""
    version: str  # Semantic version (e.g., "1.2.3")
    key_id: str
    user_id: str
    created_at: datetime
    expires_at: Optional[datetime]
    features: Set[str]  # Supported features
    permissions: Dict[str, Any]
    compatibility_level: CompatibilityLevel
    migration_path: Optional[str] = None  # Path to migrate to newer version
    deprecation_date: Optional[datetime] = None
    end_of_life_date: Optional[datetime] = None


@dataclass
class VersionMigrationPlan:
    """Version migration plan"""
    from_version: str
    to_version: str
    migration_steps: List[Dict[str, Any]]
    estimated_downtime: timedelta
    rollback_plan: List[Dict[str, Any]]
    compatibility_issues: List[str]
    required_actions: List[str]


class APIKeyVersioningError(Exception):
    """API Key versioning specific errors"""
    pass


class APIKeyVersioningService:
    """
    API Key Versioning Service
    
    Manages API key versions, compatibility checks, lifecycle management,
    and migration between different API versions.
    """
    
    def __init__(self, redis_client: Optional[Redis] = None):
        """Initialize the API key versioning service"""
        self.settings = get_settings()
        self.redis_client = redis_client
        
        # Current API version
        self.current_api_version = "2.1.0"
        
        # Supported API versions and their compatibility
        self.supported_versions = {
            "2.1.0": {
                "features": {"rate_limiting", "device_fingerprinting", "session_security", "geolocation"},
                "compatibility": CompatibilityLevel.FULL,
                "end_of_life": None
            },
            "2.0.0": {
                "features": {"rate_limiting", "basic_auth", "session_management"},
                "compatibility": CompatibilityLevel.FULL,
                "end_of_life": datetime.now(timezone.utc) + timedelta(days=365)
            },
            "1.9.0": {
                "features": {"basic_auth", "session_management"},
                "compatibility": CompatibilityLevel.DEPRECATED,
                "end_of_life": datetime.now(timezone.utc) + timedelta(days=180)
            },
            "1.8.0": {
                "features": {"basic_auth"},
                "compatibility": CompatibilityLevel.INCOMPATIBLE,
                "end_of_life": datetime.now(timezone.utc) + timedelta(days=90)
            }
        }
        
        # Redis keys for caching
        self.VERSION_CACHE_KEY = "api_key_versioning:cache:{key_id}"
        self.COMPATIBILITY_CACHE_KEY = "api_key_versioning:compatibility:{version}"
        self.MIGRATION_PLAN_KEY = "api_key_versioning:migration:{from_version}:{to_version}"
    
    async def _get_redis_client(self) -> Redis:
        """Get Redis client instance"""
        if not self.redis_client:
            self.redis_client = redis.from_url(
                self.settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
        return self.redis_client
    
    def _parse_version(self, version: str) -> Tuple[int, int, int]:
        """Parse semantic version string"""
        try:
            return semver.VersionInfo.parse(version).to_tuple()[:3]
        except Exception:
            raise APIKeyVersioningError(f"Invalid version format: {version}")
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare two versions (-1: v1 < v2, 0: v1 == v2, 1: v1 > v2)"""
        try:
            v1 = semver.VersionInfo.parse(version1)
            v2 = semver.VersionInfo.parse(version2)
            return v1.compare(v2)
        except Exception:
            raise APIKeyVersioningError(f"Failed to compare versions: {version1} vs {version2}")
    
    async def assign_version_to_key(self, api_key_id: uuid.UUID, version: str = None) -> APIKeyVersionInfo:
        """
        Assign a version to an API key
        
        Args:
            api_key_id: API key ID
            version: Version to assign (defaults to current version)
            
        Returns:
            Version information
        """
        try:
            if version is None:
                version = self.current_api_version
            
            if version not in self.supported_versions:
                raise APIKeyVersioningError(f"Unsupported version: {version}")
            
            async with get_db_session() as session:
                # Get the API key
                result = await session.execute(
                    select(APIKey)
                    .where(APIKey.id == api_key_id)
                )
                api_key = result.scalar_one_or_none()
                
                if not api_key:
                    raise APIKeyVersioningError("API key not found")
                
                # Update API key with version information
                version_info = self.supported_versions[version]
                
                # Store version in metadata
                if not api_key.metadata:
                    api_key.metadata = {}
                
                api_key.metadata.update({
                    "api_version": version,
                    "features": list(version_info["features"]),
                    "compatibility_level": version_info["compatibility"].value,
                    "version_assigned_at": datetime.now(timezone.utc).isoformat()
                })
                
                await session.commit()
                
                # Create version info object
                version_info_obj = APIKeyVersionInfo(
                    version=version,
                    key_id=str(api_key_id),
                    user_id=str(api_key.user_id),
                    created_at=api_key.created_at,
                    expires_at=api_key.expires_at,
                    features=version_info["features"],
                    permissions=api_key.permissions or {},
                    compatibility_level=version_info["compatibility"],
                    end_of_life_date=version_info.get("end_of_life")
                )
                
                # Cache version information
                redis_client = await self._get_redis_client()
                cache_key = self.VERSION_CACHE_KEY.format(key_id=api_key_id)
                await redis_client.setex(
                    cache_key,
                    timedelta(hours=24),
                    json.dumps(asdict(version_info_obj), default=str)
                )
                
                return version_info_obj
                
        except Exception as e:
            raise APIKeyVersioningError(f"Failed to assign version to key: {str(e)}")
    
    async def get_key_version_info(self, api_key_id: uuid.UUID) -> Optional[APIKeyVersionInfo]:
        """
        Get version information for an API key
        
        Args:
            api_key_id: API key ID
            
        Returns:
            Version information or None if not found
        """
        try:
            # Try cache first
            redis_client = await self._get_redis_client()
            cache_key = self.VERSION_CACHE_KEY.format(key_id=api_key_id)
            cached_data = await redis_client.get(cache_key)
            
            if cached_data:
                data = json.loads(cached_data)
                # Convert string dates back to datetime objects
                for date_field in ["created_at", "expires_at", "deprecation_date", "end_of_life_date"]:
                    if data.get(date_field):
                        data[date_field] = datetime.fromisoformat(data[date_field])
                
                data["features"] = set(data["features"])
                data["compatibility_level"] = CompatibilityLevel(data["compatibility_level"])
                return APIKeyVersionInfo(**data)
            
            # Get from database
            async with get_db_session() as session:
                result = await session.execute(
                    select(APIKey)
                    .where(APIKey.id == api_key_id)
                )
                api_key = result.scalar_one_or_none()
                
                if not api_key or not api_key.metadata:
                    return None
                
                version = api_key.metadata.get("api_version")
                if not version:
                    return None
                
                version_info = self.supported_versions.get(version, {})
                
                version_info_obj = APIKeyVersionInfo(
                    version=version,
                    key_id=str(api_key_id),
                    user_id=str(api_key.user_id),
                    created_at=api_key.created_at,
                    expires_at=api_key.expires_at,
                    features=version_info.get("features", set()),
                    permissions=api_key.permissions or {},
                    compatibility_level=version_info.get("compatibility", CompatibilityLevel.INCOMPATIBLE),
                    end_of_life_date=version_info.get("end_of_life")
                )
                
                # Cache the result
                await redis_client.setex(
                    cache_key,
                    timedelta(hours=24),
                    json.dumps(asdict(version_info_obj), default=str)
                )
                
                return version_info_obj
                
        except Exception as e:
            raise APIKeyVersioningError(f"Failed to get key version info: {str(e)}")
    
    async def check_compatibility(self, api_key_id: uuid.UUID, required_features: Set[str]) -> Dict[str, Any]:
        """
        Check if an API key version is compatible with required features
        
        Args:
            api_key_id: API key ID
            required_features: Set of required features
            
        Returns:
            Compatibility check result
        """
        try:
            version_info = await self.get_key_version_info(api_key_id)
            
            if not version_info:
                return {
                    "compatible": False,
                    "reason": "No version information found",
                    "missing_features": list(required_features),
                    "compatibility_level": CompatibilityLevel.INCOMPATIBLE.value
                }
            
            # Check feature compatibility
            supported_features = version_info.features
            missing_features = required_features - supported_features
            
            # Determine compatibility
            if not missing_features:
                compatible = True
                reason = "All required features supported"
            elif version_info.compatibility_level in [CompatibilityLevel.FULL, CompatibilityLevel.PARTIAL]:
                compatible = True
                reason = f"Partially compatible - missing features: {', '.join(missing_features)}"
            else:
                compatible = False
                reason = f"Incompatible version - missing features: {', '.join(missing_features)}"
            
            # Check if version is deprecated or end-of-life
            warnings = []
            if version_info.compatibility_level == CompatibilityLevel.DEPRECATED:
                warnings.append("API version is deprecated")
            
            if version_info.end_of_life_date and version_info.end_of_life_date <= datetime.now(timezone.utc):
                warnings.append("API version has reached end-of-life")
                compatible = False
                reason = "API version has reached end-of-life"
            
            return {
                "compatible": compatible,
                "reason": reason,
                "compatibility_level": version_info.compatibility_level.value,
                "current_version": version_info.version,
                "latest_version": self.current_api_version,
                "supported_features": list(supported_features),
                "missing_features": list(missing_features),
                "warnings": warnings,
                "upgrade_recommended": version_info.version != self.current_api_version
            }
            
        except Exception as e:
            raise APIKeyVersioningError(f"Failed to check compatibility: {str(e)}")
    
    async def create_migration_plan(self, from_version: str, to_version: str) -> VersionMigrationPlan:
        """
        Create a migration plan between two API versions
        
        Args:
            from_version: Source version
            to_version: Target version
            
        Returns:
            Migration plan
        """
        try:
            # Check if versions are supported
            if from_version not in self.supported_versions:
                raise APIKeyVersioningError(f"Unsupported source version: {from_version}")
            
            if to_version not in self.supported_versions:
                raise APIKeyVersioningError(f"Unsupported target version: {to_version}")
            
            # Check cache first
            redis_client = await self._get_redis_client()
            cache_key = self.MIGRATION_PLAN_KEY.format(from_version=from_version, to_version=to_version)
            cached_plan = await redis_client.get(cache_key)
            
            if cached_plan:
                data = json.loads(cached_plan)
                # Convert timedelta
                data["estimated_downtime"] = timedelta(seconds=data["estimated_downtime"])
                return VersionMigrationPlan(**data)
            
            # Create migration plan
            from_info = self.supported_versions[from_version]
            to_info = self.supported_versions[to_version]
            
            from_features = from_info["features"]
            to_features = to_info["features"]
            
            # Determine migration complexity
            version_comparison = self._compare_versions(from_version, to_version)
            
            migration_steps = []
            compatibility_issues = []
            required_actions = []
            
            if version_comparison < 0:  # Upgrading
                # Features being added
                new_features = to_features - from_features
                if new_features:
                    migration_steps.append({
                        "step": "enable_new_features",
                        "description": f"Enable new features: {', '.join(new_features)}",
                        "estimated_time": timedelta(minutes=5)
                    })
                    required_actions.append(f"Update client code to use new features: {', '.join(new_features)}")
                
                # Features being removed
                removed_features = from_features - to_features
                if removed_features:
                    compatibility_issues.append(f"Features removed: {', '.join(removed_features)}")
                    migration_steps.append({
                        "step": "handle_removed_features",
                        "description": f"Handle removed features: {', '.join(removed_features)}",
                        "estimated_time": timedelta(minutes=15)
                    })
                    required_actions.append(f"Remove usage of deprecated features: {', '.join(removed_features)}")
                
            elif version_comparison > 0:  # Downgrading
                compatibility_issues.append("Downgrading may result in feature loss")
                migration_steps.append({
                    "step": "validate_downgrade",
                    "description": "Validate that downgrade is safe",
                    "estimated_time": timedelta(minutes=10)
                })
                required_actions.append("Ensure client code is compatible with older version")
            
            # Add standard migration steps
            migration_steps.extend([
                {
                    "step": "backup_current_config",
                    "description": "Backup current API key configuration",
                    "estimated_time": timedelta(minutes=2)
                },
                {
                    "step": "update_version",
                    "description": f"Update API version from {from_version} to {to_version}",
                    "estimated_time": timedelta(minutes=1)
                },
                {
                    "step": "validate_migration",
                    "description": "Validate migration success",
                    "estimated_time": timedelta(minutes=5)
                }
            ])
            
            # Rollback plan
            rollback_plan = [
                {
                    "step": "restore_backup",
                    "description": f"Restore API key configuration to version {from_version}",
                    "estimated_time": timedelta(minutes=3)
                },
                {
                    "step": "validate_rollback",
                    "description": "Validate rollback success",
                    "estimated_time": timedelta(minutes=2)
                }
            ]
            
            # Calculate total estimated downtime
            total_time = sum((step.get("estimated_time", timedelta(0)) for step in migration_steps), timedelta(0))
            
            migration_plan = VersionMigrationPlan(
                from_version=from_version,
                to_version=to_version,
                migration_steps=migration_steps,
                estimated_downtime=total_time,
                rollback_plan=rollback_plan,
                compatibility_issues=compatibility_issues,
                required_actions=required_actions
            )
            
            # Cache the plan
            plan_data = asdict(migration_plan)
            plan_data["estimated_downtime"] = total_time.total_seconds()
            await redis_client.setex(
                cache_key,
                timedelta(hours=24),
                json.dumps(plan_data, default=str)
            )
            
            return migration_plan
            
        except Exception as e:
            raise APIKeyVersioningError(f"Failed to create migration plan: {str(e)}")
    
    async def migrate_key_version(self, api_key_id: uuid.UUID, target_version: str) -> Dict[str, Any]:
        """
        Migrate an API key to a different version
        
        Args:
            api_key_id: API key ID
            target_version: Target version to migrate to
            
        Returns:
            Migration result
        """
        try:
            # Get current version info
            current_version_info = await self.get_key_version_info(api_key_id)
            if not current_version_info:
                raise APIKeyVersioningError("No version information found for API key")
            
            current_version = current_version_info.version
            
            if current_version == target_version:
                return {
                    "success": True,
                    "message": "API key is already at target version",
                    "current_version": current_version,
                    "target_version": target_version
                }
            
            # Create migration plan
            migration_plan = await self.create_migration_plan(current_version, target_version)
            
            # Execute migration
            migration_start = datetime.now(timezone.utc)
            
            try:
                # Assign new version
                new_version_info = await self.assign_version_to_key(api_key_id, target_version)
                
                # Clear cache to force refresh
                redis_client = await self._get_redis_client()
                cache_key = self.VERSION_CACHE_KEY.format(key_id=api_key_id)
                await redis_client.delete(cache_key)
                
                migration_end = datetime.now(timezone.utc)
                actual_downtime = migration_end - migration_start
                
                return {
                    "success": True,
                    "message": f"Successfully migrated from {current_version} to {target_version}",
                    "previous_version": current_version,
                    "new_version": target_version,
                    "migration_plan": asdict(migration_plan),
                    "actual_downtime": actual_downtime.total_seconds(),
                    "estimated_downtime": migration_plan.estimated_downtime.total_seconds(),
                    "compatibility_issues": migration_plan.compatibility_issues,
                    "required_actions": migration_plan.required_actions
                }
                
            except Exception as migration_error:
                # Attempt rollback
                try:
                    await self.assign_version_to_key(api_key_id, current_version)
                    return {
                        "success": False,
                        "message": f"Migration failed, rolled back to {current_version}",
                        "error": str(migration_error),
                        "rollback_successful": True
                    }
                except Exception as rollback_error:
                    return {
                        "success": False,
                        "message": "Migration failed and rollback failed",
                        "migration_error": str(migration_error),
                        "rollback_error": str(rollback_error),
                        "rollback_successful": False
                    }
                    
        except Exception as e:
            raise APIKeyVersioningError(f"Failed to migrate key version: {str(e)}")
    
    async def get_version_lifecycle_info(self) -> Dict[str, Any]:
        """
        Get lifecycle information for all supported API versions
        
        Returns:
            Version lifecycle information
        """
        try:
            current_time = datetime.now(timezone.utc)
            lifecycle_info = {}
            
            for version, info in self.supported_versions.items():
                end_of_life = info.get("end_of_life")
                
                lifecycle_info[version] = {
                    "version": version,
                    "features": list(info["features"]),
                    "compatibility_level": info["compatibility"].value,
                    "is_current": version == self.current_api_version,
                    "end_of_life_date": end_of_life,
                    "days_until_eol": (end_of_life - current_time).days if end_of_life else None,
                    "is_deprecated": info["compatibility"] == CompatibilityLevel.DEPRECATED,
                    "is_incompatible": info["compatibility"] == CompatibilityLevel.INCOMPATIBLE
                }
            
            return {
                "current_api_version": self.current_api_version,
                "total_supported_versions": len(self.supported_versions),
                "versions": lifecycle_info,
                "migration_recommendations": await self._get_migration_recommendations()
            }
            
        except Exception as e:
            raise APIKeyVersioningError(f"Failed to get version lifecycle info: {str(e)}")
    
    async def _get_migration_recommendations(self) -> List[Dict[str, Any]]:
        """Get migration recommendations for deprecated versions"""
        recommendations = []
        current_time = datetime.now(timezone.utc)
        
        for version, info in self.supported_versions.items():
            if info["compatibility"] in [CompatibilityLevel.DEPRECATED, CompatibilityLevel.INCOMPATIBLE]:
                end_of_life = info.get("end_of_life")
                urgency = "high" if end_of_life and (end_of_life - current_time).days < 30 else "medium"
                
                recommendations.append({
                    "from_version": version,
                    "to_version": self.current_api_version,
                    "urgency": urgency,
                    "reason": f"Version {version} is {info['compatibility'].value}",
                    "end_of_life_date": end_of_life
                })
        
        return recommendations


# Global instance
_api_key_versioning_service = None

def get_api_key_versioning_service() -> APIKeyVersioningService:
    """Get global API key versioning service instance"""
    global _api_key_versioning_service
    if _api_key_versioning_service is None:
        _api_key_versioning_service = APIKeyVersioningService()
    return _api_key_versioning_service
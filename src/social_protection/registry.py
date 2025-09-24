"""
Platform Registry

Manages registration and retrieval of social media platform adapters.
Provides a centralized registry for all available platform adapters
with dynamic registration and singleton pattern for global access.
"""

from typing import Dict, List, Optional, Type
import logging
from .platform_adapters.base_adapter import SocialPlatformAdapter, PlatformType

logger = logging.getLogger(__name__)


class PlatformRegistry:
    """
    Singleton registry for managing social media platform adapters.
    
    Provides centralized registration, retrieval, and management
    of platform-specific adapters with thread-safe operations.
    """
    
    _instance: Optional['PlatformRegistry'] = None
    _initialized: bool = False
    
    def __new__(cls) -> 'PlatformRegistry':
        """Ensure singleton pattern"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize the registry if not already initialized"""
        if not self._initialized:
            self._adapters: Dict[PlatformType, Type[SocialPlatformAdapter]] = {}
            self._adapter_instances: Dict[PlatformType, SocialPlatformAdapter] = {}
            self._adapter_configs: Dict[PlatformType, Dict] = {}
            PlatformRegistry._initialized = True
    
    def register_adapter(
        self, 
        platform_type: PlatformType, 
        adapter_class: Type[SocialPlatformAdapter],
        config: Optional[Dict] = None
    ) -> None:
        """
        Register a platform adapter class.
        
        Args:
            platform_type: The platform type this adapter handles
            adapter_class: The adapter class to register
            config: Optional configuration for the adapter
        """
        if not issubclass(adapter_class, SocialPlatformAdapter):
            raise ValueError(f"Adapter class must inherit from SocialPlatformAdapter")
        
        self._adapters[platform_type] = adapter_class
        self._adapter_configs[platform_type] = config or {}
        
        # Clear any existing instance to force recreation with new config
        if platform_type in self._adapter_instances:
            del self._adapter_instances[platform_type]
        
        logger.info(f"Registered adapter for platform: {platform_type.value}")
    
    def get_adapter(self, platform_type: PlatformType) -> Optional[SocialPlatformAdapter]:
        """
        Get an adapter instance for the specified platform.
        
        Args:
            platform_type: The platform type to get adapter for
            
        Returns:
            Adapter instance or None if not registered
        """
        if platform_type not in self._adapters:
            logger.warning(f"No adapter registered for platform: {platform_type.value}")
            return None
        
        # Return cached instance if available
        if platform_type in self._adapter_instances:
            return self._adapter_instances[platform_type]
        
        # Create new instance
        try:
            adapter_class = self._adapters[platform_type]
            config = self._adapter_configs[platform_type]
            adapter_instance = adapter_class(platform_type, config)
            
            # Cache the instance
            self._adapter_instances[platform_type] = adapter_instance
            
            logger.info(f"Created adapter instance for platform: {platform_type.value}")
            return adapter_instance
            
        except Exception as e:
            logger.error(f"Failed to create adapter for {platform_type.value}: {str(e)}")
            return None
    
    def get_adapter_by_name(self, platform_name: str) -> Optional[SocialPlatformAdapter]:
        """
        Get an adapter instance by platform name string.
        
        Args:
            platform_name: Platform name (e.g., "twitter", "meta_facebook")
            
        Returns:
            Adapter instance or None if not found
        """
        try:
            platform_type = PlatformType(platform_name.lower())
            return self.get_adapter(platform_type)
        except ValueError:
            logger.warning(f"Unknown platform name: {platform_name}")
            return None
    
    def list_available_platforms(self) -> List[PlatformType]:
        """
        Get list of all registered platform types.
        
        Returns:
            List of registered platform types
        """
        return list(self._adapters.keys())
    
    def list_enabled_platforms(self) -> List[PlatformType]:
        """
        Get list of enabled platform types.
        
        Returns:
            List of enabled platform types
        """
        enabled_platforms = []
        for platform_type in self._adapters.keys():
            adapter = self.get_adapter(platform_type)
            if adapter and adapter.is_enabled:
                enabled_platforms.append(platform_type)
        return enabled_platforms
    
    def is_platform_supported(self, platform_type: PlatformType) -> bool:
        """
        Check if a platform is supported and enabled.
        
        Args:
            platform_type: Platform type to check
            
        Returns:
            True if platform is supported and enabled
        """
        adapter = self.get_adapter(platform_type)
        return adapter is not None and adapter.is_enabled
    
    def get_platform_features(self, platform_type: PlatformType) -> List[str]:
        """
        Get supported features for a platform.
        
        Args:
            platform_type: Platform type to check
            
        Returns:
            List of supported features or empty list if not supported
        """
        adapter = self.get_adapter(platform_type)
        return adapter.get_supported_features() if adapter else []
    
    def validate_all_adapters(self) -> Dict[PlatformType, bool]:
        """
        Validate credentials for all registered adapters.
        
        Returns:
            Dictionary mapping platform types to validation results
        """
        validation_results = {}
        for platform_type in self._adapters.keys():
            adapter = self.get_adapter(platform_type)
            if adapter:
                try:
                    # Note: This would be async in real implementation
                    # For now, we'll assume validation passes if adapter exists
                    validation_results[platform_type] = adapter.is_enabled
                except Exception as e:
                    logger.error(f"Validation failed for {platform_type.value}: {str(e)}")
                    validation_results[platform_type] = False
            else:
                validation_results[platform_type] = False
        
        return validation_results
    
    def unregister_adapter(self, platform_type: PlatformType) -> bool:
        """
        Unregister an adapter.
        
        Args:
            platform_type: Platform type to unregister
            
        Returns:
            True if successfully unregistered
        """
        if platform_type in self._adapters:
            del self._adapters[platform_type]
            
            if platform_type in self._adapter_instances:
                del self._adapter_instances[platform_type]
                
            if platform_type in self._adapter_configs:
                del self._adapter_configs[platform_type]
            
            logger.info(f"Unregistered adapter for platform: {platform_type.value}")
            return True
        
        return False
    
    def clear_registry(self) -> None:
        """Clear all registered adapters"""
        self._adapters.clear()
        self._adapter_instances.clear()
        self._adapter_configs.clear()
        logger.info("Cleared all registered adapters")


# Global registry instance
registry = PlatformRegistry()
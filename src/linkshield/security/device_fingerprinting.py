#!/usr/bin/env python3
"""
LinkShield Backend Device Fingerprinting Service

Service for generating and validating device fingerprints to detect
session hijacking and unauthorized access attempts.
"""

import hashlib
import json
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class DeviceFingerprintingService:
    """
    Service for device fingerprinting and validation.
    
    Generates unique device fingerprints based on browser and system characteristics
    to help detect session hijacking and unauthorized access attempts.
    """
    
    def __init__(self):
        """Initialize the device fingerprinting service."""
        self.logger = logger
        
        # Weights for different fingerprint components
        self.component_weights = {
            'user_agent': 0.3,
            'screen_resolution': 0.2,
            'timezone': 0.15,
            'language': 0.15,
            'platform': 0.1,
            'plugins': 0.05,
            'canvas': 0.05
        }
    
    def generate_fingerprint(self, fingerprint_data: Dict[str, Any]) -> str:
        """
        Generate a device fingerprint from provided data.
        
        Args:
            fingerprint_data: Dictionary containing device characteristics
            
        Returns:
            Hexadecimal fingerprint string
        """
        try:
            # Normalize and extract key components
            normalized_data = self._normalize_fingerprint_data(fingerprint_data)
            
            # Create fingerprint string
            fingerprint_string = json.dumps(normalized_data, sort_keys=True)
            
            # Generate hash
            fingerprint_hash = hashlib.sha256(fingerprint_string.encode()).hexdigest()
            
            self.logger.debug(f"Generated fingerprint: {fingerprint_hash[:16]}...")
            return fingerprint_hash
            
        except Exception as e:
            self.logger.error(f"Error generating fingerprint: {e}")
            # Return a default fingerprint based on minimal data
            return self._generate_fallback_fingerprint(fingerprint_data)
    
    def validate_fingerprint(
        self, 
        stored_fingerprint: str, 
        current_fingerprint_data: Dict[str, Any],
        tolerance: float = 0.8
    ) -> Tuple[bool, float]:
        """
        Validate a current fingerprint against a stored one.
        
        Args:
            stored_fingerprint: Previously stored fingerprint
            current_fingerprint_data: Current device data
            tolerance: Similarity threshold (0.0 to 1.0)
            
        Returns:
            Tuple of (is_valid, similarity_score)
        """
        try:
            current_fingerprint = self.generate_fingerprint(current_fingerprint_data)
            similarity = self._calculate_fingerprint_similarity(
                stored_fingerprint, 
                current_fingerprint,
                current_fingerprint_data
            )
            
            is_valid = similarity >= tolerance
            
            self.logger.debug(
                f"Fingerprint validation: similarity={similarity:.3f}, "
                f"valid={is_valid}, tolerance={tolerance}"
            )
            
            return is_valid, similarity
            
        except Exception as e:
            self.logger.error(f"Error validating fingerprint: {e}")
            return False, 0.0
    
    def detect_suspicious_changes(
        self, 
        old_data: Dict[str, Any], 
        new_data: Dict[str, Any]
    ) -> List[str]:
        """
        Detect suspicious changes between fingerprint data.
        
        Args:
            old_data: Previous fingerprint data
            new_data: Current fingerprint data
            
        Returns:
            List of suspicious change indicators
        """
        suspicious_changes = []
        
        try:
            # Check for major user agent changes
            if self._is_major_user_agent_change(
                old_data.get('user_agent', ''), 
                new_data.get('user_agent', '')
            ):
                suspicious_changes.append('major_user_agent_change')
            
            # Check for screen resolution changes
            if self._is_suspicious_resolution_change(
                old_data.get('screen_resolution'), 
                new_data.get('screen_resolution')
            ):
                suspicious_changes.append('screen_resolution_change')
            
            # Check for timezone changes
            if old_data.get('timezone') != new_data.get('timezone'):
                suspicious_changes.append('timezone_change')
            
            # Check for platform changes
            if old_data.get('platform') != new_data.get('platform'):
                suspicious_changes.append('platform_change')
            
            # Check for language changes
            if old_data.get('language') != new_data.get('language'):
                suspicious_changes.append('language_change')
                
        except Exception as e:
            self.logger.error(f"Error detecting suspicious changes: {e}")
            suspicious_changes.append('analysis_error')
        
        return suspicious_changes
    
    def _normalize_fingerprint_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize fingerprint data for consistent hashing."""
        normalized = {}
        
        # User agent (simplified)
        user_agent = data.get('user_agent', '')
        normalized['user_agent'] = self._normalize_user_agent(user_agent)
        
        # Screen resolution
        screen_res = data.get('screen_resolution', '')
        normalized['screen_resolution'] = str(screen_res).lower()
        
        # Timezone
        timezone_val = data.get('timezone', '')
        normalized['timezone'] = str(timezone_val)
        
        # Language
        language = data.get('language', '')
        normalized['language'] = str(language).lower()
        
        # Platform
        platform = data.get('platform', '')
        normalized['platform'] = str(platform).lower()
        
        # Plugins (if available)
        plugins = data.get('plugins', [])
        if isinstance(plugins, list):
            normalized['plugins'] = sorted([str(p).lower() for p in plugins])
        else:
            normalized['plugins'] = []
        
        # Canvas fingerprint (if available)
        canvas = data.get('canvas', '')
        normalized['canvas'] = str(canvas)
        
        return normalized
    
    def _normalize_user_agent(self, user_agent: str) -> str:
        """Normalize user agent string for fingerprinting."""
        if not user_agent:
            return ''
        
        # Extract major browser and version info
        ua_lower = user_agent.lower()
        
        # Identify browser
        if 'chrome' in ua_lower:
            browser = 'chrome'
        elif 'firefox' in ua_lower:
            browser = 'firefox'
        elif 'safari' in ua_lower and 'chrome' not in ua_lower:
            browser = 'safari'
        elif 'edge' in ua_lower:
            browser = 'edge'
        else:
            browser = 'other'
        
        # Extract OS
        if 'windows' in ua_lower:
            os_type = 'windows'
        elif 'mac' in ua_lower:
            os_type = 'mac'
        elif 'linux' in ua_lower:
            os_type = 'linux'
        elif 'android' in ua_lower:
            os_type = 'android'
        elif 'ios' in ua_lower:
            os_type = 'ios'
        else:
            os_type = 'other'
        
        return f"{browser}_{os_type}"
    
    def _calculate_fingerprint_similarity(
        self, 
        fp1: str, 
        fp2: str, 
        current_data: Dict[str, Any]
    ) -> float:
        """Calculate similarity between two fingerprints."""
        if fp1 == fp2:
            return 1.0
        
        # If fingerprints are completely different, check component similarity
        try:
            # Generate normalized data for stored fingerprint (approximation)
            # In practice, you might want to store the original data
            similarity_score = 0.0
            
            # For now, return a basic similarity based on hash comparison
            # This is a simplified approach
            common_chars = sum(1 for a, b in zip(fp1, fp2) if a == b)
            max_length = max(len(fp1), len(fp2))
            
            if max_length > 0:
                similarity_score = common_chars / max_length
            
            return similarity_score
            
        except Exception as e:
            self.logger.error(f"Error calculating fingerprint similarity: {e}")
            return 0.0
    
    def _generate_fallback_fingerprint(self, data: Dict[str, Any]) -> str:
        """Generate a fallback fingerprint with minimal data."""
        fallback_data = {
            'user_agent': data.get('user_agent', 'unknown'),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        fallback_string = json.dumps(fallback_data, sort_keys=True)
        return hashlib.sha256(fallback_string.encode()).hexdigest()
    
    def _is_major_user_agent_change(self, old_ua: str, new_ua: str) -> bool:
        """Check if user agent change is major (different browser/OS)."""
        if not old_ua or not new_ua:
            return False
        
        old_normalized = self._normalize_user_agent(old_ua)
        new_normalized = self._normalize_user_agent(new_ua)
        
        return old_normalized != new_normalized
    
    def _is_suspicious_resolution_change(
        self, 
        old_res: Optional[str], 
        new_res: Optional[str]
    ) -> bool:
        """Check if screen resolution change is suspicious."""
        if not old_res or not new_res:
            return False
        
        return str(old_res) != str(new_res)
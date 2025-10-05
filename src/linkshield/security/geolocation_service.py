"""
Geolocation Service for Enhanced Session Security

This service provides geolocation-based anomaly detection for session validation,
including impossible travel detection and location-based risk assessment.

Author: LinkShield Security Team
"""

import logging
import math
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
import asyncio
import aiohttp
from geopy.distance import geodesic

logger = logging.getLogger(__name__)


@dataclass
class LocationData:
    """Represents geographical location data"""
    latitude: float
    longitude: float
    country: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    timezone: Optional[str] = None
    accuracy: Optional[float] = None
    timestamp: Optional[datetime] = None


@dataclass
class TravelAnalysis:
    """Results of travel analysis between two locations"""
    distance_km: float
    time_difference_hours: float
    max_possible_speed_kmh: float
    is_impossible: bool
    risk_score: float
    indicators: List[str]


class GeolocationService:
    """
    Service for geolocation-based security analysis and anomaly detection.
    
    Features:
    - IP-based geolocation lookup
    - Impossible travel detection
    - Location-based risk assessment
    - Geographic anomaly detection
    """
    
    def __init__(self):
        self.max_reasonable_speed_kmh = 1000  # Maximum reasonable travel speed (commercial flight)
        self.high_risk_countries = {
            # Countries with higher cybersecurity risks (example list)
            'CN', 'RU', 'KP', 'IR'  # ISO country codes
        }
        self.vpn_detection_enabled = True
        
    async def get_location_from_ip(self, ip_address: str) -> Optional[LocationData]:
        """
        Get geographical location from IP address using external service.
        
        Args:
            ip_address: IP address to geolocate
            
        Returns:
            LocationData object or None if lookup fails
        """
        if not ip_address or ip_address in ['127.0.0.1', 'localhost', '::1']:
            return None
            
        try:
            # Use multiple geolocation services for redundancy
            location = await self._lookup_ip_location(ip_address)
            
            if location:
                location.timestamp = datetime.now(timezone.utc)
                logger.debug(f"Located IP {ip_address} to {location.city}, {location.country}")
                
            return location
            
        except Exception as e:
            logger.error(f"Error getting location for IP {ip_address}: {e}")
            return None
    
    async def _lookup_ip_location(self, ip_address: str) -> Optional[LocationData]:
        """
        Perform IP geolocation lookup using external API.
        
        Note: In production, you would use a real geolocation service like:
        - MaxMind GeoIP2
        - IPinfo.io
        - ipapi.co
        """
        try:
            # Mock implementation - replace with actual geolocation service
            async with aiohttp.ClientSession() as session:
                # Example using ipapi.co (free tier available)
                url = f"http://ipapi.co/{ip_address}/json/"
                
                async with session.get(url, timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if 'latitude' in data and 'longitude' in data:
                            return LocationData(
                                latitude=float(data['latitude']),
                                longitude=float(data['longitude']),
                                country=data.get('country_code'),
                                city=data.get('city'),
                                region=data.get('region'),
                                timezone=data.get('timezone')
                            )
                            
        except Exception as e:
            logger.warning(f"IP lookup failed for {ip_address}: {e}")
            
        return None
    
    def analyze_travel_pattern(
        self, 
        previous_location: LocationData, 
        current_location: LocationData,
        time_between: timedelta
    ) -> TravelAnalysis:
        """
        Analyze travel pattern between two locations to detect impossible travel.
        
        Args:
            previous_location: Previous known location
            current_location: Current location
            time_between: Time elapsed between locations
            
        Returns:
            TravelAnalysis with impossibility assessment
        """
        # Calculate distance between locations
        distance_km = geodesic(
            (previous_location.latitude, previous_location.longitude),
            (current_location.latitude, current_location.longitude)
        ).kilometers
        
        time_hours = time_between.total_seconds() / 3600
        
        # Avoid division by zero
        if time_hours <= 0:
            time_hours = 0.01  # 36 seconds minimum
        
        required_speed = distance_km / time_hours
        
        # Determine if travel is impossible
        is_impossible = required_speed > self.max_reasonable_speed_kmh
        
        # Calculate risk score based on multiple factors
        risk_score = self._calculate_travel_risk(
            distance_km, required_speed, previous_location, current_location
        )
        
        # Generate indicators
        indicators = []
        if is_impossible:
            indicators.append(f"Impossible travel: {required_speed:.0f} km/h required")
        if distance_km > 5000:  # Intercontinental travel
            indicators.append("Intercontinental travel detected")
        if previous_location.country != current_location.country:
            indicators.append("Cross-border travel detected")
        if current_location.country in self.high_risk_countries:
            indicators.append(f"High-risk country: {current_location.country}")
        
        return TravelAnalysis(
            distance_km=distance_km,
            time_difference_hours=time_hours,
            max_possible_speed_kmh=required_speed,
            is_impossible=is_impossible,
            risk_score=risk_score,
            indicators=indicators
        )
    
    def _calculate_travel_risk(
        self, 
        distance_km: float, 
        speed_kmh: float,
        prev_location: LocationData,
        curr_location: LocationData
    ) -> float:
        """
        Calculate risk score for travel pattern (0.0 to 1.0).
        """
        risk_score = 0.0
        
        # Speed-based risk
        if speed_kmh > self.max_reasonable_speed_kmh:
            risk_score += 0.8  # Very high risk for impossible travel
        elif speed_kmh > 800:  # Faster than commercial flight
            risk_score += 0.6
        elif speed_kmh > 300:  # Very fast travel
            risk_score += 0.3
        
        # Distance-based risk
        if distance_km > 10000:  # Very long distance
            risk_score += 0.2
        elif distance_km > 5000:  # Long distance
            risk_score += 0.1
        
        # Country-based risk
        if curr_location.country in self.high_risk_countries:
            risk_score += 0.3
        
        # Cross-border risk
        if prev_location.country != curr_location.country:
            risk_score += 0.1
        
        return min(risk_score, 1.0)
    
    async def detect_location_anomalies(
        self, 
        user_id: str,
        current_ip: str,
        session_history: List[Dict]
    ) -> Dict:
        """
        Detect location-based anomalies for a user session.
        
        Args:
            user_id: User identifier
            current_ip: Current IP address
            session_history: List of previous session locations
            
        Returns:
            Dictionary with anomaly detection results
        """
        current_location = await self.get_location_from_ip(current_ip)
        
        if not current_location:
            return {
                'anomaly_detected': False,
                'risk_score': 0.0,
                'reason': 'Unable to determine location'
            }
        
        anomalies = []
        max_risk_score = 0.0
        
        # Analyze against recent session history
        for session_data in session_history[-5:]:  # Check last 5 sessions
            if 'location' not in session_data or 'timestamp' not in session_data:
                continue
                
            prev_location_data = session_data['location']
            prev_location = LocationData(**prev_location_data)
            
            time_diff = datetime.now(timezone.utc) - session_data['timestamp']
            
            if time_diff.total_seconds() > 0:  # Only analyze past sessions
                analysis = self.analyze_travel_pattern(
                    prev_location, current_location, time_diff
                )
                
                if analysis.is_impossible or analysis.risk_score > 0.5:
                    anomalies.append({
                        'type': 'impossible_travel' if analysis.is_impossible else 'suspicious_travel',
                        'analysis': analysis,
                        'previous_location': f"{prev_location.city}, {prev_location.country}",
                        'current_location': f"{current_location.city}, {current_location.country}"
                    })
                    
                max_risk_score = max(max_risk_score, analysis.risk_score)
        
        return {
            'anomaly_detected': len(anomalies) > 0,
            'risk_score': max_risk_score,
            'anomalies': anomalies,
            'current_location': {
                'latitude': current_location.latitude,
                'longitude': current_location.longitude,
                'country': current_location.country,
                'city': current_location.city,
                'region': current_location.region
            }
        }
    
    def is_high_risk_location(self, location: LocationData) -> bool:
        """
        Check if location is considered high-risk for security.
        """
        if not location or not location.country:
            return False
            
        return location.country in self.high_risk_countries
    
    async def validate_session_location(
        self, 
        session_id: str,
        user_id: str, 
        ip_address: str,
        previous_sessions: List[Dict]
    ) -> Dict:
        """
        Comprehensive location validation for session security.
        
        Args:
            session_id: Current session ID
            user_id: User identifier
            ip_address: Current IP address
            previous_sessions: Historical session data
            
        Returns:
            Validation results with risk assessment
        """
        try:
            # Get current location
            current_location = await self.get_location_from_ip(ip_address)
            
            if not current_location:
                return {
                    'valid': True,  # Don't block if we can't determine location
                    'risk_score': 0.1,
                    'warnings': ['Unable to determine location from IP']
                }
            
            # Detect anomalies
            anomaly_results = await self.detect_location_anomalies(
                user_id, ip_address, previous_sessions
            )
            
            # Determine validation result
            is_valid = True
            warnings = []
            
            if anomaly_results['anomaly_detected']:
                if anomaly_results['risk_score'] > 0.8:
                    is_valid = False
                    warnings.append("High-risk location anomaly detected")
                elif anomaly_results['risk_score'] > 0.5:
                    warnings.append("Suspicious location pattern detected")
            
            if self.is_high_risk_location(current_location):
                warnings.append(f"Access from high-risk country: {current_location.country}")
                anomaly_results['risk_score'] = max(anomaly_results['risk_score'], 0.4)
            
            return {
                'valid': is_valid,
                'risk_score': anomaly_results['risk_score'],
                'warnings': warnings,
                'location': anomaly_results.get('current_location'),
                'anomalies': anomaly_results.get('anomalies', [])
            }
            
        except Exception as e:
            logger.error(f"Error validating session location: {e}")
            return {
                'valid': True,  # Fail open for availability
                'risk_score': 0.0,
                'warnings': ['Location validation error']
            }
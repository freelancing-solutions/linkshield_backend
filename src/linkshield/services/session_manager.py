"""
Session Manager Service

Implements concurrent session limits and enhanced session management for REQ-009.
Provides centralized session management with configurable limits per user role,
automatic termination of oldest sessions, and session conflict notification.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Tuple
from uuid import UUID
import json

from sqlalchemy import select, update, delete, and_, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from linkshield.models.user import User, UserSession, UserRole
from linkshield.models.admin import SessionLimitsConfig
from linkshield.config.settings import get_settings
from linkshield.config.database import get_db_session
from linkshield.security.device_fingerprinting import DeviceFingerprintingService
from linkshield.security.geolocation_service import GeolocationService
from linkshield.services.notification_service import NotificationService


logger = logging.getLogger(__name__)


class SessionConflictError(Exception):
    """Raised when session limit is exceeded and cannot be resolved."""
    pass


class SessionManager:
    """
    Centralized session management service implementing concurrent session limits.
    
    Features:
    - Configurable session limits per user role
    - Automatic termination of oldest sessions when limit exceeded
    - Session conflict notification to users
    - Administrative override capability
    - Enhanced session tracking and validation
    """
    
    def __init__(self, db_session: Optional[AsyncSession] = None):
        """
        Initialize session manager with security services.
        
        Args:
            db_session: Optional database session. If not provided, will create new sessions as needed.
        """
        self.db_session = db_session
        self.settings = get_settings()
        self.notification_service = NotificationService()
        self.device_fingerprinting = DeviceFingerprintingService()
        self.geolocation_service = GeolocationService()
        
        # Role-based session limits (can be overridden by settings)
        self.role_session_limits = {
            UserRole.USER: self.settings.SESSION_MAX_CONCURRENT_SESSIONS,
            UserRole.MODERATOR: self.settings.SESSION_MAX_CONCURRENT_SESSIONS + 2,
            UserRole.ADMIN: self.settings.SESSION_MAX_CONCURRENT_SESSIONS + 5,
            UserRole.SUPER_ADMIN: self.settings.SESSION_MAX_CONCURRENT_SESSIONS + 10,
        }
    
    async def get_db_session(self) -> AsyncSession:
        """Get database session, creating new one if needed."""
        if self.db_session:
            return self.db_session
        return get_db_session()
    
    def get_session_limit_for_user(self, user: User) -> int:
        """
        Get the maximum concurrent session limit for a user based on their role.
        
        Args:
            user: User object
            
        Returns:
            Maximum number of concurrent sessions allowed
        """
        return self.role_session_limits.get(user.role, self.settings.SESSION_MAX_CONCURRENT_SESSIONS)
    
    async def get_active_sessions(self, user_id: UUID) -> List[UserSession]:
        """
        Get all active sessions for a user, ordered by last activity (newest first).
        
        Args:
            user_id: User ID
            
        Returns:
            List of active UserSession objects
        """
        async with self.get_db_session() as session:
            stmt = (
                select(UserSession)
                .where(
                    and_(
                        UserSession.user_id == user_id,
                        UserSession.is_active == True,
                        UserSession.expires_at > datetime.now(timezone.utc)
                    )
                )
                .order_by(desc(UserSession.last_accessed_at))
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())
    
    async def count_active_sessions(self, user_id: UUID) -> int:
        """
        Count active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Number of active sessions
        """
        async with self.get_db_session() as session:
            stmt = (
                select(func.count(UserSession.id))
                .where(
                    and_(
                        UserSession.user_id == user_id,
                        UserSession.is_active == True,
                        UserSession.expires_at > datetime.now(timezone.utc)
                    )
                )
            )
            result = await session.execute(stmt)
            return result.scalar() or 0
    
    async def terminate_oldest_sessions(self, user: User, keep_count: int) -> List[UUID]:
        """
        Terminate the oldest sessions for a user, keeping only the specified number.
        
        Args:
            user: User object
            keep_count: Number of sessions to keep (newest by last activity)
            
        Returns:
            List of terminated session IDs
        """
        active_sessions = await self.get_active_sessions(user.id)
        
        if len(active_sessions) <= keep_count:
            return []
        
        # Sessions are already ordered by last_accessed_at desc, so we want to terminate
        # sessions beyond the keep_count
        sessions_to_terminate = active_sessions[keep_count:]
        terminated_session_ids = []
        
        async with self.get_db_session() as session:
            for user_session in sessions_to_terminate:
                # Mark session as inactive
                stmt = (
                    update(UserSession)
                    .where(UserSession.id == user_session.id)
                    .values(
                        is_active=False,
                        terminated_at=datetime.now(timezone.utc)
                    )
                )
                await session.execute(stmt)
                terminated_session_ids.append(user_session.id)
                
                logger.info(
                    f"Terminated session {user_session.id} for user {user.id} due to concurrent session limit"
                )
            
            await session.commit()
        
        # Notify user about terminated sessions
        if terminated_session_ids:
            await self._notify_session_termination(user, terminated_session_ids)
        
        return terminated_session_ids
    
    async def enforce_session_limit(self, user: User, exclude_session_id: Optional[UUID] = None) -> bool:
        """
        Enforce concurrent session limits for a user.
        
        Args:
            user: User object
            exclude_session_id: Session ID to exclude from count (e.g., current session being created)
            
        Returns:
            True if enforcement was successful, False if limit cannot be enforced
            
        Raises:
            SessionConflictError: If session limit is exceeded and cannot be resolved
        """
        session_limit = self.get_session_limit_for_user(user)
        active_sessions = await self.get_active_sessions(user.id)
        
        # Filter out excluded session if provided
        if exclude_session_id:
            active_sessions = [s for s in active_sessions if s.id != exclude_session_id]
        
        current_count = len(active_sessions)
        
        if current_count < session_limit:
            return True
        
        # Need to terminate oldest sessions
        sessions_to_keep = session_limit - 1  # Make room for new session
        terminated_ids = await self.terminate_oldest_sessions(user, sessions_to_keep)
        
        if terminated_ids:
            logger.info(
                f"Enforced session limit for user {user.id}: terminated {len(terminated_ids)} sessions"
            )
            return True
        
        # If we couldn't terminate any sessions, raise an error
        raise SessionConflictError(
            f"Cannot enforce session limit of {session_limit} for user {user.id}"
        )
    
    async def create_session_with_limit_check(
        self,
        user: User,
        session_token: str,
        refresh_token: Optional[str] = None,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        expires_at: Optional[datetime] = None
    ) -> UserSession:
        """
        Create a new session while enforcing concurrent session limits.
        
        Args:
            user: User object
            session_token: Session token
            refresh_token: Optional refresh token
            device_info: Device information
            ip_address: Client IP address
            user_agent: User agent string
            expires_at: Session expiration time
            
        Returns:
            Created UserSession object
            
        Raises:
            SessionConflictError: If session limit cannot be enforced
        """
        # Enforce session limit before creating new session
        await self.enforce_session_limit(user)
        
        # Set default expiration if not provided
        if expires_at is None:
            expires_at = datetime.now(timezone.utc) + timedelta(
                days=self.settings.SESSION_DURATION_DAYS
            )
        
        # Create new session
        new_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            refresh_token=refresh_token,
            device_info=device_info,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            last_accessed_at=datetime.now(timezone.utc)
        )
        
        async with self.get_db_session() as session:
            session.add(new_session)
            await session.commit()
            await session.refresh(new_session)
        
        logger.info(f"Created new session {new_session.id} for user {user.id}")
        
        # Notify user about new session if enabled
        if self.settings.SESSION_NOTIFICATION_ON_NEW_LOGIN:
            await self._notify_new_session(user, new_session)
        
        return new_session
    
    async def terminate_session(self, session_id: UUID, user_id: Optional[UUID] = None) -> bool:
        """
        Terminate a specific session.
        
        Args:
            session_id: Session ID to terminate
            user_id: Optional user ID for additional validation
            
        Returns:
            True if session was terminated, False if not found
        """
        async with self.get_db_session() as session:
            conditions = [
                UserSession.id == session_id,
                UserSession.is_active == True
            ]
            
            if user_id:
                conditions.append(UserSession.user_id == user_id)
            
            stmt = (
                update(UserSession)
                .where(and_(*conditions))
                .values(
                    is_active=False,
                    terminated_at=datetime.now(timezone.utc)
                )
            )
            
            result = await session.execute(stmt)
            await session.commit()
            
            if result.rowcount > 0:
                logger.info(f"Terminated session {session_id}")
                return True
            
            return False
    
    async def terminate_all_user_sessions(self, user_id: UUID, exclude_session_id: Optional[UUID] = None) -> int:
        """
        Terminate all active sessions for a user.
        
        Args:
            user_id: User ID
            exclude_session_id: Optional session ID to exclude from termination
            
        Returns:
            Number of sessions terminated
        """
        conditions = [
            UserSession.user_id == user_id,
            UserSession.is_active == True
        ]
        
        if exclude_session_id:
            conditions.append(UserSession.id != exclude_session_id)
        
        async with self.get_db_session() as session:
            stmt = (
                update(UserSession)
                .where(and_(*conditions))
                .values(
                    is_active=False,
                    terminated_at=datetime.now(timezone.utc)
                )
            )
            
            result = await session.execute(stmt)
            await session.commit()
            
            terminated_count = result.rowcount
            logger.info(f"Terminated {terminated_count} sessions for user {user_id}")
            
            return terminated_count
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions from the database.
        
        Returns:
            Number of sessions cleaned up
        """
        async with self.get_db_session() as session:
            stmt = (
                update(UserSession)
                .where(
                    and_(
                        UserSession.is_active == True,
                        UserSession.expires_at <= datetime.now(timezone.utc)
                    )
                )
                .values(
                    is_active=False,
                    terminated_at=datetime.now(timezone.utc)
                )
            )
            
            result = await session.execute(stmt)
            await session.commit()
            
            cleaned_count = result.rowcount
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired sessions")
            
            return cleaned_count
    
    async def get_session_statistics(self, user_id: UUID) -> Dict[str, Any]:
        """
        Get session statistics for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Dictionary containing session statistics
        """
        async with self.get_db_session() as session:
            # Active sessions count
            active_count_stmt = (
                select(func.count(UserSession.id))
                .where(
                    and_(
                        UserSession.user_id == user_id,
                        UserSession.is_active == True,
                        UserSession.expires_at > datetime.now(timezone.utc)
                    )
                )
            )
            active_count = await session.scalar(active_count_stmt) or 0
            
            # Total sessions count (all time)
            total_count_stmt = (
                select(func.count(UserSession.id))
                .where(UserSession.user_id == user_id)
            )
            total_count = await session.scalar(total_count_stmt) or 0
            
            # Most recent session
            recent_session_stmt = (
                select(UserSession)
                .where(UserSession.user_id == user_id)
                .order_by(desc(UserSession.created_at))
                .limit(1)
            )
            recent_session = await session.scalar(recent_session_stmt)
            
            return {
                "active_sessions": active_count,
                "total_sessions": total_count,
                "most_recent_session": {
                    "created_at": recent_session.created_at.isoformat() if recent_session else None,
                    "ip_address": recent_session.ip_address if recent_session else None,
                    "device_info": recent_session.device_info if recent_session else None
                } if recent_session else None
            }
    
    async def _notify_session_termination(self, user: User, terminated_session_ids: List[UUID]) -> None:
        """
        Notify user about terminated sessions.
        
        Args:
            user: User object
            terminated_session_ids: List of terminated session IDs
        """
        try:
            message = (
                f"Security Notice: {len(terminated_session_ids)} of your sessions were "
                f"automatically terminated due to concurrent session limits. "
                f"If this was not expected, please review your account security."
            )
            
            await self.notification_service.send_security_notification(
                user=user,
                title="Sessions Terminated",
                message=message,
                notification_type="session_limit_enforcement"
            )
        except Exception as e:
            logger.error(f"Failed to send session termination notification to user {user.id}: {e}")
    
    async def update_session_activity(
        self, 
        session_id: str, 
        fingerprint_data: Optional[Dict] = None,
        ip_address: Optional[str] = None
    ) -> bool:
        """
        Update session activity timestamp and detect potential hijacking.
        
        Args:
            session_id: Session ID to update
            fingerprint_data: Current device fingerprint data
            ip_address: Current IP address
            
        Returns:
            True if session was updated successfully
        """
        try:
            async with self.get_db_session() as db:
                # Get current session data for hijacking detection
                current_session = await db.execute(
                    select(UserSession)
                    .where(UserSession.session_token == session_id)
                )
                session = current_session.scalar_one_or_none()
                
                if not session:
                    logger.warning(f"Session {session_id} not found for activity update")
                    return False
                
                # Detect potential session hijacking
                hijacking_detected = False
                hijacking_indicators = []
                
                if fingerprint_data and ip_address:
                    hijacking_detected, hijacking_indicators = await self._detect_session_hijacking(
                        session, fingerprint_data, ip_address
                    )
                
                # Update session activity
                update_data = {
                    'last_accessed_at': datetime.now(timezone.utc)
                }
                
                # Update IP if provided and different
                if ip_address and ip_address != session.ip_address:
                    update_data['ip_address'] = ip_address
                
                # Handle hijacking if detected
                if hijacking_detected:
                    await self._handle_hijacking_detection(session_id, session.user_id, hijacking_indicators)
                    return False  # Don't update if hijacking detected
                
                result = await db.execute(
                    update(UserSession)
                    .where(UserSession.session_token == session_id)
                    .values(**update_data)
                )
                
                if result.rowcount > 0:
                    await db.commit()
                    logger.debug(f"Updated activity for session {session_id}")
                    return True
                else:
                    logger.warning(f"Failed to update session {session_id}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error updating session activity for {session_id}: {e}")
            return False
    
    async def _detect_session_hijacking(
        self, 
        session: UserSession, 
        current_fingerprint: Dict, 
        current_ip: str
    ) -> Tuple[bool, List[str]]:
        """
        Enhanced session hijacking detection using device fingerprinting and geolocation.
        
        Args:
            session: Current session object
            current_fingerprint: Current device fingerprint
            current_ip: Current IP address
            
        Returns:
            Tuple of (hijacking_detected, list_of_indicators)
        """
        indicators = []
        
        try:
            # Device fingerprint analysis
            if hasattr(session, 'device_fingerprint') and session.device_fingerprint:
                stored_fingerprint = json.loads(session.device_fingerprint)
                
                # Use device fingerprinting service for comparison
                hijacking_result = await self.device_fingerprinting.detect_session_hijacking(
                    stored_fingerprint, current_fingerprint, current_ip
                )
                
                if hijacking_result.is_hijacked:
                    indicators.extend(hijacking_result.indicators)
            
            # Geolocation analysis
            if current_ip and current_ip != session.ip_address:
                current_location = await self.geolocation_service.get_location_from_ip(current_ip)
                
                if current_location and hasattr(session, 'geolocation_data') and session.geolocation_data:
                    try:
                        stored_location_data = json.loads(session.geolocation_data)
                        
                        # Check for impossible travel
                        if all(key in stored_location_data for key in ['latitude', 'longitude', 'timestamp']):
                            from linkshield.security.geolocation_service import LocationData
                            from datetime import datetime
                            
                            stored_location = LocationData(
                                latitude=stored_location_data['latitude'],
                                longitude=stored_location_data['longitude'],
                                country=stored_location_data.get('country'),
                                city=stored_location_data.get('city')
                            )
                            
                            # Calculate time difference
                            stored_time = datetime.fromisoformat(stored_location_data['timestamp'].replace('Z', '+00:00'))
                            time_diff = datetime.now(timezone.utc) - stored_time
                            
                            # Analyze travel pattern
                            travel_analysis = self.geolocation_service.analyze_travel_pattern(
                                stored_location, current_location, time_diff
                            )
                            
                            if travel_analysis.is_impossible:
                                indicators.append(f"Impossible travel detected: {travel_analysis.max_possible_speed_kmh:.0f} km/h required")
                            
                            if travel_analysis.risk_score > 0.7:
                                indicators.append(f"High-risk location change (score: {travel_analysis.risk_score:.2f})")
                                
                    except (json.JSONDecodeError, KeyError, ValueError) as e:
                        logger.warning(f"Error parsing stored location data: {e}")
            
            # IP-based checks
            if current_ip != session.ip_address:
                if not self._is_acceptable_ip_change(session.ip_address, current_ip):
                    indicators.append(f"Suspicious IP change: {session.ip_address} -> {current_ip}")
            
            # Determine if hijacking is detected (require multiple indicators for high confidence)
            hijacking_detected = len(indicators) >= 2 or any("impossible travel" in indicator.lower() for indicator in indicators)
            
            return hijacking_detected, indicators
            
        except Exception as e:
            logger.error(f"Error in hijacking detection: {e}")
            return False, [f"Detection error: {str(e)}"]
    
    def _is_acceptable_ip_change(self, old_ip: str, new_ip: str) -> bool:
        """
        Check if IP address change is acceptable (same subnet, mobile carrier, etc.).
        """
        try:
            import ipaddress
            
            old_addr = ipaddress.ip_address(old_ip)
            new_addr = ipaddress.ip_address(new_ip)
            
            # Same IP
            if old_addr == new_addr:
                return True
            
            # Check if in same /24 subnet (common for home networks)
            old_network = ipaddress.ip_network(f"{old_ip}/24", strict=False)
            if new_addr in old_network:
                return True
            
            # Additional checks for mobile carriers, VPNs, etc. could be added here
            
            return False
        except Exception:
            return False
    
    def _calculate_fingerprint_similarity(self, fp1: Dict, fp2: Dict) -> float:
        """
        Calculate similarity score between two device fingerprints.
        """
        if not fp1 or not fp2:
            return 0.0
        
        # Weight different fingerprint components
        weights = {
            'user_agent': 0.3,
            'screen_resolution': 0.2,
            'timezone': 0.15,
            'language': 0.1,
            'platform': 0.15,
            'canvas_fingerprint': 0.1
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for key, weight in weights.items():
            if key in fp1 and key in fp2:
                if fp1[key] == fp2[key]:
                    total_score += weight
                total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def _detect_impossible_travel(self, session: UserSession, current_location: Dict) -> bool:
        """
        Detect impossible travel based on time and distance between locations.
        """
        # This would require geolocation data and distance calculation
        # Simplified implementation - would need actual geolocation service
        return False
    
    async def _handle_hijacking_detection(
        self, 
        session_id: str, 
        user_id: UUID, 
        indicators: List[str]
    ) -> None:
        """
        Handle detected session hijacking attempt.
        """
        try:
            # Terminate the suspicious session
            await self.terminate_session(UUID(session_id.replace('-', '')[:32].ljust(32, '0')))
            
            # Log security event
            logger.warning(
                f"Session hijacking detected for user {user_id}, session {session_id}. "
                f"Indicators: {', '.join(indicators)}"
            )
            
            # Get user for notification
            async with self.get_db_session() as db:
                user_result = await db.execute(
                    select(User).where(User.id == user_id)
                )
                user = user_result.scalar_one_or_none()
                
                if user:
                    # Send security alert
                    await self.notification_service.send_security_notification(
                        user=user,
                        title="Security Alert: Suspicious Session Activity",
                        message=(
                            f"Suspicious activity detected on your account. "
                            f"Session has been terminated for security. "
                            f"If this was not you, please change your password immediately."
                        ),
                        notification_type="hijacking_detection"
                    )
        
        except Exception as e:
            logger.error(f"Error handling hijacking detection: {e}")
    
    async def _notify_new_session(self, user: User, session: UserSession) -> None:
        """
        Notify user about new session creation.
        
        Args:
            user: User object
            session: New UserSession object
        """
        try:
            message = (
                f"New login detected from {session.ip_address or 'unknown IP'} "
                f"using {session.device_info or 'unknown device'}. "
                f"If this was not you, please secure your account immediately."
            )
            
            await self.notification_service.send_security_notification(
                user=user,
                title="New Login Detected",
                message=message,
                notification_type="new_session_alert"
            )
        except Exception as e:
            logger.error(f"Failed to send new session notification to user {user.id}: {e}")


# Global session manager instance
session_manager = SessionManager()
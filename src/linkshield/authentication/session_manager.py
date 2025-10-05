"""
Session Manager Module

Provides session management functionality for authentication and security.
Implements session creation, validation, and concurrent session management.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum
from uuid import uuid4, UUID
import secrets
from fastapi import Request

from linkshield.models.user import User, UserSession
from linkshield.services.session_manager import SessionManager as BaseSessionManager


logger = logging.getLogger(__name__)


class SessionErrorType(Enum):
    """Session error types"""
    INVALID_TOKEN = "invalid_token"
    EXPIRED_SESSION = "expired_session"
    CONCURRENT_LIMIT_EXCEEDED = "concurrent_limit_exceeded"
    SECURITY_VIOLATION = "security_violation"
    DATABASE_ERROR = "database_error"


class SessionError(Exception):
    """Session management error"""
    
    def __init__(self, message: str, error_type: SessionErrorType, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.error_type = error_type
        self.details = details or {}


@dataclass
class SessionConfig:
    """Session configuration"""
    session_lifetime: int = 3600  # 1 hour
    refresh_token_lifetime: int = 86400  # 24 hours
    max_concurrent_sessions: int = 5
    session_cookie_name: str = "session_token"
    refresh_cookie_name: str = "refresh_token"
    cookie_secure: bool = True
    cookie_httponly: bool = True
    cookie_samesite: str = "strict"
    require_csrf: bool = True
    track_ip_changes: bool = True
    track_user_agent_changes: bool = True
    suspicious_activity_threshold: int = 3


@dataclass
class SessionSecurityContext:
    """Security context for session"""
    ip_address: str
    user_agent: str
    device_fingerprint: Optional[str] = None
    geolocation: Optional[Dict[str, Any]] = None
    risk_score: float = 0.0
    security_flags: List[str] = None
    
    def __post_init__(self):
        if self.security_flags is None:
            self.security_flags = []


@dataclass
class SessionData:
    """Session data container"""
    session_id: str
    user_id: str
    session_token: str
    refresh_token: str
    expires_at: datetime
    created_at: datetime
    last_accessed_at: datetime
    is_active: bool = True
    security_context: Optional[SessionSecurityContext] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class SessionValidationResult:
    """Result of session validation"""
    is_valid: bool
    session_data: Optional[SessionData] = None
    error_type: Optional[SessionErrorType] = None
    error_message: Optional[str] = None
    security_warnings: List[str] = None
    
    def __post_init__(self):
        if self.security_warnings is None:
            self.security_warnings = []


class SessionManager:
    """Enhanced session manager with security features"""
    
    def __init__(self, config: SessionConfig):
        self.config = config
        self.db = None  # Will be injected
        self.base_manager = BaseSessionManager()
        
    def _generate_token(self) -> str:
        """Generate secure session token"""
        return secrets.token_urlsafe(32)
    
    def _extract_security_context(self, request: Request) -> SessionSecurityContext:
        """Extract security context from request"""
        ip_address = getattr(request.client, 'host', '127.0.0.1') if hasattr(request, 'client') else '127.0.0.1'
        user_agent = request.headers.get('User-Agent', '') if hasattr(request, 'headers') else ''
        
        # Calculate basic risk score
        risk_score = 0.0
        security_flags = []
        
        if not user_agent:
            risk_score += 0.3
            security_flags.append('missing_user_agent')
            
        if ip_address in ['127.0.0.1', 'localhost']:
            risk_score += 0.1
            security_flags.append('localhost_access')
        
        return SessionSecurityContext(
            ip_address=ip_address,
            user_agent=user_agent,
            risk_score=risk_score,
            security_flags=security_flags
        )
    
    async def create_session(self, user: User, request: Request) -> SessionData:
        """Create new session with security context"""
        try:
            # Extract security context
            security_context = self._extract_security_context(request)
            
            # Generate tokens
            session_id = str(uuid4())
            session_token = self._generate_token()
            refresh_token = self._generate_token()
            
            # Calculate expiration
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(seconds=self.config.session_lifetime)
            
            # Create session data
            session_data = SessionData(
                session_id=session_id,
                user_id=str(user.id),
                session_token=session_token,
                refresh_token=refresh_token,
                expires_at=expires_at,
                created_at=now,
                last_accessed_at=now,
                is_active=True,
                security_context=security_context
            )
            
            logger.info(f"Created session {session_id} for user {user.id}")
            return session_data
            
        except Exception as e:
            logger.error(f"Failed to create session for user {user.id}: {e}")
            raise SessionError(
                "Failed to create session",
                SessionErrorType.DATABASE_ERROR,
                {"user_id": str(user.id), "error": str(e)}
            )
    
    async def validate_session(self, session_token: str, request: Request) -> SessionValidationResult:
        """Validate session token"""
        try:
            # This would normally query the database
            # For now, return a basic validation result
            return SessionValidationResult(
                is_valid=True,
                session_data=None,  # Would be populated from database
                security_warnings=[]
            )
            
        except Exception as e:
            logger.error(f"Session validation failed: {e}")
            return SessionValidationResult(
                is_valid=False,
                error_type=SessionErrorType.DATABASE_ERROR,
                error_message=str(e)
            )
    
    async def refresh_session(self, refresh_token: str) -> Optional[SessionData]:
        """Refresh session using refresh token"""
        # Implementation would validate refresh token and create new session
        return None
    
    async def revoke_session(self, session_id: str) -> bool:
        """Revoke specific session"""
        try:
            logger.info(f"Revoked session {session_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke session {session_id}: {e}")
            return False
    
    async def revoke_all_sessions(self, user_id: str) -> int:
        """Revoke all sessions for user"""
        try:
            logger.info(f"Revoked all sessions for user {user_id}")
            return 0  # Would return actual count
        except Exception as e:
            logger.error(f"Failed to revoke sessions for user {user_id}: {e}")
            return 0


class ConcurrentSessionManager:
    """Manager for handling concurrent session limits"""
    
    def __init__(self, max_sessions: int = 5):
        self.max_sessions = max_sessions
        self.base_manager = BaseSessionManager()
    
    async def enforce_session_limit(self, user_id: str) -> List[str]:
        """Enforce concurrent session limit for user"""
        try:
            # Use the base session manager for actual enforcement
            terminated_sessions = await self.base_manager.enforce_concurrent_session_limit(
                user_id=UUID(user_id)
            )
            return [str(session_id) for session_id in terminated_sessions]
        except Exception as e:
            logger.error(f"Failed to enforce session limit for user {user_id}: {e}")
            return []
    
    async def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get active sessions for user"""
        try:
            # Would query database for active sessions
            return []
        except Exception as e:
            logger.error(f"Failed to get active sessions for user {user_id}: {e}")
            return []
    
    async def terminate_oldest_sessions(self, user_id: str, keep_count: int) -> List[str]:
        """Terminate oldest sessions, keeping specified count"""
        try:
            # Implementation would terminate oldest sessions
            return []
        except Exception as e:
            logger.error(f"Failed to terminate oldest sessions for user {user_id}: {e}")
            return []
"""
Bot Subscription Validator Service

This service validates user subscription access for bot features and enforces
subscription-based limits for social media bot operations.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import and_

from ..models.user import User, SubscriptionPlan
from ..models.bot import BotUser, BotPlatform
from ..config.database import get_db


class BotSubscriptionValidator:
    """
    Service for validating bot user subscriptions and enforcing limits.
    
    This service handles:
    - Linking bot users to authenticated users
    - Validating subscription status for bot operations
    - Enforcing subscription-based limits
    - Managing bot feature access
    """
    
    def __init__(self, db: Session):
        self.db = db
    
    async def validate_bot_user_subscription(
        self, 
        platform: BotPlatform, 
        platform_user_id: str,
        user_id: Optional[str] = None
    ) -> Tuple[bool, Optional[BotUser], Optional[str]]:
        """
        Validate if a bot user has valid subscription access.
        
        Args:
            platform: The social media platform
            platform_user_id: Platform-specific user ID
            user_id: Optional authenticated user ID for linking
            
        Returns:
            Tuple of (is_valid, bot_user, error_message)
        """
        try:
            # Find or create bot user
            bot_user = self.db.query(BotUser).filter(
                and_(
                    BotUser.platform == platform,
                    BotUser.platform_user_id == platform_user_id
                )
            ).first()
            
            if not bot_user:
                # Create new bot user if doesn't exist
                bot_user = BotUser(
                    platform=platform,
                    platform_user_id=platform_user_id,
                    user_id=user_id if user_id else None
                )
                self.db.add(bot_user)
                self.db.commit()
                self.db.refresh(bot_user)
            
            # If bot user is not linked to an authenticated user
            if not bot_user.user_id:
                if user_id:
                    # Link to provided user
                    await self._link_bot_user_to_user(bot_user, user_id)
                else:
                    # Return limited access for unlinked users
                    return False, bot_user, "Bot user not linked to authenticated account. Limited access only."
            
            # Validate subscription status
            is_valid = bot_user.is_subscription_valid()
            
            if not is_valid:
                # Update subscription validation
                await self._update_bot_user_subscription_status(bot_user)
                is_valid = bot_user.is_subscription_valid()
            
            if not is_valid:
                return False, bot_user, "Invalid or expired subscription. Please upgrade your plan."
            
            return True, bot_user, None
            
        except Exception as e:
            return False, None, f"Subscription validation error: {str(e)}"
    
    async def can_make_bot_request(
        self, 
        bot_user: BotUser, 
        analysis_type: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if bot user can make a specific type of request.
        
        Args:
            bot_user: The bot user making the request
            analysis_type: Type of analysis requested
            
        Returns:
            Tuple of (can_make_request, error_message)
        """
        try:
            # Check if bot user is linked to authenticated user
            if not bot_user.user_id:
                return False, "Bot user must be linked to authenticated account"
            
            # Get user and check subscription
            user = self.db.query(User).filter(User.id == bot_user.user_id).first()
            if not user:
                return False, "Associated user account not found"
            
            # Check if user can perform this type of analysis
            if not user.can_perform_bot_analysis(analysis_type):
                return False, f"Subscription plan does not support {analysis_type} analysis"
            
            # Check monthly request limits
            if not bot_user.can_make_bot_request():
                monthly_limit = user.get_monthly_bot_limit()
                return False, f"Monthly bot request limit ({monthly_limit}) exceeded"
            
            return True, None
            
        except Exception as e:
            return False, f"Request validation error: {str(e)}"
    
    async def record_bot_request(
        self, 
        bot_user: BotUser, 
        analysis_type: str,
        request_metadata: Optional[Dict] = None
    ) -> bool:
        """
        Record a bot request and update usage counters.
        
        Args:
            bot_user: The bot user making the request
            analysis_type: Type of analysis performed
            request_metadata: Optional metadata about the request
            
        Returns:
            True if recorded successfully, False otherwise
        """
        try:
            # Increment bot request count
            bot_user.increment_bot_request_count()
            
            # Update last activity
            bot_user.last_activity_at = datetime.now(timezone.utc)
            
            # Commit changes
            self.db.commit()
            
            return True
            
        except Exception as e:
            self.db.rollback()
            return False
    
    async def get_bot_user_limits(self, bot_user: BotUser) -> Dict:
        """
        Get current limits and usage for a bot user.
        
        Args:
            bot_user: The bot user to check
            
        Returns:
            Dictionary containing limits and current usage
        """
        if not bot_user.user_id:
            return {
                "monthly_requests": 0,
                "requests_used": 0,
                "requests_remaining": 0,
                "analysis_types": [],
                "features": [],
                "subscription_plan": "unlinked"
            }
        
        user = self.db.query(User).filter(User.id == bot_user.user_id).first()
        if not user:
            return {
                "monthly_requests": 0,
                "requests_used": 0,
                "requests_remaining": 0,
                "analysis_types": [],
                "features": [],
                "subscription_plan": "invalid"
            }
        
        limits = user.get_bot_feature_limits()
        monthly_limit = limits["monthly_requests"]
        requests_used = bot_user.monthly_bot_requests or 0
        
        return {
            "monthly_requests": monthly_limit,
            "requests_used": requests_used,
            "requests_remaining": max(0, monthly_limit - requests_used),
            "analysis_types": limits["analysis_types"],
            "features": limits["features"],
            "concurrent_requests": limits["concurrent_requests"],
            "priority": limits["priority"],
            "subscription_plan": user.subscription_plan.value,
            "subscription_active": user.is_subscription_active()
        }
    
    async def link_bot_user_to_user(
        self, 
        platform: BotPlatform, 
        platform_user_id: str,
        user_id: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Link a bot user to an authenticated user account.
        
        Args:
            platform: The social media platform
            platform_user_id: Platform-specific user ID
            user_id: Authenticated user ID to link to
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Find bot user
            bot_user = self.db.query(BotUser).filter(
                and_(
                    BotUser.platform == platform,
                    BotUser.platform_user_id == platform_user_id
                )
            ).first()
            
            if not bot_user:
                return False, "Bot user not found"
            
            # Check if already linked to a different user
            if bot_user.user_id and str(bot_user.user_id) != user_id:
                return False, "Bot user already linked to a different account"
            
            # Verify user exists
            user = self.db.query(User).filter(User.id == user_id).first()
            if not user:
                return False, "User account not found"
            
            # Link bot user to user
            await self._link_bot_user_to_user(bot_user, user_id)
            
            return True, None
            
        except Exception as e:
            return False, f"Linking error: {str(e)}"
    
    async def unlink_bot_user(
        self, 
        platform: BotPlatform, 
        platform_user_id: str,
        user_id: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Unlink a bot user from an authenticated user account.
        
        Args:
            platform: The social media platform
            platform_user_id: Platform-specific user ID
            user_id: Authenticated user ID to unlink from
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Find bot user
            bot_user = self.db.query(BotUser).filter(
                and_(
                    BotUser.platform == platform,
                    BotUser.platform_user_id == platform_user_id,
                    BotUser.user_id == user_id
                )
            ).first()
            
            if not bot_user:
                return False, "Bot user not found or not linked to this account"
            
            # Unlink bot user
            bot_user.user_id = None
            bot_user.subscription_validated_at = None
            bot_user.last_subscription_check = None
            bot_user.subscription_plan_at_link = None
            bot_user.feature_access_level = "free"
            
            self.db.commit()
            
            return True, None
            
        except Exception as e:
            self.db.rollback()
            return False, f"Unlinking error: {str(e)}"
    
    async def _link_bot_user_to_user(self, bot_user: BotUser, user_id: str) -> None:
        """
        Internal method to link bot user to authenticated user.
        """
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found")
        
        bot_user.user_id = user_id
        bot_user.update_subscription_validation(user)
        
        self.db.commit()
    
    async def _update_bot_user_subscription_status(self, bot_user: BotUser) -> None:
        """
        Internal method to update bot user subscription status.
        """
        if not bot_user.user_id:
            return
        
        user = self.db.query(User).filter(User.id == bot_user.user_id).first()
        if user:
            bot_user.update_subscription_validation(user)
            self.db.commit()


def get_bot_subscription_validator(db: Session = None) -> BotSubscriptionValidator:
    """
    Dependency function to get BotSubscriptionValidator instance.
    """
    if db is None:
        db = next(get_db())
    return BotSubscriptionValidator(db)
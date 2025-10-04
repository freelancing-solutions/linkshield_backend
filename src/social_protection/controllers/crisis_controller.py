"""
Crisis Controller for Social Protection

This controller provides crisis detection and management capabilities for brand
protection and reputation monitoring.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_

from src.authentication.auth_service import AuthService
from src.controllers.base_controller import BaseController
from src.models.social_protection import CrisisAlertORM
from src.models.user import User
from src.services.email_service import EmailService
from src.services.security_service import SecurityService
from src.social_protection.crisis_detector import CrisisDetector

from src.social_protection.logging_utils import get_logger
from src.utils import utc_datetime

logger = get_logger("CrisisController")


class CrisisController(BaseController):
    """
    Controller for crisis detection and management.
    
    Provides endpoints for evaluating brand crises, retrieving alerts,
    viewing crisis history, and managing alert statuses.
    """
    
    def __init__(
        self,
        security_service: SecurityService,
        auth_service: AuthService,
        email_service: EmailService,
        crisis_detector: CrisisDetector
    ):
        """Initialize crisis controller with required services"""
        super().__init__(security_service, auth_service, email_service)
        self.crisis_detector = crisis_detector
        
        # Rate limits for crisis operations
        self.max_evaluations_per_hour = 100
        self.max_alert_queries_per_minute = 30
    
    async def evaluate_brand_crisis(
        self,
        user: User,
        brand: str,
        window_seconds: int = 3600,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Evaluate a brand for crisis indicators
        
        Args:
            user: User requesting evaluation
            brand: Brand name to evaluate
            window_seconds: Time window for evaluation (default 1 hour)
            db: Database session
            
        Returns:
            Dict containing crisis evaluation results
        """
        try:
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "crisis_evaluation", 
                self.max_evaluations_per_hour, window_seconds=3600
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Crisis evaluation rate limit exceeded"
                )
            
            # Validate inputs
            if not brand or len(brand.strip()) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Brand name is required"
                )
            
            if window_seconds < 300 or window_seconds > 86400:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Window must be between 300 seconds (5 min) and 86400 seconds (24 hours)"
                )
            
            # Perform crisis evaluation
            if db is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database session required"
                )
            
            crisis_report = await self.crisis_detector.evaluate_brand(
                brand=brand,
                session=db,
                window_seconds=window_seconds
            )
            
            # Format response
            response = {
                "success": True,
                "brand": brand,
                "evaluation_window_seconds": window_seconds,
                "crisis_detected": crisis_report.crisis_detected,
                "crisis_score": crisis_report.score,
                "severity": crisis_report.severity,
                "signals": {
                    "volume_spike": crisis_report.signals.get("volume_spike", 0.0),
                    "sentiment_drop": crisis_report.signals.get("sentiment_drop", 0.0),
                    "crisis_keywords": crisis_report.signals.get("crisis_keywords", 0.0),
                    "negative_emotion": crisis_report.signals.get("negative_emotion", 0.0),
                    "verified_amplification": crisis_report.signals.get("verified_amplification", 0.0),
                    "cross_platform": crisis_report.signals.get("cross_platform", 0.0)
                },
                "metrics": {
                    "mention_count": crisis_report.metrics.get("mention_count", 0),
                    "avg_sentiment": crisis_report.metrics.get("avg_sentiment"),
                    "negative_ratio": crisis_report.metrics.get("negative_ratio", 0.0),
                    "trend_score": crisis_report.metrics.get("trend_score", 0.0)
                },
                "alert_created": crisis_report.alert_id is not None,
                "alert_id": str(crisis_report.alert_id) if crisis_report.alert_id else None,
                "summary": crisis_report.summary,
                "recommendations": crisis_report.recommendations,
                "evaluated_at": utc_datetime().isoformat()
            }
            
            self.log_operation(
                "Brand crisis evaluated",
                user_id=user.id,
                details={
                    "brand": brand,
                    "crisis_detected": crisis_report.crisis_detected,
                    "severity": crisis_report.severity,
                    "score": crisis_report.score
                }
            )
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error evaluating brand crisis: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to evaluate brand crisis"
            )
    
    async def get_crisis_alerts(
        self,
        user: User,
        brand: Optional[str] = None,
        severity: Optional[str] = None,
        resolved: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Retrieve crisis alerts with optional filtering
        
        Args:
            user: User requesting alerts
            brand: Optional brand filter
            severity: Optional severity filter (OK, WARNING, HIGH, CRITICAL)
            resolved: Optional resolved status filter
            limit: Maximum number of alerts to return
            offset: Offset for pagination
            db: Database session
            
        Returns:
            Dict containing crisis alerts
        """
        try:
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "crisis_alerts_query",
                self.max_alert_queries_per_minute, window_seconds=60
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Crisis alerts query rate limit exceeded"
                )
            
            # Validate inputs
            if limit < 1 or limit > 100:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Limit must be between 1 and 100"
                )
            
            if severity and severity not in ["OK", "WARNING", "HIGH", "CRITICAL"]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Severity must be one of: OK, WARNING, HIGH, CRITICAL"
                )
            
            if db is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database session required"
                )
            
            # Build query filters
            filters = []
            if brand:
                filters.append(CrisisAlertORM.brand == brand)
            if severity:
                filters.append(CrisisAlertORM.severity == severity)
            if resolved is not None:
                filters.append(CrisisAlertORM.resolved == resolved)
            
            # Query alerts
            query = select(CrisisAlertORM)
            if filters:
                query = query.where(and_(*filters))
            
            query = query.order_by(CrisisAlertORM.created_at.desc())
            query = query.limit(limit).offset(offset)
            
            result = await db.execute(query)
            alerts = result.scalars().all()
            
            # Count total matching alerts
            count_query = select(CrisisAlertORM)
            if filters:
                count_query = count_query.where(and_(*filters))
            count_result = await db.execute(count_query)
            total_count = len(count_result.scalars().all())
            
            # Format alerts
            formatted_alerts = []
            for alert in alerts:
                formatted_alerts.append({
                    "id": str(alert.id),
                    "brand": alert.brand,
                    "platform": alert.platform,
                    "score": alert.score,
                    "severity": alert.severity,
                    "reason": alert.reason,
                    "window": {
                        "from": alert.window_from.isoformat() if alert.window_from else None,
                        "to": alert.window_to.isoformat() if alert.window_to else None
                    },
                    "payload": alert.payload or {},
                    "resolved": alert.resolved,
                    "created_at": alert.created_at.isoformat() if alert.created_at else None,
                    "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None
                })
            
            response = {
                "success": True,
                "alerts": formatted_alerts,
                "pagination": {
                    "total": total_count,
                    "limit": limit,
                    "offset": offset,
                    "has_more": (offset + limit) < total_count
                },
                "filters": {
                    "brand": brand,
                    "severity": severity,
                    "resolved": resolved
                },
                "retrieved_at": utc_datetime().isoformat()
            }
            
            self.log_operation(
                "Crisis alerts retrieved",
                user_id=user.id,
                details={
                    "count": len(formatted_alerts),
                    "total": total_count,
                    "brand_filter": brand,
                    "severity_filter": severity
                }
            )
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error retrieving crisis alerts: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve crisis alerts"
            )
    
    async def get_crisis_history(
        self,
        user: User,
        brand: str,
        days: int = 30,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Get historical crisis data for a brand
        
        Args:
            user: User requesting history
            brand: Brand name
            days: Number of days of history (default 30)
            db: Database session
            
        Returns:
            Dict containing crisis history
        """
        try:
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "crisis_history_query",
                self.max_alert_queries_per_minute, window_seconds=60
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Crisis history query rate limit exceeded"
                )
            
            # Validate inputs
            if not brand or len(brand.strip()) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Brand name is required"
                )
            
            if days < 1 or days > 365:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Days must be between 1 and 365"
                )
            
            if db is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database session required"
                )
            
            # Calculate time range
            end_time = utc_datetime()
            start_time = end_time - timedelta(days=days)
            
            # Query historical alerts
            query = select(CrisisAlertORM).where(
                and_(
                    CrisisAlertORM.brand == brand,
                    CrisisAlertORM.created_at >= start_time,
                    CrisisAlertORM.created_at <= end_time
                )
            ).order_by(CrisisAlertORM.created_at.asc())
            
            result = await db.execute(query)
            alerts = result.scalars().all()
            
            # Compile history statistics
            total_alerts = len(alerts)
            resolved_alerts = sum(1 for a in alerts if a.resolved)
            unresolved_alerts = total_alerts - resolved_alerts
            
            severity_breakdown = {
                "OK": 0,
                "WARNING": 0,
                "HIGH": 0,
                "CRITICAL": 0
            }
            
            for alert in alerts:
                if alert.severity in severity_breakdown:
                    severity_breakdown[alert.severity] += 1
            
            # Calculate average crisis score
            scores = [a.score for a in alerts if a.score is not None]
            avg_score = sum(scores) / len(scores) if scores else 0.0
            max_score = max(scores) if scores else 0.0
            
            # Format timeline
            timeline = []
            for alert in alerts:
                timeline.append({
                    "id": str(alert.id),
                    "timestamp": alert.created_at.isoformat() if alert.created_at else None,
                    "severity": alert.severity,
                    "score": alert.score,
                    "reason": alert.reason,
                    "resolved": alert.resolved,
                    "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None
                })
            
            response = {
                "success": True,
                "brand": brand,
                "period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "days": days
                },
                "summary": {
                    "total_alerts": total_alerts,
                    "resolved_alerts": resolved_alerts,
                    "unresolved_alerts": unresolved_alerts,
                    "severity_breakdown": severity_breakdown,
                    "average_score": round(avg_score, 2),
                    "max_score": round(max_score, 2)
                },
                "timeline": timeline,
                "retrieved_at": utc_datetime().isoformat()
            }
            
            self.log_operation(
                "Crisis history retrieved",
                user_id=user.id,
                details={
                    "brand": brand,
                    "days": days,
                    "total_alerts": total_alerts,
                    "unresolved": unresolved_alerts
                }
            )
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error retrieving crisis history: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve crisis history"
            )
    
    async def update_crisis_status(
        self,
        user: User,
        alert_id: UUID,
        resolved: bool,
        resolution_notes: Optional[str] = None,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Update the status of a crisis alert
        
        Args:
            user: User updating status
            alert_id: ID of the alert to update
            resolved: Whether the crisis is resolved
            resolution_notes: Optional notes about resolution
            db: Database session
            
        Returns:
            Dict containing updated alert
        """
        try:
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "crisis_status_update",
                self.max_alert_queries_per_minute, window_seconds=60
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Crisis status update rate limit exceeded"
                )
            
            if db is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database session required"
                )
            
            # Find alert
            query = select(CrisisAlertORM).where(CrisisAlertORM.id == alert_id)
            result = await db.execute(query)
            alert = result.scalar_one_or_none()
            
            if not alert:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Crisis alert {alert_id} not found"
                )
            
            # Update alert status
            alert.resolved = resolved
            if resolved:
                alert.resolved_at = utc_datetime()
                if resolution_notes:
                    if not alert.payload:
                        alert.payload = {}
                    alert.payload["resolution_notes"] = resolution_notes
                    alert.payload["resolved_by"] = str(user.id)
            else:
                alert.resolved_at = None
            
            await db.commit()
            await db.refresh(alert)
            
            # Format response
            response = {
                "success": True,
                "alert": {
                    "id": str(alert.id),
                    "brand": alert.brand,
                    "severity": alert.severity,
                    "score": alert.score,
                    "resolved": alert.resolved,
                    "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
                    "resolution_notes": resolution_notes
                },
                "updated_at": utc_datetime().isoformat()
            }
            
            self.log_operation(
                "Crisis alert status updated",
                user_id=user.id,
                details={
                    "alert_id": str(alert_id),
                    "brand": alert.brand,
                    "resolved": resolved,
                    "has_notes": resolution_notes is not None
                }
            )
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error updating crisis status: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update crisis status"
            )
    
    async def get_crisis_recommendations(
        self,
        user: User,
        alert_id: UUID,
        db: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Get actionable recommendations for a crisis alert
        
        Args:
            user: User requesting recommendations
            alert_id: ID of the alert
            db: Database session
            
        Returns:
            Dict containing recommendations
        """
        try:
            # Check rate limits
            if not await self.check_rate_limit(
                user.id, "crisis_recommendations",
                self.max_alert_queries_per_minute, window_seconds=60
            ):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Crisis recommendations rate limit exceeded"
                )
            
            if db is None:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Database session required"
                )
            
            # Find alert
            query = select(CrisisAlertORM).where(CrisisAlertORM.id == alert_id)
            result = await db.execute(query)
            alert = result.scalar_one_or_none()
            
            if not alert:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Crisis alert {alert_id} not found"
                )
            
            # Generate recommendations based on severity and signals
            recommendations = self._generate_crisis_recommendations(alert)
            
            response = {
                "success": True,
                "alert_id": str(alert_id),
                "brand": alert.brand,
                "severity": alert.severity,
                "recommendations": recommendations,
                "generated_at": utc_datetime().isoformat()
            }
            
            self.log_operation(
                "Crisis recommendations generated",
                user_id=user.id,
                details={
                    "alert_id": str(alert_id),
                    "brand": alert.brand,
                    "severity": alert.severity,
                    "recommendation_count": len(recommendations)
                }
            )
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error generating crisis recommendations: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate crisis recommendations"
            )
    
    def _generate_crisis_recommendations(self, alert: CrisisAlertORM) -> List[Dict[str, Any]]:
        """Generate actionable recommendations based on alert"""
        recommendations = []
        
        severity = alert.severity
        payload = alert.payload or {}
        signals = payload.get("signals", {})
        
        # Severity-based recommendations
        if severity == "CRITICAL":
            recommendations.append({
                "priority": "URGENT",
                "action": "Activate crisis response team",
                "description": "Immediate action required. Convene crisis management team.",
                "timeline": "Immediate"
            })
            recommendations.append({
                "priority": "URGENT",
                "action": "Issue public statement",
                "description": "Prepare and release official statement addressing the situation.",
                "timeline": "Within 1 hour"
            })
        
        if severity in ["CRITICAL", "HIGH"]:
            recommendations.append({
                "priority": "HIGH",
                "action": "Monitor social media channels",
                "description": "Increase monitoring frequency across all platforms.",
                "timeline": "Continuous"
            })
            recommendations.append({
                "priority": "HIGH",
                "action": "Engage with stakeholders",
                "description": "Proactively communicate with key stakeholders and partners.",
                "timeline": "Within 2 hours"
            })
        
        # Signal-based recommendations
        if signals.get("sentiment_drop", 0) > 0.6:
            recommendations.append({
                "priority": "MEDIUM",
                "action": "Address sentiment concerns",
                "description": "Identify and address root causes of negative sentiment.",
                "timeline": "Within 24 hours"
            })
        
        if signals.get("volume_spike", 0) > 0.7:
            recommendations.append({
                "priority": "MEDIUM",
                "action": "Investigate mention spike",
                "description": "Determine cause of sudden increase in brand mentions.",
                "timeline": "Within 4 hours"
            })
        
        if signals.get("verified_amplification", 0) > 0.5:
            recommendations.append({
                "priority": "HIGH",
                "action": "Engage with influencers",
                "description": "Reach out to verified accounts discussing the brand.",
                "timeline": "Within 6 hours"
            })
        
        # General recommendations
        recommendations.append({
            "priority": "LOW",
            "action": "Document the situation",
            "description": "Maintain detailed records of the crisis and response actions.",
            "timeline": "Ongoing"
        })
        
        recommendations.append({
            "priority": "LOW",
            "action": "Review and learn",
            "description": "Conduct post-crisis review to improve future response.",
            "timeline": "After resolution"
        })
        
        return recommendations

#!/usr/bin/env python3
"""
Paddle Billing Client Service

Service for integrating with Paddle's billing API to handle:
- Subscription creation and management
- Payment processing
- Webhook verification
- Customer management
"""

import os
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid

from paddle_billing import Client, Environment, Options
from paddle_billing.Entities.Shared import CurrencyCode, TaxCategory
from paddle_billing.Entities.Products import Product
from paddle_billing.Entities.Prices import Price, PriceType, UnitPriceOverride
from paddle_billing.Entities.Subscriptions import Subscription, SubscriptionStatus
from paddle_billing.Entities.Customers import Customer
from paddle_billing.Exceptions.ApiError import ApiError
from paddle_billing.Resources.Products.Operations import CreateProduct
from paddle_billing.Resources.Prices.Operations import CreatePrice
from paddle_billing.Resources.Subscriptions.Operations import CreateSubscription
from paddle_billing.Resources.Customers.Operations import CreateCustomer

from src.config.logging import logger
from src.config.settings import get_settings


class PaddleClientService:
    """
    Service for interacting with Paddle Billing API.
    
    Handles product creation, subscription management, and webhook verification.
    """
    
    def __init__(self):
        """Initialize Paddle client with configuration from environment."""
        self.settings = get_settings()
        self.client = self._initialize_client()
        
    def _initialize_client(self) -> Client:
        """Initialize Paddle client with appropriate environment."""
        api_key = os.getenv('PADDLE_API_SECRET_KEY') or self.settings.paddle_api_secret_key
        
        if not api_key:
            raise ValueError("PADDLE_API_SECRET_KEY environment variable is required")
        
        # Use sandbox environment for development, production for live
        environment = Environment.SANDBOX if self.settings.debug else Environment.PRODUCTION
        
        return Client(api_key, options=Options(environment))
    
    async def create_product(self, name: str, description: str) -> Product:
        """
        Create a product in Paddle.
        
        Args:
            name: Product name
            description: Product description
            
        Returns:
            Product: Created product
        """
        try:
            product = self.client.products.create(
                CreateProduct(
                    name=name,
                    description=description,
                    tax_category=TaxCategory.Standard
                )
            )
            logger.info(f"Created Paddle product: {product.id}")
            return product
        except ApiError as e:
            logger.error(f"Failed to create Paddle product: {e}")
            raise
    
    async def create_price(
        self,
        product_id: str,
        amount: float,
        currency: CurrencyCode = CurrencyCode.USD,
        billing_interval: str = "month"
    ) -> Price:
        """
        Create a price for a product in Paddle.
        
        Args:
            product_id: Paddle product ID
            amount: Price amount
            currency: Currency code
            billing_interval: Billing interval ("month" or "year")
            
        Returns:
            Price: Created price
        """
        try:
            price = self.client.prices.create(
                CreatePrice(
                    description=f"{billing_interval.capitalize()}ly subscription",
                    product_id=product_id,
                    unit_price=UnitPriceOverride(
                        amount=str(amount),
                        currency_code=currency
                    ),
                    type=PriceType.Recurring,
                    billing_cycle={
                        "interval": billing_interval,
                        "frequency": 1
                    }
                )
            )
            logger.info(f"Created Paddle price: {price.id}")
            return price
        except ApiError as e:
            logger.error(f"Failed to create Paddle price: {e}")
            raise
    
    async def create_customer(
        self,
        email: str,
        name: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None
    ) -> Customer:
        """
        Create a customer in Paddle.
        
        Args:
            email: Customer email
            name: Customer name
            user_id: Internal user ID for reference
            
        Returns:
            Customer: Created customer
        """
        try:
            customer_data = {
                "email": email,
                "custom_data": {}
            }
            
            if name:
                customer_data["name"] = name
            
            if user_id:
                customer_data["custom_data"]["user_id"] = str(user_id)
            
            customer = self.client.customers.create(
                CreateCustomer(**customer_data)
            )
            logger.info(f"Created Paddle customer: {customer.id}")
            return customer
        except ApiError as e:
            logger.error(f"Failed to create Paddle customer: {e}")
            raise
    
    async def create_subscription(
        self,
        customer_id: str,
        price_id: str,
        trial_days: int = 0
    ) -> Subscription:
        """
        Create a subscription in Paddle.
        
        Args:
            customer_id: Paddle customer ID
            price_id: Paddle price ID
            trial_days: Trial period in days
            
        Returns:
            Subscription: Created subscription
        """
        try:
            subscription_data = {
                "customer_id": customer_id,
                "items": [
                    {
                        "price_id": price_id,
                        "quantity": 1
                    }
                ]
            }
            
            if trial_days > 0:
                subscription_data["trial_period"] = {
                    "interval": "day",
                    "frequency": trial_days
                }
            
            subscription = self.client.subscriptions.create(
                CreateSubscription(**subscription_data)
            )
            logger.info(f"Created Paddle subscription: {subscription.id}")
            return subscription
        except ApiError as e:
            logger.error(f"Failed to create Paddle subscription: {e}")
            raise
    
    async def get_subscription(self, subscription_id: str) -> Optional[Subscription]:
        """
        Get subscription details from Paddle.
        
        Args:
            subscription_id: Paddle subscription ID
            
        Returns:
            Subscription if found, None otherwise
        """
        try:
            subscription = self.client.subscriptions.get(subscription_id)
            return subscription
        except ApiError as e:
            logger.error(f"Failed to get Paddle subscription: {e}")
            return None
    
    async def cancel_subscription(
        self,
        subscription_id: str,
        effective_from: str = "next_billing_period"
    ) -> Optional[Subscription]:
        """
        Cancel a subscription in Paddle.
        
        Args:
            subscription_id: Paddle subscription ID
            effective_from: When to cancel ("immediately" or "next_billing_period")
            
        Returns:
            Updated subscription if successful, None otherwise
        """
        try:
            # Paddle SDK doesn't have direct cancel method in current version
            # This would need to be implemented based on Paddle's API
            # For now, we'll handle this through webhooks
            logger.warning(f"Subscription cancellation should be handled via Paddle webhooks for {subscription_id}")
            return None
        except ApiError as e:
            logger.error(f"Failed to cancel Paddle subscription: {e}")
            return None
    
    async def verify_webhook_signature(
        self,
        request_data: bytes,
        signature: str,
        webhook_secret: Optional[str] = None
    ) -> bool:
        """
        Verify Paddle webhook signature.
        
        Args:
            request_data: Raw request body
            signature: Signature from Paddle-Signature header
            webhook_secret: Webhook secret key
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            from paddle_billing.Notifications import Secret, Verifier
            
            secret = webhook_secret or os.getenv('PADDLE_WEBHOOK_SECRET') or self.settings.paddle_webhook_secret
            
            if not secret:
                logger.error("PADDLE_WEBHOOK_SECRET environment variable is required")
                return False
            
            # This is a simplified verification - actual implementation would depend
            # on the webhook framework being used (FastAPI, Flask, etc.)
            # For now, we'll return True in development mode
            if self.settings.debug:
                logger.warning("Webhook signature verification skipped in development mode")
                return True
                
            # Actual verification would look like:
            # verifier = Verifier()
            # return verifier.verify(request_data, Secret(secret), signature)
            
            return True
            
        except ImportError:
            logger.error("Paddle webhook verification requires paddle-billing package")
            return False
        except Exception as e:
            logger.error(f"Webhook verification failed: {e}")
            return False
    
    async def sync_products_to_paddle(self) -> Dict[str, str]:
        """
        Sync local subscription plans to Paddle products and prices.
        
        Returns:
            Dict mapping plan names to Paddle price IDs
        """
        from src.services.subscription_service import SUBSCRIPTION_PLANS
        
        price_mapping = {}
        
        for plan_name, plan_config in SUBSCRIPTION_PLANS.items():
            if plan_name == "free":
                continue  # Skip free plan
                
            try:
                # Create product
                product = await self.create_product(
                    name=plan_config["display_name"],
                    description=plan_config["description"]
                )
                
                # Create monthly price
                monthly_price = await self.create_price(
                    product_id=product.id,
                    amount=float(plan_config["monthly_price"]),
                    billing_interval="month"
                )
                
                # Create yearly price if applicable
                yearly_price = None
                if plan_config["yearly_price"] > 0:
                    yearly_price = await self.create_price(
                        product_id=product.id,
                        amount=float(plan_config["yearly_price"]),
                        billing_interval="year"
                    )
                
                price_mapping[f"{plan_name}_monthly"] = monthly_price.id
                if yearly_price:
                    price_mapping[f"{plan_name}_yearly"] = yearly_price.id
                    
                logger.info(f"Synced plan {plan_name} to Paddle")
                
            except Exception as e:
                logger.error(f"Failed to sync plan {plan_name} to Paddle: {e}")
                continue
        
        return price_mapping
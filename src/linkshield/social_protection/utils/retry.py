#!/usr/bin/env python3
"""
Retry Utilities

Provides retry decorators with exponential backoff for handling transient failures.
"""

import asyncio
import functools
from typing import Callable, Type, Tuple, Optional
from linkshield.social_protection.logging_utils import get_logger

logger = get_logger("RetryUtils")


def async_retry(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable] = None
):
    """
    Decorator for retrying async functions with exponential backoff.
    
    Args:
        max_attempts: Maximum number of retry attempts
        initial_delay: Initial delay in seconds before first retry
        max_delay: Maximum delay in seconds between retries
        exponential_base: Base for exponential backoff calculation
        exceptions: Tuple of exception types to catch and retry
        on_retry: Optional callback function called on each retry
        
    Returns:
        Decorated function with retry logic
        
    Example:
        @async_retry(max_attempts=3, initial_delay=1.0, exceptions=(ConnectionError,))
        async def fetch_data():
            # Your async code here
            pass
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            attempt = 0
            delay = initial_delay
            
            while attempt < max_attempts:
                try:
                    return await func(*args, **kwargs)
                    
                except exceptions as e:
                    attempt += 1
                    
                    if attempt >= max_attempts:
                        logger.error(
                            f"Max retry attempts ({max_attempts}) reached for {func.__name__}",
                            error=str(e),
                            attempts=attempt
                        )
                        raise
                    
                    # Calculate delay with exponential backoff
                    current_delay = min(delay, max_delay)
                    
                    logger.warning(
                        f"Retry attempt {attempt}/{max_attempts} for {func.__name__}",
                        error=str(e),
                        delay_seconds=current_delay,
                        next_attempt=attempt + 1
                    )
                    
                    # Call retry callback if provided
                    if on_retry:
                        try:
                            if asyncio.iscoroutinefunction(on_retry):
                                await on_retry(attempt, e, current_delay)
                            else:
                                on_retry(attempt, e, current_delay)
                        except Exception as callback_error:
                            logger.error(
                                f"Error in retry callback: {str(callback_error)}"
                            )
                    
                    # Wait before retrying
                    await asyncio.sleep(current_delay)
                    
                    # Increase delay for next attempt
                    delay *= exponential_base
            
            # This should never be reached, but just in case
            raise RuntimeError(f"Unexpected retry loop exit for {func.__name__}")
        
        return wrapper
    return decorator


def sync_retry(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable] = None
):
    """
    Decorator for retrying synchronous functions with exponential backoff.
    
    Args:
        max_attempts: Maximum number of retry attempts
        initial_delay: Initial delay in seconds before first retry
        max_delay: Maximum delay in seconds between retries
        exponential_base: Base for exponential backoff calculation
        exceptions: Tuple of exception types to catch and retry
        on_retry: Optional callback function called on each retry
        
    Returns:
        Decorated function with retry logic
        
    Example:
        @sync_retry(max_attempts=3, initial_delay=1.0, exceptions=(ConnectionError,))
        def fetch_data():
            # Your sync code here
            pass
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import time
            
            attempt = 0
            delay = initial_delay
            
            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                    
                except exceptions as e:
                    attempt += 1
                    
                    if attempt >= max_attempts:
                        logger.error(
                            f"Max retry attempts ({max_attempts}) reached for {func.__name__}",
                            error=str(e),
                            attempts=attempt
                        )
                        raise
                    
                    # Calculate delay with exponential backoff
                    current_delay = min(delay, max_delay)
                    
                    logger.warning(
                        f"Retry attempt {attempt}/{max_attempts} for {func.__name__}",
                        error=str(e),
                        delay_seconds=current_delay,
                        next_attempt=attempt + 1
                    )
                    
                    # Call retry callback if provided
                    if on_retry:
                        try:
                            on_retry(attempt, e, current_delay)
                        except Exception as callback_error:
                            logger.error(
                                f"Error in retry callback: {str(callback_error)}"
                            )
                    
                    # Wait before retrying
                    time.sleep(current_delay)
                    
                    # Increase delay for next attempt
                    delay *= exponential_base
            
            # This should never be reached, but just in case
            raise RuntimeError(f"Unexpected retry loop exit for {func.__name__}")
        
        return wrapper
    return decorator


class RetryConfig:
    """Configuration for retry behavior"""
    
    def __init__(
        self,
        max_attempts: int = 3,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0
    ):
        self.max_attempts = max_attempts
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
    
    def to_dict(self):
        """Convert config to dictionary"""
        return {
            "max_attempts": self.max_attempts,
            "initial_delay": self.initial_delay,
            "max_delay": self.max_delay,
            "exponential_base": self.exponential_base
        }

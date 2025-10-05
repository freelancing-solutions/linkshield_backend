"""
Bot Service Startup Script.

This module provides startup functionality for the bot service,
including command registration, webhook setup, and lifecycle management.
"""

import asyncio
import logging
from typing import Dict, Any

from ..config.settings import settings
from .lifecycle import bot_lifecycle_manager
from .registration import bot_registration_manager, bot_configuration_manager

logger = logging.getLogger(__name__)


async def initialize_bot_service() -> Dict[str, Any]:
    """
    Initialize the complete bot service.
    
    This function handles the complete initialization workflow:
    1. Initialize configuration manager
    2. Initialize registration manager
    3. Register commands and set up webhooks
    4. Start lifecycle management
    
    Returns:
        Dictionary with initialization results
    """
    results = {
        "success": False,
        "initialized_components": [],
        "registered_platforms": [],
        "errors": []
    }
    
    try:
        logger.info("Starting bot service initialization...")
        
        # Step 1: Initialize configuration manager
        try:
            await bot_configuration_manager.initialize()
            results["initialized_components"].append("configuration_manager")
            logger.info("✓ Configuration manager initialized")
        except Exception as e:
            error_msg = f"Configuration manager initialization failed: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)
            return results
        
        # Step 2: Initialize registration manager
        try:
            await bot_registration_manager.initialize()
            results["initialized_components"].append("registration_manager")
            logger.info("✓ Registration manager initialized")
        except Exception as e:
            error_msg = f"Registration manager initialization failed: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)
            return results
        
        # Step 3: Get enabled platforms
        enabled_platforms = await bot_configuration_manager.get_enabled_platforms()
        logger.info(f"Enabled platforms: {enabled_platforms}")
        
        if not enabled_platforms:
            logger.warning("No bot platforms are enabled")
            results["success"] = True  # Not an error, just no platforms enabled
            return results
        
        # Step 4: Register commands and set up webhooks
        try:
            registration_results = await bot_registration_manager.register_all_commands()
            
            for platform, success in registration_results.items():
                if success:
                    results["registered_platforms"].append(platform)
                    logger.info(f"✓ Platform {platform} registered successfully")
                else:
                    error_msg = f"Platform {platform} registration failed"
                    logger.error(error_msg)
                    results["errors"].append(error_msg)
            
            results["initialized_components"].append("command_registration")
            
        except Exception as e:
            error_msg = f"Command registration failed: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)
            return results
        
        # Step 5: Initialize lifecycle manager
        try:
            await bot_lifecycle_manager.initialize()
            results["initialized_components"].append("lifecycle_manager")
            logger.info("✓ Lifecycle manager initialized")
        except Exception as e:
            error_msg = f"Lifecycle manager initialization failed: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)
            return results
        
        # Step 6: Start bot platforms
        try:
            await bot_lifecycle_manager.start_all_bots()
            results["initialized_components"].append("bot_platforms")
            logger.info("✓ Bot platforms started")
        except Exception as e:
            error_msg = f"Bot platform startup failed: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)
            return results
        
        results["success"] = True
        logger.info("🎉 Bot service initialization completed successfully!")
        
        # Log summary
        logger.info(f"Initialized components: {results['initialized_components']}")
        logger.info(f"Registered platforms: {results['registered_platforms']}")
        
        return results
        
    except Exception as e:
        error_msg = f"Bot service initialization failed: {e}"
        logger.error(error_msg)
        results["errors"].append(error_msg)
        return results


async def shutdown_bot_service() -> Dict[str, Any]:
    """
    Shutdown the complete bot service gracefully.
    
    Returns:
        Dictionary with shutdown results
    """
    results = {
        "success": False,
        "shutdown_components": [],
        "errors": []
    }
    
    try:
        logger.info("Starting bot service shutdown...")
        
        # Shutdown lifecycle manager (this will handle platform shutdown)
        try:
            await bot_lifecycle_manager.shutdown()
            results["shutdown_components"].append("lifecycle_manager")
            logger.info("✓ Lifecycle manager shutdown")
        except Exception as e:
            error_msg = f"Lifecycle manager shutdown failed: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)
        
        # Shutdown registration manager
        try:
            await bot_registration_manager.shutdown()
            results["shutdown_components"].append("registration_manager")
            logger.info("✓ Registration manager shutdown")
        except Exception as e:
            error_msg = f"Registration manager shutdown failed: {e}"
            logger.error(error_msg)
            results["errors"].append(error_msg)
        
        results["success"] = True
        logger.info("🏁 Bot service shutdown completed")
        
        return results
        
    except Exception as e:
        error_msg = f"Bot service shutdown failed: {e}"
        logger.error(error_msg)
        results["errors"].append(error_msg)
        return results


async def restart_bot_service() -> Dict[str, Any]:
    """
    Restart the complete bot service.
    
    Returns:
        Dictionary with restart results
    """
    logger.info("Restarting bot service...")
    
    # Shutdown first
    shutdown_results = await shutdown_bot_service()
    
    # Wait a moment
    await asyncio.sleep(2)
    
    # Initialize again
    init_results = await initialize_bot_service()
    
    return {
        "success": shutdown_results["success"] and init_results["success"],
        "shutdown_results": shutdown_results,
        "initialization_results": init_results
    }


async def check_bot_service_health() -> Dict[str, Any]:
    """
    Check the health of the bot service.
    
    Returns:
        Dictionary with health information
    """
    try:
        # Get lifecycle manager status
        status = await bot_lifecycle_manager.get_status()
        health = await bot_lifecycle_manager.get_health_status()
        
        # Get enabled platforms
        enabled_platforms = await bot_configuration_manager.get_enabled_platforms()
        
        # Check each platform's bot info
        platform_info = {}
        for platform in enabled_platforms:
            try:
                bot_info = await bot_registration_manager.get_bot_info(platform)
                platform_info[platform] = {
                    "bot_info_available": bot_info is not None,
                    "bot_info": bot_info
                }
            except Exception as e:
                platform_info[platform] = {
                    "bot_info_available": False,
                    "error": str(e)
                }
        
        return {
            "healthy": health["healthy"],
            "status": status,
            "health": health,
            "enabled_platforms": enabled_platforms,
            "platform_info": platform_info
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "healthy": False,
            "error": str(e)
        }


async def register_commands_only() -> Dict[str, Any]:
    """
    Register bot commands without full service initialization.
    
    Useful for updating commands without restarting the entire service.
    
    Returns:
        Dictionary with registration results
    """
    try:
        logger.info("Registering bot commands...")
        
        # Initialize managers if not already initialized
        if not bot_configuration_manager.is_initialized:
            await bot_configuration_manager.initialize()
        
        if not bot_registration_manager.is_initialized:
            await bot_registration_manager.initialize()
        
        # Register commands
        results = await bot_registration_manager.register_all_commands()
        
        success_count = sum(1 for success in results.values() if success)
        total_count = len(results)
        
        logger.info(f"Command registration completed: {success_count}/{total_count} platforms successful")
        
        return {
            "success": success_count > 0,
            "results": results,
            "successful_platforms": [platform for platform, success in results.items() if success],
            "failed_platforms": [platform for platform, success in results.items() if not success]
        }
        
    except Exception as e:
        error_msg = f"Command registration failed: {e}"
        logger.error(error_msg)
        return {
            "success": False,
            "error": error_msg
        }


def print_bot_service_info():
    """Print bot service configuration information."""
    print("\n" + "="*60)
    print("🤖 LinkShield Bot Service Configuration")
    print("="*60)
    
    print(f"Environment: {settings.ENVIRONMENT}")
    print(f"App URL: {settings.APP_URL}")
    
    print("\n📱 Platform Configuration:")
    platforms = [
        ("Discord", settings.BOT_ENABLE_DISCORD, bool(settings.DISCORD_BOT_TOKEN)),
        ("Telegram", settings.BOT_ENABLE_TELEGRAM, bool(settings.TELEGRAM_BOT_TOKEN)),
        ("Twitter", settings.BOT_ENABLE_TWITTER, bool(settings.TWITTER_BOT_BEARER_TOKEN))
    ]
    
    for platform, enabled, has_token in platforms:
        status = "✅" if enabled and has_token else "❌" if enabled else "⏸️"
        token_status = "✅" if has_token else "❌"
        print(f"  {status} {platform:<10} | Enabled: {enabled:<5} | Token: {token_status}")
    
    print("\n🔗 Webhook Endpoints:")
    base_url = settings.APP_URL.rstrip('/')
    endpoints = [
        ("Discord", f"{base_url}/api/v1/bots/discord/webhook"),
        ("Telegram", f"{base_url}/api/v1/bots/telegram/webhook"),
        ("Twitter", f"{base_url}/api/v1/bots/twitter/webhook")
    ]
    
    for platform, endpoint in endpoints:
        print(f"  {platform:<10}: {endpoint}")
    
    print("\n⚙️ Bot Settings:")
    print(f"  Rate Limit: {settings.BOT_RATE_LIMIT_PER_MINUTE}/minute")
    print(f"  Quick Analysis Timeout: {settings.QUICK_ANALYSIS_TIMEOUT_SECONDS}s")
    print(f"  Max Response Length: {settings.BOT_MAX_RESPONSE_LENGTH}")
    print(f"  Analytics Enabled: {settings.BOT_ENABLE_ANALYTICS}")
    
    print("\n🔒 Security:")
    webhook_secrets = [
        ("Discord", bool(settings.DISCORD_WEBHOOK_SECRET)),
        ("Telegram", bool(settings.TELEGRAM_WEBHOOK_SECRET)),
        ("Twitter", bool(settings.TWITTER_WEBHOOK_SECRET))
    ]
    
    for platform, has_secret in webhook_secrets:
        status = "✅" if has_secret else "❌"
        print(f"  {platform} Webhook Secret: {status}")
    
    print("="*60 + "\n")


# CLI-style functions for manual execution

async def main():
    """Main function for running bot service initialization."""
    print_bot_service_info()
    
    print("🚀 Initializing bot service...")
    results = await initialize_bot_service()
    
    if results["success"]:
        print("✅ Bot service initialized successfully!")
        print(f"Registered platforms: {results['registered_platforms']}")
    else:
        print("❌ Bot service initialization failed!")
        for error in results["errors"]:
            print(f"  - {error}")
    
    return results


if __name__ == "__main__":
    # Run the main initialization
    asyncio.run(main())
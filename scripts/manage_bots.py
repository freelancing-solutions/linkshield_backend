#!/usr/bin/env python3
"""
Bot Management CLI Script.

This script provides command-line tools for managing bot registration,
webhook setup, and service lifecycle.
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.bots.startup import (
    initialize_bot_service,
    shutdown_bot_service,
    restart_bot_service,
    check_bot_service_health,
    register_commands_only,
    print_bot_service_info
)
from src.bots.registration import bot_registration_manager, bot_configuration_manager
from src.bots.lifecycle import bot_lifecycle_manager
from src.config.settings import settings


async def cmd_init(args):
    """Initialize the bot service."""
    print("🚀 Initializing bot service...")
    results = await initialize_bot_service()
    
    if results["success"]:
        print("✅ Bot service initialized successfully!")
        if results["registered_platforms"]:
            print(f"Registered platforms: {', '.join(results['registered_platforms'])}")
        return 0
    else:
        print("❌ Bot service initialization failed!")
        for error in results["errors"]:
            print(f"  - {error}")
        return 1


async def cmd_shutdown(args):
    """Shutdown the bot service."""
    print("🛑 Shutting down bot service...")
    results = await shutdown_bot_service()
    
    if results["success"]:
        print("✅ Bot service shutdown completed!")
        return 0
    else:
        print("❌ Bot service shutdown failed!")
        for error in results["errors"]:
            print(f"  - {error}")
        return 1


async def cmd_restart(args):
    """Restart the bot service."""
    print("🔄 Restarting bot service...")
    results = await restart_bot_service()
    
    if results["success"]:
        print("✅ Bot service restarted successfully!")
        return 0
    else:
        print("❌ Bot service restart failed!")
        if "shutdown_results" in results:
            print("Shutdown errors:")
            for error in results["shutdown_results"].get("errors", []):
                print(f"  - {error}")
        if "initialization_results" in results:
            print("Initialization errors:")
            for error in results["initialization_results"].get("errors", []):
                print(f"  - {error}")
        return 1


async def cmd_status(args):
    """Check bot service status."""
    print("📊 Checking bot service status...")
    
    try:
        health = await check_bot_service_health()
        
        if health.get("healthy", False):
            print("✅ Bot service is healthy")
        else:
            print("❌ Bot service is unhealthy")
        
        if "status" in health:
            status = health["status"]
            print(f"\nOverall Status: {status.get('overall_status', 'unknown')}")
            
            if status.get("startup_time"):
                print(f"Startup Time: {status['startup_time']}")
            
            if status.get("uptime_seconds"):
                uptime_hours = status["uptime_seconds"] / 3600
                print(f"Uptime: {uptime_hours:.1f} hours")
            
            print("\nPlatform Status:")
            for platform, platform_status in status.get("platform_statuses", {}).items():
                print(f"  {platform}: {platform_status}")
        
        if "platform_info" in health:
            print("\nPlatform Bot Info:")
            for platform, info in health["platform_info"].items():
                if info.get("bot_info_available"):
                    bot_info = info.get("bot_info", {})
                    username = bot_info.get("username") or bot_info.get("first_name", "Unknown")
                    print(f"  {platform}: ✅ {username}")
                else:
                    error = info.get("error", "No bot info available")
                    print(f"  {platform}: ❌ {error}")
        
        return 0 if health.get("healthy", False) else 1
        
    except Exception as e:
        print(f"❌ Failed to check status: {e}")
        return 1


async def cmd_register(args):
    """Register bot commands."""
    if args.platform:
        print(f"🔧 Registering commands for {args.platform}...")
        
        # Initialize managers
        await bot_configuration_manager.initialize()
        await bot_registration_manager.initialize()
        
        if args.platform == "discord":
            result = await bot_registration_manager.register_discord_commands()
        elif args.platform == "telegram":
            result = await bot_registration_manager.setup_telegram_webhook()
        elif args.platform == "twitter":
            result = await bot_registration_manager.setup_twitter_webhook()
        else:
            print(f"❌ Unknown platform: {args.platform}")
            return 1
        
        if result:
            print(f"✅ {args.platform} commands registered successfully!")
            return 0
        else:
            print(f"❌ {args.platform} command registration failed!")
            return 1
    else:
        print("🔧 Registering commands for all platforms...")
        results = await register_commands_only()
        
        if results["success"]:
            print("✅ Command registration completed!")
            if results["successful_platforms"]:
                print(f"Successful: {', '.join(results['successful_platforms'])}")
            if results["failed_platforms"]:
                print(f"Failed: {', '.join(results['failed_platforms'])}")
            return 0
        else:
            print("❌ Command registration failed!")
            if "error" in results:
                print(f"  - {results['error']}")
            return 1


async def cmd_info(args):
    """Show bot service configuration information."""
    print_bot_service_info()
    
    # Also show current status if requested
    if args.status:
        print("\n📊 Current Status:")
        await cmd_status(args)
    
    return 0


async def cmd_platform(args):
    """Platform-specific operations."""
    if args.action == "restart":
        print(f"🔄 Restarting platform: {args.name}")
        
        await bot_lifecycle_manager.initialize()
        await bot_lifecycle_manager.restart_platform(args.name)
        
        print(f"✅ Platform {args.name} restart initiated")
        return 0
    
    elif args.action == "info":
        print(f"ℹ️ Platform information: {args.name}")
        
        await bot_configuration_manager.initialize()
        await bot_registration_manager.initialize()
        
        # Get platform config
        config = await bot_configuration_manager.get_platform_config(args.name)
        if config:
            print(f"Enabled: {config.get('enabled', False)}")
            print(f"Features: {list(config.get('features', {}).keys())}")
            print(f"API Endpoint: {config.get('api_endpoint', 'N/A')}")
        else:
            print("❌ Platform configuration not found")
            return 1
        
        # Get bot info
        bot_info = await bot_registration_manager.get_bot_info(args.name)
        if bot_info:
            print(f"Bot Info: {bot_info}")
        else:
            print("❌ Bot info not available")
        
        return 0
    
    else:
        print(f"❌ Unknown platform action: {args.action}")
        return 1


async def cmd_test(args):
    """Test bot functionality."""
    print("🧪 Testing bot functionality...")
    
    # Initialize managers
    await bot_configuration_manager.initialize()
    await bot_registration_manager.initialize()
    
    enabled_platforms = await bot_configuration_manager.get_enabled_platforms()
    
    if not enabled_platforms:
        print("❌ No platforms are enabled")
        return 1
    
    print(f"Testing platforms: {', '.join(enabled_platforms)}")
    
    all_passed = True
    
    for platform in enabled_platforms:
        print(f"\n🔍 Testing {platform}...")
        
        # Test bot info retrieval
        try:
            bot_info = await bot_registration_manager.get_bot_info(platform)
            if bot_info:
                username = bot_info.get("username") or bot_info.get("first_name", "Unknown")
                print(f"  ✅ Bot info: {username}")
            else:
                print(f"  ❌ Bot info not available")
                all_passed = False
        except Exception as e:
            print(f"  ❌ Bot info error: {e}")
            all_passed = False
        
        # Test webhook signature verification (with dummy data)
        try:
            result = await bot_registration_manager.verify_webhook_signature(
                platform, b"test", "test_signature"
            )
            print(f"  ✅ Signature verification: {'working' if result is not None else 'error'}")
        except Exception as e:
            print(f"  ❌ Signature verification error: {e}")
            all_passed = False
    
    if all_passed:
        print("\n✅ All tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed!")
        return 1


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="LinkShield Bot Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/manage_bots.py init                    # Initialize bot service
  python scripts/manage_bots.py status                  # Check status
  python scripts/manage_bots.py register                # Register all commands
  python scripts/manage_bots.py register -p discord    # Register Discord commands only
  python scripts/manage_bots.py platform restart discord  # Restart Discord platform
  python scripts/manage_bots.py test                    # Test bot functionality
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Init command
    subparsers.add_parser("init", help="Initialize bot service")
    
    # Shutdown command
    subparsers.add_parser("shutdown", help="Shutdown bot service")
    
    # Restart command
    subparsers.add_parser("restart", help="Restart bot service")
    
    # Status command
    subparsers.add_parser("status", help="Check bot service status")
    
    # Register command
    register_parser = subparsers.add_parser("register", help="Register bot commands")
    register_parser.add_argument(
        "-p", "--platform",
        choices=["discord", "telegram", "twitter"],
        help="Register commands for specific platform only"
    )
    
    # Info command
    info_parser = subparsers.add_parser("info", help="Show configuration information")
    info_parser.add_argument(
        "-s", "--status",
        action="store_true",
        help="Also show current status"
    )
    
    # Platform command
    platform_parser = subparsers.add_parser("platform", help="Platform-specific operations")
    platform_parser.add_argument(
        "action",
        choices=["restart", "info"],
        help="Action to perform"
    )
    platform_parser.add_argument(
        "name",
        choices=["discord", "telegram", "twitter"],
        help="Platform name"
    )
    
    # Test command
    subparsers.add_parser("test", help="Test bot functionality")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Map commands to functions
    command_map = {
        "init": cmd_init,
        "shutdown": cmd_shutdown,
        "restart": cmd_restart,
        "status": cmd_status,
        "register": cmd_register,
        "info": cmd_info,
        "platform": cmd_platform,
        "test": cmd_test
    }
    
    # Run the command
    try:
        return asyncio.run(command_map[args.command](args))
    except KeyboardInterrupt:
        print("\n⏹️ Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
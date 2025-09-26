#!/usr/bin/env python3
"""Simple test script for bot models."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from bots.models import BotCommand, CommandType
from models.social_protection import PlatformType

def test_bot_command():
    """Test basic BotCommand creation."""
    try:
        command = BotCommand(
            command_type=CommandType.ANALYZE_ACCOUNT,
            platform=PlatformType.TWITTER,
            user_id='12345'
        )
        print('✅ BotCommand created successfully')
        print(f'   Command type: {command.command_type}')
        print(f'   Platform: {command.platform}')
        print(f'   User ID: {command.user_id}')
        return True
    except Exception as e:
        print(f'❌ BotCommand creation failed: {e}')
        return False

def test_serialization():
    """Test BotCommand serialization."""
    try:
        command = BotCommand(
            command_type=CommandType.CHECK_COMPLIANCE,
            platform="telegram",
            user_id='67890',
            parameters={"content": "test content"}
        )
        
        # Test to_dict
        command_dict = command.to_dict()
        print('✅ BotCommand serialization successful')
        print(f'   Serialized: {command_dict}')
        
        # Test from_dict
        restored_command = BotCommand.from_dict(command_dict)
        print('✅ BotCommand deserialization successful')
        print(f'   Restored command type: {restored_command.command_type}')
        return True
    except Exception as e:
        print(f'❌ Serialization test failed: {e}')
        return False

if __name__ == "__main__":
    print("Testing Bot Models...")
    print("=" * 50)
    
    success = True
    success &= test_bot_command()
    success &= test_serialization()
    
    print("=" * 50)
    if success:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed!")
    
    sys.exit(0 if success else 1)
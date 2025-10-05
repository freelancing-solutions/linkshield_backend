#!/usr/bin/env python3
"""
Import Fixer Script for LinkShield Backend

This script fixes import statements in test files to use the new linkshield package structure.
It replaces old src.* imports with linkshield.* imports and removes manual sys.path manipulations.
"""

import os
import re
from pathlib import Path


def fix_imports_in_file(file_path: Path) -> bool:
    """
    Fix import statements in a single file.
    
    Args:
        file_path: Path to the file to fix
        
    Returns:
        bool: True if file was modified, False otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Pattern 1: Replace "from src.module import ..." with "from linkshield.module import ..."
        content = re.sub(r'from src\.([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)', 
                        r'from linkshield.\1', content)
        
        # Pattern 2: Replace "import src.module" with "import linkshield.module"
        content = re.sub(r'import src\.([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)', 
                        r'import linkshield.\1', content)
        
        # Pattern 3: Remove sys.path manipulations for src directory
        content = re.sub(r'sys\.path\.(?:insert|append)\([^)]*["\']src["\'][^)]*\)\s*\n?', '', content)
        content = re.sub(r'sys\.path\.(?:insert|append)\([^)]*src_path[^)]*\)\s*\n?', '', content)
        
        # Pattern 4: Replace "from app import app" with proper linkshield import
        content = re.sub(r'from app import app', 'from linkshield.main import create_app', content)
        
        # Pattern 5: Update TestClient usage to use create_app()
        content = re.sub(r'TestClient\(app\)', 'TestClient(create_app())', content)
        
        # Pattern 6: Remove unused sys import if no longer needed
        lines = content.split('\n')
        has_sys_usage = any('sys.' in line and 'sys.path' not in line for line in lines)
        if not has_sys_usage:
            content = re.sub(r'^import sys\s*\n', '', content, flags=re.MULTILINE)
            content = re.sub(r'^from sys import [^\n]*\n', '', content, flags=re.MULTILINE)
        
        # Only write if content changed
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✓ Fixed imports in {file_path}")
            return True
        else:
            print(f"- No changes needed in {file_path}")
            return False
            
    except Exception as e:
        print(f"✗ Error processing {file_path}: {e}")
        return False


def main():
    """Main function to fix imports in all test files."""
    project_root = Path(__file__).parent.parent
    tests_dir = project_root / "tests"
    
    if not tests_dir.exists():
        print(f"Tests directory not found: {tests_dir}")
        return
    
    print("🔧 Fixing import statements in test files...")
    print(f"📁 Scanning: {tests_dir}")
    
    # Find all Python test files
    test_files = list(tests_dir.rglob("*.py"))
    
    if not test_files:
        print("No Python test files found.")
        return
    
    print(f"📄 Found {len(test_files)} Python files")
    
    modified_count = 0
    for test_file in test_files:
        if fix_imports_in_file(test_file):
            modified_count += 1
    
    print(f"\n✅ Import fixing complete!")
    print(f"📊 Modified {modified_count} out of {len(test_files)} files")
    
    if modified_count > 0:
        print("\n🧪 Next steps:")
        print("1. Run pytest to validate the fixes")
        print("2. Check for any remaining import issues")


if __name__ == "__main__":
    main()
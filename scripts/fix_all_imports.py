#!/usr/bin/env python3
"""
Comprehensive Import Fixer Script for LinkShield Backend

This script fixes import statements in both source and test files to use the new linkshield package structure.
It replaces old src.* imports with linkshield.* imports and removes manual sys.path manipulations.
"""

import os
import re
from pathlib import Path


def fix_imports_in_file(file_path: Path, is_source_file: bool = False) -> bool:
    """
    Fix import statements in a single file.
    
    Args:
        file_path: Path to the file to fix
        is_source_file: True if this is a source file (not a test file)
        
    Returns:
        bool: True if file was modified, False otherwise
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        if is_source_file:
            # For source files: Replace "from src.module" with relative imports or linkshield imports
            # Pattern 1: Replace "from src.module import ..." with "from linkshield.module import ..."
            content = re.sub(r'from src\.([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)', 
                            r'from linkshield.\1', content)
            
            # Pattern 2: Replace "import src.module" with "import linkshield.module"
            content = re.sub(r'import src\.([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)', 
                            r'import linkshield.\1', content)
        else:
            # For test files: Replace "from src.module" with "from linkshield.module"
            content = re.sub(r'from src\.([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)', 
                            r'from linkshield.\1', content)
            
            content = re.sub(r'import src\.([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)', 
                            r'import linkshield.\1', content)
        
        # Common patterns for both source and test files
        
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
            file_type = "source" if is_source_file else "test"
            print(f"✓ Fixed imports in {file_type} file: {file_path}")
            return True
        else:
            file_type = "source" if is_source_file else "test"
            print(f"- No changes needed in {file_type} file: {file_path}")
            return False
            
    except Exception as e:
        print(f"✗ Error processing {file_path}: {e}")
        return False


def main():
    """Main function to fix imports in all source and test files."""
    project_root = Path(__file__).parent.parent
    src_dir = project_root / "src" / "linkshield"
    tests_dir = project_root / "tests"
    
    print("🔧 Fixing import statements in all Python files...")
    
    total_modified = 0
    total_files = 0
    
    # Fix source files
    if src_dir.exists():
        print(f"📁 Scanning source files: {src_dir}")
        source_files = list(src_dir.rglob("*.py"))
        print(f"📄 Found {len(source_files)} source files")
        
        source_modified = 0
        for source_file in source_files:
            total_files += 1
            if fix_imports_in_file(source_file, is_source_file=True):
                source_modified += 1
                total_modified += 1
        
        print(f"📊 Modified {source_modified} out of {len(source_files)} source files")
    else:
        print(f"⚠️  Source directory not found: {src_dir}")
    
    # Fix test files
    if tests_dir.exists():
        print(f"\n📁 Scanning test files: {tests_dir}")
        test_files = list(tests_dir.rglob("*.py"))
        print(f"📄 Found {len(test_files)} test files")
        
        test_modified = 0
        for test_file in test_files:
            total_files += 1
            if fix_imports_in_file(test_file, is_source_file=False):
                test_modified += 1
                total_modified += 1
        
        print(f"📊 Modified {test_modified} out of {len(test_files)} test files")
    else:
        print(f"⚠️  Tests directory not found: {tests_dir}")
    
    print(f"\n✅ Import fixing complete!")
    print(f"📊 Total: Modified {total_modified} out of {total_files} files")
    
    if total_modified > 0:
        print("\n🧪 Next steps:")
        print("1. Run pytest to validate the fixes")
        print("2. Check for any remaining import issues")
        print("3. Verify that all modules can be imported correctly")


if __name__ == "__main__":
    main()
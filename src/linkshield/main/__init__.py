"""
LinkShield Main Module

Exports the main application factory function for creating FastAPI instances.
"""

# Remove the __getattr__ to avoid recursion since parent module handles it
__all__ = ["create_app"]
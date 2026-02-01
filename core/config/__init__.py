"""
Configuration package.

Exposes:
- Settings + get_settings (preferred modern config)
"""

from .config import Settings, get_settings

__all__ = ["Settings", "get_settings"]
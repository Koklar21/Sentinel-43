"""
Configuration package.

Exposes:
- get_settings (from .settings — the preferred modern config module)
"""

from .settings import get_settings

__all__ = [
    "get_settings",
] 
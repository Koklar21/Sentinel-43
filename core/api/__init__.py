"""
Sentinel-43 API Package

Provides FastAPI application entry points,
router registration, and API-level utilities.
"""

# `app` is exposed lazily (PEP 562). Importing it eagerly here made
# `import core.api` -- and therefore `import core.api.middleware.<x>` -- pull in
# the whole application at package-init time. That created a circular import:
#
#   core.middleware.sentinel_firewall
#     -> core.api.middleware.sentinel_firewall_middleware
#       -> core.api  (this file)  -> from .main import app
#         -> core.api.main -> from core.middleware import SentinelFirewall
#           -> core.middleware still mid-__init__  -> ImportError
#
# which the firewall registration block in core/api/main.py used to swallow
# (fail-open, no firewall). With that block now failing closed, the cycle has
# to actually be broken. Nothing in the codebase imports `from core.api import
# app`; `uvicorn core.api.main:app` reads `app` off the module, not the
# package. The lazy hook keeps `from core.api import app` working for any
# external caller without the eager-import cycle.

__all__ = ["app"]


def __getattr__(name: str):
    if name == "app":
        from .main import app

        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""
Sentinel-43 Policy Gate Package

Purpose:
- Holds enforcement modules that sit *outside* Core and *before* IntegrationHub.
- Provides governance + risk gating + audit-chain logging.

Keep this package free of "business core" logic.
"""

from .ghost_governance import engine, SystemOrchestrator, Decision, TransactionContext, ReasonCodes, CONFIG

__all__ = [
    "engine",
    "SystemOrchestrator",
    "Decision",
    "TransactionContext",
    "ReasonCodes",
    "CONFIG",
]
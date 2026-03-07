from __future__ import annotations

from .expectations import get_default_expectations
from .registry import register_expectations


def bootstrap_expectations() -> None:
    """
    Register all default Sentinel-43 expectations.
    """
    register_expectations(get_default_expectations())
"""
Sentinel-43 Dashboard Layout
Footer
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class Footer:
    """
    Dashboard footer component.
    """

    def __init__(
        self,
        *,
        application_name: str = "Sentinel-43",
        version: str = "0.1.0",
    ) -> None:
        self.application_name = application_name
        self.version = version

    def render(self) -> dict[str, Any]:
        return {
            "application": self.application_name,
            "version": self.version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": "Sentinel-43 Dashboard Online",
        }


footer = Footer()



def build_footer(
    application_name: str = "Sentinel-43",
    version: str = "0.1.0",
) -> Footer:
    """
    Factory function for Footer instances.
    Returns a new Footer with the specified configuration.
    """
    return Footer(
        application_name=application_name,
        version=version,
    )

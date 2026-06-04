"""
Sentinel-43 Dashboard Component
Status Card
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class StatusCard:
    title: str
    value: str
    status: str
    description: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


class StatusCardManager:
    """
    Dashboard status card manager.

    Tracks summary cards for:
    - API status
    - Watchtower status
    - Remote Gateway status
    - node counts
    - alert counts
    - route counts
    """

    def __init__(self) -> None:
        self._cards: dict[str, StatusCard] = {}

    def upsert_card(
        self,
        *,
        card_id: str,
        title: str,
        value: str,
        status: str,
        description: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> StatusCard:
        card = StatusCard(
            title=title,
            value=value,
            status=status,
            description=description,
            metadata=metadata or {},
        )

        self._cards[card_id] = card
        return card

    def get_card(self, card_id: str) -> StatusCard | None:
        return self._cards.get(card_id)

    def get_cards(self) -> list[StatusCard]:
        return list(self._cards.values())

    def remove_card(self, card_id: str) -> bool:
        if card_id not in self._cards:
            return False

        del self._cards[card_id]
        return True

    def clear(self) -> None:
        self._cards.clear()

    def count(self) -> int:
        return len(self._cards)

    def to_dict(self) -> dict[str, Any]:
        return {
            "card_count": len(self._cards),
            "cards": [
                {
                    "title": card.title,
                    "value": card.value,
                    "status": card.status,
                    "description": card.description,
                    "timestamp": card.timestamp,
                    "metadata": card.metadata,
                }
                for card in self._cards.values()
            ],
        }


status_card_manager = StatusCardManager()

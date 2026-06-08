"""
Sentinel-43 Dashboard Component
Status Card
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any


VALID_STATUSES = frozenset({
    "ok",
    "warning",
    "error",
    "degraded",
    "offline",
    "unknown",
})

STALE_THRESHOLD = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class StatusCard:
    card_id: str
    title: str
    value: str
    status: str
    description: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_stale(
        self,
        *,
        now: datetime | None = None,
        stale_threshold: timedelta = STALE_THRESHOLD,
    ) -> bool:
        current_time = now or datetime.now(timezone.utc)
        return current_time - self.timestamp > stale_threshold

    def to_dict(
        self,
        *,
        now: datetime | None = None,
        stale_threshold: timedelta = STALE_THRESHOLD,
    ) -> dict[str, Any]:
        return {
            "card_id": self.card_id,
            "title": self.title,
            "value": self.value,
            "status": self.status,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "is_stale": self.is_stale(
                now=now,
                stale_threshold=stale_threshold,
            ),
            "metadata": dict(self.metadata),
        }


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

    def __init__(
        self,
        *,
        stale_threshold: timedelta = STALE_THRESHOLD,
    ) -> None:
        if stale_threshold <= timedelta(seconds=0):
            raise ValueError("stale_threshold must be greater than 0")

        self._cards: dict[str, StatusCard] = {}
        self._stale_threshold = stale_threshold

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
        normalized_card_id = card_id.strip()
        normalized_title = title.strip()
        normalized_status = status.lower().strip()

        if not normalized_card_id:
            raise ValueError("card_id must not be empty")

        if not normalized_title:
            raise ValueError("title must not be empty")

        if not isinstance(value, str) or not value.strip():
            raise ValueError("value must be a non-empty string")

        if normalized_status not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {status!r}")

        existing = self._cards.get(normalized_card_id)
        merged_metadata = dict(existing.metadata) if existing else {}

        if metadata:
            merged_metadata.update(dict(metadata))

        card = StatusCard(
            card_id=normalized_card_id,
            title=normalized_title,
            value=value.strip(),
            status=normalized_status,
            description=description.strip() if isinstance(description, str) else "",
            timestamp=datetime.now(timezone.utc),
            metadata=merged_metadata,
        )

        self._cards[normalized_card_id] = card
        return card

    def get_card(self, card_id: str) -> StatusCard | None:
        card = self._cards.get(card_id.strip())

        if card is None:
            return None

        return replace(card, metadata=dict(card.metadata))

    def get_cards(self) -> list[StatusCard]:
        return [
            replace(card, metadata=dict(card.metadata))
            for card in self._cards.values()
        ]

    def is_stale(self, card: StatusCard) -> bool:
        return card.is_stale(stale_threshold=self._stale_threshold)

    def remove_card(self, card_id: str, *, reason: str) -> bool:
        if not reason or not reason.strip():
            raise ValueError("remove reason must not be empty")

        normalized_card_id = card_id.strip()

        if normalized_card_id not in self._cards:
            return False

        del self._cards[normalized_card_id]
        return True

    def clear(self, *, reason: str) -> None:
        if not reason or not reason.strip():
            raise ValueError("clear reason must not be empty")

        self._cards.clear()

    def count(self) -> int:
        return len(self._cards)

    def to_dict(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)

        return {
            "card_count": len(self._cards),
            "cards": [
                card.to_dict(
                    now=now,
                    stale_threshold=self._stale_threshold,
                )
                for card in self._cards.values()
            ],
        }

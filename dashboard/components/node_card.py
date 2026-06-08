"""
Sentinel-43 Dashboard Component
Node Card
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any


VALID_STATUSES = frozenset({
    "online",
    "offline",
    "degraded",
    "unknown",
    "error",
})

VALID_NODE_TYPES = frozenset({
    "watchtower",
    "api",
    "core",
    "dependency",
    "remote",
})

STALE_THRESHOLD = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class NodeCard:
    node_id: str
    name: str
    status: str
    node_type: str
    last_seen: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def effective_status(
        self,
        *,
        now: datetime | None = None,
        stale_threshold: timedelta = STALE_THRESHOLD,
    ) -> str:
        current_time = now or datetime.now(timezone.utc)

        if current_time - self.last_seen > stale_threshold:
            return "unknown"

        return self.status

    def to_dict(
        self,
        *,
        now: datetime | None = None,
        stale_threshold: timedelta = STALE_THRESHOLD,
    ) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "status": self.status,
            "effective_status": self.effective_status(
                now=now,
                stale_threshold=stale_threshold,
            ),
            "node_type": self.node_type,
            "last_seen": self.last_seen.isoformat(),
            "metadata": dict(self.metadata),
        }


class NodeCardManager:
    """
    Dashboard node card manager.

    Tracks:
    - Watchtower nodes
    - API nodes
    - core nodes
    - dependency nodes
    - remote targets
    """

    def __init__(
        self,
        *,
        stale_threshold: timedelta = STALE_THRESHOLD,
    ) -> None:
        if stale_threshold <= timedelta(seconds=0):
            raise ValueError("stale_threshold must be greater than 0")

        self._nodes: dict[str, NodeCard] = {}
        self._stale_threshold = stale_threshold

    def upsert_node(
        self,
        *,
        node_id: str,
        name: str,
        status: str,
        node_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> NodeCard:
        normalized_node_id = node_id.strip()
        normalized_name = name.strip()
        normalized_status = status.lower().strip()
        normalized_node_type = node_type.lower().strip()

        for field_name, value in (
            ("node_id", normalized_node_id),
            ("name", normalized_name),
        ):
            if not value:
                raise ValueError(f"{field_name} must not be empty")

        if normalized_status not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {status!r}")

        if normalized_node_type not in VALID_NODE_TYPES:
            raise ValueError(f"Invalid node_type: {node_type!r}")

        existing = self._nodes.get(normalized_node_id)
        merged_metadata = dict(existing.metadata) if existing else {}

        if metadata:
            merged_metadata.update(dict(metadata))

        node = NodeCard(
            node_id=normalized_node_id,
            name=normalized_name,
            status=normalized_status,
            node_type=normalized_node_type,
            last_seen=datetime.now(timezone.utc),
            metadata=merged_metadata,
        )

        self._nodes[normalized_node_id] = node
        return node

    def get_node(self, node_id: str) -> NodeCard | None:
        node = self._nodes.get(node_id.strip())

        if node is None:
            return None

        return replace(node, metadata=dict(node.metadata))

    def get_nodes(self) -> list[NodeCard]:
        return [
            replace(node, metadata=dict(node.metadata))
            for node in self._nodes.values()
        ]

    def is_stale(self, node: NodeCard) -> bool:
        return (
            datetime.now(timezone.utc) - node.last_seen
            > self._stale_threshold
        )

    def get_by_status(self, status: str) -> list[NodeCard]:
        normalized_status = status.lower().strip()

        if normalized_status not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {status!r}")

        return [
            replace(node, metadata=dict(node.metadata))
            for node in self._nodes.values()
            if not self.is_stale(node) and node.status == normalized_status
        ]

    def remove_node(self, node_id: str, *, reason: str) -> bool:
        if not reason or not reason.strip():
            raise ValueError("remove reason must not be empty")

        normalized_node_id = node_id.strip()

        if normalized_node_id not in self._nodes:
            return False

        del self._nodes[normalized_node_id]
        return True

    def clear(self, *, reason: str) -> None:
        if not reason or not reason.strip():
            raise ValueError("clear reason must not be empty")

        self._nodes.clear()

    def count(self) -> int:
        return len(self._nodes)

    def to_dict(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)

        return {
            "node_count": len(self._nodes),
            "nodes": [
                node.to_dict(
                    now=now,
                    stale_threshold=self._stale_threshold,
                )
                for node in self._nodes.values()
            ],
        }

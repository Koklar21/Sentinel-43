"""
Sentinel-43 Dashboard Component
Node Card
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class NodeCard:
    node_id: str
    name: str
    status: str
    node_type: str
    last_seen: str
    metadata: dict[str, Any] = field(default_factory=dict)


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

    def __init__(self) -> None:
        self._nodes: dict[str, NodeCard] = {}

    def upsert_node(
        self,
        *,
        node_id: str,
        name: str,
        status: str,
        node_type: str,
        metadata: dict[str, Any] | None = None,
        last_seen: str | None = None,
    ) -> NodeCard:
        node = NodeCard(
            node_id=node_id,
            name=name,
            status=status,
            node_type=node_type,
            last_seen=last_seen or datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )

        self._nodes[node_id] = node
        return node

    def get_node(self, node_id: str) -> NodeCard | None:
        return self._nodes.get(node_id)

    def get_nodes(self) -> list[NodeCard]:
        return list(self._nodes.values())

    def get_by_status(self, status: str) -> list[NodeCard]:
        normalized = status.lower()

        return [
            node
            for node in self._nodes.values()
            if node.status.lower() == normalized
        ]

    def remove_node(self, node_id: str) -> bool:
        if node_id not in self._nodes:
            return False

        del self._nodes[node_id]
        return True

    def clear(self) -> None:
        self._nodes.clear()

    def count(self) -> int:
        return len(self._nodes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": len(self._nodes),
            "nodes": [
                {
                    "node_id": node.node_id,
                    "name": node.name,
                    "status": node.status,
                    "node_type": node.node_type,
                    "last_seen": node.last_seen,
                    "metadata": node.metadata,
                }
                for node in self._nodes.values()
            ],
        }


node_card_manager = NodeCardManager()

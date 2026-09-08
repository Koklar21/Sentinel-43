# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Thread-safe in-process registry for Sentinel-43 expectations.

The registry is intentionally side-effect free:
    - no Watchtower calls
    - no environment reads
    - no timestamps
    - no network I/O
    - no monitoring state

Application startup or monitoring layers may inspect registry_status() and
report it elsewhere.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import Any

from .contracts import (
    ExpectationCategory,
    ExpectationContract,
)


class ExpectationRegistry:
    """Register and retrieve expectation contracts by name/category."""

    def __init__(self) -> None:
        self._by_name: dict[
            str,
            ExpectationContract,
        ] = {}

        self._by_category: dict[
            ExpectationCategory,
            dict[
                str,
                ExpectationContract,
            ],
        ] = {}

        self._lock = threading.RLock()

    def register(
        self,
        expectation: ExpectationContract,
    ) -> None:
        name = str(
            expectation.name
        ).strip()

        if not name:
            raise ValueError(
                "expectation.name must not be empty"
            )

        category = expectation.category

        if not isinstance(
            category,
            ExpectationCategory,
        ):
            raise TypeError(
                "expectation.category must be an ExpectationCategory"
            )

        with self._lock:
            if name in self._by_name:
                raise ValueError(
                    f"expectation {name!r} is already registered"
                )

            self._by_name[
                name
            ] = expectation

            category_map = (
                self._by_category.setdefault(
                    category,
                    {},
                )
            )

            category_map[
                name
            ] = expectation

    def register_many(
        self,
        expectations: Iterable[
            ExpectationContract
        ],
    ) -> None:
        materialized = list(
            expectations
        )

        names: set[str] = set()

        for expectation in materialized:
            name = str(
                expectation.name
            ).strip()

            if not name:
                raise ValueError(
                    "expectation.name must not be empty"
                )

            if name in names:
                raise ValueError(
                    f"duplicate expectation {name!r} in registration batch"
                )

            names.add(
                name
            )

            if not isinstance(
                expectation.category,
                ExpectationCategory,
            ):
                raise TypeError(
                    "expectation.category must be an ExpectationCategory"
                )

        with self._lock:
            collisions = sorted(
                name
                for name in names
                if name in self._by_name
            )

            if collisions:
                raise ValueError(
                    "expectations already registered: "
                    + ", ".join(
                        repr(name)
                        for name in collisions
                    )
                )

            for expectation in materialized:
                name = str(
                    expectation.name
                ).strip()

                self._by_name[
                    name
                ] = expectation

                category_map = (
                    self._by_category.setdefault(
                        expectation.category,
                        {},
                    )
                )

                category_map[
                    name
                ] = expectation

    def get(
        self,
        name: str,
    ) -> ExpectationContract:
        normalized = str(
            name
        ).strip()

        if not normalized:
            raise ValueError(
                "expectation name must not be empty"
            )

        with self._lock:
            try:
                return self._by_name[
                    normalized
                ]
            except KeyError as exc:
                raise KeyError(
                    f"expectation {normalized!r} is not registered"
                ) from exc

    def all(
        self,
    ) -> tuple[
        ExpectationContract,
        ...
    ]:
        with self._lock:
            return tuple(
                self._by_name.values()
            )

    def by_category(
        self,
        category: ExpectationCategory,
    ) -> tuple[
        ExpectationContract,
        ...
    ]:
        if not isinstance(
            category,
            ExpectationCategory,
        ):
            raise TypeError(
                "category must be an ExpectationCategory"
            )

        with self._lock:
            return tuple(
                self._by_category.get(
                    category,
                    {},
                ).values()
            )

    def status(
        self,
    ) -> dict[str, Any]:
        """Return a side-effect-free registry summary."""
        with self._lock:
            return {
                "expectation_count": len(
                    self._by_name
                ),
                "categories": {
                    category.value: len(
                        items
                    )
                    for category, items
                    in self._by_category.items()
                },
            }

    def clear(
        self,
    ) -> None:
        """Clear all registered expectations."""
        with self._lock:
            self._by_name.clear()
            self._by_category.clear()

    def __len__(
        self,
    ) -> int:
        with self._lock:
            return len(
                self._by_name
            )

    def __contains__(
        self,
        name: object,
    ) -> bool:
        if not isinstance(
            name,
            str,
        ):
            return False

        normalized = name.strip()

        if not normalized:
            return False

        with self._lock:
            return (
                normalized
                in self._by_name
            )


_registry = ExpectationRegistry()


def get_registry(
) -> ExpectationRegistry:
    return _registry


def register_expectation(
    expectation: ExpectationContract,
) -> None:
    _registry.register(
        expectation
    )


def register_expectations(
    expectations: Iterable[
        ExpectationContract
    ],
) -> None:
    _registry.register_many(
        expectations
    )


def get_expectation(
    name: str,
) -> ExpectationContract:
    return _registry.get(
        name
    )


def list_expectations(
) -> tuple[
    ExpectationContract,
    ...
]:
    return _registry.all()


def list_expectations_by_category(
    category: ExpectationCategory,
) -> tuple[
    ExpectationContract,
    ...
]:
    return _registry.by_category(
        category
    )


def registry_status(
) -> dict[str, Any]:
    return _registry.status()


def clear_registry(
) -> None:
    """Clear the global registry, primarily for tests/bootstrap reset."""
    _registry.clear()


__all__ = [
    "ExpectationRegistry",
    "clear_registry",
    "get_expectation",
    "get_registry",
    "list_expectations",
    "list_expectations_by_category",
    "register_expectation",
    "register_expectations",
    "registry_status",
]

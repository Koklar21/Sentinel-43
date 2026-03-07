from __future__ import annotations

from typing import Dict, Iterable, Tuple

from .contracts import ExpectationCategory, ExpectationContract


class ExpectationRegistry:
    """
    Central registry for Sentinel-43 expectations.

    Responsibilities:
    - Register expectations
    - Retrieve expectations by name or category
    - Provide ordered iteration of expectations
    """

    def __init__(self) -> None:
        self._by_name: Dict[str, ExpectationContract] = {}
        self._by_category: Dict[ExpectationCategory, Dict[str, ExpectationContract]] = {}

    # -----------------------------
    # Registration
    # -----------------------------

    def register(self, expectation: ExpectationContract) -> None:
        name = expectation.name

        if name in self._by_name:
            raise ValueError(f"Expectation '{name}' is already registered.")

        self._by_name[name] = expectation

        category_map = self._by_category.setdefault(expectation.category, {})
        category_map[name] = expectation

    def register_many(self, expectations: Iterable[ExpectationContract]) -> None:
        for expectation in expectations:
            self.register(expectation)

    # -----------------------------
    # Retrieval
    # -----------------------------

    def get(self, name: str) -> ExpectationContract:
        try:
            return self._by_name[name]
        except KeyError as exc:
            raise KeyError(f"Expectation '{name}' is not registered.") from exc

    def all(self) -> Tuple[ExpectationContract, ...]:
        return tuple(self._by_name.values())

    def by_category(
        self, category: ExpectationCategory
    ) -> Tuple[ExpectationContract, ...]:
        return tuple(self._by_category.get(category, {}).values())

    # -----------------------------
    # Utilities
    # -----------------------------

    def clear(self) -> None:
        self._by_name.clear()
        self._by_category.clear()

    def __len__(self) -> int:
        return len(self._by_name)

    def __contains__(self, name: str) -> bool:
        return name in self._by_name


# -------------------------------------------------
# Global registry instance (default system registry)
# -------------------------------------------------

_registry = ExpectationRegistry()


def get_registry() -> ExpectationRegistry:
    """
    Returns the global Sentinel-43 expectation registry.
    """
    return _registry


def register_expectation(expectation: ExpectationContract) -> None:
    """
    Register a single expectation globally.
    """
    _registry.register(expectation)


def register_expectations(expectations: Iterable[ExpectationContract]) -> None:
    """
    Register multiple expectations globally.
    """
    _registry.register_many(expectations)


def get_expectation(name: str) -> ExpectationContract:
    """
    Retrieve a registered expectation by name.
    """
    return _registry.get(name)


def list_expectations() -> Tuple[ExpectationContract, ...]:
    """
    Return all registered expectations.
    """
    return _registry.all()


def list_expectations_by_category(
    category: ExpectationCategory,
) -> Tuple[ExpectationContract, ...]:
    """
    Return expectations belonging to a specific category.
    """
    return _registry.by_category(category)
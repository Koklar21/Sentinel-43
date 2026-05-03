"""


# ============================================================
# Rule Registry
# ============================================================
class RuleRegistry:
    """
    Registry for Watchtower rule callables.

    Rules can be registered dynamically by other Sentinel subsystems
    to extend monitoring behavior.

    A rule callable should accept:

        rule(event: dict, thresholds: ThresholdProfile) -> Optional[str]

    Return:
        None -> no alert condition
        str  -> alert reason
    """

    def __init__(self) -> None:
        self._rules: Dict[str, Callable[..., Optional[str]]] = {}

    def register(self, name: str, rule: Callable[..., Optional[str]]) -> None:
        if name in self._rules:
            raise ValueError(f"Rule '{name}' already registered")

        self._rules[name] = rule

    def get(self, name: str) -> Optional[Callable[..., Optional[str]]]:
        return self._rules.get(name)

    def has(self, name: str) -> bool:
        return name in self._rules

    def items(self):
        return self._rules.items()

    def list_rules(self):
        return list(self._rules.keys())


# Global registry used by Watchtower
registry = RuleRegistry()


# ============================================================
# Default Rule Hooks (optional extension point)
# ============================================================
def register_default_rules() -> None:
    """
    Hook point for registering built-in monitoring rules.

    Currently unused but intentionally included so the monitoring
    subsystem can grow without rewriting the Watchtower core.
    """
    pass


__all__ = [
    "ThresholdProfile",
    "thresholds_for",
    "RuleRegistry",
    "registry",
    "register_default_rules",
]

class MonitoringError(Exception):
    """Base exception for Sentinel monitoring subsystem."""


class MonitoringConfigError(MonitoringError):
    """Raised when monitoring configuration is invalid."""


class EventNormalizationError(MonitoringError):
    """Raised when an incoming event cannot be normalized safely."""


class RuleRegistrationError(MonitoringError):
    """Raised when a monitoring rule cannot be registered."""


class WatchtowerStateError(MonitoringError):
    """Raised when a Watchtower state transition or state operation fails."""
def _env_int(name: str, default: int) -> int:
    """
    Read an integer environment variable.

    Returns:
        Parsed integer value if valid.
        Default value if missing or invalid.

    Logs:
        Warning when an invalid integer is supplied.
    """
    value = _env(name)

    if value is None:
        return default

    try:
        return int(value)

    except ValueError:
        import logging

        logging.getLogger(__name__).warning(
            "Invalid integer for %s=%r; using default %d",
            name,
            value,
            default,
        )
        return default

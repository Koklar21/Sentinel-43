# =============================================================================
# Sentinel-43 — core/test package marker
#
# Makes core/test a proper Python package so files inside it (e.g. the
# JWT auth test module) can be imported as core.test.<module_name> if
# needed, and so test discovery tools that expect __init__.py find it
# correctly.
# =============================================================================

# =============================================================================
# Sentinel-43
#
# Focused regression coverage for the coordinated local secret rotation tool.
# =============================================================================

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO / "core" / "scripts" / "rotate_secrets.py"

_spec = importlib.util.spec_from_file_location("s43_rotate_secrets", _SCRIPT)
assert _spec is not None and _spec.loader is not None
rotate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rotate)


def _base_env() -> dict[str, str]:
    values = {key: "a" * 64 for key in rotate.SECRET_KEYS}
    values.update(
        {
            "POSTGRES_PASSWORD": "1" * 64,
            "DATABASE_URL": (
                "postgresql+asyncpg://s43:"
                + ("1" * 64)
                + "@s43-db:5432/s43?sslmode=disable"
            ),
            "SENTINEL_ENV": "development",
            "S43_ENV": "development",
            "S43_AUDIT_HMAC_KEY": "2" * 64,
            "S43_JORM_ENABLED": "true",
            "S43_JORM_ROOT_KEY": "3" * 64,
            "S43_SPARTA_ENABLED": "false",
            "S43_EBPF_ENABLED": "false",
        }
    )
    return values


def test_database_url_password_rewrite_preserves_shape():
    original = (
        "postgresql+asyncpg://s43:old@s43-db:5432/s43"
        "?sslmode=disable"
    )

    rewritten = rotate._database_url_with_password(original, "new-secret")

    assert rewritten == (
        "postgresql+asyncpg://s43:new-secret@s43-db:5432/s43"
        "?sslmode=disable"
    )


def test_state_preserving_rotation_keeps_durable_roots():
    existing = _base_env()

    replacements, rotated = rotate._build_replacements(
        existing,
        full_reset=False,
    )

    assert replacements["S43_AUDIT_HMAC_KEY"] == existing["S43_AUDIT_HMAC_KEY"]
    assert replacements["S43_JORM_ROOT_KEY"] == existing["S43_JORM_ROOT_KEY"]
    assert "S43_AUDIT_HMAC_KEY" not in rotated
    assert "S43_JORM_ROOT_KEY" not in rotated
    assert replacements["POSTGRES_PASSWORD"] != existing["POSTGRES_PASSWORD"]
    assert replacements["POSTGRES_PASSWORD"] in replacements["DATABASE_URL"]
    assert rotate.ROTATION_TIMESTAMP_KEY in replacements


def test_full_reset_rotates_durable_roots():
    existing = _base_env()

    replacements, rotated = rotate._build_replacements(
        existing,
        full_reset=True,
    )

    assert replacements["S43_AUDIT_HMAC_KEY"] != existing["S43_AUDIT_HMAC_KEY"]
    assert replacements["S43_JORM_ROOT_KEY"] != existing["S43_JORM_ROOT_KEY"]
    assert "S43_AUDIT_HMAC_KEY" in rotated
    assert "S43_JORM_ROOT_KEY" in rotated


def test_duplicate_env_assignments_are_rejected(tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "POSTGRES_PASSWORD=one\nPOSTGRES_PASSWORD=two\n",
        encoding="utf-8",
    )

    with pytest.raises(rotate.RotationError, match="Duplicate"):
        rotate._read_env(env_path)

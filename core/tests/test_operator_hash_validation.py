# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed: (1) AGPL-3.0-or-later, or (2) commercial.
# =============================================================================
#
# core/tests/test_operator_hash_validation.py
#
# P0-1 follow-up: _valid_argon2_hash() (core/api/routers/auth.py) used to be
# a shape check only -- prefix, "$" count, overall length -- and never
# actually parsed the encoded hash. A malformed-but-shape-valid value like
# "$argon2id$v=19$m=65536,t=3,p=4$$" (empty salt AND empty digest) passed
# it: argon2.extract_parameters() parses that as salt_len=0, hash_len=0
# rather than raising, so the shape check alone could never catch it. Such
# a hash can never verify a real password, so an operator configuring it
# would silently lose break-glass access with no loud failure at startup --
# exactly the kind of misconfiguration this gate exists to catch.
#
# _valid_argon2_hash() now calls argon2.extract_parameters() for real and
# additionally requires type=argon2id and non-degenerate salt/digest
# lengths. This file pins both the helper directly and the startup-refusal
# behavior end to end, following test_tls_posture.py's pattern (pure
# monkeypatch against core.api.main, no DB / disposable Postgres needed).
# =============================================================================

from __future__ import annotations

import os

import pytest

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_JWT_SECRET", "test-secret-operator-hash-000000000000")
os.environ.setdefault("S43_JWT_ALGORITHM", "HS256")

import core.api.main as m  # noqa: E402
from core.api.routers.auth import _valid_argon2_hash  # noqa: E402
from core.auth.users import hash_password  # noqa: E402

# The exact malformed-but-shape-valid example: well-formed prefix, correct
# "$" delimiter count, well under any length cap -- but an empty salt AND
# an empty digest segment.
_MALFORMED_SHAPE_VALID_HASH = "$argon2id$v=19$m=65536,t=3,p=4$$"


def _cfg(monkeypatch, *, env, operator_hash):
    monkeypatch.setattr(m, "SENTINEL_ENV", env)
    # core.api.main freezes IS_LOCAL_ENV at import from SENTINEL_ENV;
    # _validate_security_config() gates the non-local checks on that frozen
    # value, so a test simulating production must patch it too.
    monkeypatch.setattr(m, "IS_LOCAL_ENV", env in m.LOCAL_TEST_ENVIRONMENTS)
    monkeypatch.setattr(m, "JWT_SECRET", "x" * 16)
    monkeypatch.setattr(m, "WS_REQUIRE_AUTH", True)
    monkeypatch.setattr(m, "ALLOW_DEV_OPERATOR_FALLBACK", False)
    monkeypatch.setattr(m, "_ALLOWED_ORIGINS", frozenset({"https://beta.example.com"}))
    monkeypatch.setattr(m, "_TRUSTED_HOSTS", ["beta.example.com"])
    monkeypatch.delenv("S43_ALLOW_INSECURE_ORIGINS", raising=False)
    # Satisfy the other non-local startup preconditions so the operator-hash
    # check is the only variable under test.
    monkeypatch.setenv("S43_TLS_TERMINATED_AT_TRUSTED_EDGE", "true")
    if operator_hash is None:
        monkeypatch.delenv("S43_OPERATOR_PASSWORD_HASH", raising=False)
    else:
        monkeypatch.setenv("S43_OPERATOR_PASSWORD_HASH", operator_hash)


# ---------------------------------------------------------------------------
# _valid_argon2_hash() itself -- real parsing, not shape-sniffing
# ---------------------------------------------------------------------------

def test_malformed_shape_valid_hash_is_rejected():
    """
    The exact regression case: passes every shape check (starts with
    "$argon2id$", exactly 5 "$" delimiters, well under the length cap) but
    carries an empty salt and an empty digest. Real parsing must reject it.
    """
    assert _valid_argon2_hash(_MALFORMED_SHAPE_VALID_HASH) is False


def test_real_argon2id_hash_is_accepted():
    assert _valid_argon2_hash(hash_password("a-real-operator-password-123456")) is True


def test_legacy_sha256_shape_is_rejected():
    assert _valid_argon2_hash("a" * 64) is False


def test_wrong_argon2_variant_is_rejected():
    # argon2i is a real, syntactically-valid Argon2 hash -- just not the
    # variant this deployment produces or accepts.
    real = hash_password("a-real-operator-password-123456")
    argon2i = real.replace("$argon2id$", "$argon2i$", 1)
    assert _valid_argon2_hash(argon2i) is False


def test_empty_and_non_string_values_are_rejected():
    assert _valid_argon2_hash("") is False
    assert _valid_argon2_hash(None) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _validate_security_config() -- the hash reaches a startup refusal, not
# just the helper returning False in isolation
# ---------------------------------------------------------------------------

def test_malformed_shape_valid_hash_refuses_nonlocal_startup(monkeypatch):
    _cfg(monkeypatch, env="production", operator_hash=_MALFORMED_SHAPE_VALID_HASH)
    with pytest.raises(RuntimeError, match="not a well-formed Argon2id"):
        m._validate_security_config()


def test_real_argon2id_hash_allows_nonlocal_startup(monkeypatch):
    _cfg(monkeypatch, env="production", operator_hash=hash_password("a-real-operator-password-123456"))
    m._validate_security_config()  # no raise


def test_unconfigured_operator_hash_does_not_itself_block_startup(monkeypatch):
    # No S43_OPERATOR_PASSWORD_HASH at all is a different concern (no env
    # operator configured in this deployment) -- _validate_security_config()
    # only judges a hash that IS present.
    _cfg(monkeypatch, env="production", operator_hash=None)
    m._validate_security_config()  # no raise

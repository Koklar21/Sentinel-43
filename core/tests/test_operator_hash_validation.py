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
<<<<<<< Updated upstream
# PR #257 blocker 1: core.auth.users.is_valid_argon2id_hash() is the one
# canonical Argon2 acceptance policy for S43_OPERATOR_PASSWORD_HASH --
# core.api.routers.auth._valid_argon2_hash() is a thin wrapper over it, and
# core.api.main._validate_security_config() calls the wrapper at startup.
# These tests exercise the canonical function directly plus both call
# sites, so a regression in any one of the three is caught here.
=======
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
>>>>>>> Stashed changes
# =============================================================================

from __future__ import annotations

<<<<<<< Updated upstream
import importlib

import pytest

from core.auth.users import hash_password, is_valid_argon2id_hash


# =============================================================================
# Canonical validator -- direct tests
# =============================================================================

def test_accepts_a_real_generated_hash():
    assert is_valid_argon2id_hash(hash_password("correct horse battery staple")) is True


def test_accepts_hash_and_rejects_wrong_password_via_verify_password():
    from core.auth.users import verify_password

    digest = hash_password("the-real-password")
    assert is_valid_argon2id_hash(digest) is True
    assert verify_password("the-real-password", digest) is True
    assert verify_password("wrong-password", digest) is False


def test_rejects_legacy_sha256_hex_digest():
    import hashlib

    legacy = hashlib.sha256(b"anything").hexdigest()
    assert len(legacy) == 64
    assert is_valid_argon2id_hash(legacy) is False


def test_rejects_empty_string():
    assert is_valid_argon2id_hash("") is False


def test_rejects_none():
    assert is_valid_argon2id_hash(None) is False


def test_rejects_non_string_types():
    assert is_valid_argon2id_hash(12345) is False
    assert is_valid_argon2id_hash(b"$argon2id$v=19$m=65536,t=3,p=4$abc$def") is False
    assert is_valid_argon2id_hash({"hash": "x"}) is False


def test_rejects_truncated_hash():
    full = hash_password("truncate-me")
    assert is_valid_argon2id_hash(full[: len(full) // 2]) is False


def test_rejects_fake_string_with_correct_separator_count_but_no_salt_or_hash():
    fake = "$argon2id$v=19$m=65536,t=3,p=4$"
    assert fake.count("$") == 4
    assert is_valid_argon2id_hash(fake) is False


@pytest.mark.parametrize("variant", ["argon2i", "argon2d"])
def test_rejects_non_id_variants(variant):
    # Genuine argon2-cffi low-level test vectors for the other two variants
    # (salt="somesalt" / hash from the argon2-cffi test suite) -- structurally
    # valid Argon2, wrong variant.
    value = f"${variant}$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    assert is_valid_argon2id_hash(value) is False


def test_rejects_unsupported_version():
    value = "$argon2id$v=18$m=65536,t=3,p=4$c29tZXNhbHQxeXo$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    assert is_valid_argon2id_hash(value) is False


def test_rejects_non_numeric_version():
    value = "$argon2id$v=xx$m=65536,t=3,p=4$c29tZXNhbHQxeXo$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    assert is_valid_argon2id_hash(value) is False


def test_rejects_malformed_salt_encoding():
    value = "$argon2id$v=19$m=65536,t=3,p=4$!!!not-base64!!!$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    assert is_valid_argon2id_hash(value) is False


def test_rejects_trailing_garbage_field():
    real = hash_password("trailing-garbage-case")
    assert is_valid_argon2id_hash(real + "$extra") is False


def test_rejects_excessive_length():
    value = "$argon2id$v=19$m=65536,t=3,p=4$" + "A" * 2000 + "$" + "B" * 2000
    assert len(value) > 512
    assert is_valid_argon2id_hash(value) is False


def test_rejects_excessive_memory_cost():
    value = "$argon2id$v=19$m=4294967295,t=3,p=4$c29tZXNhbHQxeXo$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    assert is_valid_argon2id_hash(value) is False


def test_rejects_excessive_time_cost():
    value = "$argon2id$v=19$m=65536,t=4294967295,p=4$c29tZXNhbHQxeXo$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    assert is_valid_argon2id_hash(value) is False


def test_rejects_excessive_parallelism():
    value = "$argon2id$v=19$m=65536,t=3,p=16777215$c29tZXNhbHQxeXo$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    assert is_valid_argon2id_hash(value) is False


def test_rejects_undersized_salt_and_hash_even_with_valid_charset():
    # Structurally clean base64, well under the project's real salt/hash
    # sizes -- accepting this would be the exact "empty/short salt slipped
    # past a shape-only check" hole PR #257 closes.
    value = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub"
    assert is_valid_argon2id_hash(value) is False


# =============================================================================
# core.api.routers.auth._valid_argon2_hash -- thin-wrapper parity
# =============================================================================

def test_router_wrapper_delegates_to_canonical_function():
    from core.api.routers.auth import _valid_argon2_hash

    good = hash_password("wrapper-parity-check")
    bad = "not-a-hash"
    assert _valid_argon2_hash(good) == is_valid_argon2id_hash(good) is True
    assert _valid_argon2_hash(bad) == is_valid_argon2id_hash(bad) is False


# =============================================================================
# core.api.main._validate_security_config() -- startup fail-closed behavior
# =============================================================================

@pytest.fixture
def main_module(monkeypatch):
    """
    Import core.api.main fresh under a minimal valid non-local config, then
    hand back the module for _validate_security_config() to be re-run with
    a mutated S43_OPERATOR_PASSWORD_HASH. Reloading avoids cross-test import
    caching masking a startup-time check.
    """
    monkeypatch.setenv("SENTINEL_ENV", "production")
    monkeypatch.setenv("S43_ENV", "production")
    monkeypatch.setenv("S43_JWT_SECRET", "test-jwt-secret-value-1234567890")
    monkeypatch.setenv("S43_WS_REQUIRE_AUTH", "true")
    monkeypatch.setenv("S43_ALLOWED_ORIGINS", "https://example.test")
    monkeypatch.delenv("S43_OPERATOR_PASSWORD_HASH", raising=False)

    import core.api.main as main

    importlib.reload(main)
    yield main
    monkeypatch.undo()
    importlib.reload(main)


def test_startup_accepts_a_real_generated_hash(main_module, monkeypatch):
    monkeypatch.setenv("S43_OPERATOR_PASSWORD_HASH", hash_password("startup-ok"))
    main_module._validate_security_config()  # must not raise


def test_startup_rejects_legacy_sha256_in_non_local_mode(main_module, monkeypatch):
    import hashlib

    monkeypatch.setenv("S43_OPERATOR_PASSWORD_HASH", hashlib.sha256(b"legacy").hexdigest())
    with pytest.raises(RuntimeError, match="Argon2id"):
        main_module._validate_security_config()


def test_startup_rejects_malformed_hash_no_silent_fallback(main_module, monkeypatch):
    monkeypatch.setenv("S43_OPERATOR_PASSWORD_HASH", "$argon2id$v=19$m=65536,t=3,p=4$")
    with pytest.raises(RuntimeError, match="Argon2id"):
        main_module._validate_security_config()
=======
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
    monkeypatch.setattr(m, "JWT_SECRET", "x" * 16)
    monkeypatch.setattr(m, "WS_REQUIRE_AUTH", True)
    monkeypatch.setattr(m, "_ALLOWED_ORIGINS", frozenset({"https://beta.example.com"}))
    monkeypatch.delenv("S43_ALLOW_INSECURE_ORIGINS", raising=False)
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
>>>>>>> Stashed changes

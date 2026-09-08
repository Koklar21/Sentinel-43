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
# PR #257 blocker 1: core.auth.users.is_valid_argon2id_hash() is the one
# canonical Argon2 acceptance policy for S43_OPERATOR_PASSWORD_HASH --
# core.api.routers.auth._valid_argon2_hash() is a thin wrapper over it, and
# core.api.main._validate_security_config() calls the wrapper at startup.
# These tests exercise the canonical function directly plus both call
# sites, so a regression in any one of the three is caught here.
# =============================================================================

from __future__ import annotations

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

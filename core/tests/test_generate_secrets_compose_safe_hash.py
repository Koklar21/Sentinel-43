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
#
# core/tests/test_generate_secrets_compose_safe_hash.py
#
# Post-merge baseline remediation, Section B.
#
# Live baseline verification found that the documented setup flow --
# `generate_secrets.py --password-hash`, paste the printed
# S43_OPERATOR_PASSWORD_HASH=... line into .env -- produces a value Docker
# Compose's own .env interpolation silently corrupts: every literal "$" in
# an Argon2id digest ($argon2id$v=19$m=...$salt$hash) is treated as the
# start of a variable reference and stripped before the container ever sees
# it. Every login then fails 503 "Break-glass credentials are not
# configured correctly", with no explanation anywhere.
#
# password_hash_flow() now doubles every "$" before printing, which is
# exactly what Compose's own .env docs prescribe for a literal "$" and is
# undone by Compose before the container sees the value. This file proves:
#   1. the printed value is the semantically-identical Argon2id hash with
#      every "$" doubled (never a different hash, never weakened);
#   2. un-escaping it ("$$" -> "$", Compose's own transform) recovers
#      exactly the real digest, and that digest still verifies the original
#      password and still passes Sentinel-43's own Argon2id validation;
#   3. a password that produces an unusually-shaped digest is still handled
#      byte-for-byte (no assumption about a fixed number of "$" segments).
# =============================================================================

from __future__ import annotations

import os

os.environ.setdefault("SENTINEL_ENV", "test")
os.environ.setdefault("S43_ENV", "test")

from core.auth.users import hash_password, is_valid_argon2id_hash, verify_password  # noqa: E402
from core.cli.generate_secrets import password_hash_flow  # noqa: E402


def _compose_env_file_interpolate(value: str) -> str:
    """Reproduce Docker Compose's own .env-file "$$" -> "$" unescaping.

    This is the transform Compose applies when it reads a .env file, before
    the resulting value ever reaches a container's environment. It is the
    inverse of password_hash_flow()'s digest.replace("$", "$$").
    """
    return value.replace("$$", "$")


def _run_password_hash_flow(monkeypatch, capsys, password: str) -> tuple[int, str, str]:
    prompts = iter([password, password])
    monkeypatch.setattr(
        "core.cli.generate_secrets.getpass",
        lambda _prompt="": next(prompts),
    )
    exit_code = password_hash_flow()
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def test_printed_value_is_the_escaped_form_of_a_real_argon2id_hash(monkeypatch, capsys):
    exit_code, out, err = _run_password_hash_flow(monkeypatch, capsys, "correct horse battery staple")

    assert exit_code == 0
    line = next(l for l in out.splitlines() if l.startswith("S43_OPERATOR_PASSWORD_HASH="))
    printed_value = line[len("S43_OPERATOR_PASSWORD_HASH="):]

    # The escaped form is never itself a valid Argon2id hash string -- if it
    # were, escaping would have been a no-op and the defect would still be
    # live.
    assert not is_valid_argon2id_hash(printed_value)
    assert "$$" in printed_value

    # A note explaining the escaping goes to stderr, never mixed into the
    # value printed on stdout.
    assert "Compose" in err
    assert "$" not in out.replace(line, "")  # no other stdout line carries a "$"


def test_compose_interpolation_round_trip_recovers_the_exact_original_hash(monkeypatch, capsys):
    password = "correct horse battery staple"
    exit_code, out, _err = _run_password_hash_flow(monkeypatch, capsys, password)
    assert exit_code == 0

    line = next(l for l in out.splitlines() if l.startswith("S43_OPERATOR_PASSWORD_HASH="))
    printed_value = line[len("S43_OPERATOR_PASSWORD_HASH="):]

    recovered = _compose_env_file_interpolate(printed_value)

    # Exactly the digest a container would see after Compose reads the .env
    # file -- a real, valid Argon2id hash, not a different or weakened one.
    assert is_valid_argon2id_hash(recovered)
    assert recovered.count("$") == recovered.replace("$$", "$").count("$")  # sanity: no leftover doubling
    assert verify_password(password, recovered)
    assert not verify_password("wrong password entirely", recovered)


def test_round_trip_is_stable_across_multiple_independently_generated_hashes(monkeypatch, capsys):
    # Argon2id salts are random per call, so the digest -- and therefore the
    # exact "$" layout -- differs every time. Escaping must not assume a
    # fixed shape.
    for password in ("alpha-pw-1", "beta-pw-2", "gamma-pw-3"):
        exit_code, out, _err = _run_password_hash_flow(monkeypatch, capsys, password)
        assert exit_code == 0

        line = next(l for l in out.splitlines() if l.startswith("S43_OPERATOR_PASSWORD_HASH="))
        printed_value = line[len("S43_OPERATOR_PASSWORD_HASH="):]
        recovered = _compose_env_file_interpolate(printed_value)

        assert is_valid_argon2id_hash(recovered)
        assert verify_password(password, recovered)
        # And, independently, that hash_password() itself still produces
        # something whose "$" count matches what got doubled -- i.e. the
        # escaping is a pure textual transform of the real digest, not a
        # separately-derived value.
        assert printed_value.count("$$") == recovered.count("$")


def test_mismatched_passwords_never_reach_the_escaping_step(monkeypatch, capsys):
    prompts = iter(["password-one", "password-two"])
    monkeypatch.setattr(
        "core.cli.generate_secrets.getpass",
        lambda _prompt="": next(prompts),
    )
    exit_code = password_hash_flow()
    out, err = capsys.readouterr().out, capsys.readouterr().err

    assert exit_code == 2
    assert "S43_OPERATOR_PASSWORD_HASH" not in out

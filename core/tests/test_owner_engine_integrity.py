# =============================================================================
# Sentinel-43 -- owner-designated engine integrity
#
# The runtime refuses to decide with an engine nobody reviewed: it hashes
# Sentinel-43/Shadow_mode.py and compares it to EXPECTED_ENGINE_SHA256. These
# tests keep that protection honest in both directions:
#
#   * the checked-in owner engine and the pin MUST agree, so the pin can never
#     silently drift from the file that is actually shipped (the failure this
#     catches took the beta deployment down: the pin recorded a Windows
#     checkout's CRLF rendering, so CI's LF checkout was refused);
#   * a file that differs in CODE must still be refused, so normalising line
#     endings has not weakened the check into a formality.
#
# No network, no skips.
# =============================================================================
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from core.governance.sentinel43_engine import (
    ENGINE_CLASS_NAME,
    EXPECTED_ENGINE_SHA256,
    EngineUnavailable,
    engine_digest,
    engine_source_path,
    load_engine_module,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _engine_bytes() -> bytes:
    return engine_source_path().read_bytes()


# ---------------------------------------------------------------------------
# The pin and the checked-in engine agree
# ---------------------------------------------------------------------------
def test_the_checked_in_engine_matches_its_integrity_pin():
    """The file this repository ships IS the reviewed engine."""
    assert engine_digest(_engine_bytes()) == EXPECTED_ENGINE_SHA256


def test_the_pin_matches_the_engine_as_git_stores_it():
    """Not only as this checkout materialised it.

    The digest must be a property of the repository's content, so every
    checkout -- CI's LF, a Windows CRLF working copy, the container image --
    agrees on which engine is authorised.
    """
    stored = subprocess.run(
        ["git", "show", "HEAD:Sentinel-43/Shadow_mode.py"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout
    assert engine_digest(stored) == EXPECTED_ENGINE_SHA256


@pytest.mark.parametrize("newline", [b"\n", b"\r\n", b"\r"])
def test_the_digest_does_not_depend_on_the_checkout(newline):
    """Every line-ending rendering of the same engine is the same engine."""
    lf = _engine_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    rendered = lf.replace(b"\n", newline)
    assert engine_digest(rendered) == EXPECTED_ENGINE_SHA256


def test_the_running_engine_reports_the_pinned_digest():
    """What the runtime loads, and records on every decision it makes."""
    _module, identity = load_engine_module()
    assert identity.sha256 == EXPECTED_ENGINE_SHA256
    assert identity.engine_class == ENGINE_CLASS_NAME
    assert identity.path == "Sentinel-43/Shadow_mode.py"


# ---------------------------------------------------------------------------
# The protection still refuses an unreviewed engine
# ---------------------------------------------------------------------------
def test_an_engine_whose_code_changed_is_refused(tmp_path):
    """One added statement -- not a line ending -- and the runtime refuses it."""
    root = tmp_path / "root"
    (root / "Sentinel-43").mkdir(parents=True)
    tampered = _engine_bytes().replace(
        b"class Sentinel43ResponseEngine:",
        b"BACKDOOR = True\n\n\nclass Sentinel43ResponseEngine:",
        1,
    )
    assert tampered != _engine_bytes(), "the tamper anchor no longer matches"
    (root / "Sentinel-43" / "Shadow_mode.py").write_bytes(tampered)

    with pytest.raises(EngineUnavailable, match="not the reviewed"):
        load_engine_module(root)


def test_a_whitespace_only_code_change_is_still_refused(tmp_path):
    """Normalising newlines does not extend to normalising code: indentation
    and spacing are part of the program and part of its identity."""
    root = tmp_path / "root"
    (root / "Sentinel-43").mkdir(parents=True)
    (root / "Sentinel-43" / "Shadow_mode.py").write_bytes(
        _engine_bytes() + b"\n\nEXTRA = 1\n"
    )

    with pytest.raises(EngineUnavailable, match="not the reviewed"):
        load_engine_module(root)


def test_a_missing_engine_is_refused(tmp_path):
    with pytest.raises(EngineUnavailable, match="not found"):
        load_engine_module(tmp_path)


def test_the_digest_is_a_plain_sha256_of_the_canonical_bytes():
    """The pin is verifiable by hand, with no project-specific encoding."""
    canonical = _engine_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    assert engine_digest(_engine_bytes()) == hashlib.sha256(canonical).hexdigest()

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

"""Exec-only administrator recovery through Sentinel-43 authority.

This module intentionally exposes no HTTP route. It is for a deployment
operator who already has host/container exec access and therefore already
controls the deployment boundary.

Recovery:
- targets the existing sole administrator by username
- refuses observer accounts; it never promotes an account to administrator
- restores is_active=true
- replaces the password
- revokes all live sessions for that account
- emits the authoritative identity-governance audit record before mutation
- requires PostgreSQL advisory locking; it refuses weaker backends
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from pathlib import Path

from core.audit.store import AuditConfig, AuditStore
from core.auth.users import dispose_engine, get_sessionmaker
from core.governance import build_runtime_authority_from_settings
from core.governance.identity import (
    IdentityRecoveryUnavailable,
    IdentityTargetNotFound,
)

MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 1024


class _Settings:
    environment = (
        os.getenv("SENTINEL_ENV")
        or os.getenv("S43_ENV")
        or "production"
    )
    default_mode = os.getenv("S43_DEFAULT_MODE", "HUMAN_GATED")


def _audit_store() -> AuditStore:
    signing_key = os.getenv("S43_AUDIT_HMAC_KEY", "").strip()
    if not signing_key:
        raise RuntimeError(
            "S43_AUDIT_HMAC_KEY is required; recovery refuses without "
            "authoritative audit."
        )

    sqlite_path = Path(
        os.getenv(
            "S43_AUDIT_SQLITE_PATH",
            "/app/sentinel43_state/audit.sqlite3",
        )
    )
    jsonl_raw = os.getenv("S43_AUDIT_JSONL_PATH", "").strip()
    store = AuditStore(
        AuditConfig(
            sqlite_path=sqlite_path,
            signing_key=signing_key,
            jsonl_path=Path(jsonl_raw) if jsonl_raw else None,
        )
    )
    store.initialize()
    return store


def _read_password() -> str:
    password = getpass.getpass("new admin password: ")
    if not MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN:
        raise ValueError(
            f"password must be between {MIN_PASSWORD_LEN} and "
            f"{MAX_PASSWORD_LEN} characters"
        )
    if password != getpass.getpass("repeat new admin password: "):
        raise ValueError("passwords do not match")
    return password


async def _recover(username: str, password: str) -> None:
    audit = _audit_store()
    try:
        authority = build_runtime_authority_from_settings(
            _Settings(),
            audit_store=audit,
        )
        sessionmaker = get_sessionmaker()
        async with sessionmaker() as session:
            user = await authority.identity.recover_admin(
                session,
                actor="deployment:exec-admin-recovery",
                username=username,
                new_password=password,
            )
        print(
            f"Recovered administrator account: {user.username}",
            file=sys.stdout,
        )
    finally:
        audit.close()
        await dispose_engine()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Recover the existing Sentinel-43 sole administrator. "
            "Observer accounts cannot be promoted by this command. "
            "Run only from a trusted host/container exec context."
        )
    )
    parser.add_argument("username", help="existing administrator username to recover")
    args = parser.parse_args()

    username = args.username.strip()
    if not username:
        parser.error("username must not be blank")

    try:
        password = _read_password()
        asyncio.run(_recover(username, password))
    except IdentityTargetNotFound:
        print("ERROR: no account with that username.", file=sys.stderr)
        return 2
    except IdentityRecoveryUnavailable as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"ERROR: administrator recovery failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# =============================================================================
# Sentinel-43 — pre-Alembic baseline compatibility check (Pass 5A-Migration)
#
# Mission §9 / §10. Before an EXISTING pre-Alembic database can be adopted
# into Alembic (`alembic stamp 0001_baseline`), its `users` table must be
# semantically compatible with what 0001_baseline represents. This module is
# the gate: env.py calls assert_users_baseline() whenever a `users` table
# exists but no `alembic_version` table does.
#
# It compares SEMANTICS, not backend-generated names: a pre-Alembic database
# created by the old create_all() carries Postgres default constraint names
# (users_pkey, users_email_key, ...) rather than the naming_convention names
# (pk_users, uq_users_email, ...). That difference is expected and NOT drift
# — see core/auth/users.py NAMING_CONVENTION and MIGRATION_BASELINE_PASS5AM.md.
#
# FAIL CLOSED: on any incompatibility it raises BaselineIncompatibleError with
# a SANITIZED report (schema property names only — never row data, never
# credentials/hashes, never a connection string). It never "repairs" or
# stamps anyway.
# =============================================================================

from __future__ import annotations

from sqlalchemy import inspect
from sqlalchemy.engine import Connection


class BaselineIncompatibleError(RuntimeError):
    """The existing database's schema is not compatible with 0001_baseline."""


# Expected `users` schema == the (historically stable) core.auth.users.User
# model. Verified against git history: the model is byte-identical to its
# original definition (fce06d8) — the model source IS the historical schema,
# there was never a migration, only create_all() from this exact model.
#
# Each entry: column -> (accepted type families, nullable-expected)
_TYPE_FAMILIES = {
    "string": ("VARCHAR", "CHAR", "TEXT", "STRING", "NVARCHAR"),
    "uuid": ("UUID",),
    "bool": ("BOOLEAN", "BOOL"),
    "datetime": ("TIMESTAMP", "DATETIME"),
}

_EXPECTED_COLUMNS: dict[str, tuple[str, bool]] = {
    # column:          (type family, nullable?)
    "user_id":         ("uuid", False),
    "username":        ("string", False),
    "email":           ("string", True),
    "password_hash":   ("string", False),
    "role":            ("string", False),
    "is_active":       ("bool", False),
    "created_at":      ("datetime", False),
    "last_login_at":   ("datetime", True),
}

_EXPECTED_PK = ["user_id"]

# Columns that must be UNIQUE (via a unique constraint OR a unique index —
# the model uses `unique=True` which, combined with `index=True` on username,
# yields a unique index there and a unique constraint on email).
_EXPECTED_UNIQUE_COLUMNS = {"username", "email"}


def _type_family(reflected_type) -> str:
    name = type(reflected_type).__name__.upper()
    for family, tokens in _TYPE_FAMILIES.items():
        if any(tok in name for tok in tokens):
            return family
    # Fall back to the compiled name for a better message
    return name.lower()


def check_users_baseline(connection: Connection) -> list[str]:
    """
    Return a list of human-readable, SANITIZED drift descriptions.
    Empty list == compatible.
    """
    problems: list[str] = []
    insp = inspect(connection)

    if not insp.has_table("users"):
        return ["table 'users' is missing"]

    # --- columns: presence, type family, nullability ---
    cols = {c["name"]: c for c in insp.get_columns("users")}
    for name, (family, nullable_expected) in _EXPECTED_COLUMNS.items():
        if name not in cols:
            problems.append(f"column 'users.{name}' is missing")
            continue
        actual_family = _type_family(cols[name]["type"])
        if actual_family != family:
            problems.append(
                f"column 'users.{name}' has incompatible type "
                f"(expected {family}, found {actual_family})"
            )
        # PK columns are implicitly NOT NULL regardless of reflected flag
        if name not in _EXPECTED_PK:
            actual_nullable = bool(cols[name].get("nullable", True))
            if actual_nullable != nullable_expected:
                problems.append(
                    f"column 'users.{name}' has wrong nullability "
                    f"(expected {'NULL' if nullable_expected else 'NOT NULL'}, "
                    f"found {'NULL' if actual_nullable else 'NOT NULL'})"
                )

    # --- primary key (columns, not name) ---
    pk = insp.get_pk_constraint("users")
    pk_cols = list(pk.get("constrained_columns") or [])
    if pk_cols != _EXPECTED_PK:
        problems.append(
            f"primary key columns differ (expected {_EXPECTED_PK}, found {pk_cols or 'none'})"
        )

    # --- uniqueness (semantic: constraint OR unique index) ---
    unique_cols: set[str] = set()
    for uc in insp.get_unique_constraints("users"):
        cc = uc.get("column_names") or []
        if len(cc) == 1:
            unique_cols.add(cc[0])
    for ix in insp.get_indexes("users"):
        if ix.get("unique") and len(ix.get("column_names") or []) == 1:
            unique_cols.add(ix["column_names"][0])
    for col in _EXPECTED_UNIQUE_COLUMNS:
        if col not in unique_cols:
            problems.append(f"column 'users.{col}' is missing its expected UNIQUE constraint/index")

    # --- unexpected NOT NULL on a column the model allows to be NULL is
    #     covered above; unexpected required (NOT NULL) columns beyond the
    #     model are reported so a stamp can't silently accept a stricter schema
    for name, meta in cols.items():
        if name in _EXPECTED_COLUMNS:
            continue
        if not meta.get("nullable", True) and meta.get("default") is None \
           and meta.get("server_default") is None:
            problems.append(
                f"column 'users.{name}' is an unexpected NOT NULL column with no default "
                f"(not part of the 0001 baseline)"
            )

    return problems


def assert_users_baseline(connection: Connection) -> None:
    """
    Raise BaselineIncompatibleError (sanitized) if the existing `users` table
    is not compatible with 0001_baseline. Fail closed — never stamp anyway.
    """
    problems = check_users_baseline(connection)
    if problems:
        raise BaselineIncompatibleError(
            "This database's existing schema is NOT compatible with the "
            "Sentinel-43 0001_baseline and will not be adopted into Alembic. "
            "Resolve the differences below (or point Alembic at the correct "
            "database) and retry. Nothing was changed or stamped.\n"
            + "\n".join(f"  - {p}" for p in problems)
        )

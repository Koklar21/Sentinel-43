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

"""Load the owner-designated Sentinel-43 runtime components.

The owner sources live under Sentinel-43/, which is not a normal Python
package name. This loader imports those files by path, records provenance,
and constructs the ONE live Nexus/Node/AI-escalation component set owned by
Sentinel43RuntimeAuthority.

None of these components owns an engine, store, executor, queue, or approval
path. They all bind to the same runtime authority.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Final


_OWNER_DIR: Final[Path] = Path("Sentinel-43")
_OWNER_SOURCES: Final[dict[str, tuple[str, str]]] = {
    "nexus": ("Sentienal_Nexus.py", "SentinelNexus"),
    "node": ("Sentienal_core.py", "SentinelNode"),
    "ai_escalation": ("sentinel_AI_escalation.py", "SentinelAIEscalation"),
}
_MODULE_PREFIX: Final[str] = "sentinel43_owner_component"
_LOAD_LOCK = threading.RLock()


@dataclass(frozen=True, slots=True)
class OwnerComponentIdentity:
    role: str
    path: str
    sha256: str
    class_name: str

    def to_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "path": self.path,
            "sha256": self.sha256,
            "class": self.class_name,
        }


@dataclass(frozen=True, slots=True)
class OwnerRuntimeComponents:
    nexus: Any
    node: Any
    ai_escalation: Any
    identities: tuple[OwnerComponentIdentity, ...]

    def identity_map(self) -> dict[str, dict[str, str]]:
        return {
            identity.role: identity.to_dict()
            for identity in self.identities
        }


def _canonical_digest(source: bytes) -> str:
    normalized = source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(normalized).hexdigest()


def _source_path(filename: str, root: Path | None = None) -> Path:
    base = root if root is not None else Path(__file__).resolve().parents[2]
    return base / _OWNER_DIR / filename


def _load_module(
    *,
    role: str,
    filename: str,
    class_name: str,
    root: Path | None = None,
) -> tuple[ModuleType, OwnerComponentIdentity]:
    path = _source_path(filename, root)
    if not path.is_file():
        raise RuntimeError(
            f"owner-designated Sentinel-43 component missing: {path}"
        )

    source = path.read_bytes()
    identity = OwnerComponentIdentity(
        role=role,
        path=str((_OWNER_DIR / filename)).replace("\\", "/"),
        sha256=_canonical_digest(source),
        class_name=class_name,
    )

    module_name = f"{_MODULE_PREFIX}_{role}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load owner component module from {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise

    if not hasattr(module, class_name):
        raise RuntimeError(
            f"{path} does not define required owner component {class_name}"
        )

    return module, identity


def load_owner_runtime_components(
    authority: Any,
    *,
    root: Path | None = None,
) -> OwnerRuntimeComponents:
    """Load and bind the current owner-designated orchestration components."""

    if authority is None:
        raise ValueError("owner runtime components require an authority")

    with _LOAD_LOCK:
        loaded: dict[str, Any] = {}
        identities: list[OwnerComponentIdentity] = []

        for role, (filename, class_name) in _OWNER_SOURCES.items():
            module, identity = _load_module(
                role=role,
                filename=filename,
                class_name=class_name,
                root=root,
            )
            component_class = getattr(module, class_name)
            loaded[role] = component_class(authority=authority)
            identities.append(identity)

        return OwnerRuntimeComponents(
            nexus=loaded["nexus"],
            node=loaded["node"],
            ai_escalation=loaded["ai_escalation"],
            identities=tuple(identities),
        )


__all__ = [
    "OwnerComponentIdentity",
    "OwnerRuntimeComponents",
    "load_owner_runtime_components",
]

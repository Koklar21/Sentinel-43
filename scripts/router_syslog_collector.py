#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
"""Local UDP syslog collector for Sentinel-43 router telemetry.

This process runs on the host, not inside the S43 authority boundary. It accepts
UDP datagrams only from the configured router IP, extracts bounded observation
facts, and forwards them to the authenticated /internal/router/events endpoint.

It never assigns a threat label, severity, governance decision, or enforcement
action. Those semantics remain server-owned.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import uuid
from collections import deque
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


_REPO_ROOT = Path(__file__).resolve().parents[1]
_MAX_DATAGRAM_BYTES = 8192
_MAX_MESSAGE_CHARS = 4096

_IP_PATTERNS = {
    "source_ip": (
        re.compile(r"\b(?:SRC|SOURCE|SRC_IP|SOURCE_IP)\s*[=:]\s*([^\s,;]+)", re.IGNORECASE),
        re.compile(r"\bsrc\s+([^\s,;]+)", re.IGNORECASE),
    ),
    "destination_ip": (
        re.compile(r"\b(?:DST|DEST|DESTINATION|DST_IP|DESTINATION_IP)\s*[=:]\s*([^\s,;]+)", re.IGNORECASE),
        re.compile(r"\bdst\s+([^\s,;]+)", re.IGNORECASE),
    ),
}
_PORT_PATTERNS = {
    "source_port": re.compile(r"\b(?:SPT|SPORT|SRC_PORT|SOURCE_PORT)\s*[=:]\s*(\d{1,5})", re.IGNORECASE),
    "destination_port": re.compile(r"\b(?:DPT|DPORT|DST_PORT|DESTINATION_PORT)\s*[=:]\s*(\d{1,5})", re.IGNORECASE),
}
_PROTOCOL_RE = re.compile(r"\b(?:PROTO|PROTOCOL)\s*[=:]\s*([A-Za-z0-9_.-]{1,32})", re.IGNORECASE)
_ACTION_RE = re.compile(r"\b(?:ACTION|ACT)\s*[=:]\s*([A-Za-z0-9_.-]{1,32})", re.IGNORECASE)
_ACTION_WORD_RE = re.compile(r"\b(DROP|DROPPED|DENY|DENIED|BLOCK|BLOCKED|REJECT|REJECTED|ALLOW|ALLOWED|ACCEPT|ACCEPTED)\b", re.IGNORECASE)


class CollectorError(RuntimeError):
    pass


def _read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        raise CollectorError(f"environment file does not exist: {path}")

    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[](),")))
    except ValueError:
        return ""


def _first_ip(message: str, field: str) -> str:
    for pattern in _IP_PATTERNS[field]:
        match = pattern.search(message)
        if match:
            value = _normalize_ip(match.group(1))
            if value:
                return value
    return ""


def _port(message: str, field: str) -> int | None:
    match = _PORT_PATTERNS[field].search(message)
    if not match:
        return None
    value = int(match.group(1))
    return value if 0 <= value <= 65535 else None


def _facts(message: str, router_ip: str) -> dict[str, object]:
    protocol_match = _PROTOCOL_RE.search(message)
    action_match = _ACTION_RE.search(message) or _ACTION_WORD_RE.search(message)

    payload: dict[str, object] = {
        "event_id": str(uuid.uuid4()),
        "router_ip": router_ip,
        "message": message[:_MAX_MESSAGE_CHARS],
        "protocol": (protocol_match.group(1).lower() if protocol_match else ""),
        "action": (action_match.group(1).lower() if action_match else ""),
    }

    source_ip = _first_ip(message, "source_ip")
    destination_ip = _first_ip(message, "destination_ip")
    source_port = _port(message, "source_port")
    destination_port = _port(message, "destination_port")

    if source_ip:
        payload["source_ip"] = source_ip
    if destination_ip:
        payload["destination_ip"] = destination_ip
    if source_port is not None:
        payload["source_port"] = source_port
    if destination_port is not None:
        payload["destination_port"] = destination_port

    return payload


def _resolve_path(raw: str, *, base: Path) -> Path:
    path = Path(raw)
    return path if path.is_absolute() else base / path


def _ssl_context(api_url: str, ca_cert: Path) -> ssl.SSLContext | None:
    if not api_url.lower().startswith("https://"):
        return None
    if not ca_cert.is_file():
        raise CollectorError(
            f"HTTPS CA certificate does not exist: {ca_cert}. "
            "Generate/provision the proxy certificate before starting the collector."
        )
    return ssl.create_default_context(cafile=str(ca_cert))


def _post(
    *,
    api_url: str,
    token: str,
    ca_cert: Path,
    payload: dict[str, object],
    timeout: float = 5.0,
) -> dict[str, object]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(
        api_url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "sentinel43-router-collector/1",
        },
    )

    context = _ssl_context(api_url, ca_cert)

    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(65536)
            decoded = json.loads(body.decode("utf-8")) if body else {}
            return decoded if isinstance(decoded, dict) else {}
    except HTTPError as exc:
        body = exc.read(2048).decode("utf-8", errors="replace")
        raise CollectorError(
            f"S43 router ingress returned HTTP {exc.code}: {body}"
        ) from exc
    except URLError as exc:
        raise CollectorError(f"S43 router ingress is unreachable: {exc.reason}") from exc


def _post_with_retry(
    *,
    api_url: str,
    token: str,
    ca_cert: Path,
    payload: dict[str, object],
    attempts: int = 3,
) -> dict[str, object]:
    last_error: CollectorError | None = None

    for attempt in range(1, attempts + 1):
        try:
            return _post(
                api_url=api_url,
                token=token,
                ca_cert=ca_cert,
                payload=payload,
            )
        except CollectorError as exc:
            last_error = exc
            if attempt >= attempts:
                break
            time.sleep(0.5 * (2 ** (attempt - 1)))

    assert last_error is not None
    raise last_error


def _settings(env_path: Path) -> dict[str, object]:
    values = _read_env(env_path)

    if not _truthy(values.get("S43_ROUTER_ENABLED")):
        raise CollectorError("S43_ROUTER_ENABLED is not true")

    token = values.get("S43_ROUTER_INGEST_TOKEN", "").strip()
    if len(token) < 32:
        raise CollectorError("S43_ROUTER_INGEST_TOKEN is missing or too short")

    raw_sources = values.get("S43_EDGE_SOURCE_IPS", values.get("S43_ROUTER_SOURCE_IP", ""))
    source_ips = tuple(filter(None, (_normalize_ip(item) for item in raw_sources.split(","))))
    if not source_ips:
        raise CollectorError("trusted edge source configuration is missing or invalid")

    api_url = values.get(
        "S43_ROUTER_API_URL",
        "https://localhost/internal/router/events",
    ).strip()
    if not api_url:
        raise CollectorError("S43_ROUTER_API_URL is missing")

    listen_address = values.get("S43_ROUTER_LISTEN_ADDRESS", "0.0.0.0").strip() or "0.0.0.0"

    try:
        listen_port = int(values.get("S43_ROUTER_SYSLOG_PORT", "5514"))
    except ValueError as exc:
        raise CollectorError("S43_ROUTER_SYSLOG_PORT must be an integer") from exc
    if not 1 <= listen_port <= 65535:
        raise CollectorError("S43_ROUTER_SYSLOG_PORT must be 1..65535")

    try:
        max_eps = int(values.get("S43_ROUTER_MAX_EVENTS_PER_SECOND", "50"))
    except ValueError as exc:
        raise CollectorError("S43_ROUTER_MAX_EVENTS_PER_SECOND must be an integer") from exc
    if not 1 <= max_eps <= 1000:
        raise CollectorError("S43_ROUTER_MAX_EVENTS_PER_SECOND must be 1..1000")

    ca_raw = values.get(
        "S43_ROUTER_CA_CERT",
        "deploy/proxy/certs/s43.crt",
    ).strip()
    ca_cert = _resolve_path(ca_raw, base=_REPO_ROOT)

    return {
        "env_path": env_path,
        "env_mtime_ns": env_path.stat().st_mtime_ns,
        "token": token,
        "router_ip": source_ips[0],
        "source_ips": source_ips,
        "api_url": api_url,
        "listen_address": listen_address,
        "listen_port": listen_port,
        "max_eps": max_eps,
        "ca_cert": ca_cert,
    }


def _refresh_token_if_changed(settings: dict[str, object]) -> str:
    """Reload only the credential when secret rotation rewrites the env file."""
    env_path = settings["env_path"]
    if not isinstance(env_path, Path):
        raise CollectorError("collector environment path is invalid")

    current_mtime = env_path.stat().st_mtime_ns
    if current_mtime != int(settings["env_mtime_ns"]):
        values = _read_env(env_path)
        token = values.get("S43_ROUTER_INGEST_TOKEN", "").strip()
        if len(token) < 32:
            raise CollectorError(
                "rotated S43_ROUTER_INGEST_TOKEN is missing or too short"
            )
        settings["token"] = token
        settings["env_mtime_ns"] = current_mtime
        print("router ingest credential reloaded after environment update")

    return str(settings["token"])


def _run_listener(settings: dict[str, object], *, once: bool) -> int:
    source_ips = {str(item) for item in settings.get("source_ips", (settings["router_ip"],))}
    listen_address = str(settings["listen_address"])
    listen_port = int(settings["listen_port"])
    max_eps = int(settings["max_eps"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.bind((listen_address, listen_port))

    accepted_times: deque[float] = deque()
    accepted = 0
    ignored = 0
    dropped_rate = 0

    print(
        f"S43 router collector listening on {listen_address}:{listen_port}; "
        "accepting syslog only from " + ", ".join(sorted(source_ips))
    )

    try:
        while True:
            try:
                data, peer = sock.recvfrom(_MAX_DATAGRAM_BYTES)
            except socket.timeout:
                continue

            peer_ip = _normalize_ip(peer[0])
            if peer_ip not in source_ips:
                ignored += 1
                continue

            now = time.monotonic()
            while accepted_times and accepted_times[0] < now - 1.0:
                accepted_times.popleft()
            if len(accepted_times) >= max_eps:
                dropped_rate += 1
                continue
            accepted_times.append(now)

            message = data.decode("utf-8", errors="replace").strip()
            if not message:
                continue

            payload = _facts(message, peer_ip)
            try:
                result = _post_with_retry(
                    api_url=str(settings["api_url"]),
                    token=_refresh_token_if_changed(settings),
                    ca_cert=settings["ca_cert"],
                    payload=payload,
                )
            except CollectorError as exc:
                print(
                    f"forward_failed event_id={payload['event_id']} error={exc}",
                    file=sys.stderr,
                )
                if once:
                    return 1
                continue

            accepted += 1
            print(
                "accepted "
                f"event_id={result.get('event_id', payload['event_id'])} "
                f"type={result.get('event_type', 'unknown')} "
                f"detector={bool(result.get('detector_ingested', False))}"
            )

            if once:
                break
    except KeyboardInterrupt:
        print(
            f"collector stopped; accepted={accepted} ignored_source={ignored} "
            f"dropped_rate={dropped_rate}"
        )
    finally:
        sock.close()

    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="s43-router-syslog")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument(
        "--test-event",
        default="",
        help="Post one non-threatening synthetic router observation and exit.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Exit after forwarding the first accepted router datagram.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    env_path = Path(args.env_file)
    if not env_path.is_absolute():
        env_path = _REPO_ROOT / env_path

    try:
        settings = _settings(env_path)

        if args.test_event:
            payload = _facts(args.test_event, str(settings["router_ip"]))
            result = _post_with_retry(
                api_url=str(settings["api_url"]),
                token=_refresh_token_if_changed(settings),
                ca_cert=settings["ca_cert"],
                payload=payload,
            )
            print(
                "router ingress test accepted: "
                f"event_id={result.get('event_id', payload['event_id'])} "
                f"type={result.get('event_type', 'unknown')} "
                f"detector={bool(result.get('detector_ingested', False))}"
            )
            return 0

        return _run_listener(settings, once=args.once)

    except (CollectorError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

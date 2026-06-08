from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from Core.logging_init import init_logging, get_logger
from Core.runtime import SentinelRuntime
from ..bootstrap import bootstrap_expectations

APP_NAME = "sentinel-43-core"
APP_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")
WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))
CORE_HEARTBEAT_SECONDS = int(os.getenv("S43_CORE_HEARTBEAT_SECONDS", "15"))

START_TIME = time.time()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def uptime_seconds() -> float:
    return round(time.time() - START_TIME, 3)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="sentinel43")
    p.add_argument("--mode", choices=["normal", "shadow"], default="normal")
    p.add_argument("--dry-run", action="store_true", help="Run without taking actions.")
    p.add_argument("--log-level", default=None, help="Override log level, e.g. INFO.")
    return p.parse_args(argv)


def watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = f"{WATCHTOWER_URL}{path}"
    data = None
    headers = {"Content-Type": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method.upper(),
    )

    try:
        with urllib.request.urlopen(request, timeout=WATCHTOWER_TIMEOUT) as response:
            body = response.read().decode("utf-8")
            if not body:
                return {"status_code": response.status}

            result = json.loads(body)
            if isinstance(result, dict):
                result.setdefault("status_code", response.status)
                return result

            return {"status_code": response.status, "body": result}

    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            detail = str(exc)

        return {
            "error": "watchtower_http_error",
            "status_code": exc.code,
            "detail": detail,
        }

    except Exception as exc:
        return {
            "error": "watchtower_unreachable",
            "detail": str(exc),
        }


def register_core_with_watchtower(mode: str, dry_run: bool) -> dict[str, Any]:
    payload = {
        "module_id": APP_NAME,
        "module_type": "core-runtime",
        "version": APP_VERSION,
        "endpoint": None,
        "capabilities": [
            "runtime",
            "shutdown_signal_handling",
            "core_heartbeat",
            "mode_control",
            "dry_run_control",
        ],
        "metadata": {
            "mode": mode,
            "dry_run": dry_run,
            "started_ts": START_TIME,
            "timestamp": utc_now(),
        },
    }

    return watchtower_request("POST", "/watchtower/modules/register", payload)


def send_core_heartbeat(
    status: str,
    mode: str,
    dry_run: bool,
    message: str,
) -> dict[str, Any]:
    payload = {
        "module_id": APP_NAME,
        "status": status,
        "metrics": {
            "uptime_seconds": uptime_seconds(),
            "mode": mode,
            "dry_run": dry_run,
            "timestamp": utc_now(),
        },
        "message": message,
    }

    return watchtower_request("POST", "/watchtower/modules/heartbeat", payload)


def report_core_dependency(
    status: str,
    mode: str,
    dry_run: bool,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "name": APP_NAME,
        "status": status,
        "version": APP_VERSION,
        "details": {
            "mode": mode,
            "dry_run": dry_run,
            "uptime_seconds": uptime_seconds(),
            "timestamp": utc_now(),
            **(details or {}),
        },
    }

    return watchtower_request("POST", "/watchtower/dependencies/report", payload)


def heartbeat_loop(
    stop_event: threading.Event,
    mode: str,
    dry_run: bool,
    logger: Any,
) -> None:
    while not stop_event.wait(CORE_HEARTBEAT_SECONDS):
        result = send_core_heartbeat(
            status="online",
            mode=mode,
            dry_run=dry_run,
            message="Sentinel-43 core runtime heartbeat online",
        )

        if "error" in result:
            logger.warning("Watchtower heartbeat failed: %s", result)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    init_logging()
    logger = get_logger(__name__)

    runtime = SentinelRuntime(mode=args.mode, dry_run=args.dry_run)
    stop_heartbeat = threading.Event()
    heartbeat_thread: threading.Thread | None = None

    def _handle_signal(signum, frame) -> None:
        logger.warning("Shutdown signal received: %s", signum)

        report_core_dependency(
            status="degraded",
            mode=args.mode,
            dry_run=args.dry_run,
            details={"reason": f"shutdown_signal_{signum}"},
        )

        send_core_heartbeat(
            status="degraded",
            mode=args.mode,
            dry_run=args.dry_run,
            message=f"Shutdown signal received: {signum}",
        )

        stop_heartbeat.set()
        runtime.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        register_result = register_core_with_watchtower(args.mode, args.dry_run)
        if "error" in register_result:
            logger.warning("Core failed to register with Watchtower: %s", register_result)
        else:
            logger.info("Core registered with Watchtower")

        report_core_dependency(
            status="online",
            mode=args.mode,
            dry_run=args.dry_run,
            details={"event": "core_starting"},
        )

        send_core_heartbeat(
            status="online",
            mode=args.mode,
            dry_run=args.dry_run,
            message="Sentinel-43 core runtime starting",
        )

        heartbeat_thread = threading.Thread(
            target=heartbeat_loop,
            args=(stop_heartbeat, args.mode, args.dry_run, logger),
            daemon=True,
            name="sentinel43-core-watchtower-heartbeat",
        )
        heartbeat_thread.start()

        runtime.start()

        report_core_dependency(
            status="online",
            mode=args.mode,
            dry_run=args.dry_run,
            details={"event": "core_runtime_started"},
        )

        runtime.block_forever()
        return 0

    except Exception as exc:
        logger.exception("Fatal error in Sentinel-43 runtime")

        report_core_dependency(
            status="failed",
            mode=args.mode,
            dry_run=args.dry_run,
            details={
                "event": "fatal_runtime_error",
                "error": str(exc),
            },
        )

        send_core_heartbeat(
            status="failed",
            mode=args.mode,
            dry_run=args.dry_run,
            message=f"Fatal runtime error: {exc}",
        )

        return 1

    finally:
        stop_heartbeat.set()

        report_core_dependency(
            status="offline",
            mode=args.mode,
            dry_run=args.dry_run,
            details={"event": "core_shutdown"},
        )

        send_core_heartbeat(
            status="offline",
            mode=args.mode,
            dry_run=args.dry_run,
            message="Sentinel-43 core runtime shutting down",
        )

        runtime.stop()

        if heartbeat_thread and heartbeat_thread.is_alive():
            heartbeat_thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
from __future__ import annotations

import argparse
import signal
import sys

from Core.logging_init import init_logging, get_logger
from Core.runtime import SentinelRuntime


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="sentinel43")
    p.add_argument("--mode", choices=["normal", "shadow"], default="normal")
    p.add_argument("--dry-run", action="store_true", help="Run without taking actions.")
    p.add_argument("--log-level", default=None, help="Override log level (e.g., INFO).")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    init_logging()
    logger = get_logger(__name__)

    runtime = SentinelRuntime(mode=args.mode, dry_run=args.dry_run)

    def _handle_signal(signum, frame):
        logger.warning("Shutdown signal received: %s", signum)
        runtime.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        runtime.start()
        runtime.block_forever()
        return 0
    except Exception:
        logger.exception("Fatal error in Sentinel-43 runtime")
        return 1
    finally:
        runtime.stop()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
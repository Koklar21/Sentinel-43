from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from Core.logging_init import get_logger


@dataclass
class SentinelRuntime:
    mode: str = "normal"
    dry_run: bool = False

    def __post_init__(self) -> None:
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._logger = get_logger(self.__class__.__name__)

    def start(self) -> None:
        self._logger.info("Starting Sentinel-43 (mode=%s dry_run=%s)", self.mode, self.dry_run)

        # Example worker thread. We’ll replace this with your real orchestration calls.
        t = threading.Thread(target=self._main_loop, name="sentinel-main-loop", daemon=True)
        self._threads.append(t)
        t.start()

    def stop(self) -> None:
        if self._stop_event.is_set():
            return
        self._logger.info("Stopping Sentinel-43...")
        self._stop_event.set()

        for t in self._threads:
            if t.is_alive():
                t.join(timeout=5)

        self._logger.info("Sentinel-43 stopped.")

    def block_forever(self) -> None:
        # Keeps process alive until stop requested
        while not self._stop_event.is_set():
            time.sleep(0.25)

    def _main_loop(self) -> None:
        self._logger.info("Main loop online.")
        while not self._stop_event.is_set():
            # TODO: call your orchestration functions here (nexus/core/escalation/shadow)
            time.sleep(1.0)
        self._logger.info("Main loop offline.")
"""Output and resource monitoring.

Two jobs, both read-only observations of a running container:

  wait    block until the program exits, with a wall-clock deadline
  collect read stdout, stderr, exit code and resource kill state

The timeout is the only enforcement the controller performs itself. It cannot
be expressed as a Docker field: `--stop-timeout` is how long the daemon waits
*after* asking a program to stop, not a deadline on the program. And a blocking
`/wait` cannot be interrupted, so the wait runs on a worker thread while the
main thread watches the clock, then SIGKILLs the container.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass

from . import engine


@dataclass
class Outcome:
    """What a sandboxed program produced, and how it ended."""

    exit_code: int
    stdout: str
    stderr: str
    duration: float
    container_id: str
    timed_out: bool = False
    oom_killed: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def killed(self) -> bool:
        """True when the sandbox stopped the program, not the program itself."""
        return self.timed_out or self.oom_killed


class Monitor:
    """Waits for a container to finish and collects its output."""

    def __init__(self, client: engine.Client) -> None:
        self.client = client

    def wait_and_collect(
        self, container_id: str, timeout: float
    ) -> tuple:
        """Wait with a deadline, then read logs.

        Returns (exit_code, stdout, stderr, timed_out).
        """
        exit_code, timed_out = self._wait(container_id, timeout)

        status, log_raw = self.client.request(
            "GET",
            "/containers/%s/logs?stdout=1&stderr=1" % container_id,
            timeout=timeout + 60,
        )
        if status >= 400:
            raise engine.EngineError(
                "logs failed (%d): %s" % (status, engine.message(log_raw))
            )
        stdout, stderr = engine.demux(log_raw)
        return exit_code, stdout, stderr, timed_out

    def _wait(self, container_id: str, timeout: float) -> tuple:
        """Block on /wait, killing the container if the deadline passes."""
        outcome = {}

        def waiter():
            try:
                status, raw = self.client.request(
                    "POST",
                    "/containers/%s/wait" % container_id,
                    timeout=timeout + 60,
                )
                if status >= 400:
                    outcome["error"] = "wait failed (%d): %s" % (
                        status,
                        engine.message(raw),
                    )
                else:
                    outcome["exit_code"] = json.loads(raw)["StatusCode"]
            except engine.EngineError as exc:
                outcome["error"] = str(exc)

        worker = threading.Thread(target=waiter, daemon=True)
        worker.start()
        worker.join(timeout)

        timed_out = worker.is_alive()
        if timed_out:
            # Kill, then give the daemon a moment to reap the process so the
            # waiting request can return normally.
            self.client.request(
                "POST", "/containers/%s/kill?signal=SIGKILL" % container_id
            )
            worker.join(5)
            outcome.setdefault("exit_code", 137)

        if "error" in outcome:
            raise engine.EngineError(outcome["error"])

        return outcome.get("exit_code", 137), timed_out

    def state(self, container_id: str) -> dict:
        """Container state as reported by the Engine."""
        data = self.client.json("GET", "/containers/%s/json" % container_id)
        return data.get("State", {})

    def oom_killed(self, container_id: str) -> bool:
        """Whether the kernel killed this container for exceeding its memory."""
        return bool(self.state(container_id).get("OOMKilled", False))

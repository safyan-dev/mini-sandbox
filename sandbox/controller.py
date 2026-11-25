"""Lifecycle management.

The controller owns the five responsibilities and delegates the rest:

    create     POST /containers/create with the security posture applied
    configure  security.host_config()  - all restrictions, in one place
    execute    executor.start()        - starts the container
    monitor    monitor.wait_and_collect() - deadline, output, kill state
    destroy    DELETE /containers/{id} - in a finally block, always

Python never isolates a process. It chooses JSON; the Engine turns that JSON
into kernel syscalls inside the Linux VM. The only enforcement this package
performs itself is the wall-clock deadline, and even that is carried out by
asking the Engine to SIGKILL the container.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import config, engine, executor as executor_module, monitor as monitor_module
from . import security
from .monitor import Outcome


@dataclass
class Sandbox:
    """Manages one container for the lifetime of one program execution."""

    client: engine.Client = field(default_factory=engine.Client)
    image: str = config.SANDBOX_IMAGE
    program_args: list = field(default_factory=list)

    container_id: str | None = None
    host_program_dir: str | None = None

    def __post_init__(self) -> None:
        self._executor = executor_module.Executor(self.client)
        self._monitor = monitor_module.Monitor(self.client)

    # --- create -------------------------------------------------------
    def create(self, code: str) -> str:
        """Ask the Engine for a container and deliver the program to it."""
        self.host_program_dir = self._executor.stage(code)
        response = self.client.json(
            "POST", "/containers/create", self._payload()
        )
        self.container_id = response["Id"]
        return self.container_id

    # --- configure ----------------------------------------------------
    def _payload(self) -> dict:
        """The create request: program, working directory, and restrictions.

        The security fields come entirely from security.host_config(), so the
        posture has exactly one definition and cannot drift from what is tested.
        """
        return {
            "Image": self.image,
            "Cmd": [self._executor.program_path(), *self.program_args],
            "WorkingDir": config.SANDBOX_SCRATCH,
            "AttachStdout": True,
            "AttachStderr": True,
            # A non-TTY container keeps stdout and stderr separately framed,
            # which is what lets us report them apart.
            "Tty": False,
            # No port publishing: with no network there is nothing to publish.
            "ExposedPorts": {},
            "HostConfig": security.host_config(self.host_program_dir),
        }

    # --- execute ------------------------------------------------------
    def execute(self) -> None:
        """Start the container. The program runs inside the Linux VM."""
        self._require_container()
        self._executor.start(self.container_id)

    # --- monitor ------------------------------------------------------
    def monitor(self, timeout: float = config.DEFAULT_TIMEOUT) -> tuple:
        """Wait for exit and collect output. Returns (code, out, err, timed_out)."""
        self._require_container()
        return self._monitor.wait_and_collect(self.container_id, timeout)

    def state(self) -> dict:
        return self._monitor.state(self.container_id) if self.container_id else {}

    def oom_killed(self) -> bool:
        return self._monitor.oom_killed(self.container_id) if self.container_id else False

    # --- destroy ------------------------------------------------------
    def destroy(self) -> None:
        """Force-remove the container and its staged program. Idempotent."""
        if self.container_id:
            self.client.request(
                "DELETE", "/containers/%s?force=1&v=1" % self.container_id
            )
            self.container_id = None
        self._executor.cleanup()
        self.host_program_dir = None

    # --- the whole lifecycle in one call ------------------------------
    def run(self, code: str, timeout: float = config.DEFAULT_TIMEOUT) -> Outcome:
        """create -> execute -> monitor -> destroy, in that order.

        Destruction is in a finally block: a container must not outlive the
        program, even when the program crashes or the controller is interrupted.
        """
        started = time.monotonic()
        try:
            self.create(code)
            self.execute()
            exit_code, stdout, stderr, timed_out = self.monitor(timeout=timeout)
            oom = self.oom_killed() if not timed_out else False
            return Outcome(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration=time.monotonic() - started,
                container_id=self.container_id or "",
                timed_out=timed_out,
                oom_killed=oom,
            )
        finally:
            self.destroy()

    def _require_container(self) -> None:
        if not self.container_id:
            raise RuntimeError("create() must be called before this step")

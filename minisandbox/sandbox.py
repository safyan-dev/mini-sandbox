"""The sandbox lifecycle: create, configure, execute, monitor, destroy.

Python's role here is management, not enforcement. Every restriction we ask for
is a field in the JSON we send to the Engine; the Engine turns it into kernel
syscalls inside the Linux VM. Nothing in this file can isolate a process on its
own - it can only request isolation and check that it was granted.

Stage 4 adds filesystem isolation:
  - the container root filesystem is read-only, so image files cannot be altered
  - the program is delivered through a read-only bind mount of ephemeral,
    controller-owned scratch, never a host user directory
  - writable state is tmpfs only (memory-backed, noexec, discarded with the
    container), so nothing a program writes can persist
  - no path from inside the container reaches the Docker socket or the host
"""

from __future__ import annotations

import io
import json
import shutil
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config, engine


@dataclass
class Result:
    """What a sandboxed program produced."""

    exit_code: int
    stdout: str
    stderr: str
    duration: float
    container_id: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass
class Sandbox:
    """Manages one container for the lifetime of one program execution."""

    client: engine.Client = field(default_factory=engine.Client)
    image: str = config.SANDBOX_IMAGE
    container_id: str | None = None
    host_program_dir: str | None = None

    # --- Responsibility 1: create -------------------------------------
    def create(self, code: str) -> str:
        """Ask the Engine for a container and deliver the program to it.

        The program cannot be injected with the archive endpoint once the root
        filesystem is read-only (the Engine rejects it), so it is staged in a
        throwaway controller-owned directory and bind-mounted read-only.
        """
        self._stage_program(code)
        payload = self._configure()
        response = self.client.json("POST", "/containers/create", payload)
        self.container_id = response["Id"]
        return self.container_id

    # --- Responsibility 2: configure ----------------------------------
    def _configure(self) -> dict:
        """Build the create request.

        This is the only place security posture is expressed. Each later stage
        adds fields here; the Engine is what enforces them.
        """
        return {
            "Image": self.image,
            "Cmd": [self._program_path()],
            "WorkingDir": config.SANDBOX_SCRATCH,
            "AttachStdout": True,
            "AttachStderr": True,
            # A non-TTY container keeps stdout and stderr separately framed,
            # which is what lets us report them apart.
            "Tty": False,
            "HostConfig": {
                "AutoRemove": False,
                # --- Stage 4: filesystem isolation ---
                # The image filesystem becomes immutable. A program may read it
                # but cannot modify the interpreter, add binaries, or tamper
                # with anything that outlives the run.
                "ReadonlyRootfs": True,
                # The only writable locations are memory-backed tmpfs mounts.
                # noexec stops a written file from becoming a program; nosuid
                # stops privilege bits from mattering; size bounds memory use.
                "Tmpfs": {
                    config.SANDBOX_SCRATCH: "rw,noexec,nosuid,nodev,size=%s,mode=1777"
                    % config.SCRATCH_SIZE,
                    config.SANDBOX_TMP: "rw,noexec,nosuid,nodev,size=%s,mode=1777"
                    % config.SCRATCH_SIZE,
                },
                # The program arrives read-only from controller scratch. Not
                # `$HOME`, not Documents: a temporary directory that is deleted
                # along with the container.
                "Binds": [
                    "%s:%s:ro" % (self.host_program_dir, config.SANDBOX_PROGRAM_DIR)
                ],
                # Never `-v /var/run/docker.sock`: mounting it would hand the
                # program control of the daemon and therefore of the host.
            },
        }

    def _stage_program(self, code: str) -> None:
        """Write the program to a throwaway directory owned by the controller."""
        self.host_program_dir = tempfile.mkdtemp(prefix="minisandbox-")
        path = Path(self.host_program_dir) / "main.py"
        path.write_text(code, encoding="utf-8")

    def _program_path(self) -> str:
        return "%s/main.py" % config.SANDBOX_PROGRAM_DIR

    # --- Responsibility 3: execute ------------------------------------
    def execute(self) -> None:
        """Start the container. The program runs inside the Linux VM."""
        self._require_container()
        self.client.request("POST", "/containers/%s/start" % self.container_id)

    # --- Responsibility 4: monitor ------------------------------------
    def monitor(self, timeout: float = 60.0) -> tuple:
        """Wait for exit and collect stdout, stderr and the exit code."""
        self._require_container()
        status, raw = self.client.request(
            "POST", "/containers/%s/wait" % self.container_id, timeout=timeout
        )
        if status >= 400:
            raise engine.EngineError("wait failed (%d)" % status)
        exit_code = json.loads(raw)["StatusCode"]

        status, log_raw = self.client.request(
            "GET",
            "/containers/%s/logs?stdout=1&stderr=1" % self.container_id,
            timeout=timeout,
        )
        if status >= 400:
            raise engine.EngineError("logs failed (%d)" % status)
        stdout, stderr = engine.demux(log_raw)
        return exit_code, stdout, stderr

    # --- Responsibility 5: destroy ------------------------------------
    def destroy(self) -> None:
        """Force-remove the container and its staged program. Idempotent."""
        if self.container_id:
            self.client.request(
                "DELETE", "/containers/%s?force=1&v=1" % self.container_id
            )
            self.container_id = None
        if self.host_program_dir:
            shutil.rmtree(self.host_program_dir, ignore_errors=True)
            self.host_program_dir = None

    # --- Convenience: the full lifecycle in one call -------------------
    def run(self, code: str, timeout: float = 60.0) -> Result:
        """create -> execute -> monitor -> destroy, in that order.

        Destruction is in a finally block: a container must not outlive the
        program, even when the program crashes or the controller is interrupted.
        """
        started = time.monotonic()
        try:
            self.create(code)
            self.execute()
            exit_code, stdout, stderr = self.monitor(timeout=timeout)
            return Result(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration=time.monotonic() - started,
                container_id=self.container_id or "",
            )
        finally:
            self.destroy()

    def _require_container(self) -> None:
        if not self.container_id:
            raise RuntimeError("create() must be called before this step")

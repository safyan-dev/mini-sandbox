"""The sandbox lifecycle: create, configure, execute, monitor, destroy.

Python's role here is management, not enforcement. Every restriction we ask for
is a field in the JSON we send to the Engine; the Engine turns it into kernel
syscalls inside the Linux VM. Nothing in this file can isolate a process on its
own - it can only request isolation and check that it was granted.

Stage 3 implements the lifecycle with the Stage 2 image baseline (unprivileged
user, no package manager). Filesystem, network, process and resource
restrictions are added in Stages 4-6 by extending `_configure`.
"""

from __future__ import annotations

import io
import json
import tarfile
import time
import urllib.parse
from dataclasses import dataclass, field

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

    # --- Responsibility 1: create -------------------------------------
    def create(self, code: str) -> str:
        """Ask the Engine for a container and inject the program into it.

        The program is written with the archive endpoint rather than passed on
        the command line: argv has length limits and would appear in `docker
        ps`, whereas a file keeps the program as data.
        """
        payload = self._configure(code)
        response = self.client.json("POST", "/containers/create", payload)
        self.container_id = response["Id"]
        self._put_code(code)
        return self.container_id

    # --- Responsibility 2: configure ----------------------------------
    def _configure(self, code: str) -> dict:
        """Build the create request.

        This is the only place security posture is expressed. Each later stage
        adds fields here; the Engine is what enforces them.
        """
        return {
            "Image": self.image,
            "Cmd": ["/sandbox/main.py"],
            "WorkingDir": config.SANDBOX_WORKDIR,
            "AttachStdout": True,
            "AttachStderr": True,
            # A non-TTY container keeps stdout and stderr separately framed,
            # which is what lets us report them apart.
            "Tty": False,
            "HostConfig": {
                # Baseline only. Stages 4-6 add network, filesystem,
                # capability and resource restrictions here.
                "AutoRemove": False,
            },
        }

    def _put_code(self, code: str) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            data = code.encode("utf-8")
            info = tarfile.TarInfo("main.py")
            info.size = len(data)
            info.mode = 0o644
            info.uid = config.SANDBOX_UID
            info.gid = config.SANDBOX_UID
            archive.addfile(info, io.BytesIO(data))
        buffer.seek(0)

        path = "/containers/%s/archive?path=%s" % (
            self.container_id,
            urllib.parse.quote(config.SANDBOX_WORKDIR, safe=""),
        )
        status, raw = self.client.request(
            "PUT",
            path,
            body=buffer.read(),
            headers={"Content-Type": "application/x-tar"},
        )
        if status >= 400:
            raise engine.EngineError("code injection failed (%d): %s" % (status, raw[:200]))

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
        """Force-remove the container. Safe to call more than once."""
        if not self.container_id:
            return
        self.client.request(
            "DELETE", "/containers/%s?force=1&v=1" % self.container_id
        )
        self.container_id = None

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

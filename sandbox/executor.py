"""Program execution.

Delivers a program into a container and starts it.

Delivery is not obvious: once the root filesystem is read-only, the Engine
rejects `PUT /archive` ("container rootfs is marked read-only"), and a tmpfs
cannot receive an archive because it does not exist until the container starts.
So the program is written to a throwaway controller-owned directory and
bind-mounted read-only. That directory is deleted when the sandbox is destroyed.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from . import config, engine


class Executor:
    """Stages a program on the host and starts the container that runs it."""

    def __init__(self, client: engine.Client) -> None:
        self.client = client
        self.host_program_dir: str | None = None

    def stage(self, code: str) -> str:
        """Write the program to a temporary directory. Returns that directory."""
        self.host_program_dir = tempfile.mkdtemp(prefix="minisandbox-")
        path = Path(self.host_program_dir) / "main.py"
        path.write_text(code, encoding="utf-8")
        os.chmod(self.host_program_dir, 0o755)
        return self.host_program_dir

    def start(self, container_id: str) -> None:
        """Start the container. The program runs inside the Linux VM."""
        status, raw = self.client.request(
            "POST", "/containers/%s/start" % container_id
        )
        if status >= 400:
            raise engine.EngineError(
                "container failed to start (%d): %s" % (status, engine.message(raw))
            )

    def cleanup(self) -> None:
        """Delete the staged program. Idempotent."""
        if not self.host_program_dir:
            return
        import shutil

        shutil.rmtree(self.host_program_dir, ignore_errors=True)
        self.host_program_dir = None

    @staticmethod
    def program_path() -> str:
        return "%s/main.py" % config.SANDBOX_PROGRAM_DIR

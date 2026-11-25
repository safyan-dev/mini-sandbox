"""Static configuration shared by every stage of the controller."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BASE_IMAGE = "ubuntu:24.04"

SANDBOX_IMAGE = "minisandbox/sandbox:latest"

DOCKERFILE_DIR = PROJECT_ROOT / "docker"

SANDBOX_USER = "sandbox"
SANDBOX_UID = 1000

# Image working directory (created read-only once the rootfs is read-only).
SANDBOX_WORKDIR = "/sandbox"

# Program is delivered through a read-only bind mount so untrusted code cannot
# modify itself.
SANDBOX_PROGRAM_DIR = "/sandbox/program"

# Writable scratch lives on tmpfs: memory-backed, noexec, and gone with the
# container.
SANDBOX_SCRATCH = "/sandbox/work"
SANDBOX_TMP = "/tmp"
SCRATCH_SIZE = "16m"

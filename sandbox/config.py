"""Static configuration shared by the sandbox and the environment."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BASE_IMAGE = "ubuntu:24.04"

SANDBOX_IMAGE = "minisandbox/sandbox:latest"

DOCKERFILE_DIR = PROJECT_ROOT / "environment"

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

# --- resource limits ---
# Byte counts, because the Engine API takes integers, not "64m" strings.
MEMORY_LIMIT = 64 * 1024 * 1024
# Equal to the memory limit: swap would otherwise let a program exceed its
# memory ceiling by spilling to disk in the VM.
MEMORY_SWAP = MEMORY_LIMIT
# One core, expressed in billionths of a core (the API's NanoCpus unit).
NANO_CPUS = 1_000_000_000
# Maximum number of tasks (threads and processes) in the container's cgroup.
PIDS_LIMIT = 64
# Wall-clock ceiling, enforced by the controller.
DEFAULT_TIMEOUT = 10.0

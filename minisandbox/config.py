"""Static configuration shared by every stage of the controller."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

BASE_IMAGE = "ubuntu:24.04"

SANDBOX_IMAGE = "minisandbox/sandbox:latest"

DOCKERFILE_DIR = PROJECT_ROOT / "docker"

SANDBOX_USER = "sandbox"
SANDBOX_UID = 1000
SANDBOX_WORKDIR = "/sandbox"

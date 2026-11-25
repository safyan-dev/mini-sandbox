"""Execution tests: program delivery, output capture, exit codes, teardown.

These test the lifecycle itself rather than the restrictions: that a program
reaches the container, that stdout and stderr stay separate, that exit codes
survive, and that nothing outlives a run.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import tempfile

from sandbox import engine
from sandbox.controller import Sandbox


def hello() -> list:
    """A normal program runs, sees the sandbox, and exits 0."""
    result = Sandbox().run(
        "import os\nprint('hello')\nprint('uid', os.getuid())\n",
        timeout=30,
    )
    return [
        ("exit code 0", result.exit_code == 0, "got %d" % result.exit_code),
        ("stdout captured", "hello" in result.stdout, repr(result.stdout.strip())),
        ("runs unprivileged", "uid 1000" in result.stdout, "uid 1000"),
    ]


def streams() -> list:
    """stdout and stderr are captured separately."""
    result = Sandbox().run(
        "import sys\nprint('to-out')\nprint('to-err', file=sys.stderr)\n",
        timeout=30,
    )
    return [
        ("stdout only has stdout", "to-out" in result.stdout, repr(result.stdout.strip())),
        ("stderr only has stderr", "to-err" in result.stderr, repr(result.stderr.strip())),
        (
            "no cross-contamination",
            "to-err" not in result.stdout and "to-out" not in result.stderr,
            "streams stay separate",
        ),
    ]


def exit_codes() -> list:
    """A non-zero exit code survives the round trip."""
    result = Sandbox().run("import sys\nsys.exit(7)\n", timeout=30)
    return [("exit code 7", result.exit_code == 7, "got %d" % result.exit_code)]


def crash() -> list:
    """An unhandled exception is reported as exit 1 with a traceback."""
    result = Sandbox().run("1 / 0\n", timeout=30)
    return [
        ("crash exits 1", result.exit_code == 1, "got %d" % result.exit_code),
        (
            "traceback captured",
            "ZeroDivisionError" in result.stderr,
            "ZeroDivisionError in stderr",
        ),
    ]


def program_args() -> list:
    """Arguments reach the program as argv."""
    result = Sandbox(program_args=["alpha", "beta"]).run(
        "import sys\nprint('ARGS', sys.argv[1:])\n", timeout=30
    )
    return [
        (
            "argv passed",
            "['alpha', 'beta']" in result.stdout,
            result.stdout.strip(),
        )
    ]


def teardown() -> list:
    """No container and no staged directory survives a run."""
    client = engine.Client()
    before = _containers(client) + _containers_running_ids(client)

    # An unrelated directory that must be left alone. It deliberately does not
    # use the "minisandbox-" prefix, so it cannot be confused with staged code.
    scratch = tempfile.mkdtemp(prefix="unrelated-scratch-")

    Sandbox().run("print('x')\n", timeout=30)

    after = _containers(client) + _containers_running_ids(client)
    remaining = [c for c in after if c not in before]

    staged = _staged_dirs()

    result = [
        ("no leftover containers", not remaining, "%d leaked" % len(remaining)),
        ("no staged program dirs", not staged, "%d left on disk" % len(staged)),
        (
            "unrelated dirs untouched",
            os.path.isdir(scratch) and not os.listdir(scratch),
            "sandbox stays out of unrelated paths",
        ),
    ]
    shutil.rmtree(scratch, ignore_errors=True)
    return result


def destroyed_on_failure() -> list:
    """A container is destroyed even when monitoring fails."""
    box = Sandbox()
    box.create("print('x')\n")
    cid = box.container_id
    try:
        box.monitor(timeout=0.001)
    except engine.EngineError:
        pass
    finally:
        box.destroy()

    client = engine.Client()
    status, _ = client.request("GET", "/containers/%s/json" % cid)
    return [
        ("destroyed after error", status == 404, "inspect returned %d" % status),
        ("staged dir released", box.host_program_dir is None, "cleaned up"),
    ]


def _containers(client) -> list:
    _, raw = client.request("GET", "/containers/json?all=1")
    return [
        entry["Id"]
        for entry in json.loads(raw or b"[]")
        if "minisandbox/sandbox" in (entry.get("Image") or "")
    ]


def _containers_running_ids(client) -> list:
    _, raw = client.request("GET", "/containers/json")
    return [
        "alive:%s" % entry["Id"]
        for entry in json.loads(raw or b"[]")
        if "minisandbox/sandbox" in (entry.get("Image") or "")
    ]


def _staged_dirs() -> list:
    """Staged program directories the executor leaves behind, if any."""
    pattern = os.path.join(os.environ.get("TMPDIR", "/tmp"), "minisandbox-[0-9a-z]*")
    return [
        path
        for path in glob.glob(pattern)
        if os.path.isdir(path) and os.path.isfile(os.path.join(path, "main.py"))
    ]

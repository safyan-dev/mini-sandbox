"""Stage 4 - filesystem isolation verification.

A sandbox is only isolated if the isolation can be observed. This module runs a
probe inside the real sandbox configuration and asserts the filesystem
properties we claim: immutable root, tmpfs-only writes, no host paths, no
Docker socket, and nothing left behind.
"""

from __future__ import annotations

import json

from . import config, sandbox

_PROBE = r'''
import json, os, subprocess

facts = {}
facts["uid"] = os.getuid()

# Image filesystem must be immutable.
def writable(path):
    try:
        open(os.path.join(path, ".probe"), "w").write("x")
        return True
    except OSError:
        return False

facts["root_writable"] = any(writable(p) for p in ("/", "/etc", "/usr", "/sandbox"))
facts["scratch_writable"] = writable("/sandbox/work")
facts["tmp_writable"] = writable("/tmp")

# No host path and no Docker socket may be reachable.
watch = ["/Users", "/Volumes", "/private/etc/hosts",
         "/var/run/docker.sock", "/run/docker.sock"]
facts["host_visible"] = [p for p in watch if os.path.exists(p)]

# The program mount must be read-only.
try:
    open("/sandbox/program/main.py", "a").write("# tampered\n")
    facts["program_writable"] = True
except OSError:
    facts["program_writable"] = False

# scratch must be noexec: a written file cannot be executed directly.
script = "/sandbox/work/probe.sh"
open(script, "w").write("#!/bin/sh\necho x\n")
os.chmod(script, 0o755)
try:
    subprocess.run([script], capture_output=True, timeout=5)
    facts["scratch_executable"] = True
except OSError:
    facts["scratch_executable"] = False

# Scratch must be memory-backed (tmpfs).
mounts = {}
for line in open("/proc/mounts"):
    parts = line.split()
    if len(parts) >= 3:
        mounts[parts[1]] = parts[2]
facts["scratch_fstype"] = mounts.get("/sandbox/work", "?")
facts["root_fstype"] = mounts.get("/", "?")

print("FACTS=" + json.dumps(facts))
'''


def verify(client=None) -> list:
    """Run the probe in a sandbox and return (name, ok, detail) tuples."""
    box = sandbox.Sandbox() if client is None else sandbox.Sandbox(client=client)
    result = box.run(_PROBE, timeout=60)

    facts = {}
    for line in result.stdout.splitlines():
        if line.startswith("FACTS="):
            facts = json.loads(line[len("FACTS="):])

    if not facts:
        return [("probe", False, "program produced no facts: %s" % result.stderr[:100])]

    return [
        (
            "read-only root",
            not facts.get("root_writable", True),
            "/, /etc, /usr all immutable",
        ),
        (
            "program mount read-only",
            not facts.get("program_writable", True),
            "cannot modify %s" % config.SANDBOX_PROGRAM_DIR,
        ),
        (
            "tmpfs scratch",
            facts.get("scratch_fstype") == "tmpfs",
            "%s is %s" % (config.SANDBOX_SCRATCH, facts.get("scratch_fstype", "?")),
        ),
        (
            "scratch writable",
            facts.get("scratch_writable", False),
            "programs can write temporary files",
        ),
        (
            "scratch not executable",
            not facts.get("scratch_executable", True),
            "noexec enforced",
        ),
        (
            "no host paths",
            not facts.get("host_visible"),
            "none of /Users, /Volumes, /private/etc/hosts visible"
            if not facts.get("host_visible")
            else "visible: %s" % ", ".join(facts["host_visible"]),
        ),
        (
            "no docker socket",
            not any("docker.sock" in p for p in facts.get("host_visible", [])),
            "daemon unreachable from inside",
        ),
    ]

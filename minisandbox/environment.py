"""Stage 1 - environment verification, over the Engine API.

The point of this module is not to run untrusted code. It exists to prove the
chain we are about to build on actually works:

    macOS host  ->  Docker Desktop Linux VM  ->  Linux kernel features

If any link is broken then every later stage (isolation, limits, seccomp) is
built on sand. `doctor()` checks the chain top to bottom and reports each link.
"""

from __future__ import annotations

import json
import platform
import sys
import urllib.parse

from . import config, engine

# Runs *inside* the container. Emits `key=value` lines the controller parses.
# It uses only coreutils so it works on a bare ubuntu image with no installs.
_PROBE = r"""
echo "os_id=$(. /etc/os-release; echo $PRETTY_NAME)"
echo "kernel=$(uname -r)"
echo "arch=$(uname -m)"
echo "namespaces=$(ls /proc/self/ns | tr '\n' ',' | sed 's/,$//')"
echo "cgroup_type=$(stat -fc %T /sys/fs/cgroup)"
echo "cgroup_ro=$([ -w /sys/fs/cgroup ] && echo no || echo yes)"
echo "seccomp_mode=$(awk '/^Seccomp:/{print $2}' /proc/self/status)"
echo "cap_eff=$(awk '/^CapEff:/{print $2}' /proc/self/status)"
echo "uid=$(id -u)"
"""


class Check:
    def __init__(self, name: str, ok: bool, detail: str) -> None:
        self.name = name
        self.ok = ok
        self.detail = detail

    def render(self) -> str:
        mark = "PASS" if self.ok else "FAIL"
        return "  [%s] %-22s %s" % (mark, self.name, self.detail)


def _host_checks() -> list:
    py = "%d.%d.%d" % sys.version_info[:3]
    return [
        Check("python", sys.version_info >= (3, 8), "Python %s (%s)" % (py, sys.executable)),
        Check(
            "host",
            platform.system() == "Darwin",
            "%s %s %s" % (platform.system(), platform.release(), platform.machine()),
        ),
        Check(
            "docker socket",
            True,
            engine.default_socket(),
        ),
    ]


def _engine_checks(client: engine.Client) -> tuple:
    """Returns (checks, info_dict_or_None)."""
    try:
        info = client.json("GET", "/info")
    except engine.EngineError as exc:
        return [Check("docker daemon", False, str(exc))], None

    cpu = int(info.get("NCPU") or 0)
    mem = int(info.get("MemTotal") or 0) / 1024 ** 3
    checks = [
        Check("docker daemon", True, "engine %s, API ready" % info.get("ServerVersion", "?")),
        Check(
            "linux vm",
            info.get("OSType") == "linux",
            "%s / kernel %s / %d cpu / %.1f GiB"
            % (
                info.get("OperatingSystem", "?"),
                info.get("KernelVersion", "?"),
                cpu,
                mem,
            ),
        ),
    ]
    return checks, info


def _probe_checks(client: engine.Client) -> list:
    """Launch one short-lived container and verify kernel features inside it."""
    try:
        client.json(
            "POST",
            "/images/%s/json" % urllib.parse.quote(config.BASE_IMAGE, safe=""),
        )
    except engine.EngineError:
        status, raw = client.request(
            "POST",
            "/images/create?fromImage=%s" % urllib.parse.quote(config.BASE_IMAGE, safe=""),
            timeout=600,
        )
        if status >= 400:
            return [Check("base image", False, "pull failed: %s" % raw[:120])]

    try:
        created = client.json(
            "POST",
            "/containers/create",
            {
                "Image": config.BASE_IMAGE,
                "Cmd": ["-c", _PROBE],
                "Entrypoint": ["bash"],
                "AttachStdout": True,
                "AttachStderr": True,
            },
        )
    except engine.EngineError as exc:
        return [Check("probe container", False, str(exc))]

    cid = created["Id"]
    try:
        client.request("POST", "/containers/%s/start" % cid)
        client.request("POST", "/containers/%s/wait" % cid, timeout=180)
        _, raw = client.request(
            "GET", "/containers/%s/logs?stdout=1&stderr=1" % cid, timeout=180
        )
        stdout, _ = engine.demux(raw)
    finally:
        client.request("DELETE", "/containers/%s?force=1&v=1" % cid)

    facts = {}
    for line in stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            facts[key.strip()] = value.strip()

    if not facts:
        return [Check("probe container", False, "no output from container")]

    ns = [n for n in facts.get("namespaces", "").split(",") if n]
    needed = {"pid", "net", "mnt", "ipc", "uts", "cgroup"}
    missing = needed - set(ns)

    return [
        Check("linux userland", "Ubuntu" in facts.get("os_id", ""), facts.get("os_id", "unknown")),
        Check(
            "namespaces",
            not missing,
            "%d present (pid, net, mnt, ipc, uts, cgroup)" % len(ns)
            if not missing
            else "missing: %s" % ", ".join(sorted(missing)),
        ),
        Check(
            "cgroup v2",
            facts.get("cgroup_type") == "cgroup2fs",
            "%s (mounted %s)"
            % (
                facts.get("cgroup_type", "?"),
                "read-only" if facts.get("cgroup_ro") == "yes" else "read-write",
            ),
        ),
        Check(
            "seccomp",
            facts.get("seccomp_mode") in ("1", "2"),
            "mode %s filter active" % facts.get("seccomp_mode", "?"),
        ),
        Check(
            "capabilities",
            bool(facts.get("cap_eff")),
            "CapEff %s" % facts.get("cap_eff", "?"),
        ),
    ]


def doctor(verbose: bool = False) -> int:
    """Run the full environment check. Returns a process exit code."""
    print("MiniSandbox environment check\n")

    host_checks = _host_checks()
    client = engine.Client()
    engine_checks, info = _engine_checks(client)

    probe = _probe_checks(client) if info is not None else []

    print("Host (macOS)")
    for c in host_checks:
        print(c.render())

    print("\nLinux VM (Docker Desktop)")
    for c in engine_checks:
        print(c.render())

    if probe:
        print("\nInside a container (kernel features)")
        for c in probe:
            print(c.render())

    failed = [c for c in host_checks + engine_checks + probe if not c.ok]
    print()
    if failed:
        print("%d check(s) failed" % len(failed))
        return 1

    print("Environment ready: macOS controls a Linux VM whose kernel provides")
    print("namespaces, cgroup v2 and seccomp to containers.")
    print("Note: cgroup fs inside a container is read-only, so resource limits")
    print("must be set at container creation - that arrives in Stage 6.")
    return 0

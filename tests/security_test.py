"""Security tests: filesystem, execution and network/resource restrictions.

Every check runs a probe inside the real sandbox configuration, so a passing
test means the restriction was observed from inside the container - not that a
field was present in a request body.
"""

from __future__ import annotations

from sandbox import config
from sandbox.controller import Sandbox

from .support import facts

# --- filesystem ---------------------------------------------------------
_FILESYSTEM_PROBE = r'''
import json, os, subprocess

facts = {}
facts["uid"] = os.getuid()

def writable(path):
    try:
        open(os.path.join(path, ".probe"), "w").write("x")
        return True
    except OSError:
        return False

facts["root_writable"] = any(writable(p) for p in ("/", "/etc", "/usr", "/sandbox"))
facts["scratch_writable"] = writable("/sandbox/work")

watch = ["/Users", "/Volumes", "/private/etc/hosts",
         "/var/run/docker.sock", "/run/docker.sock"]
facts["host_visible"] = [p for p in watch if os.path.exists(p)]

try:
    open("/sandbox/program/main.py", "a").write("# tampered\n")
    facts["program_writable"] = True
except OSError:
    facts["program_writable"] = False

script = "/sandbox/work/probe.sh"
open(script, "w").write("#!/bin/sh\necho x\n")
os.chmod(script, 0o755)
try:
    subprocess.run([script], capture_output=True, timeout=5)
    facts["scratch_executable"] = True
except OSError:
    facts["scratch_executable"] = False

mounts = {}
for line in open("/proc/mounts"):
    parts = line.split()
    if len(parts) >= 3:
        mounts[parts[1]] = parts[2]
facts["scratch_fstype"] = mounts.get("/sandbox/work", "?")

print("FACTS=" + json.dumps(facts))
'''


def filesystem(client=None) -> list:
    """Filesystem isolation: read-only root, tmpfs scratch, no host paths."""
    result = _sandbox(client).run(_FILESYSTEM_PROBE, timeout=60)
    f = facts(result.stdout)

    if not f:
        return [("probe", False, "no facts: %s" % result.stderr[:100])]

    return [
        ("read-only root", not f.get("root_writable", True), "/, /etc, /usr immutable"),
        (
            "program mount read-only",
            not f.get("program_writable", True),
            "cannot modify %s" % config.SANDBOX_PROGRAM_DIR,
        ),
        (
            "tmpfs scratch",
            f.get("scratch_fstype") == "tmpfs",
            "%s is %s" % (config.SANDBOX_SCRATCH, f.get("scratch_fstype", "?")),
        ),
        ("scratch writable", f.get("scratch_writable", False), "temporary files work"),
        (
            "scratch not executable",
            not f.get("scratch_executable", True),
            "noexec enforced",
        ),
        (
            "no host paths",
            not f.get("host_visible"),
            "none visible" if not f.get("host_visible")
            else "visible: %s" % ", ".join(f["host_visible"]),
        ),
        (
            "no docker socket",
            not any("docker.sock" in p for p in f.get("host_visible", [])),
            "daemon unreachable from inside",
        ),
    ]


# --- execution ----------------------------------------------------------
_EXECUTION_PROBE = r'''
import json, os, subprocess

facts = {"uid": os.getuid()}

status = open("/proc/self/status").read()
for line in status.splitlines():
    for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if line.startswith(key + ":"):
            facts[key.lower()] = line.split()[1]
    if line.startswith("NoNewPrivs:"):
        facts["no_new_privs"] = int(line.split()[1])
    if line.startswith("Seccomp:"):
        facts["seccomp_mode"] = int(line.split()[1])

facts["visible_pids"] = sorted(int(p) for p in os.listdir("/proc") if p.isdigit())

def attempt(fn):
    try:
        fn()
        return True
    except (OSError, AttributeError):
        return False

facts["can_unshare_user"] = attempt(lambda: os.unshare(os.CLONE_NEWUSER))
facts["can_unshare_mount"] = attempt(lambda: os.unshare(os.CLONE_NEWNS))
facts["can_setuid_root"] = attempt(lambda: os.setuid(0))

try:
    proc = subprocess.run(
        ["/usr/bin/mount", "-t", "tmpfs", "none", "/mnt"],
        capture_output=True, text=True, timeout=5,
    )
    facts["can_mount"] = proc.returncode == 0
except OSError:
    facts["can_mount"] = False

print("FACTS=" + json.dumps(facts))
'''


def execution(client=None) -> list:
    """Execution restrictions: uid, capabilities, privs, seccomp, namespaces."""
    result = _sandbox(client).run(_EXECUTION_PROBE, timeout=60)
    f = facts(result.stdout)

    if not f:
        return [("probe", False, "no facts: %s" % result.stderr[:100])]

    def cap_empty(key):
        return f.get(key) == "0000000000000000"

    return [
        ("non-root user", f.get("uid") == 1000, "uid=%s (never 0)" % f.get("uid")),
        (
            "no capabilities",
            all(cap_empty(k) for k in ("capinh", "capprm", "capeff", "capbnd", "capamb")),
            "CapEff=%s CapBnd=%s" % (f.get("capeff"), f.get("capbnd")),
        ),
        (
            "no-new-privileges",
            f.get("no_new_privs") == 1,
            "NoNewPrivs=%s" % f.get("no_new_privs"),
        ),
        (
            "seccomp filter",
            f.get("seccomp_mode") == 2,
            "mode 2 (default profile active)",
        ),
        (
            "pid namespace",
            f.get("visible_pids") == [1],
            "sees %d process(es)" % len(f.get("visible_pids", [])),
        ),
        (
            "cannot create user namespace",
            not f.get("can_unshare_user"),
            "unshare(CLONE_NEWUSER) denied",
        ),
        (
            "cannot create mount namespace",
            not f.get("can_unshare_mount"),
            "unshare(CLONE_NEWNS) denied",
        ),
        ("cannot become root", not f.get("can_setuid_root"), "setuid(0) denied"),
        ("cannot mount", not f.get("can_mount"), "mount() denied"),
    ]


# --- network and resources ---------------------------------------------
_NETWORK_PROBE = r'''
import json, os, socket

facts = {"interfaces": sorted(os.listdir("/sys/class/net"))}

connected = []
for host, port in [("1.1.1.1", 443), ("8.8.8.8", 53)]:
    try:
        sock = socket.create_connection((host, port), timeout=3)
        sock.close()
        connected.append("%s:%d" % (host, port))
    except Exception:
        pass
facts["connected"] = connected

try:
    socket.gethostbyname("example.com")
    facts["dns"] = True
except Exception:
    facts["dns"] = False

print("FACTS=" + json.dumps(facts))
'''

_MEMORY_PROBE = r'''
blocks = []
print("allocating", flush=True)
while True:
    blocks.append(bytearray(1024 * 1024))
'''

_PIDS_PROBE = r'''
import json, os, time

children = 0
blocked = False
try:
    while True:
        pid = os.fork()
        if pid == 0:
            time.sleep(30)
            os._exit(0)
        children += 1
except OSError:
    blocked = True

print("FACTS=" + json.dumps({"children": children, "blocked": blocked}))
'''

_LOOP = (
    "import time\n"
    "t0 = time.monotonic()\n"
    "n = 0\n"
    "while time.monotonic() - t0 < 1:\n"
    "    n += 1\n"
    "print('ITER', n)\n"
)

_STUBS = (
    "gre0", "gretap0", "ip6tnl0", "sit0", "tunl0", "erspan0",
    "ip6gre0", "ip6_vti0", "ip_vti0", "bonding_masters",
)


def network(client=None) -> list:
    """Network isolation: no interface, no route, no DNS."""
    result = _sandbox(client).run(_NETWORK_PROBE, timeout=20)
    f = facts(result.stdout)

    interfaces = f.get("interfaces", [])
    real = [i for i in interfaces if i != "lo" and i not in _STUBS]

    return [
        (
            "no network interfaces",
            not real,
            "interfaces: %s" % ", ".join(interfaces) if interfaces else "none",
        ),
        (
            "cannot reach the internet",
            not f.get("connected"),
            "blocked 1.1.1.1:443, 8.8.8.8:53"
            if not f.get("connected")
            else "connected: %s" % ", ".join(f["connected"]),
        ),
        ("no dns", not f.get("dns"), "name resolution fails"),
    ]


def memory(client=None) -> list:
    """Memory ceiling: the kernel OOM-kills the program."""
    result = _sandbox(client).run(_MEMORY_PROBE, timeout=30)
    return [
        (
            "memory limit enforced",
            result.oom_killed and result.exit_code == 137,
            "OOM-killed at %dMB (exit 137)" % (config.MEMORY_LIMIT // (1024 * 1024)),
        )
    ]


def processes(client=None) -> list:
    """Pid ceiling: fork() past the limit returns EAGAIN."""
    result = _sandbox(client).run(_PIDS_PROBE, timeout=20)
    f = facts(result.stdout)
    children = f.get("children", 0)
    return [
        (
            "pids limit enforced",
            f.get("blocked", False) and children <= config.PIDS_LIMIT,
            "fork blocked after %d (limit %d)" % (children, config.PIDS_LIMIT),
        )
    ]


def cpu(client=None) -> list:
    """CPU quota: measure throttling against an unthrottled run."""
    free = _sandbox(client).run(_LOOP, timeout=20)
    slow = _throttled(0.1, client).run(_LOOP, timeout=20)

    free_n = _iterations(free.stdout)
    slow_n = _iterations(slow.stdout)
    ratio = (slow_n / free_n) if free_n else 0

    return [
        (
            "cpu quota throttles",
            0 < ratio < 0.5,
            "0.1 core ran %d vs %d (%.0f%%)" % (slow_n, free_n, ratio * 100),
        )
    ]


def timeout(client=None) -> list:
    """Deadline: the controller SIGKILLs a program that runs too long."""
    result = _sandbox(client).run(
        "import time\nprint('running', flush=True)\ntime.sleep(600)\n", timeout=2
    )
    return [
        (
            "timeout enforced",
            result.timed_out and result.exit_code == 137,
            "controller killed it after ~2s",
        )
    ]


# --- helpers ------------------------------------------------------------
def _sandbox(client=None) -> Sandbox:
    return Sandbox() if client is None else Sandbox(client=client)


def _throttled(cpus: float, client=None) -> Sandbox:
    """A sandbox whose CPU quota is small enough to actually bind."""

    class Throttled(Sandbox):
        def _payload(self):
            payload = super()._payload()
            payload["HostConfig"]["NanoCpus"] = int(cpus * 1_000_000_000)
            return payload

    return Throttled() if client is None else Throttled(client=client)


def _iterations(stdout: str) -> int:
    for line in stdout.splitlines():
        if line.startswith("ITER "):
            return int(line.split()[1])
    return 0

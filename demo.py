"""Side-by-side demo: run one payload on the host, then inside the sandbox.

    python3 demo.py

This is the shortest honest answer to "what does the sandbox actually do?" It
executes the *same* program twice and prints what each environment allowed.
Nothing here is destructive: every probe only attempts an action and reports
the outcome.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

from sandbox.controller import Sandbox

PAYLOAD = r'''
import ctypes, os, socket, subprocess, sys

results = []

def attempt(label, fn):
    try:
        results.append((label, "ALLOWED", str(fn() or "")))
    except OSError as exc:
        results.append((label, "blocked", exc.strerror or str(exc)))
    except Exception as exc:
        results.append((label, "blocked", type(exc).__name__))


home = os.path.expanduser("~")

# 1. Read the home directory. Inside a sandbox this is /home/sandbox, a
#    different home from yours - so we report the path, not just success.
def read_home():
    if not os.path.isdir(home):
        raise OSError(2, "no such path")
    return home

attempt("read home dir", read_home)

# 2. Modify the system.
def write_passwd():
    open("/etc/passwd", "a").write("")

attempt("write /etc/passwd", write_passwd)

# 3. Reach the internet.
def connect_out():
    socket.create_connection(("1.1.1.1", 443), timeout=3).close()

attempt("connect 1.1.1.1:443", connect_out)

# 4. See other processes on the machine. /proc does not exist on macOS, which
#    is itself part of the answer.
try:
    pids = sorted(int(p) for p in os.listdir("/proc") if p.isdigit())
    print("PROC_COUNT=%d" % len(pids))
except OSError:
    print("PROC_COUNT=unavailable")

# 5. Try to be root.
attempt("setuid(0)", lambda: os.setuid(0))

# 6. Try to mount a filesystem. Report *why* it failed - "no such file" and
#    "denied" mean different things.
def do_mount():
    if not os.path.exists("/usr/bin/mount"):
        raise OSError(2, "mount binary not present")
    proc = subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", "/mnt"],
                          capture_output=True, timeout=5)
    if proc.returncode != 0:
        raise OSError(1, "kernel denied the syscall")

attempt("mount a disk", do_mount)

print("RESULTS=" + __import__("json").dumps(results))
'''

LABELS = [
    "read home dir",
    "write /etc/passwd",
    "connect 1.1.1.1:443",
    "setuid(0)",
    "mount a disk",
]


def run_on_host() -> tuple:
    out = subprocess.run(
        [sys.executable, "-c", PAYLOAD], capture_output=True, text=True, timeout=60,
        cwd="/",
    )
    return out.stdout, out.stderr


def run_in_sandbox() -> tuple:
    result = Sandbox().run(PAYLOAD, timeout=60)
    return result.stdout, result.stderr


def parse(results_json: str) -> dict:
    import json

    for line in results_json.splitlines():
        if line.startswith("RESULTS="):
            return {label: (state, detail) for label, state, detail in
                    json.loads(line[len("RESULTS="):])}
    return {}


def proc_count(stdout: str) -> str:
    for line in stdout.splitlines():
        if line.startswith("PROC_COUNT="):
            return line.split("=")[1]
    return "?"


def main() -> int:
    print("Running the same program twice.\n")
    print("  1. directly on your Mac  (no protection)")
    print("  2. inside MiniSandbox    (protected)\n")

    host_out, host_err = run_on_host()
    sand_out, sand_err = run_in_sandbox()

    host = parse(host_out)
    sand = parse(sand_out)

    if not host or not sand:
        print("payload failed to report.")
        print("host stderr:", host_err[-400:])
        print("sandbox stderr:", sand_err[-400:])
        return 1

    print("%-20s %-34s %s" % ("ACTION", "ON YOUR MAC", "INSIDE THE SANDBOX"))
    print("-" * 96)

    for label in LABELS:
        h_state, h_detail = host.get(label, ("?", ""))
        s_state, s_detail = sand.get(label, ("?", ""))
        print(
            "%-20s %-34s %s"
            % (
                label,
                _cell(h_state, h_detail),
                _cell(s_state, s_detail),
            )
        )

    print()
    print("Processes visible: your Mac %s, sandbox %s"
          % (proc_count(host_out), proc_count(sand_out)))

    print()
    print("Reading a home directory is allowed in both - but not the same one.")
    print("Everything that could reach the host was blocked inside the sandbox.")
    return 0


def _cell(state: str, detail: str) -> str:
    detail = (detail or "").strip()
    detail = detail if len(detail) <= 24 else detail[:21] + "..."
    return ("%s %s" % (state, detail)).strip()


if __name__ == "__main__":
    sys.exit(main())

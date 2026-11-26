"""Adversarial program: try to reach or modify anything outside the sandbox."""

import os
import subprocess
import sys

results = []


def attempt(label, fn):
    try:
        detail = fn()
        results.append(("ALLOWED", label, detail))
    except OSError as exc:
        results.append(("BLOCKED", label, exc.strerror or str(exc)))


# 1. Modify the container image (should be read-only).
attempt("write /etc/passwd", lambda: open("/etc/passwd", "a").write("evil:x:0:0::/:/bin/sh\n"))
attempt("write /usr/bin/python3", lambda: open("/usr/bin/python3", "wb").write(b"x"))
attempt("write /sandbox", lambda: open("/sandbox/evil", "w").write("x"))
attempt("mkdir /opt/evil", lambda: os.mkdir("/opt/evil"))

# 2. Report whether sensitive host paths exist at all. These are Mac-only
#    locations: none of them can exist inside the container's filesystem tree.
host_paths = [
    "/Users",
    "/Volumes",
    "/private/etc/hosts",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/proc/1/root/Users",
]
host_visible = [p for p in host_paths if os.path.exists(p)]

# 3. Try to traverse out of the read-only program mount.
attempt("write through program mount", lambda: open("/sandbox/program/new.py", "w").write("x"))
attempt("traverse program mount", lambda: os.listdir("/sandbox/program/../../../../Users"))

# 4. Writable scratch should work, and should not persist after the run.
attempt("write scratch", lambda: open("/sandbox/work/ok.txt", "w").write("hello scratch"))
attempt("write /tmp", lambda: open("/tmp/ok.txt", "w").write("hello tmp"))

# 5. Scratch must not be executable: a file written there cannot become a
#    program. Executing it directly must fail with EACCES, which is what the
#    noexec mount option enforces.
def try_exec():
    path = "/sandbox/work/run.sh"
    with open(path, "w") as handle:
        handle.write("#!/bin/sh\necho pwned\n")
    os.chmod(path, 0o755)
    try:
        subprocess.run([path], capture_output=True, timeout=5)
    except OSError as exc:
        return "exec blocked: %s" % (exc.strerror or exc)
    return "exec permitted (bad)"


attempt("execute scratch file", try_exec)

print("=== image filesystem ===")
for outcome, label, detail in results[:4]:
    print("  %-8s %-24s %s" % (outcome, label, detail))

print("\n=== host paths inside container ===")
if host_visible:
    print("  VISIBLE (bad):", ", ".join(host_visible))
else:
    print("  none visible:", ", ".join(host_paths))

print("\n=== program mount ===")
for outcome, label, detail in results[4:6]:
    print("  %-8s %-24s %s" % (outcome, label, detail))

print("\n=== scratch ===")
for outcome, label, detail in results[6:]:
    print("  %-8s %-24s %s" % (outcome, label, detail))

print("\n=== capabilities ===")
cap = open("/proc/self/status").read()
for line in cap.splitlines():
    if line.startswith(("CapEff", "NoNewPrivs", "Seccomp:")):
        print(" ", line)

sys.exit(0)

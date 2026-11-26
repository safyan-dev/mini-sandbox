"""Adversarial program: try to escape the execution restrictions."""

import ctypes
import os
import signal
import subprocess

results = []


def attempt(label, fn):
    try:
        detail = fn()
        results.append(("ALLOWED", label, detail))
    except OSError as exc:
        results.append(("BLOCKED", label, exc.strerror or str(exc)))
    except Exception as exc:
        results.append(("BLOCKED", label, type(exc).__name__))


print("=== identity ===")
print("  uid:", os.getuid(), "gid:", os.getgid())
status = open("/proc/self/status").read()
for line in status.splitlines():
    if line.startswith(("CapEff", "CapBnd", "NoNewPrivs", "Seccomp:")):
        print(" ", line)

print("\n=== privilege escalation attempts ===")
attempt("setuid(0)", lambda: os.setuid(0))
attempt("setgid(0)", lambda: os.setgid(0))

# Try to regain capabilities via prctl/PR_CAPBSET? Requires CAP_SETPCAP.
libc = ctypes.CDLL("libc.so.6", use_errno=True)


def prctl_ambient_raise():
    r = libc.prctl(47, 0, 0, 0, 0)  # PR_CAP_AMBIENT_RAISE
    if r != 0:  # -1 means the kernel refused it
        raise OSError(ctypes.get_errno(), "prctl refused")
    return r


attempt("prctl(PR_CAP_AMBIENT_RAISE)", prctl_ambient_raise)

print("\n=== namespace escapes ===")
attempt("unshare(CLONE_NEWUSER)", lambda: os.unshare(os.CLONE_NEWUSER))
attempt("unshare(CLONE_NEWNS)", lambda: os.unshare(os.CLONE_NEWNS))
attempt("unshare(CLONE_NEWNET)", lambda: os.unshare(os.CLONE_NEWNET))
attempt("unshare(CLONE_NEWPID)", lambda: os.unshare(os.CLONE_NEWPID))

print("\n=== syscalls seccomp should block ===")


def syscall(name, *args):
    return libc.syscall(*args)


attempt("mount(2)", lambda: (
    subprocess.run(["/usr/bin/mount", "-t", "tmpfs", "none", "/mnt"],
                   capture_output=True, timeout=5, check=True)
))

# ptrace: try to attach to pid 1 (self). Seccomp blocks ptrace by default.
def try_ptrace():
    r = libc.ptrace(16, 1, None, None)  # PTRACE_ATTACH = 16
    if r != 0:
        raise OSError(ctypes.get_errno(), "ptrace failed")
    return r


attempt("ptrace(PTRACE_ATTACH, pid=1)", try_ptrace)

# bpf: blocked by default seccomp
def try_bpf():
    r = libc.syscall(321, 0, None, 0)  # bpf syscall number
    if r < 0:
        raise OSError(ctypes.get_errno(), "bpf failed")
    return r


attempt("bpf(2)", try_bpf)

print("\n=== process visibility ===")
pids = sorted(int(p) for p in os.listdir("/proc") if p.isdigit())
print("  visible pids:", pids)
print("  pid 1 is:", open("/proc/1/comm").read().strip())

print("\n=== seccomp blocks a privileged clone ===")
def try_clone_privileged():
    r = libc.syscall(220, 0x20000, 0, 0, 0, 0)  # clone(CLONE_NEWUSER)
    if r < 0:
        raise OSError(ctypes.get_errno(), "clone failed")
    return r


attempt("clone(CLONE_NEWUSER)", try_clone_privileged)

print("\n=== summary ===")
for outcome, label, detail in results:
    print("  %-8s %-32s %s" % (outcome, label, detail))

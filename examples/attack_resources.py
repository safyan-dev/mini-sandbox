"""Adversarial program: try to exhaust network, memory, CPU, processes and time."""

import os
import socket
import sys

mode = sys.argv[1] if len(sys.argv) > 1 else "all"


def network():
    print("=== network ===")
    interfaces = sorted(os.listdir("/sys/class/net"))
    print("  interfaces:", interfaces)

    for host, port in [("1.1.1.1", 443), ("8.8.8.8", 53), ("93.184.216.34", 80)]:
        try:
            sock = socket.create_connection((host, port), timeout=3)
            sock.close()
            print("  CONNECTED to %s:%d (bad)" % (host, port))
        except Exception as exc:
            print("  blocked %s:%d -> %s" % (host, port, type(exc).__name__))

    try:
        socket.gethostbyname("example.com")
        print("  DNS resolved (bad)")
    except Exception as exc:
        print("  DNS blocked ->", type(exc).__name__)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"x", ("1.1.1.1", 53))
        print("  UDP send allowed (bad)")
    except Exception as exc:
        print("  UDP blocked ->", type(exc).__name__)


def memory():
    print("=== memory ===")
    limit = 64 * 1024 * 1024
    blocks = []
    print("  limit should be ~64MB, allocating until killed")
    try:
        while True:
            blocks.append(bytearray(1024 * 1024))
    except MemoryError:
        print("  MemoryError after", len(blocks), "MB")


def cpu():
    print("=== cpu ===")
    import time

    start = time.monotonic()
    spins = 0
    while time.monotonic() - start < 2:
        spins += 1
    print("  spins in 2s:", spins, "(throttled by the CPU quota)")


def processes():
    print("=== processes ===")
    children = 0
    try:
        while True:
            pid = os.fork()
            if pid == 0:
                import time

                time.sleep(30)
                os._exit(0)
            children += 1
    except OSError as exc:
        print("  fork blocked after", children, "children ->", exc.strerror)
    finally:
        print("  total children created:", children)


def time_bomb():
    print("=== time ===")
    print("  sleeping forever; the controller must kill this", flush=True)
    import time

    time.sleep(600)
    print("  finished (bad: timeout did not work)")


modes = {
    "network": network,
    "memory": memory,
    "cpu": cpu,
    "processes": processes,
    "time": time_bomb,
}

if mode == "all":
    for name in ("network", "cpu", "processes"):
        modes[name]()
else:
    modes[mode]()

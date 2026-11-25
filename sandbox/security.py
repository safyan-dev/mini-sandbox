"""Security configuration.

The single place the sandbox's posture is expressed. Every value here becomes a
field in the Engine API request; the Engine turns those fields into kernel
syscalls inside the Linux VM. Nothing in this module enforces anything on its
own - it only declares what should be enforced.
"""

from __future__ import annotations

from . import config


def host_config(program_dir: str) -> dict:
    """The HostConfig for one sandbox container.

    Four groups of restrictions, each independent of the others:

      filesystem  immutable root, tmpfs-only scratch, program bind-mounted read-only
      execution   no capabilities, no-new-privileges, default seccomp, never privileged
      network     its own network namespace with no interface to send on
      resources   memory, cpu and pids cgroup ceilings

    They live together because they are one decision: what this container is
    allowed to do. Splitting them across the lifecycle would make it possible to
    create a container that silently misses one.
    """
    return {
        "AutoRemove": False,

        # --- filesystem isolation ---
        # The image filesystem becomes immutable. A program may read it but
        # cannot modify the interpreter, add binaries, or tamper with anything
        # that outlives the run.
        "ReadonlyRootfs": True,
        # The only writable locations are memory-backed tmpfs mounts. noexec
        # stops a written file from becoming a program; nosuid stops privilege
        # bits from mattering; size bounds memory use.
        "Tmpfs": {
            config.SANDBOX_SCRATCH: "rw,noexec,nosuid,nodev,size=%s,mode=1777"
            % config.SCRATCH_SIZE,
            config.SANDBOX_TMP: "rw,noexec,nosuid,nodev,size=%s,mode=1777"
            % config.SCRATCH_SIZE,
        },
        # The program arrives read-only from controller scratch. Not `$HOME`,
        # not Documents: a throwaway directory deleted along with the container.
        "Binds": ["%s:%s:ro" % (program_dir, config.SANDBOX_PROGRAM_DIR)],
        # Never bind the Docker socket: mounting it would hand the program
        # control of the daemon and therefore of the host.

        # --- execution restrictions ---
        # The image already runs as uid 1000, but that alone is not a guarantee:
        # Docker's default bounding set still includes ~14 capabilities.
        # Dropping ALL removes even the unused ones.
        "CapDrop": ["ALL"],
        # Privileged mode disables nearly every restriction (all capabilities,
        # device access, seccomp, AppArmor). It must never be reachable; being
        # explicit means a future change that enables it must delete this line.
        "Privileged": False,
        # PR_SET_NO_NEW_PRIVS: execve can never gain privileges from a
        # setuid/setgid binary or a file capability.
        "SecurityOpt": ["no-new-privileges:true"],
        # Docker's default seccomp profile is applied implicitly when no seccomp
        # option is given. It blocks ~44 syscalls (reboot, mount, ptrace, bpf,
        # kexec, ...). We rely on the default rather than pass "seccomp=default",
        # which the API rejects at start: it tries to parse the string as a
        # custom JSON profile.

        # --- network isolation ---
        # "none" gives the container its own network namespace with only a
        # loopback interface: no veth, no route to the host, no DNS, no
        # internet. This is not a firewall rule that could be bypassed - there
        # is no interface to send a packet on.
        "NetworkMode": "none",

        # --- resource limits (cgroup v2 in the VM) ---
        # Memory ceiling. Exceeding it triggers the kernel OOM killer.
        "Memory": config.MEMORY_LIMIT,
        # Swap equal to Memory so the ceiling cannot be dodged by spilling to
        # swap. By default Docker allows 2x memory in swap, which would make the
        # memory limit advisory.
        "MemorySwap": config.MEMORY_SWAP,
        # CPU ceiling in billionths of a core. Excess CPU time is throttled, so
        # a busy loop runs slower rather than hogging the VM.
        "NanoCpus": config.NANO_CPUS,
        # Task ceiling for the cgroup. fork() past it returns EAGAIN.
        "PidsLimit": config.PIDS_LIMIT,
    }

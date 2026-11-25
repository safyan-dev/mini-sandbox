# MiniSandbox

A small, dependency-free Python controller that runs **untrusted Python programs**
inside a restricted Linux container on macOS. The goal is education: see how
sandboxing actually works, not to build a product.

```
macOS host
  └── Python controller        creates / manages / destroys sandboxes
        └── Docker Desktop     Linux VM
              └── Linux sandbox container
                    └── untrusted Python program
```

macOS cannot run Linux kernel isolation primitives, so every restriction is
enforced **inside Docker Desktop's Linux VM**. The controller on the Mac talks
to the Docker Engine API over the daemon's Unix socket and does no enforcement
work itself.

## Requirements

- macOS
- Docker Desktop running (Linux container engine)
- Python 3.8+ (standard library only, no pip installs)

## Usage

```sh
python3 -m minisandbox doctor          # verify the macOS -> Docker Linux VM chain
python3 -m minisandbox build           # build + verify the sandbox image
python3 -m minisandbox verify          # re-check an existing sandbox image
python3 -m minisandbox check-filesystem # verify filesystem isolation in a real sandbox
python3 -m minisandbox run examples/hello.py
python3 -m minisandbox run examples/attack_filesystem.py --timeout 5
```

`doctor` verifies the whole chain: macOS host → Docker Desktop Linux VM →
container, and confirms that namespaces, cgroup v2 and seccomp are reachable.

## The sandbox image (Stage 2)

`docker/Dockerfile` defines `minisandbox/sandbox:latest`: Ubuntu 24.04 plus the
Python 3 interpreter and nothing else.

| Property | Why it matters |
|---|---|
| only `python3` installed, `--no-install-recommends` | smaller attack surface |
| `apt`, `dpkg` and `perl` removed | code cannot install anything |
| no `gcc`/`make`/`curl`/`wget`/`git` | code cannot build or download |
| setuid bits cleared | no binary can raise privileges |
| dedicated `sandbox` user (uid 1000), nologin | untrusted code is never root |
| nothing `COPY`ed from the host | no personal files or credentials |

## The controller (Stage 3)

Python owns five responsibilities and nothing else. It never isolates a
process; it asks the Engine for an environment and the Linux kernel enforces it.

| Responsibility | Where | What it does |
|---|---|---|
| Create | `Sandbox.create()` | `POST /containers/create`, then inject the program |
| Configure | `Sandbox._configure()` | build the request body (all security fields live here) |
| Execute | `Sandbox.execute()` | `POST /containers/{id}/start` |
| Monitor | `Sandbox.monitor()` | `POST /wait`, then demux the log stream |
| Destroy | `Sandbox.destroy()` | `DELETE /containers/{id}?force=1&v=1` |

`Sandbox.run()` chains all five, with `destroy()` in a `finally` block so a
container never outlives its program.

## Filesystem isolation (Stage 4)

The container root filesystem is immutable; the only writable paths are
memory-backed tmpfs mounts that vanish with the container.

| Setting | Effect |
|---|---|
| `ReadonlyRootfs: true` | image files cannot be modified or added to |
| program bind-mounted `:ro` from controller scratch | code cannot rewrite itself |
| `Tmpfs` `/sandbox/work`, `/tmp` (`noexec,nosuid,nodev`) | scratch exists but cannot become an exploit |
| no `$HOME`, no `/Volumes`, no host dirs in `Binds` | host files are unreachable |
| no `/var/run/docker.sock` mount | the program cannot control the daemon |

Note: a read-only rootfs means the Engine rejects `PUT /archive`, so the program
is staged in a throwaway `tempfile.mkdtemp()` directory and bind-mounted. That
directory is deleted in `destroy()`.

`check-filesystem` runs a probe inside the real sandbox and asserts each of the
properties above.

## Features (built one stage at a time)

| # | Feature               | Status |
|---|-----------------------|--------|
| 1 | Sandbox creation      | done (Stage 3) |
| 2 | Code execution        | done (Stage 3) |
| 3 | Filesystem isolation  | done (Stage 4) |
| 4 | Network isolation     | **not yet** — the sandbox can still reach the internet |
| 5 | Process isolation     | partial — pid namespace, unprivileged user; `cap_drop`/`no-new-privileges` in Stage 5 |
| 6 | Resource limits       | **not yet** — no cgroup limits, a program can exhaust the VM |
| 7 | Execution timeout     | partial — controller-side wait timeout, container is destroyed |
| 8 | Sandbox destruction   | done (Stage 3) |

## Layout

```
docker/
  Dockerfile      sandbox image definition (Stage 2)
minisandbox/
  cli.py          command-line entry point
  engine.py       Docker Engine API client over the Unix socket
  environment.py  Stage 1 environment verification (`doctor`)
  image.py        Stage 2 image build + verification
  sandbox.py      lifecycle: create/configure/execute/monitor/destroy
  filesystem.py   Stage 4 filesystem isolation verification
  config.py       image names, mount paths and static settings
examples/
  hello.py               prints identity and kernel info
  fail.py                writes to both streams and exits non-zero
  crash.py               raises an unhandled exception
  attack_filesystem.py   tries to escape or modify the filesystem
```

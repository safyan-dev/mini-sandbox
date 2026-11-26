# MiniSandbox

Run untrusted Python on your Mac without trusting it.

A small, dependency-free controller that gives a program its own private Linux
machine — one it can break, fill up, or misbehave inside, and still leave your
computer untouched.

---

## What is a sandbox?

A sandbox is a **lie told to a program**. It gets a whole computer that feels
normal, while every wall it thinks is real is a boundary the kernel won't let it
cross.

The key idea: you don't *block* a program from reading your files. You give it a
world where **those files were never created**. Subtraction, not policing.

Your Mac can't do this alone — macOS has no Linux security boundaries. So Docker
Desktop runs a small Linux VM, and that VM's kernel is where every restriction
actually lives.

```
   Python controller        decides what to restrict   (writes JSON)
          │
   Docker Engine            translates JSON into syscalls
          │
   Linux kernel             enforces it  ← the only real enforcer
          │
   untrusted program        runs inside the fence
```

That last line is the whole design: **Python never isolates anything.** It only
asks, and checks that it was granted.

---

## What's inside the fence

Seven independent promises. Each one answers a different question.

| Question | Answer | How |
|---|---|---|
| Who does it think it is? | a nobody user | `uid 1000`, never root |
| What can it see or change? | almost nothing | read-only root, RAM-only scratch |
| Can it talk to anyone? | no | own network namespace, no interface |
| What can it ask the kernel for? | very little | no capabilities, seccomp filter |
| How much can it take? | a fixed budget | 64MB, 1 CPU, 64 processes |
| How long can it run? | 10 seconds | then the controller kills it |
| Does it survive the run? | no | the container is deleted, always |

Two of those — the **time limit** and the **cleanup** — are done by Python
itself. Everything else is the kernel doing the work. That split is the most
useful thing to take away from this project.

---

## Quick start

```sh
python3 cli.py doctor             # is the Mac → Linux VM → kernel chain alive?
python3 cli.py build              # build the sandbox image, then verify it
python3 cli.py run examples/hello.py
python3 -m tests                  # 38 checks across 14 test groups
```

Run `doctor` first. If it fails, nothing else can work — everything above it is a
promise the kernel has to keep.

### See it work in one command

```sh
python3 demo.py
```

`demo.py` runs the *same* program twice — once on your Mac, once in the sandbox —
and prints what each one allowed. It's safe: every probe only tries something and
reports the outcome.

```
ACTION               ON YOUR MAC                  INSIDE THE SANDBOX
read home dir        ALLOWED /Users/<you>         ALLOWED /home/sandbox
connect 1.1.1.1:443  ALLOWED                      blocked Network unreachable
mount a disk         blocked mount binary missing  blocked kernel denied
```

Reading a home directory works in both — but not the same one. Everything that
could reach the host was stopped.

---

## How it was tested

Not *"does it work"* — **"does it hold."** A test that says *"I turned on the
read-only filesystem"* proves nothing. A test that **tries to write** and reads
the refusal proves everything.

Three questions, asked of every feature:

1. **Does it run?** A normal program exits cleanly.
2. **Does it report?** A crash gives exit 1 and a real traceback.
3. **Does it resist?** Every attack comes back `blocked`.

Two testing habits did most of the work:

- **Attack it.** A fork bomb, a 200MB allocation, `setuid(0)`, a `mount` call.
  If it isn't blocked, the fence isn't there.
- **Remove a control and watch a number change.** This is the honest test:

| Config | Capabilities | NoNewPrivs | Seccomp | `unshare` |
|---|---|---|---|---|
| Normal | `0` | 1 | 2 | blocked |
| No `CapDrop` | `a80425fb` | 1 | 2 | blocked |
| **Privileged** | `1ffffffffff` | 0 | **0** | **allowed** |

One flag turned three walls off at once. That's why it's worth knowing exactly
which single setting would undo your sandbox.

---

## Three things worth remembering

**A limit with a loophole isn't a limit.**
The memory ceiling was 64MB, but Docker allowed 2× that in swap — so a program
could spill to disk and ignore it. Fixed by setting swap equal to memory. The
same bug exists in every rate limiter that forgets retries.

**A configured limit is not a proven limit.**
At 1 CPU on a 10-CPU machine, a busy loop never touches the ceiling. The test
passed while proving nothing. Shrinking the quota to 0.1 core finally showed
10% throughput. An alarm that never fires is not a working alarm.

**You can't stop a program leaving. You make leaving meaningless.**
There is no "forbid" switch. Instead the path doesn't exist, the permission bit
is gone, and the syscall is filtered — three independent reasons the same escape
fails.

---

## Project layout

```
cli.py            entry point: doctor | build | verify | run | check
demo.py           the same attack, on your Mac and in the sandbox
sandbox/          lifecycle + every restriction
  controller.py     create → execute → monitor → destroy
  security.py       all restrictions live here, nowhere else
  executor.py       delivers the program and starts it
  monitor.py        timeout, output, OOM detection
  engine.py         talks to the Docker Engine API
environment/      the Linux image
  Dockerfile        Ubuntu + python3, minus apt, minus setuid
tests/            security and execution tests
examples/         demo programs and attack programs
```

---

## Limits & non-goals

One image, one sandbox, one program at a time. No GUI, no multi-user, no cloud,
no Kubernetes, no multi-language support. This exists to understand sandboxing —
not to replace one.

## Requirements

- macOS
- Docker Desktop running (Linux container engine)
- Python 3.8+ — standard library only, no `pip install`

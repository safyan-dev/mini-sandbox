"""MiniSandbox command line.

    python3 cli.py doctor            verify macOS -> Linux VM -> kernel
    python3 cli.py build             build and verify the sandbox image
    python3 cli.py verify            re-check an existing image
    python3 cli.py run FILE          execute a program in a sandbox
    python3 cli.py check             run the security and execution tests
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from environment import doctor, image
from sandbox import config, engine
from sandbox.controller import Sandbox
from tests.__main__ import main as run_tests


def _print_checks(checks) -> int:
    failed = 0
    for name, ok, detail in checks:
        print("  [%s] %-30s %s" % ("PASS" if ok else "FAIL", name, detail))
        if not ok:
            failed += 1
    return failed


def _build(args) -> int:
    client = engine.Client()
    print("Building sandbox image %s" % config.SANDBOX_IMAGE)
    try:
        image.build(client, no_cache=args.no_cache)
    except engine.EngineError as exc:
        print("build failed: %s" % exc)
        return 1

    meta = image.info(client)
    print("\nImage:   %s" % config.SANDBOX_IMAGE)
    print("Id:      %s" % meta["id"])
    print("Size:    %s" % meta["size"])
    print("Created: %s" % meta["created"])

    print("\nVerifying image contents")
    failed = _print_checks(image.verify(client))
    if failed:
        print("\n%d check(s) failed" % failed)
        return 1
    print("\nImage ready.")
    return 0


def _verify(_args) -> int:
    client = engine.Client()
    print("Verifying image %s\n" % config.SANDBOX_IMAGE)
    failed = _print_checks(image.verify(client))
    if failed:
        print("\n%d check(s) failed" % failed)
        return 1
    print("\nImage verified.")
    return 0


def _run(args) -> int:
    path = Path(args.file)
    if not path.is_file():
        print("no such file: %s" % path)
        return 2

    code = path.read_text(encoding="utf-8")

    print("Sandbox: %s" % config.SANDBOX_IMAGE)
    print("Program: %s (%d bytes)" % (path, len(code)))
    print("Lifecycle: create -> configure -> execute -> monitor -> destroy\n")

    box = Sandbox(program_args=args.args)
    try:
        result = box.run(code, timeout=args.timeout)
    except engine.EngineError as exc:
        print("sandbox error: %s" % exc)
        return 1

    if result.stdout:
        sys.stdout.write(result.stdout)
        if not result.stdout.endswith("\n"):
            sys.stdout.write("\n")
    if result.stderr:
        sys.stderr.write(result.stderr)
        if not result.stderr.endswith("\n"):
            sys.stderr.write("\n")

    if result.timed_out:
        state = "timeout - killed by controller"
    elif result.oom_killed:
        state = "OOM - killed by kernel"
    else:
        state = "exited"

    print(
        "\nexit %d  |  %.2fs  |  %s  |  container %s destroyed"
        % (result.exit_code, result.duration, state, result.container_id[:12])
    )
    return result.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="minisandbox",
        description="Run untrusted Python inside a restricted Linux container.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="verify macOS -> Docker Linux VM -> kernel")

    build = sub.add_parser("build", help="build and verify the sandbox image")
    build.add_argument("--no-cache", action="store_true")

    sub.add_parser("verify", help="re-check an existing sandbox image")

    sub.add_parser("check", help="run the security and execution tests")

    run = sub.add_parser("run", help="execute a Python file in a sandbox")
    run.add_argument("file", help="path to the .py program")
    run.add_argument("--timeout", type=float, default=config.DEFAULT_TIMEOUT)

    return parser


def main(argv: list | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)

    # Everything after a literal "--" goes to the sandboxed program, not to
    # argparse. Without the split, argparse would try to parse the program's
    # own flags as sandbox flags.
    program_args = []
    if "--" in raw:
        split = raw.index("--")
        raw, program_args = raw[:split], raw[split + 1:]

    args = build_parser().parse_args(raw)
    args.args = program_args

    if args.command == "doctor":
        return doctor.run()
    if args.command == "build":
        return _build(args)
    if args.command == "verify":
        return _verify(args)
    if args.command == "check":
        return run_tests([])
    if args.command == "run":
        return _run(args)

    return 2


if __name__ == "__main__":
    sys.exit(main())

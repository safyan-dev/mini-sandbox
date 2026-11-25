"""Command-line entry point for the MiniSandbox controller."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import config, engine, environment, image, sandbox


def _print_checks(checks) -> int:
    failed = 0
    for name, ok, detail in checks:
        print("  [%s] %-22s %s" % ("PASS" if ok else "FAIL", name, detail))
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
    print("\nImage ready: minimal Ubuntu + Python 3, runs as unprivileged user.")
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

    box = sandbox.Sandbox()
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

    print(
        "\nexit %d  |  %.2fs  |  container %s destroyed"
        % (result.exit_code, result.duration, result.container_id[:12])
    )
    return result.exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="minisandbox",
        description="Run untrusted Python inside a restricted Linux container.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser(
        "doctor", help="verify the macOS -> Docker Linux VM -> kernel chain"
    )
    doctor.add_argument("-v", "--verbose", action="store_true")

    build = sub.add_parser("build", help="build and verify the sandbox image")
    build.add_argument("--no-cache", action="store_true")

    sub.add_parser("verify", help="re-check an existing sandbox image")

    run = sub.add_parser("run", help="execute a Python file in a sandbox")
    run.add_argument("file", help="path to the .py program")
    run.add_argument("--timeout", type=float, default=60.0)

    return parser


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "doctor":
        return environment.doctor(verbose=args.verbose)
    if args.command == "build":
        return _build(args)
    if args.command == "verify":
        return _verify(args)
    if args.command == "run":
        return _run(args)

    return 2


if __name__ == "__main__":
    sys.exit(main())
